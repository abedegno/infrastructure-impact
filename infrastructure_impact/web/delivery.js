/* Publication-bound static transport. No vendor access, private storage or writes. */
async function createStaticDelivery(fetchPart, siteBase) {
  const response = await fetchPart(siteBase + 'data/index.json', { cache: 'no-cache' });
  if (!response.ok) throw Error('Publication index unavailable. Reload after deployment.');
  const text = await response.text();
  if (new TextEncoder().encode(text).length > 2000000)
    throw Error('Publication index exceeds budget');
  const index = JSON.parse(text);
  if (
    index.schema_version !== 1 ||
    !/^[a-f0-9]{32}$/.test(index.publication?.id || '') ||
    !index.generated_at ||
    !index.cohorts
  )
    throw Error('Invalid publication index');
  const cache = new Map();
  async function read(descriptor, full = false) {
    if (
      !descriptor ||
      !(full
        ? descriptor.path === 'snapshot.json'
        : /^data\/[a-f0-9]{64}\.json$/.test(descriptor.path)) ||
      !/^[a-f0-9]{64}$/.test(descriptor.sha256) ||
      !Number.isInteger(descriptor.bytes) ||
      descriptor.bytes < 1 ||
      (!full &&
        (descriptor.bytes > 8000000 || descriptor.path !== `data/${descriptor.sha256}.json`))
    )
      throw Error('Invalid evidence part descriptor');
    const key = descriptor.path;
    if (!cache.has(key))
      cache.set(
        key,
        (async () => {
          const r = await fetchPart(siteBase + key);
          if (!r.ok) throw Error('Evidence part unavailable. Reload after deployment.');
          const raw = new Uint8Array(await r.arrayBuffer());
          if (raw.length !== descriptor.bytes) throw Error('Evidence part size mismatch');
          const digest = Array.from(
            new Uint8Array(await crypto.subtle.digest('SHA-256', raw)),
            (b) => b.toString(16).padStart(2, '0'),
          ).join('');
          if (digest !== descriptor.sha256) throw Error('Evidence part fingerprint mismatch');
          const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
          if (
            value.publication?.id !== index.publication.id ||
            value.generated_at !== index.generated_at
          )
            throw Error('Mixed publication generations. Reload after deployment.');
          if (!full && value.schema_version !== 1) throw Error('Unsupported evidence part version');
          return full ? value : value.data;
        })().catch((error) => {
          cache.delete(key);
          throw error;
        }),
      );
    return cache.get(key);
  }
  const common = await read(index.bootstrap);
  async function parts(descriptors, requireArray = false) {
    const unique = [...new Map(descriptors.map((d) => [d.path, d])).values()];
    const results = new Array(unique.length);
    let cursor = 0;
    await Promise.all(
      Array.from({ length: Math.min(6, unique.length) }, async () => {
        while (cursor < unique.length) {
          const i = cursor++;
          results[i] = await read(unique[i]);
          if (requireArray && !Array.isArray(results[i])) throw Error('Invalid study part array');
        }
      }),
    );
    return results.flat();
  }
  const load = async function (ids, includeChanges = false) {
    const cohort = [...new Set(ids ?? Object.keys(common.benchmark_cohort))].sort();
    if (cohort.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw Error('Invalid CVE cohort');
    // Selecting the entire archive is an explicit large download. The default and
    // custom cohorts never fetch the compatibility snapshot.
    if (
      cohort.length === common.all_cves.length &&
      cohort.every((id, i) => id === common.all_cves[i])
    )
      return read(index.full, true);
    if (cohort.length > 200) throw Error('Select up to 200 CVEs, or the whole archive');
    if (
      cohort.some(
        (id) =>
          (common.all_cves.includes(id) || Object.hasOwn(common.benchmark_cohort, id)) &&
          !Object.hasOwn(index.cohorts, id),
      )
    )
      throw Error('Publication cohort index is incomplete');
    const rows = await parts(cohort.flatMap((id) => index.cohorts[id] || []));
    const records = new Map(),
      events = new Map(),
      coverage = [],
      cases = new Map();
    for (const row of rows) {
      if (row.kind === 'record') {
        if (!records.has(row.index))
          records.set(row.index, { record: row.record, assessments: new Map() });
        for (const [i, a] of row.assessments) records.get(row.index).assessments.set(i, a);
      } else if (row.kind === 'timeline') events.set(row.index, row.value);
      else if (row.kind === 'coverage') coverage.push(row.value);
      else if (row.kind === 'scorecard') {
        if (!cases.has(row.vendor)) cases.set(row.vendor, []);
        cases.get(row.vendor).push(row.value);
      } else throw Error('Unsupported evidence row');
    }
    return {
      ...common,
      records: [...records]
        .sort(([a], [b]) => a - b)
        .map(([, r]) => ({
          ...r.record,
          assessments: [...r.assessments].sort(([a], [b]) => a - b).map(([, a]) => a),
        })),
      coverage,
      timeline: {
        ...common.timeline,
        events: [...events].sort(([a], [b]) => a - b).map(([, e]) => e),
      },
      scorecards: {
        ...common.scorecards,
        vendors: common.scorecards.vendors.map((v) => ({ ...v, cases: cases.get(v.vendor) || [] })),
      },
      changes: includeChanges ? await parts(index.changes) : [],
    };
  };
  load.publication = index.publication;
  load.generated_at = index.generated_at;
  function studyIndex() {
    if (!Object.hasOwn(index, 'switching')) return null;
    const contracts = window.InfrastructureSwitchingContracts;
    contracts.validate('static-index-v1.json', index);
    const declared = index.switching.claims.flatMap((part) => part.claim_ids);
    if (new Set(declared).size !== declared.length) throw Error('Duplicate declared study claims');
    return index.switching;
  }
  async function readClaims(entry) {
    const rows = await read(entry.part);
    window.InfrastructureSwitchingContracts.validate(
      'switching-evidence-v1.json',
      rows,
      '/properties/claims',
    );
    const actual = rows.map((c) => c.claim_id);
    if (
      new Set(actual).size !== actual.length ||
      actual.length !== entry.claim_ids.length ||
      actual.some((id, i) => id !== entry.claim_ids[i])
    )
      throw Error('Study claim part membership mismatch');
    return rows;
  }
  async function claimParts(entries) {
    const results = new Array(entries.length);
    let cursor = 0;
    await Promise.all(
      Array.from({ length: Math.min(6, entries.length) }, async () => {
        while (cursor < entries.length) {
          const i = cursor++;
          results[i] = await readClaims(entries[i]);
        }
      }),
    );
    return results.flat();
  }
  load.switchingSummary = async () => {
    const study = studyIndex();
    if (!study) return null;
    const result = await read(study.summary);
    window.InfrastructureSwitchingContracts.summary(result, index);
    return JSON.parse(JSON.stringify(result));
  };
  load.switchingClaims = async (ids) => {
    const study = studyIndex();
    if (!study) throw Error('Switching unavailable');
    if (
      !Array.isArray(ids) ||
      ids.some((id) => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))
    )
      throw Error('Invalid study claim IDs');
    const requested = new Set(ids);
    const selected = study.claims.filter((p) => p.claim_ids.some((id) => requested.has(id)));
    const rows = await claimParts(selected);
    const found = rows.filter((c) => requested.has(c.claim_id));
    if (found.length !== requested.size) throw Error('Missing study claims');
    return JSON.parse(JSON.stringify(found));
  };
  async function hydrateSwitching() {
    const study = studyIndex();
    if (!study) return null;
    const contracts = window.InfrastructureSwitchingContracts;
    const summary = await load.switchingSummary();
    const metadata = await read(study.inputs);
    contracts.header(metadata, index, summary.selection.definition_sha256);
    const claims = await claimParts(study.claims);
    const entries = await parts(study.kev_entries, true);
    if (
      entries.some(
        (e) => !e || typeof e !== 'object' || Object.keys(e).sort().join(',') !== 'cve_id,entry',
      ) ||
      new Set(entries.map((e) => e.cve_id)).size !== entries.length
    )
      throw Error('Invalid KEV entry parts');
    const details = await parts(study.evidence_metadata, true);
    if (
      details.some(
        (d) =>
          !d ||
          typeof d !== 'object' ||
          Object.keys(d).sort().join(',') !== 'kind,value' ||
          !['coverage', 'score_availability'].includes(d.kind),
      ) ||
      (!study.has_score_availability && details.some((d) => d.kind === 'score_availability'))
    )
      throw Error('Invalid study metadata');
    // Reconstruct fresh objects only after validating the cached strict header.
    const evidence = {
      ...metadata.evidence,
      claims,
      coverage: details.filter((d) => d.kind === 'coverage').map((d) => d.value),
    };
    if (study.has_score_availability)
      evidence.score_availability = details
        .filter((d) => d.kind === 'score_availability')
        .map((d) => d.value);
    const report = {
      ...summary,
      inputs: {
        evidence,
        kev: {
          ...metadata.kev,
          entries: Object.fromEntries(entries.map((e) => [e.cve_id, e.entry])),
        },
      },
    };
    delete report.representation;
    return window.InfrastructureSwitching.prepareReport(report);
  }
  let switchingPromise;
  load.switchingReport = () => {
    if (!switchingPromise)
      switchingPromise = hydrateSwitching().catch((error) => {
        switchingPromise = null;
        throw error;
      });
    return switchingPromise;
  };
  return load;
}
