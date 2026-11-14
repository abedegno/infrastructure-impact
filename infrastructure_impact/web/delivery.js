/* Publication-bound static transport. No vendor access, private storage or writes. */
async function createStaticDelivery(fetchPart, siteBase) {
  const response = await fetchPart(siteBase + 'data/index.json', { cache: 'no-cache' });
  if (!response.ok) throw Error('Publication index unavailable. Reload after deployment.');
  async function boundedBytes(response, max, options = {}) {
    if (!response.body?.getReader) {
      const raw = new Uint8Array(
        await (options.operation
          ? options.operation.run(response.arrayBuffer())
          : response.arrayBuffer()),
      );
      if (raw.length > max) throw Error('Evidence response exceeds budget');
      return raw;
    }
    const reader = response.body.getReader(),
      chunks = [];
    let size = 0,
      complete = false;
    try {
      for (;;) {
        const entry = await (options.operation
          ? options.operation.run(reader.read())
          : reader.read());
        if (entry.done) {
          complete = true;
          break;
        }
        size += entry.value.length;
        if (size > max) throw Error('Evidence response exceeds budget');
        chunks.push(entry.value);
      }
    } finally {
      if (!complete) options.operation?.close();
      // A response's cancel promise is advisory, not a cleanup dependency.
      try {
        Promise.resolve(reader.cancel()).catch(() => {});
      } catch {}
      try {
        reader.releaseLock();
      } catch {}
    }
    const raw = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      raw.set(chunk, offset);
      offset += chunk.length;
    }
    return raw;
  }
  const text = response.body?.getReader
    ? new TextDecoder('utf-8', { fatal: true }).decode(await boundedBytes(response, 2000000))
    : await response.text();
  if (new TextEncoder().encode(text).length > 2000000)
    throw Error('Publication index exceeds budget');
  const decodedIndex = window.InfrastructureJSON.parse(text),
    index =
      decodedIndex.schema_version === 2
        ? window.InfrastructureJSON.parseStrict(text, { transport: true })
        : decodedIndex;
  if (
    ![1, 2].includes(index.schema_version) ||
    !/^[a-f0-9]{32}$/.test(index.publication?.id || '') ||
    !index.generated_at ||
    !index.cohorts
  )
    throw Error('Invalid publication index');
  const cache = new Map(),
    requestSlots = index.schema_version === 2 ? window.InfrastructureJSON.requestPool() : null;
  async function read(descriptor, full = false, options = {}) {
    if (
      !descriptor ||
      !(full
        ? descriptor.path === (full === 'catalog' ? 'publication-v2.json' : 'snapshot.json')
        : /^data\/[a-f0-9]{64}\.json$/.test(descriptor.path)) ||
      !/^[a-f0-9]{64}$/.test(descriptor.sha256) ||
      !Number.isInteger(descriptor.bytes) ||
      descriptor.bytes < 1 ||
      (!full &&
        (descriptor.bytes > 8000000 || descriptor.path !== `data/${descriptor.sha256}.json`))
    )
      throw Error('Invalid evidence part descriptor');
    const key = `${descriptor.path}:${descriptor.sha256}:${descriptor.bytes}`;
    if (!cache.has(key))
      cache.set(
        key,
        (async () => {
          if (index.schema_version === 2) await requestSlots.acquire(options.operation?.signal);
          try {
            const request = fetchPart(siteBase + descriptor.path, {
              signal: options.operation?.signal,
            });
            const r = await (options.operation ? options.operation.run(request) : request);
            if (!r.ok) throw Error('Evidence part unavailable. Reload after deployment.');
            const raw =
              index.schema_version === 2
                ? await boundedBytes(r, full === 'catalog' ? 2000000 : descriptor.bytes, options)
                : new Uint8Array(await r.arrayBuffer());
            if (full === 'catalog' && raw.length > 2000000)
              throw Error('Publication catalog exceeds budget');
            if (raw.length !== descriptor.bytes) throw Error('Evidence part size mismatch');
            const digest = Array.from(
              new Uint8Array(await crypto.subtle.digest('SHA-256', raw)),
              (b) => b.toString(16).padStart(2, '0'),
            ).join('');
            if (digest !== descriptor.sha256) throw Error('Evidence part fingerprint mismatch');
            const value = (
              index.schema_version === 2
                ? window.InfrastructureJSON.parseStrict
                : window.InfrastructureJSON.parse
            )(
              new TextDecoder('utf-8', { fatal: true }).decode(raw),
              index.schema_version === 2
                ? { transport: full === 'catalog' ? true : (path) => path[0] !== 'data' }
                : undefined,
            );
            if (
              value.publication?.id !== index.publication.id ||
              value.publication?.advisory_schema_version !==
                index.publication.advisory_schema_version ||
              value.generated_at !== index.generated_at
            )
              throw Error('Mixed publication generations. Reload after deployment.');
            if (!full && value.schema_version !== 1)
              throw Error('Unsupported evidence part version');
            return full ? value : value.data;
          } finally {
            if (index.schema_version === 2) requestSlots.release();
          }
        })().catch((error) => {
          cache.delete(key);
          throw error;
        }),
      );
    if (index.schema_version === 2) {
      try {
        return await cache.get(key);
      } finally {
        cache.delete(key);
      }
    }
    return cache.get(key);
  }
  let publicationV2 = null;
  if (index.schema_version === 2) {
    window.InfrastructureSwitchingContracts.validate('static-index-v2.json', index);
    const catalog = await read(index.publication_v2, 'catalog');
    publicationV2 = await window.InfrastructurePublicationV2.open(
      (path, options) => fetchPart(siteBase + path, options),
      catalog,
      index,
      {
        requestSlots,
        cohortReader: ({ cohort, fields, ...options }) =>
          boundedCohort(cohort, false, fields, options),
      },
    );
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
  let evidencePromise;
  async function currentEvidence(options = {}) {
    if (!evidencePromise)
      evidencePromise = (async () => {
        const hasCapability = Object.hasOwn(index, 'current_evidence'),
          hasMarker = Object.hasOwn(common, 'current_evidence_version');
        if (hasCapability !== hasMarker || (hasMarker && common.current_evidence_version !== 1))
          throw Error('Required current-evidence capability unavailable');
        if (!Object.hasOwn(index, 'current_evidence'))
          return window.InfrastructureCurrentEvidence.unavailable(
            index.publication,
            index.generated_at,
          );
        window.InfrastructureSwitchingContracts.validate(
          index.schema_version === 2 ? 'static-index-v2.json' : 'static-index-v1.json',
          index,
        );
        const capability = index.current_evidence;
        const report = validateCurrentEvidence(
          await read(capability.report, false, options),
          index.publication,
          index.generated_at,
        );
        const ids = capability.retained.flatMap((p) => p.decision_ids),
          expected = report.decisions.map((d) => d.decision_id);
        if (
          new Set(ids).size !== ids.length ||
          ids.length !== expected.length ||
          expected.some((id) => !ids.includes(id))
        )
          throw Error('Incomplete retained part membership');
        // Validate the complete routing catalogue before any descriptor can be
        // skipped. Literal record validation still happens only on explicit load.
        const catalogue = common.retained_index,
          decisions = new Map(report.decisions.map((d) => [d.decision_id, d])),
          routing = new Map();
        if (
          !Array.isArray(catalogue) ||
          catalogue.length > 1000 ||
          catalogue.length !== expected.length
        )
          throw Error('Incomplete retained routing catalogue');
        for (const row of catalogue) {
          const decision = decisions.get(row?.decision_id);
          if (
            !decision ||
            routing.has(row.decision_id) ||
            row.vendor !== decision.vendor ||
            !Array.isArray(row.cves) ||
            new Set(row.cves).size !== row.cves.length ||
            row.cves.some((id) => typeof id !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(id)) ||
            !Array.isArray(row.assessments) ||
            row.assessments.some((a) => !a || !row.cves.includes(a.cve_id))
          )
            throw Error('Invalid retained routing catalogue membership');
          routing.set(row.decision_id, row.cves);
        }
        for (const descriptor of capability.retained) {
          const cves = [
              ...new Set(descriptor.decision_ids.flatMap((id) => routing.get(id))),
            ].sort(),
            declared = [...descriptor.cve_ids].sort();
          if (cves.length !== declared.length || cves.some((id, i) => id !== declared[i]))
            throw Error('Retained CVE routing mismatch');
        }
        return report;
      })().catch((error) => {
        evidencePromise = null;
        throw error;
      });
    return evidencePromise;
  }
  async function boundedCohort(ids, includeChanges = false, fields = null, options = {}) {
    if (!options.operation)
      return window.InfrastructurePublicationV2.consume(options, (next) =>
        boundedCohort(ids, includeChanges, fields, next),
      );
    const json = window.InfrastructureJSON,
      max = Math.min(options.max_bytes ?? 128000000, 128000000),
      quota = json.budget(max);
    const cohort = [...new Set(ids ?? Object.keys(common.benchmark_cohort))].sort();
    if (cohort.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw Error('Invalid CVE cohort');
    const whole =
      cohort.length > 0 &&
      cohort.length === common.all_cves.length &&
      cohort.every((id, i) => id === common.all_cves[i]);
    if (whole && !fields)
      return publicationV2.materializeRoot('snapshot.json', { ...options, max_bytes: max });
    if (cohort.length > 200 && !whole) throw Error('Select up to 200 CVEs, or the whole archive');
    if (
      cohort.some(
        (id) =>
          (common.all_cves.includes(id) || Object.hasOwn(common.benchmark_cohort, id)) &&
          !Object.hasOwn(index.cohorts, id),
      )
    )
      throw Error('Publication cohort index is incomplete');
    const wanted = fields ? new Set(fields) : null,
      needs = (k) => !wanted || wanted.has(k),
      result = {};
    quota.charge(2);
    let fieldCount = 0;
    function add(key, value) {
      quota.charge(
        json.stringBytes(key) +
          1 +
          (fieldCount++ ? 1 : 0) +
          json.measure(value, null, '', quota.remaining),
      );
      Object.defineProperty(result, key, {
        value: json.clone(value),
        enumerable: true,
        writable: true,
      });
    }
    const dynamic = new Set([
      'records',
      'coverage',
      'timeline',
      'scorecards',
      'changes',
      'current_evidence',
    ]);
    for (const key of Object.keys(common))
      if (!dynamic.has(key) && needs(key)) add(key, common[key]);
    if (needs('current_evidence')) add('current_evidence', await currentEvidence(options));
    if (needs('records')) add('records', []);
    if (needs('coverage')) add('coverage', []);
    if (needs('changes')) add('changes', []);
    if (needs('timeline')) add('timeline', { ...common.timeline, events: [] });
    if (needs('scorecards'))
      add('scorecards', {
        ...common.scorecards,
        vendors: common.scorecards.vendors.map((v) => ({ ...v, cases: [] })),
      });
    if (wanted)
      for (const key of wanted)
        if (!Object.hasOwn(result, key)) throw Error('Unknown runtime field');
    const records = new Map(),
      events = new Map(),
      cases = new Map();
    const routeKinds =
      needs('records') || needs('coverage') || needs('timeline') || needs('scorecards');
    const descriptors = routeKinds
      ? [
          ...new Map(
            cohort.flatMap((id) => index.cohorts[id] || []).map((d) => [d.path, d]),
          ).values(),
        ]
      : [];
    for (const d of descriptors) {
      // Ordinary parts contain literal JSON (no reference expansion). Their
      // complete encoded envelope bounds every retained row before parsing.
      quota.charge(d.bytes + 128);
      const rows = await read(d, false, options);
      for (const row of rows) {
        if (row.kind === 'record' && needs('records')) {
          if (!records.has(row.index))
            records.set(row.index, { record: json.clone(row.record), assessments: new Map() });
          for (const [i, a] of row.assessments)
            records.get(row.index).assessments.set(i, json.clone(a));
        } else if (row.kind === 'timeline' && needs('timeline')) events.set(row.index, row.value);
        else if (row.kind === 'coverage' && needs('coverage')) result.coverage.push(row.value);
        else if (row.kind === 'scorecard' && needs('scorecards')) {
          if (!cases.has(row.vendor)) cases.set(row.vendor, []);
          cases.get(row.vendor).push(row.value);
        } else if (!['record', 'timeline', 'coverage', 'scorecard'].includes(row.kind))
          throw Error('Unsupported evidence row');
      }
    }
    if (needs('records'))
      result.records = [...records]
        .sort(([a], [b]) => a - b)
        .map(([, r]) => ({
          ...r.record,
          assessments: [...r.assessments].sort(([a], [b]) => a - b).map(([, a]) => a),
        }));
    if (needs('timeline'))
      result.timeline.events = [...events].sort(([a], [b]) => a - b).map(([, event]) => event);
    if (needs('scorecards'))
      for (const vendor of result.scorecards.vendors) vendor.cases = cases.get(vendor.vendor) || [];
    if (includeChanges && needs('changes'))
      for (const d of index.changes) {
        quota.charge(d.bytes + 1);
        for (const value of await read(d, false, options)) result.changes.push(value);
      }
    json.measure(result, null, '', max);
    return result;
  }
  const load = async function (ids, includeChanges = false) {
    if (publicationV2) return boundedCohort(ids, includeChanges);
    const report = await currentEvidence();
    const cohort = [...new Set(ids ?? Object.keys(common.benchmark_cohort))].sort();
    if (cohort.some((id) => !/^CVE-\d{4}-\d{4,}$/.test(id))) throw Error('Invalid CVE cohort');
    // Selecting the entire archive is an explicit large download. The default and
    // custom cohorts never fetch the compatibility snapshot.
    if (
      cohort.length > 0 &&
      cohort.length === common.all_cves.length &&
      cohort.every((id, i) => id === common.all_cves[i])
    ) {
      const full = publicationV2
        ? await publicationV2.materializeRoot('snapshot.json')
        : await read(index.full, true);
      if (Object.hasOwn(index, 'current_evidence')) {
        validateCurrentEvidence(full.current_evidence, index.publication, index.generated_at);
        if (
          window.InfrastructureJSON.stringify(full.current_evidence) !==
          window.InfrastructureJSON.stringify(report)
        )
          throw Error('Full current-evidence report mismatch');
        window.InfrastructureCurrentEvidence.validatePartition(full, { completeCurrent: true });
      } else full.current_evidence = report;
      return window.InfrastructureJSON.clone(full);
    }
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
          records.set(row.index, {
            record: window.InfrastructureJSON.clone(row.record),
            assessments: new Map(),
          });
        for (const [i, a] of row.assessments)
          records.get(row.index).assessments.set(i, window.InfrastructureJSON.clone(a));
      } else if (row.kind === 'timeline') events.set(row.index, row.value);
      else if (row.kind === 'coverage') coverage.push(row.value);
      else if (row.kind === 'scorecard') {
        if (!cases.has(row.vendor)) cases.set(row.vendor, []);
        cases.get(row.vendor).push(row.value);
      } else throw Error('Unsupported evidence row');
    }
    return {
      ...window.InfrastructureJSON.clone(common),
      current_evidence: window.InfrastructureJSON.clone(report),
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
  load.currentEvidence = async () => window.InfrastructureJSON.clone(await currentEvidence());
  load.retained = async (ids = null, options = {}) => {
    if (publicationV2 && !options.operation)
      return window.InfrastructurePublicationV2.consume(options, (next) =>
        load.retained(ids, next),
      );
    const quota = publicationV2
      ? window.InfrastructureJSON.budget(Math.min(options.max_bytes ?? 128000000, 128000000))
      : null;
    quota?.charge(2);
    const report = await currentEvidence(options);
    if (!Object.hasOwn(index, 'current_evidence')) return [];
    const selected = index.current_evidence.retained.filter(
      (p) => ids === null || p.cve_ids.some((id) => ids.includes(id)),
    );
    const rows = [];
    for (const entry of selected) {
      quota?.charge(entry.part.bytes + 1);
      const items = await read(entry.part, false, options);
      if (
        !Array.isArray(items) ||
        items.length !== entry.decision_ids.length ||
        items.some((w, i) => w.decision_id !== entry.decision_ids[i])
      )
        throw Error('Retained part membership mismatch');
      const cves = [...new Set(items.flatMap((w) => w.record.cves))].sort();
      if (
        window.InfrastructureJSON.stringify(cves) !==
        window.InfrastructureJSON.stringify(entry.cve_ids)
      )
        throw Error('Retained part CVE membership mismatch');
      window.InfrastructureCurrentEvidence.validatePartition(
        {
          publication: index.publication,
          generated_at: index.generated_at,
          current_evidence: report,
          retained_advisories: items,
        },
        { completeRetained: false },
      );
      rows.push(...items);
    }
    return window.InfrastructureJSON.clone(
      rows.filter((w) => ids === null || w.record.cves.some((id) => ids.includes(id))),
    );
  };
  load.publication = index.publication;
  load.bootstrap = () =>
    window.InfrastructureJSON.clone({
      publication: common.publication,
      generated_at: common.generated_at,
      benchmark_cohort: common.benchmark_cohort,
      ...Object.fromEntries(
        ['switching_validation', 'switching_review_packet', 'switching_reviewed_source_scopes']
          .filter((key) => Object.hasOwn(common, key))
          .map((key) => [key, common[key]]),
      ),
    });
  load.generated_at = index.generated_at;
  function studyIndex() {
    if (!Object.hasOwn(index, 'switching')) return null;
    const contracts = window.InfrastructureSwitchingContracts;
    contracts.validate(
      index.schema_version === 2 ? 'static-index-v2.json' : 'static-index-v1.json',
      index,
    );
    if (index.switching.claims) validateClaimEntries(index.switching.claims);
    return index.switching;
  }
  function validateClaimEntries(entries) {
    window.InfrastructureSwitchingContracts.validate(
      'static-index-v1.json',
      entries,
      '/$defs/claim_entries',
    );
    const declared = entries.flatMap((entry) => entry.claim_ids);
    if (new Set(declared).size !== declared.length) throw Error('Duplicate declared study claims');
    if (entries.some((entry) => entry.part.path !== `data/${entry.part.sha256}.json`))
      throw Error('Non-addressed study claim part');
    return entries;
  }
  let catalogPromise;
  async function claimEntries(study) {
    if (study.claims) return study.claims;
    if (!catalogPromise)
      catalogPromise = (async () => {
        const results = new Array(study.claim_catalog.length);
        let cursor = 0;
        await Promise.all(
          Array.from({ length: Math.min(6, results.length) }, async () => {
            while (cursor < results.length) {
              const i = cursor++;
              results[i] = await read(study.claim_catalog[i]);
              window.InfrastructureSwitchingContracts.validate(
                'static-index-v1.json',
                results[i],
                '/$defs/claim_entries',
              );
            }
          }),
        );
        return validateClaimEntries(results.flat());
      })().catch((error) => {
        catalogPromise = null;
        throw error;
      });
    return catalogPromise;
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
  async function readSummary(study) {
    let result;
    if (Object.hasOwn(study, 'summary')) result = await read(study.summary);
    else {
      const fragments = study.summary_fragments;
      const pieces = new Array(fragments.parts.length);
      let cursor = 0,
        size = 0;
      // Preserve every position, including repeated content-addressed parts.
      await Promise.all(
        Array.from({ length: Math.min(6, fragments.parts.length) }, async () => {
          while (cursor < fragments.parts.length) {
            const i = cursor++;
            const piece = await read(fragments.parts[i]);
            if (typeof piece !== 'string') throw Error('Invalid summary fragment type');
            // Unicode mode treats paired surrogates as one code point, so this
            // range matches only unpaired halves that TextEncoder would replace.
            if (/[\uD800-\uDFFF]/u.test(piece)) throw Error('Invalid summary fragment Unicode');
            size += new TextEncoder().encode(piece).length;
            if (size > fragments.bytes || size > 128000000)
              throw Error('Summary reconstruction exceeds budget');
            pieces[i] = piece;
          }
        }),
      );
      if (size !== fragments.bytes) throw Error('Summary reconstruction size mismatch');
      const text = pieces.join('');
      const raw = new TextEncoder().encode(text);
      if (raw.length !== fragments.bytes || raw.length !== size)
        throw Error('Summary reconstruction size mismatch');
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), (b) =>
        b.toString(16).padStart(2, '0'),
      ).join('');
      if (digest !== fragments.sha256) throw Error('Summary reconstruction fingerprint mismatch');
      result = window.InfrastructureJSON.parse(text);
    }
    return result;
  }
  load.switchingSummary = async () => {
    const descriptor = studyIndex();
    if (!descriptor) return null;
    const result = await readSummary(descriptor);
    window.InfrastructureSwitchingContracts.summary(result, index);
    return JSON.parse(JSON.stringify(result));
  };
  let analysisPromise;
  load.switchingAnalysis = async (study) => {
    window.InfrastructureSwitchingContracts.identity(study, index);
    if (!analysisPromise)
      analysisPromise = (async () => {
        if (!Object.hasOwn(index, 'switching_analysis')) return null;
        window.InfrastructureSwitchingContracts.validate(
          index.schema_version === 2 ? 'static-index-v2.json' : 'static-index-v1.json',
          index,
        );
        const report = await readSummary(index.switching_analysis);
        return window.InfrastructureSwitchingAnalysis.validate(report, index);
      })().catch((error) => {
        analysisPromise = null;
        throw error;
      });
    return window.InfrastructureSwitchingAnalysis.select(await analysisPromise, study);
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
    const entries = await claimEntries(study);
    const selected = entries.filter((p) => p.claim_ids.some((id) => requested.has(id)));
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
    const claims = await claimParts(await claimEntries(study));
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
  let releaseHistoryPromise;
  load.switchingReleaseHistory = async (study) => {
    window.InfrastructureSwitchingContracts.identity(study, index);
    if (!releaseHistoryPromise)
      releaseHistoryPromise = (async () => {
        const response = await fetchPart(siteBase + 'switching-release-history.json', {
          cache: 'no-cache',
        });
        if (response.status === 404) return null;
        if (!response.ok)
          throw Error('Release history unavailable. Retry or reload after deployment.');
        const raw = await boundedBytes(response, 8000000);
        const history = window.InfrastructureJSON.parseStrict(
          new TextDecoder('utf-8', { fatal: true }).decode(raw),
        );
        window.InfrastructureCustomerComparison.validateHistory(history, index);
        return history;
      })().catch((error) => {
        releaseHistoryPromise = null;
        throw error;
      });
    return window.InfrastructureCustomerComparison.selectHistory(
      await releaseHistoryPromise,
      study,
    );
  };
  if (publicationV2) {
    load.switchingReleaseHistory = publicationV2.switchingReleaseHistory;
    load.switchingAnalysis = publicationV2.switchingAnalysis;
    load.switchingOverview = publicationV2.switchingOverview;
    load.switchingSummary = publicationV2.switchingOverview;
    load.switchingSelection = publicationV2.switchingSelection;
    load.switchingClaims = publicationV2.switchingClaims;
    load.switchingDetails = publicationV2.switchingDetails;
    load.runtimeSnapshot = (options) => publicationV2.runtimeSnapshot(options);
    load.streamRoot = publicationV2.streamRoot;
    load.materializeRange = publicationV2.materializeRange;
    load.factCatalog = index.publication_v2.path;
    load.switchingReport = () => {
      throw Error('Use bounded switchingSelection for publication v2');
    };
  }
  return load;
}
