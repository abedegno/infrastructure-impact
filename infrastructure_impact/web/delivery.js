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
  async function parts(descriptors) {
    const unique = [...new Map(descriptors.map((d) => [d.path, d])).values()];
    const results = new Array(unique.length);
    let cursor = 0;
    await Promise.all(
      Array.from({ length: Math.min(6, unique.length) }, async () => {
        while (cursor < unique.length) {
          const i = cursor++;
          results[i] = await read(unique[i]);
        }
      }),
    );
    return results.flat();
  }
  return async function (ids, includeChanges = false) {
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
}
