/* Snapshot transport: no vendor requests, credentials, or writable backend. */
window.snapshotMode = true;
function snapshotCompare(records, cohort, vendors, template) {
  const included = records.filter((r) => r.document_status !== 'draft');
  const rows = Object.entries(vendors).map(([vendor, name]) => {
    const claims = included
      .filter((r) => r.vendor === vendor)
      .flatMap((r) => r.assessments)
      .filter((a) => cohort.includes(a.cve_id));
    const by = cohort.map((c) => claims.filter((a) => a.cve_id === c));
    const count = (pred) => by.filter((aa) => aa.some(pred)).length;
    const assessed = count((a) => !['unknown', 'recommended'].includes(a.status));
    return {
      vendor,
      name,
      cohort_size: cohort.length,
      has_imported_advisories: included.some((r) => r.vendor === vendor),
      assessed_cves: assessed,
      no_assessment_in_dataset: cohort.length - assessed,
      affected_cves: count((a) => ['affected', 'partially_mitigated'].includes(a.status)),
      unaffected_cves: count((a) => a.status === 'unaffected'),
      investigating_cves: count((a) => a.status === 'investigating'),
      fixed_cves: count((a) => a.status === 'fixed'),
      explicit_affected_cves: count((a) => a.status === 'affected' && a.scope === 'cve_specific'),
      shared_bulletin_affected_cves: count(
        (a) => a.status === 'affected' && a.scope === 'bulletin_shared',
      ),
      product_labels: new Set(claims.map((a) => a.product)).size,
      conflicting_cves: count((a) => a.status === 'conflicting'),
    };
  });
  return {
    ...template,
    cohort,
    vendors: rows,
    draft_advisories_excluded: records.length - included.length,
  };
}
function selectSnapshot(source, ids) {
  const cohort = [...new Set(ids || source.all_cves)].sort();
  const coverage = cohort.flatMap((cid) =>
    Object.keys(source.vendors).map(
      (v) =>
        source.coverage.find((c) => c.cve_id === cid && c.vendor === v) || {
          vendor: v,
          cve_id: cid,
          state: 'not_checked',
          checks: [],
          advisory_sources: [],
        },
    ),
  );
  return {
    ...source,
    comparison: snapshotCompare(source.records, cohort, source.vendors, source.comparison),
    coverage,
    delays: source.delays.filter((d) => cohort.includes(d.cve_id)),
  };
}
function exportSnapshot(source) {
  const cohort = source.comparison.cohort;
  return {
    ...source,
    records: source.records
      .filter((r) => r.cves.some((c) => cohort.includes(c)))
      .map((r) => ({ ...r, assessments: r.assessments.filter((a) => cohort.includes(a.cve_id)) })),
  };
}
function snapshotCSV(source) {
  const fields = [
    'cve_id',
    'vendor',
    'advisory_id',
    'product',
    'status',
    'scope',
    'versions',
    'remediations',
    'source_url',
    'observed_at',
    'sha256',
  ];
  const quote = (v) => {
    v = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '');
    if (/^[=+\-@]/.test(v)) v = "'" + v;
    return '"' + v.replaceAll('"', '""') + '"';
  };
  return [
    fields.join(','),
    ...exportSnapshot(source).records.flatMap((r) =>
      r.assessments.map((a) => fields.map((f) => quote(a[f] ?? r[f])).join(',')),
    ),
  ].join('\r\n');
}
if (typeof document !== 'undefined') {
  const originalFetch = window.fetch.bind(window);
  const siteBase = new URL('.', document.baseURI).pathname;
  const snapshot = originalFetch(siteBase + 'snapshot.json').then((r) => {
    if (!r.ok) throw Error('Snapshot unavailable');
    return r.json();
  });
  let current;
  window.fetch = async (input, options) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.origin);
    if (url.origin === location.origin && url.pathname === '/api/state') {
      const ids = url.searchParams.has('cves') ? url.searchParams.get('cves').split(',') : null;
      current = selectSnapshot(await snapshot, ids);
      return new Response(JSON.stringify(current), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input, options);
  };
  document.addEventListener('click', (e) => {
    const a = e.target.closest('#json-export,#csv-export');
    if (!a) return;
    e.preventDefault();
    if (!current) return;
    const csv = a.id === 'csv-export';
    const content = csv ? snapshotCSV(current) : JSON.stringify(exportSnapshot(current), null, 2);
    const url = URL.createObjectURL(
      new Blob([content], { type: csv ? 'text/csv' : 'application/json' }),
    );
    const out = document.createElement('a');
    out.href = url;
    out.download = csv ? 'impact.csv' : 'impact.json';
    out.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}
