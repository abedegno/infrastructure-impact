// Authored synthetic report; no licensed data or credentials.
const assert = require('node:assert/strict');
global.window = {};
require('../infrastructure_impact/web/lossless-json.js');
const vc = require('../infrastructure_impact/web/vulncheck.js');
const kev = require('../infrastructure_impact/web/kev.js');
const fs = require('node:fs');
const now = '2026-11-19T12:00:00Z';
const cid = 'CVE-2026-10001',
  other = 'CVE-2026-10002',
  outside = 'CVE-2026-10003';
function report() {
  return {
    schema_version: 1,
    distribution: 'private_research_only',
    evaluated_at: now,
    attribution: {
      name: 'VulnCheck Known Exploited Vulnerabilities',
      url: 'https://www.vulncheck.com/kev',
    },
    source: {
      id: 'vulncheck-kev',
      url: 'https://api.vulncheck.com/v3/backup/vulncheck-kev',
      availability: 'available',
      checked_at: now,
      sha256: 'a'.repeat(64),
      revision_id: 1,
      retrieved_at: now,
      publisher_backup_at: now,
      parser_version: 1,
      error_code: null,
    },
    counts: { vulncheck_listed: 999 }, // never trusted
    cves: [
      {
        cve_id: cid,
        cisa_membership: 'unknown',
        vulncheck: {
          membership: 'listed',
          retained_listed: true,
          evidence: {
            vendor_label: '<img src=x onerror=alert(1)>',
            product_label: 'Synthetic',
            listed_at: now,
            canary_reported: false,
            reported_exploitation: [
              { url: 'javascript:alert(1)', date_added: now, url_status: 'valid_web_url' },
              {
                url: 'https://example.org/report#details',
                date_added: now,
                url_status: 'valid_web_url',
              },
            ],
          },
        },
      },
      {
        cve_id: other,
        cisa_membership: 'unknown',
        vulncheck: { membership: 'not_listed', retained_listed: false, evidence: null },
      },
    ],
  };
}
const original = report();
const parsed = vc.parseReport(JSON.stringify(original));
assert.equal(vc.membership(parsed, cid, now), 'listed');
assert.equal(vc.membership(parsed, other, now), 'not_listed');
assert.equal(vc.membership(parsed, outside, now), 'unknown', 'outside local scope is unknown');
assert.equal(vc.membership(parsed, cid, '2026-11-21T12:00:00Z'), 'unknown');
assert.equal(vc.membership(parsed, cid, '2026-11-19T11:54:59Z'), 'unknown');
assert.equal(vc.membership(null, cid, now), 'unknown');
for (const state of ['missing', 'failed']) {
  const failed = report();
  failed.source.availability = state;
  failed.cves.forEach((r) => (r.vulncheck.membership = 'unknown'));
  const p = vc.parseReport(JSON.stringify(failed));
  assert.equal(vc.membership(p, cid, now), 'unknown');
}
const cisa = JSON.parse(fs.readFileSync('tests/fixtures/kev-selection-cases.json')).base_report;
cisa.source.checked_at = now;
cisa.source.latest_attempt.checked_at = now;
cisa.catalogue.released_at = now;
cisa.listed_cve_ids = [other];
cisa.catalogue.count = 1;
cisa.entries = {};
const study = {
  publication: { id: 'synthetic' },
  generated_at: now,
  evaluated_at: now,
  selection: { scope_level: 'os_family', requested_window: 'all' },
  rows: [
    { vendor: 'cisco', affected_cve_ids: [cid, other] },
    { vendor: 'cisco', affected_cve_ids: [cid] },
    { vendor: 'aruba', affected_cve_ids: [outside] },
    { vendor: 'arista', affected_cve_ids: [] },
  ],
};
const model = vc.summarize(parsed, { study, cisa, kev, now });
assert.equal(model.vendors[0].vulncheck_listed, 1);
assert.equal(model.vendors[0].cisa_listed, 1);
assert.equal(model.vendors[0].cves, 2, 'per-vendor unions deduplicated');
assert.equal(model.vendors[1].vulncheck_unknown, 1);
assert.equal(
  model.vendors[1].vulncheck_listed,
  null,
  'incomplete counts do not look like a verified zero',
);
assert.equal(model.vendors[2].vulncheck_listed, 0, 'verified empty cohort is zero');
assert.equal(vc.summarize(parsed, { study, cisa, kev, now, filter: 'vulncheck' }).rows.length, 1);
assert.equal(vc.summarize(parsed, { study, cisa, kev, now, filter: 'cisa' }).rows.length, 1);
assert.equal(vc.summarize(parsed, { study, cisa, kev, now, filter: 'both' }).rows.length, 0);
assert.equal(vc.summarize(parsed, { study, cisa, kev, now, filter: 'unknown' }).rows.length, 1);
assert.deepEqual(original, report(), 'no mutation');
const withCisa = report();
withCisa.cisa_source = { availability: 'available', checked_at: now };
withCisa.cves[0].cisa_membership = 'listed';
const fallback = vc.parseReport(JSON.stringify(withCisa));
for (const unavailable of [
  kev.selectReport(null, [cid], { evaluatedAt: now }),
  { ...cisa, source: { ...cisa.source, checked_at: '2026-11-01T12:00:00Z' } },
]) {
  const chosen = vc.summarize(fallback, { cves: [cid], cisa: unavailable, kev, now });
  assert.equal(chosen.rows[0].cisa, 'listed', 'fresh local CISA replaces unavailable public CISA');
  assert.equal(chosen.cisa_checked_at, now);
}
const html = vc.render(model);
assert(html.includes('VulnCheck Known Exploited Vulnerabilities'));
assert(html.includes('CISA KEV'));
assert(html.includes('cisco') && html.includes('aruba'));
const context = vc.renderContext(parsed, cid, now);
assert(context.includes('VulnCheck KEV listed'));
assert(context.includes('&lt;img'));
assert(!context.includes('<img') && !context.includes('href="javascript:'));
assert(context.includes('href="https://example.org/report#details"'));
assert(vc.renderContext(parsed, cid, '2026-11-21T12:00:00Z').includes('VulnCheck KEV unknown'));
for (const mutate of [
  (r) => (r.source.url = 'https://evil.example'),
  (r) => r.cves.push(r.cves[0]),
  (r) => (r.cves[0].cve_id = 'invalid'),
  (r) => (r.source.checked_at = 'yesterday'),
  (r) => (r.cves[0].vulncheck.retained_listed = false),
  (r) => (r.distribution = 'public'),
]) {
  const value = report();
  mutate(value);
  assert.throws(() => vc.parseReport(JSON.stringify(value)));
}
assert.throws(() => vc.parseReport('x'.repeat(vc.MAX_FILE_BYTES + 1)));
assert.throws(() => vc.parseReport('{"schema_version":1,"schema_version":1}'));
console.log(
  'VulnCheck browser membership, scope, comparison, filtering, XSS and validation checks passed',
);

// Exercise the real app and controller with an in-memory file selection.
const { browser } = require('./helpers/ui-browser.js');
(async () => {
  const b = browser();
  const base = JSON.parse(fs.readFileSync('tests/fixtures/kev-selection-cases.json')).base_report;
  const state = {
    generated_at: base.generated_at,
    publication: base.publication,
    benchmark_cohort: { [cid]: 'Synthetic' },
    all_cves: [cid, other],
    vendors: { cisco: 'Cisco' },
    counts: { advisories: 1, evidence_snapshots: 1 },
    records: [
      {
        vendor: 'cisco',
        cves: [cid],
        title: 'Synthetic',
        source_format: 'synthetic',
        warnings: [],
        notes: [],
        assessments: [
          {
            cve_id: cid,
            product: 'Synthetic',
            status: 'affected',
            scope: 'cve_specific',
            versions: [],
          },
        ],
      },
    ],
    comparison: { cohort: [cid, other] },
    kev: kev.selectReport(base, [cid, other], { evaluatedAt: base.generated_at }),
    research_dossiers: { vendors: { cisco: 'Cisco' }, dossiers: [] },
  };
  b.requests[0].resolve(new Response(JSON.stringify(state)));
  await b.settle();
  if (b.requests.length > 1) {
    b.requests.at(-1).resolve(new Response(JSON.stringify(state)));
    await b.settle();
  }
  const fixture = JSON.stringify(report()).replaceAll(now, base.generated_at);
  const input = b.nodes.get('#vulncheck-file');
  input.files = [{ size: fixture.length, text: async () => fixture }];
  const requests = b.requests.length;
  await input.fire('change');
  await b.settle();
  assert.equal(b.requests.length, requests, 'import does not upload or fetch');
  assert(b.nodes.get('#matrix-results').innerHTML.includes('VulnCheck KEV listed'));
  assert(b.nodes.get('#vulncheck-results').innerHTML.includes('VulnCheck KEV listed'));
  const visibleMatrix = b.nodes.get('#matrix-results').innerHTML;
  b.nodes.get('#vulncheck-filter').value = 'vulncheck';
  await b.nodes.get('#vulncheck-filter').fire('change');
  assert.equal(
    b.nodes.get('#matrix-results').innerHTML,
    visibleMatrix,
    'research filter leaves published cohort alone',
  );
  await b.nodes.get('#json-export').click();
  await b.settle();
  const exported = JSON.parse(await b.downloads.at(-1).blob.text());
  assert.equal(exported.vulncheck, undefined);
  assert(
    !JSON.stringify(exported).includes('VulnCheck Known Exploited Vulnerabilities'),
    'local evidence is absent from downloads',
  );
  b.nodes.get('#vulncheck-filter').value = 'all';
  await b.nodes.get('#vulncheck-filter').fire('change');
  const accepted = b.nodes.get('#vulncheck-results').innerHTML;
  input.files = [{ size: 10, text: async () => '{invalid' }];
  await input.fire('change');
  assert.equal(
    b.nodes.get('#vulncheck-results').innerHTML,
    accepted,
    'invalid import preserves accepted report',
  );
  let resolve;
  b.nodes.get('#detail-body').innerHTML = 'Synthetic private label';
  input.files = [{ size: fixture.length, text: () => new Promise((r) => (resolve = r)) }];
  const pending = input.fire('change');
  await b.nodes.get('#vulncheck-clear').click();
  assert.equal(b.nodes.get('#detail-body').innerHTML, '', 'clear removes private dialog DOM too');
  resolve(fixture);
  await pending;
  assert(
    !b.nodes.get('#matrix-results').innerHTML.includes('VulnCheck KEV listed'),
    'clear supersedes pending import',
  );
  input.files = [{ size: fixture.length, text: async () => fixture }];
  await input.fire('change');
  b.advance(2 * 86400000);
  await b.nodes.get('#vulncheck-refresh').click();
  assert(b.nodes.get('#vulncheck-results').innerHTML.includes('VulnCheck KEV unknown'));
  assert(!b.nodes.get('#vulncheck-results').innerHTML.includes('VulnCheck KEV listed'));
  assert.equal(b.requests.length, requests, 'file import, clear and freshness controls stay local');
  console.log('Real-app local import, badges, rejection, clear race and freshness checks passed');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
