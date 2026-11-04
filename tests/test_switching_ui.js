// Project-authored synthetic study reader tests; no captured vendor material.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const fixture = JSON.parse(fs.readFileSync('tests/fixtures/switching-cases.json'));
const context = { window: {}, URL, console, Blob, setTimeout };
vm.createContext(context);
for (const file of ['kev', 'switching-contracts', 'switching'])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${file}.js`, 'utf8'), context);
assert.strictEqual(
  typeof context.window.InfrastructureSwitching.render,
  'function',
  'reader render entry point exists',
);
vm.runInContext(fs.readFileSync('infrastructure_impact/web/switching-view.js', 'utf8'), context);
const api = context.window.InfrastructureSwitching;
const select = (options = {}) =>
  api.selectReport(fixture.comparison_base_report, {
    evaluated_at: fixture.comparison_base_report.generated_at,
    ...options,
  });
const report = select(),
  html = api.render(report);
for (const text of [
  'Full study',
  '2021-01-01',
  '2026-04-07',
  '2026-11-04',
  '2026 is partial',
  'Counts measure disclosure, not vendor security quality; higher disclosure can reflect more scrutiny.',
  'nonadditive',
  'Model-unspecified',
  'Historical denominator: unknown',
  'Independent human review pending',
  '16-case switching validation',
  'Initial publication',
  'Affected advisories',
  'Observed advisories',
  'Scoped draft advisories',
  'Provider-reported CVSS',
  'Vendor advisory rating',
  'KEV',
  'Source observation windows',
  'not historical period completeness',
  'No fix-delay estimate',
])
  assert(html.includes(text), text);
for (const id of ['switching-scope', 'switching-vendor', 'switching-window'])
  assert(html.includes(`for="${id}"`), 'keyboard label ' + id);
assert(html.includes('value="os_family" selected'));
assert(html.includes('value="all" selected'));
const empty = api.render(
  select({ scope_level: 'model_qualified', vendor: 'cisco', window: '2021' }),
);
assert(empty.includes('No retained observations match'));
assert(empty.includes('does not establish no exposure'));
assert(api.render(api.selectReport(null)).includes('unavailable for this publication'));
assert(api.render(null, { loading: true }).includes('Loading switching study'));
assert(api.render(report, { loading: true }).includes('last accepted selection'));
assert(api.render(report, { error: '<img onerror=bad()>' }).includes('&lt;img onerror=bad()&gt;'));
const hostile = JSON.parse(JSON.stringify(report));
hostile.inputs.evidence.claims[0].product = '<svg onload=bad()>"';
hostile.inputs.evidence.claims[0].source.source_url = 'javascript:bad()';
hostile.inputs.evidence.claims[0].publisher.sequence = '1.5';
const safe = api.render(hostile);
assert(safe.includes('&lt;svg onload=bad()&gt;'));
assert(!safe.includes('href="javascript:'));
assert(safe.includes('Publisher revision label: 1.5'));
for (const url of [
  'http://example.com',
  'https://user:secret@example.com',
  '//example.com',
  'data:text/html,x',
]) {
  hostile.sources = [
    { source_url: url, source_sha256: 'x', retrieved_at: null, source_locator: 'x' },
  ];
  assert(!api.render(hostile).includes(`href="${url}`));
}
const r = report.rows.find((r) => r.counts.affected_cves);
assert(html.includes(`data-affected-advisories="${r.counts.affected_advisories}"`));
const stale = select({ evaluated_at: '2027-12-01T00:00:00Z' });
assert(api.render(stale).includes('KEV unknown'));
// Coverage numbers retain source-window scope and unknown historical denominators.
const covered = JSON.parse(JSON.stringify(report));
covered.rows[0].coverage.sources = [
  {
    source_url: 'https://www.cisco.com/synthetic',
    state: 'unstable',
    observed_start: '2022-01-03',
    observed_end: '2026-11-04',
    total: 91,
    issues: ['synthetic_layout_gap'],
    enumeration: {
      coverage_state: 'unstable',
      expected_total: null,
      retrieval_failed: 4,
      parse_failed: 2,
    },
  },
];
const coverageHtml = api.render(covered);
for (const value of [
  '2022-01-03',
  'Source-window reported total: 91',
  'synthetic_layout_gap',
  'retrieval_failed',
  'parse_failed',
  'unstable',
  'Historical denominator: unknown',
])
  assert(coverageHtml.includes(value), value);
assert(coverageHtml.includes('Unknown / no scored affected CVEs'));
console.log(
  'Synthetic switching reader rendering, safety, controls, missingness and stale KEV passed.',
);

// Actual app request owner: delayed successes/failures cannot replace accepted controls/exports.
(async () => {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id))
      nodes.set(id, {
        value: id === '#cohort' ? 'benchmark' : '',
        innerHTML: '',
        textContent: '',
        addEventListener() {},
        setAttribute() {},
        removeAttribute() {},
      });
    return nodes.get(id);
  }
  context.document = {
    querySelector: node,
    querySelectorAll: () => [],
    baseURI: 'http://localhost/',
  };
  context.location = { origin: 'http://localhost' };
  context.window.fetch = () => {};
  const pending = [];
  context.createStaticDelivery = () =>
    new Promise((resolve, reject) => pending.push({ resolve, reject }));
  let app = fs
    .readFileSync('infrastructure_impact/web/app.js', 'utf8')
    .replace(/\nload\(\);\n/, '\n');
  vm.runInContext(app, context);
  context.fullReport = report;
  vm.runInContext(
    'data={publication:fullReport.publication,generated_at:fullReport.generated_at}; comparisonMode="switching"; view="compare"; renderComparison=()=>{};',
    context,
  );
  const resolve = (i) =>
    pending[i].resolve({
      publication: report.publication,
      generated_at: report.generated_at,
      switchingReport: async () => report,
    });
  const read = () =>
    JSON.parse(
      vm.runInContext(
        'JSON.stringify({report:switchingReport,loading:switchingLoading,error:switchingError})',
        context,
      ),
    );
  vm.runInContext(
    `
    let comparisonPainted=false;
    renderComparison=()=>{comparisonPainted=true};
    data={publication:fullReport.publication,generated_at:fullReport.generated_at,counts:{advisories:0},comparison:{cohort:[]},kev:{selection:{kev_only:true}}};
    comparisonMode='benchmark'; draw();
  `,
    context,
  );
  assert(
    vm.runInContext('comparisonPainted', context),
    'switching option reachable even for empty global KEV selection',
  );
  vm.runInContext('comparisonMode="switching";', context);
  const first = context.loadSwitching();
  resolve(0);
  await first;
  assert.strictEqual(read().report.selection.requested_vendor, null, 'full study default');
  const old = context.loadSwitching({ vendor: 'arista' }),
    failed = context.loadSwitching({ vendor: 'cisco' });
  pending[2].reject(Error('synthetic failure'));
  await failed;
  resolve(1);
  await old;
  assert.strictEqual(
    read().report.selection.requested_vendor,
    null,
    'late old success after new failure ignored',
  );
  assert(read().error.includes('synthetic failure'));
  const older = context.loadSwitching({ window: 'pre' }),
    newer = context.loadSwitching({ vendor: 'arista', window: 'post' });
  resolve(4);
  await newer;
  resolve(3);
  await older;
  assert.strictEqual(read().report.selection.requested_window, 'post');
  assert.strictEqual(read().report.selection.requested_vendor, 'arista');
  const accepted = JSON.stringify(read().report);
  const bad = context.loadSwitching({ vendor: 'cisco' });
  const foreign = JSON.parse(JSON.stringify(report));
  foreign.generated_at = '2026-11-03T10:00:00Z';
  pending[5].resolve({ switchingReport: async () => foreign });
  await bad;
  assert.strictEqual(
    JSON.stringify(read().report),
    accepted,
    'foreign generation retains accepted report and export',
  );
  const exported = context.switchingDownload('csv');
  assert.strictEqual(await exported.text(), api.csvExport(read().report));
  const json = JSON.parse(await context.switchingDownload('json').text());
  assert.deepStrictEqual(json, read().report, 'JSON exact accepted full report');
  const legacy = context.loadSwitching();
  pending[6].resolve({ switchingReport: async () => null });
  await legacy;
  assert.strictEqual(read().report.availability, 'unavailable');
  assert.strictEqual(context.switchingDownload('json'), null);
  console.log(
    'Actual app ordering, failed/foreign generations, full-study isolation and accepted exports passed.',
  );
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
