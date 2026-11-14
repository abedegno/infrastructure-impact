// Project-authored synthetic study reader tests; no captured vendor material.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const fixture = JSON.parse(fs.readFileSync('tests/fixtures/switching-cases.json'));
const context = { window: {}, URL, console, Blob, setTimeout };
vm.createContext(context);
for (const file of ['lossless-json', 'kev', 'switching-contracts', 'switching'])
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
const safe = context.window.InfrastructureSwitchingView.claimMarkup(
  hostile.inputs.evidence.claims[0],
);
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
  assert(
    !context.window.InfrastructureSwitchingView.claimMarkup({
      ...hostile.inputs.evidence.claims[0],
      source: hostile.sources[0],
    }).includes(`href="${url}`),
  );
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

vm.runInContext(
  fs.readFileSync('infrastructure_impact/web/switching-analysis.js', 'utf8'),
  context,
);

// Actual app request owner: delayed successes/failures cannot replace accepted controls/exports.
(async () => {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id))
      nodes.set(id, {
        value: id === '#cohort' ? 'benchmark' : '',
        innerHTML: '',
        insertAdjacentHTML(position, html) {
          this.innerHTML += html;
        },
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
  let loaderCreations = 0;
  context.createStaticDelivery = async () => {
    loaderCreations++;
    const number = loaderCreations;
    return {
      publication: report.publication,
      generated_at: report.generated_at,
      switchingClaims: async (ids) => ({ number, ids }),
      switchingReport: () => new Promise((resolve, reject) => pending.push({ resolve, reject })),
    };
  };
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  let app = fs
    .readFileSync('infrastructure_impact/web/app.js', 'utf8')
    .replace(/\nload\(\);\n/, '\n');
  vm.runInContext(app, context);
  const paintAccepted = context.renderComparison;
  context.fullReport = report;
  vm.runInContext(
    'data={publication:fullReport.publication,generated_at:fullReport.generated_at}; comparisonMode="switching"; view="compare"; renderComparison=()=>{};',
    context,
  );
  const resolve = (i) => pending[i].resolve(report);
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
  await tick();
  resolve(0);
  await first;
  assert.strictEqual(read().report.selection.requested_vendor, null, 'full study default');
  const old = context.loadSwitching({ vendor: 'arista' }),
    failed = context.loadSwitching({ vendor: 'cisco' });
  await tick();
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
  await tick();
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
  await tick();
  pending[5].resolve(foreign);
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
  assert.strictEqual(loaderCreations, 1, 'one generation-bound loader across selections');
  const beforeGenerationFailure = read().report;
  vm.runInContext(
    'data={...data, publication:{id:"f".repeat(32),advisory_schema_version:2}};',
    context,
  );
  const newGeneration = context.loadSwitching();
  await tick();
  pending[6].reject(Error('new generation unavailable'));
  await newGeneration;
  const mount = context.window.InfrastructureSwitchingView.mount;
  let detailOwner;
  context.window.InfrastructureSwitchingView.mount = (root, accepted, loadClaims) => {
    detailOwner = { accepted, loadClaims };
  };
  paintAccepted();
  const oldDetail = await detailOwner.loadClaims([report.inputs.evidence.claims[0].claim_id]);
  assert.strictEqual(
    oldDetail.number,
    1,
    'failed new generation retains the accepted detail loader',
  );
  assert.deepStrictEqual(JSON.parse(JSON.stringify(detailOwner.accepted)), beforeGenerationFailure);
  assert.deepStrictEqual(
    JSON.parse(await context.switchingDownload('json').text()),
    beforeGenerationFailure,
  );
  assert.strictEqual(
    await context.switchingDownload('csv').text(),
    api.csvExport(beforeGenerationFailure),
  );
  context.window.InfrastructureSwitchingView.mount = mount;
  vm.runInContext('data={...data, publication:fullReport.publication};', context);
  const legacy = context.loadSwitching();
  await tick();
  pending[7].resolve(null);
  await legacy;
  assert.strictEqual(read().report.availability, 'unavailable');
  assert.strictEqual(context.switchingDownload('json'), null);
  assert.strictEqual(loaderCreations, 3, 'a new enclosing generation creates a new loader');
  const overview = JSON.parse(JSON.stringify(report));
  delete overview.inputs;
  overview.schema_version = 2;
  overview.representation = 'switching-overview';
  let exportRequest, resolveExport;
  const boundedDelivery = {
    promise: Promise.resolve({
      publication: report.publication,
      generated_at: report.generated_at,
      switchingSelection: (options, evaluatedAt) => {
        exportRequest = { options, evaluatedAt };
        return new Promise((resolve) => (resolveExport = resolve));
      },
    }),
  };
  const exporting = context.switchingExport('json', overview, boundedDelivery);
  await tick();
  const selectedSummary = api.summary(select());
  const jsonApi = context.window.InfrastructureJSON,
    compactBytes = jsonApi.measure(selectedSummary);
  assert(jsonApi.measure(selectedSummary, null, 2) > compactBytes);
  const originalBlob = context.Blob;
  let blobAllocations = 0;
  context.Blob = function () {
    blobAllocations++;
    throw Error('unexpected Blob allocation');
  };
  try {
    assert.throws(
      () => context.switchingDownload('json', selectedSummary, { max_bytes: compactBytes }),
      /budget/,
    );
    assert.strictEqual(blobAllocations, 0);
  } finally {
    context.Blob = originalBlob;
  }

  resolveExport(selectedSummary);
  assert.deepStrictEqual(
    JSON.parse(await (await exporting).text()),
    JSON.parse(JSON.stringify(selectedSummary)),
  );
  assert.strictEqual(
    exportRequest.evaluatedAt,
    overview.evaluated_at,
    'export uses accepted evaluation clock',
  );
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(exportRequest.options.cve_ids)),
    overview.selection.requested_cve_ids,
  );
  context.createStaticDelivery = async () => ({
    publication: report.publication,
    generated_at: report.generated_at,
    switchingOverview: async () => overview,
    switchingSelection: async (options) => api.summary(select(options)),
    switchingReport: () => {
      throw Error('v2 must not hydrate full report');
    },
  });
  vm.runInContext('switchingDelivery=null;', context);
  await context.loadSwitching();
  assert.strictEqual(read().report.representation, 'switching-overview');
  await context.loadSwitching({ vendor: 'arista' });
  assert.strictEqual(read().report.representation, 'summary');
  assert.strictEqual(read().report.selection.requested_vendor, 'arista');
  console.log(
    'Actual app v1/v2 ordering, generations, default overview and accepted summary exports passed.',
  );
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

// Collapsed details must not serialize entire retained evidence on each repaint.
const lazyReport = JSON.parse(JSON.stringify(report));
lazyReport.inputs.evidence.score_availability = [
  { vendor: 'arista', marker: 'DIAGNOSTIC_LAZY_SENTINEL' },
];
lazyReport.inputs.evidence.claims[0].conditions = ['CLAIM_LAZY_SENTINEL'];
lazyReport.sources = [{ source_url: 'https://www.arista.com/TRACE_LAZY_SENTINEL' }];
const lazyHtml = api.render(lazyReport);
for (const marker of ['CLAIM_LAZY_SENTINEL', 'DIAGNOSTIC_LAZY_SENTINEL', 'TRACE_LAZY_SENTINEL'])
  assert(!lazyHtml.includes(marker), 'collapsed ' + marker);
assert(lazyHtml.includes('data-switching-detail="claims"'));

(async () => {
  // A tiny DOM boundary harness exercises the actual expansion listener and paging.
  function surface(kind) {
    const body = {
      html: '',
      childNodes: [],
      button: null,
      insertAdjacentHTML(position, html) {
        this.html += html;
        this.childNodes.push(html);
        if (html.includes('<button'))
          this.button = {
            addEventListener: (event, callback) => {
              this.more = callback;
            },
            remove: () => {
              this.button = null;
            },
          };
      },
      querySelector() {
        return this.button;
      },
    };
    const detail = {
      dataset: { switchingDetail: kind },
      open: true,
      isConnected: true,
      querySelector: () => body,
      addEventListener: (event, callback) => {
        detail.toggle = callback;
      },
    };
    return { body, detail, root: { querySelectorAll: () => [detail] } };
  }
  const tick = () => new Promise((resolve) => setImmediate(resolve));
  const many = JSON.parse(JSON.stringify(report));
  const template = many.inputs.evidence.claims[0];
  many.inputs.evidence.claims = Array.from({ length: 61 }, (_, i) => ({
    ...template,
    claim_id: String(i),
    product: i === 0 ? '<svg onload=bad()>' : String(i),
  }));
  many.rows[0].claim_ids = many.inputs.evidence.claims.map((c) => c.claim_id);
  many.rows = [many.rows[0]];
  many.rows[0].events = [];
  const s = surface('claims'),
    batches = [];
  context.window.InfrastructureSwitchingView.mount(s.root, many, async (ids) => {
    batches.push(ids);
    return many.inputs.evidence.claims.filter((c) => ids.includes(c.claim_id));
  });
  assert.strictEqual(s.body.html, '');
  s.detail.toggle();
  await tick();
  assert.strictEqual(batches[0].length, 25);
  assert(s.body.html.includes('&lt;svg onload=bad()&gt;'));
  assert(s.body.html.includes('Initial publication'));
  assert(s.body.html.includes('25 of 61 shown'));
  await s.body.more();
  assert.strictEqual(batches[1].length, 25);
  assert(s.body.html.includes('50 of 61 shown'));
  await s.body.more();
  assert.strictEqual(batches[2].length, 11);
  assert.strictEqual(s.body.button, null, 'all 61 claims accessible in three pages');
  const diagnostics = surface('diagnostics'),
    requests = [];
  const summaryOnly = JSON.parse(JSON.stringify(many));
  delete summaryOnly.inputs;
  context.window.InfrastructureSwitchingView.mount(
    diagnostics.root,
    summaryOnly,
    async () => {
      throw Error('claims not requested');
    },
    async (request) => {
      requests.push(request);
      return {
        items: [
          { marker: 'FULL_DIAGNOSTIC_CALLBACK', attempts: Array.from({ length: 40 }, (_, i) => i) },
        ],
        next_cursor: request.cursor ? null : 'accepted-cursor',
        total: 2,
      };
    },
  );
  diagnostics.detail.toggle();
  await tick();
  assert(diagnostics.body.html.includes('FULL_DIAGNOSTIC_CALLBACK'));
  assert(diagnostics.body.html.includes('39'), 'diagnostics retain nested facts');
  await diagnostics.body.more();
  assert.strictEqual(requests[1].cursor, 'accepted-cursor');
  assert.strictEqual(requests[1].limit, 25);
  const staleSurface = surface('sources');
  let finishStale;
  context.window.InfrastructureSwitchingView.mount(
    staleSurface.root,
    summaryOnly,
    async () => [],
    () => new Promise((resolve) => (finishStale = resolve)),
  );
  staleSurface.detail.toggle();
  staleSurface.detail.isConnected = false;
  finishStale({
    items: [
      {
        source_url: 'https://example.com/LATE_CALLBACK',
        retrieved_at: null,
        source_locator: null,
        source_sha256: 'x',
      },
    ],
    next_cursor: null,
    total: 1,
  });
  await tick();
  assert(!staleSurface.body.html.includes('LATE_CALLBACK'));
  const fail = surface('claims');
  let resolve;
  context.window.InfrastructureSwitchingView.mount(
    fail.root,
    many,
    () => new Promise((r) => (resolve = r)),
  );
  fail.detail.toggle();
  fail.detail.isConnected = false;
  resolve([{ ...template, product: 'LATE_DETAIL_SENTINEL' }]);
  await tick();
  assert(!fail.body.html.includes('LATE_DETAIL_SENTINEL'));
  const rejected = surface('claims');
  context.window.InfrastructureSwitchingView.mount(rejected.root, many, async () => {
    throw Error('<img onerror=bad()>');
  });
  rejected.detail.toggle();
  await tick();
  assert(rejected.body.html.includes('role="alert"'));
  assert(rejected.body.html.includes('&lt;img onerror=bad()&gt;'));
  assert(rejected.body.html.includes('Retry detail'));
  console.log('Lazy detail paging, escaping, failure and detached-generation guards passed.');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

// Study reports are optional and belong to the accepted generation, not form controls.
const validationState = {
  validationPublication: report.publication,
  validationGeneratedAt: report.generated_at,
  validation: {
    vendor_results: [
      {
        vendor: 'arista',
        sample_cases: 5,
        full_byte_matches: 2,
        scoped_matches: 1,
        failures: [{ id: 'synthetic', outcome: 'source_missing' }],
      },
    ],
  },
  reviewPacket: { study: 'campus-branch-switching', cases: [] },
};
const validatedHtml = api.render(report, validationState);
for (const label of [
  '5 sample cases',
  '2 exact-byte matches',
  '1 structural matches',
  'synthetic: source_missing',
  'Accepted-generation validation report',
  'Blind review packet',
])
  assert(validatedHtml.includes(label), label);
assert(validatedHtml.includes('download="switching-review-packet.json"'));
assert(
  api
    .render(report, { ...validationState, validationPublication: { id: 'stale' } })
    .includes('Switching validation unavailable for this accepted generation'),
);

// Diagnostic limits derive from accepted row facts and keep collection ownership.
for (const phrase of [
  'Metric evidence limits',
  'Observed affected CVEs:',
  'Fixed-only claims without proven affected-to-fix linkage:',
  'publications without grouping evidence',
  'does not prove independent patch cycles',
  'Report-wide limitations',
])
  assert(html.includes(phrase), phrase);
assert(!html.includes(' unbundled</small>'));
