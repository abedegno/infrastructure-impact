// Synthetic Python/browser contract and transport parity; no captured material.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = {
  window: {},
  URL,
  console,
  TextEncoder,
  TextDecoder,
  Blob,
  setTimeout,
  clearTimeout,
  AbortController,
  crypto: require('crypto').webcrypto,
};
vm.createContext(context);
for (const name of ['lossless-json', 'kev', 'switching-contracts', 'switching', 'switching-view'])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
assert(
  fs.existsSync('infrastructure_impact/web/customer-comparison.js'),
  'customer browser module exists',
);
vm.runInContext(
  fs.readFileSync('infrastructure_impact/web/customer-comparison.js', 'utf8'),
  context,
);
const api = context.window.InfrastructureCustomerComparison;
const clone = (x) => JSON.parse(JSON.stringify(x));
const shared = JSON.parse(fs.readFileSync('tests/fixtures/switching-release-history-vectors.json'));
for (const vector of shared.vectors) {
  const selected = api.selectHistory(
    shared.histories[vector.history] ?? null,
    vector.study_selection,
  );
  assert.deepStrictEqual(
    clone(selected.releases.map((r) => r.version)),
    vector.expected.versions,
    vector.name,
  );
  assert.strictEqual(selected.availability, vector.expected.availability, vector.name);
  const node = selected.releases.find((r) => r.version === '10.14.0007');
  if (node) {
    assert.strictEqual(
      node.vendor_reported_fixed_cve_count,
      vector.expected.fixed_count_10_14_0007,
      vector.name,
    );
    assert.strictEqual(
      node.affected_scope_cve_count,
      vector.expected.affected_count_10_14_0007,
      vector.name,
    );
  }
}
const base = shared.histories.dated,
  selection = shared.vectors[0].study_selection;
for (const mutate of [
  (h) => (h.releases[0].vendor_reported_fixed_cve_count = 999),
  (h) => (h.releases[0].reported_release_dates = ['2099-01-01']),
  (h) => (h.private = 'secret'),
  (h) => (h.generated_at = '2026-01-01T00:00:00Z'),
  (h) => (h.observation_end = '2099-01-01'),
  (h) => (h.releases[0].release_id = 'f'.repeat(64)),
  (h) => (h.sources[0].source_url = 'https://example.com/forged'),
]) {
  const bad = clone(base);
  mutate(bad);
  assert.throws(() => api.selectHistory(bad, selection));
}
// Authored lexical vectors use a valid history shape, without new evidence claims.
function literalHistory(vendor, expression, version) {
  const h = clone(base),
    n = clone(base.releases.find((n) => n.references.length));
  n.vendor = vendor;
  n.family = vendor === 'aruba' ? 'aruba-aoscx' : 'arista-eos';
  n.version = version;
  n.release_id = context.window.InfrastructureSwitchingContracts.fingerprint({
    vendor,
    family: n.family,
    version,
  });
  n.history = [];
  n.reported_release_dates = [];
  for (const ref of n.references) {
    ref.expression = expression;
    ref.source.source_url = ref.claim_source.source_url =
      vendor === 'aruba'
        ? 'https://csaf.arubanetworking.hpe.com/synthetic.json'
        : 'https://www.arista.com/en/support/advisories-notices/security-advisory/synthetic';
  }
  h.releases = [n];
  return h;
}
for (const [vendor, expression, version] of [
  ['aruba', 'AOS-CX 10.16.1006', '10.16.1006'],
  ['aruba', 'AOS-CX 10.16.1006_aos-cx', '10.16.1006'],
  ['arista', '4.31.2F.', '4.31.2F'],
  ['arista', '4.31.2F and later releases in the 4.31.x train.', '4.31.2F'],
  ['arista', '4.30.0M and onwards', '4.30.0M'],
  ['arista', '4.30.0M and onwards.', '4.30.0M'],
]) {
  const h = literalHistory(vendor, expression, version),
    original = clone(h);
  api.validateHistory(h);
  assert.deepStrictEqual(h, original, 'literal validation preserves expressions and dates');
  const later = literalHistory(vendor, expression, vendor === 'aruba' ? '10.16.1007' : '4.31.9M');
  assert.throws(() => api.validateHistory(later), 'no later-version membership inference');
}
for (const [vendor, expression, version] of [
  ['aruba', 'Other AOS-CX 10.16.1006', '10.16.1006'],
  ['aruba', 'AOS-CX >=10.16.1006', '10.16.1006'],
  ['aruba', 'AOS-CX 10.16.1006 and above', '10.16.1006'],
  ['aruba', 'aos-cx 10.16.1006', '10.16.1006'],
  ['arista', '4.28.11Mand later releases in the 4.28.x train.', '4.28.11M'],
  ['arista', '4.31.2F and later releases in the 4.30.x train.', '4.31.2F'],
  ['arista', '>=4.31.2F.', '4.31.2F'],
  ['arista', '4.31.2F - 4.31.9M.', '4.31.2F'],
  ['arista', '4.31.2F and later', '4.31.2F'],
  ['arista', '4.30.0M and onwards and 4.31.2F', '4.30.0M'],
])
  assert.throws(() => api.validateHistory(literalHistory(vendor, expression, version)));
const python =
  process.env.PYTHON || (fs.existsSync('.venv/bin/python') ? '.venv/bin/python' : 'python3');
const fixtures = JSON.parse(
  require('child_process').execFileSync(
    python,
    [
      '-c',
      `import json,sys,tempfile
sys.path.insert(0,'tests')
from test_customer_comparison import selected
from test_static_delivery import dataset
from test_switching_aruba_fix_links import projected,reidentify
from test_switching_release_history import frame,study,build as build_history
from test_software_release_sources import ARISTA,MODELS,bundle,models
from infrastructure_impact.references import software_releases as source_docs
from infrastructure_impact.application import customer_comparison as customer,publication,switching_releases,switching_comparison
from test_switching_comparison import claim,report,FIXTURE
import copy
from infrastructure_impact.application.publication_reader import PublicationReader
summary,history=selected(vendor='aruba',window='2024')
envelope=customer.build(summary,history)
data=dataset();data['research']['switching_input']=projected();data['research']['release_input']=[frame()]
root=tempfile.mkdtemp(prefix='customer-browser-')
paths={fmt:str(publication.publish(data,root+'/'+fmt,publication_format=fmt)) for fmt in ['v1','v2']}
reader=PublicationReader(paths['v2']);overview=reader.switching_overview(evaluated_at=data['generated_at'])
other=customer.build(overview,reader.switching_release_history(overview))
context_study=study(projected())
context_history=build_history(projected(),[frame(),frame(ARISTA,source_docs.parse_arista_0148(bundle())),frame(MODELS,source_docs.parse_aruba_support_10_14(models()))])
context_envelope=customer.build(context_study,switching_releases.select_report(context_history,context_study))
for node in context_envelope['release_history']['releases']:
 for ref in node['references']: ref['advisory_id']=' =SYNTHETIC()'
for item in context_envelope['release_history']['bundles']: item['title']='<svg onload=bad()> Unicode café'

c=claim()
score=copy.deepcopy(FIXTURE['evidence']['claims'][0]['scores'][0])
c['scores']=[dict(score,value=0,provider='vendor',preferred=True),dict(score,value=9.8,provider='other',preferred=False)]
scored_study=switching_comparison.summary(switching_comparison.select_report(report([c]),vendor='arista'))
scored_envelope=customer.build(scored_study,switching_releases.select_report(None,scored_study))
fixed_ev=projected();fixed_ev['claims']=[c for c in fixed_ev['claims'] if c['status']=='fixed'];reidentify(fixed_ev)
fixed_study=study(fixed_ev,vendor='aruba',window='2024')
fixed_envelope=customer.build(fixed_study,switching_releases.select_report(build_history(fixed_ev),fixed_study))
vectors=json.load(open('tests/fixtures/switching-release-history-vectors.json'))
selections=[switching_releases.select_report(vectors['histories'].get(v['history']),v['study_selection']) for v in vectors['vectors']]
print(json.dumps(dict(selections=selections,cases=[dict(envelope=e,csv=customer.csv_export(e)) for e in [envelope,other,context_envelope,scored_envelope,fixed_envelope]],paths=paths,temporary=root)))`,
    ],
    { encoding: 'utf8' },
  ),
);
shared.vectors.forEach((vector, i) =>
  assert.deepStrictEqual(
    clone(api.selectHistory(shared.histories[vector.history] ?? null, vector.study_selection)),
    fixtures.selections[i],
    vector.name + ' full Python parity',
  ),
);
// Catch missing/reordered overview facts, conflated fix counts and unsafe labels.
const overviewCase = fixtures.cases[2].envelope;
const overviewHTML = api.render(overviewCase);
const overview = overviewHTML.match(
  /<section class="customer-overview">([\s\S]*?)<\/section>/,
)?.[1];
assert(overview, 'compact overview is present before the detailed study');
assert(overviewHTML.indexOf('customer-overview') < overviewHTML.indexOf('switching-controls'));
const overviewRows = [...overview.matchAll(/<tr data-customer-vendor="([^"]+)">([\s\S]*?)<\/tr>/g)];
assert.deepStrictEqual(
  overviewRows.map((r) => r[1]),
  ['cisco', 'aruba', 'arista'],
);
const cells = (row) => [...row.matchAll(/<td>([\s\S]*?)<\/td>/g)].map((c) => c[1]);
assert.deepStrictEqual(cells(overviewRows[1][2]).slice(0, 2), ['1', '1']);
assert(cells(overviewRows[1][2])[2].includes('0 listed; 1 unknown'));
assert(cells(overviewRows[1][2])[2].includes('not_configured'));
assert(cells(overviewRows[1][2])[3].includes('3 literal fixed versions'));
assert(cells(overviewRows[1][2])[3].includes('3 with affected-scope links'));
assert(cells(overviewRows[0][2])[3].includes('No linked release evidence'));
assert(!cells(overviewRows[0][2])[3].includes('0 literal'));
assert(cells(overviewRows[1][2])[4].includes('unknown'));
assert(cells(overviewRows[1][2])[5].includes('9 model-unspecified claims'));
assert(overview.includes('Publications are not customer upgrades'));
assert(overview.includes('CVE counts use the original advisory-publication cohort'));
assert(overview.includes('remediation-publication counts use event dates'));
assert(overview.includes('Model applicability and historical completeness remain unknown'));
const escapedOverview = clone(overviewCase);
escapedOverview.study.rows[1].coverage.state = '<img onerror=bad()>';
assert.throws(() => api.render(escapedOverview), 'invalid overview labels fail closed');
const safeError = api.render(overviewCase, { error: '<img onerror=bad()>' });
assert(safeError.includes('&lt;img onerror=bad()&gt;'));
assert(!safeError.includes('<img onerror=bad()>'));
const missingOverview = api.render(fixtures.cases[3].envelope).split('</section>')[0];
assert(missingOverview.includes('No linked release evidence'));
assert(!missingOverview.includes('0 literal fixed versions'));
const fixedOnlyOverview = api.render(fixtures.cases[4].envelope).split('</section>')[0];
assert(fixedOnlyOverview.includes('3 literal fixed versions'));
assert(fixedOnlyOverview.includes('Affected-scope release links not established'));
assert(!fixedOnlyOverview.includes('0 with affected-scope links'));
for (const test of fixtures.cases) {
  const envelope = api.build(test.envelope.study, test.envelope.release_history);
  assert.deepStrictEqual(clone(envelope), test.envelope);
  assert.strictEqual(api.csvExport(envelope), test.csv, 'exact Python CSV parity');
  const bytes = Buffer.byteLength(test.csv);
  assert.strictEqual(api.csvExport(envelope, { max_bytes: bytes }), test.csv);
  assert.throws(() => api.csvExport(envelope, { max_bytes: bytes - 1 }));
  const html = api.render(envelope);
  for (const text of [
    'Customer switching comparison',
    'Provider-reported CVSS',
    'KEV',
    'Reported fixed release',
    'Actual customer upgrades: unknown',
    'notice publication',
    'member publication',
    'release without linked CVEs',
    'Source coverage',
    'Model / SKU',
    'customer-json',
    'customer-csv',
  ])
    assert(html.includes(text), text);
  if (
    envelope.release_history.releases.some((n) =>
      n.references.some((r) => r.kind === 'affected_scope_fix'),
    )
  )
    assert(html.includes('Affected-scope link'));
  assert(
    !api
      .render(envelope, { factCatalog: 'publication-v2.json' })
      .includes('publication-export --publication'),
  );
  if (envelope.study.representation === 'switching-overview') {
    assert(html.includes('Trace selected claims / CVSS scores (load on demand)'));
    assert(html.includes('Selected provenance (load on demand)'));
  }
  assert(api.render(envelope, { loading: true }).includes('last accepted selection'));
  assert(
    api.render(envelope, { error: '<img onerror=bad()>' }).includes('&lt;img onerror=bad()&gt;'),
  );
  const bad = clone(envelope);
  bad.release_history.selection.scope_level = 'model_qualified';
  assert.throws(() => api.build(bad.study, bad.release_history));
  if (envelope.release_history.bundles.length) {
    assert(html.includes('&lt;svg onload=bad()&gt; Unicode café'));
    assert(!html.includes('<svg onload=bad()>'));
    assert(
      html.includes('bundle membership does not establish CVEs resolved per software version'),
    );
  }
  const own = api.build(test.envelope.study, test.envelope.release_history);
  own.study.rows.length = 0;
  assert(test.envelope.study.rows.length, 'composition owns its inputs');
}
(async () => {
  for (const name of ['publication-v2', 'delivery'])
    vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
  for (const fmt of ['v1', 'v2']) {
    const dir = fixtures.paths[fmt],
      reads = [];
    const fetch = async (path) => {
      reads.push(path);
      const full = require('path').join(dir, path.replace(/^\//, ''));
      if (!fs.existsSync(full)) return { ok: false, status: 404 };
      const raw = fs.readFileSync(full);
      return { ok: true, arrayBuffer: async () => raw, text: async () => raw.toString() };
    };
    const loader = await context.createStaticDelivery(fetch, '/');
    assert.strictEqual(typeof loader.switchingReleaseHistory, 'function');
    assert(!reads.some((p) => p.includes('switching-release-history')), 'history lazy');
    const study =
      fmt === 'v2'
        ? await loader.switchingOverview()
        : context.window.InfrastructureSwitching.summary(
            context.window.InfrastructureSwitching.selectReport(await loader.switchingReport()),
          );
    const history = await loader.switchingReleaseHistory(study);
    api.build(study, history);
    assert(!reads.some((p) => /snapshot\.json/.test(p)), 'no whole runtime snapshot');
    if (fmt === 'v1') {
      const file = require('path').join(dir, 'switching-release-history.json'),
        original = fs.readFileSync(file);
      fs.unlinkSync(file);
      const old = await context.createStaticDelivery(fetch, '/');
      assert.strictEqual((await old.switchingReleaseHistory(study)).availability, 'unavailable');
      await assert.rejects(
        () => old.switchingReleaseHistory({ ...study, generated_at: '2027-01-01T00:00:00Z' }),
        /mixed generations/,
      );
      const mixed = clone(history);
      mixed.generated_at = '2020-01-01T00:00:00Z';
      fs.writeFileSync(file, JSON.stringify(mixed));
      const retry = await context.createStaticDelivery(fetch, '/');
      await assert.rejects(() => retry.switchingReleaseHistory(study), /mixed generations/);
      fs.writeFileSync(file, original);
      assert.strictEqual(
        (await retry.switchingReleaseHistory(study)).availability,
        'available',
        'failed history can retry',
      );
      let cancelled = false;
      const oversized = await context.createStaticDelivery(
        async (path) =>
          path.endsWith('switching-release-history.json')
            ? {
                ok: true,
                body: {
                  getReader: () => ({
                    read: async () => ({ done: false, value: new Uint8Array(8000001) }),
                    cancel() {
                      cancelled = true;
                    },
                    releaseLock() {},
                  }),
                },
              }
            : fetch(path),
        '/',
      );
      await assert.rejects(() => oversized.switchingReleaseHistory(study), /budget/);
      assert(cancelled, 'oversize history cancels the response');
    }
    if (fmt === 'v2') {
      await assert.rejects(
        () => loader.switchingReleaseHistory(study, { max_bytes: 10 }),
        /budget/,
      );
      const catalog = JSON.parse(fs.readFileSync(require('path').join(dir, 'publication-v2.json'))),
        index = JSON.parse(fs.readFileSync(require('path').join(dir, 'data/index.json')));
      delete catalog.roots['switching-release-history.json'];
      const old = await context.window.InfrastructurePublicationV2.open(fetch, catalog, index);
      assert.strictEqual(
        (await old.switchingReleaseHistory(study)).availability,
        'unavailable',
        'optional v2 root',
      );
      await assert.rejects(
        () => old.switchingReleaseHistory({ ...study, generated_at: '2027-01-01T00:00:00Z' }),
        /mixed generations/,
      );
      await assert.rejects(
        () => loader.switchingReleaseHistory({ ...study, generated_at: '2020-01-01T00:00:00Z' }),
        /mixed generations/,
      );
    }
    const count = reads.length;
    const empty = clone(study);
    empty.selection.effective_cve_ids = [];
    empty.rows.forEach((r) => (r.affected_cve_ids = []));
    const filtered = await loader.switchingReleaseHistory(empty);
    assert(filtered.releases.every((r) => !r.references.length));
    assert.strictEqual(reads.length, count, 'complete root retained across selections');
    const restored = await loader.switchingReleaseHistory(study);
    assert.deepStrictEqual(clone(restored), clone(history), 'new selection uses complete root');
  }
  fs.rmSync(fixtures.temporary, { recursive: true, force: true });
  console.log(
    'Customer comparison shared vectors, Python CSV/overview parity and lazy v1/v2 transport passed',
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

// Actual app state and hash navigation, using a minimal DOM boundary.
(async () => {
  const ctx = {
    ...context,
    window: { ...context.window },
    location: { origin: 'https://example.test', hash: '#customer-comparison' },
  };
  const nodes = new Map(),
    listeners = {};
  const node = (id) => {
    if (!nodes.has(id))
      nodes.set(id, {
        value: id === '#cohort' ? 'benchmark' : '',
        innerHTML: '',
        hidden: false,
        addEventListener(event, fn) {
          this[event] = fn;
        },
        setAttribute() {},
        removeAttribute() {},
        querySelectorAll() {
          return [];
        },
      });
    return nodes.get(id);
  };
  ctx.document = {
    querySelector: node,
    querySelectorAll: () => [],
    baseURI: 'https://example.test/',
  };
  ctx.window.addEventListener = (event, fn) => (listeners[event] = fn);
  ctx.window.fetch = () => {};
  vm.createContext(ctx);
  const source = fs
    .readFileSync('infrastructure_impact/web/app.js', 'utf8')
    .replace(/\nload\(\);\n/, '\n');
  vm.runInContext(source, ctx);
  assert.strictEqual(vm.runInContext('view', ctx), 'compare', 'initial hash opens Comparison');
  assert.strictEqual(
    vm.runInContext('comparisonMode', ctx),
    'customer',
    'initial hash selects customer',
  );
  const renderApp = ctx.render;
  const envelope = fixtures.cases[0].envelope;
  let resolveHistory,
    historyCalls = 0;
  ctx.acceptedStudy = envelope.study;
  ctx.createStaticDelivery = async () => ({
    publication: envelope.publication,
    generated_at: envelope.generated_at,
    switchingOverview: async () => envelope.study,
    switchingSelection: async () => envelope.study,
    switchingClaims: async () => [],
    switchingReleaseHistory: () => {
      historyCalls++;
      return new Promise((r) => (resolveHistory = r));
    },
  });
  vm.runInContext(
    'data={publication:acceptedStudy.publication,generated_at:acceptedStudy.generated_at};renderComparison=()=>{};',
    ctx,
  );
  const first = ctx.loadSwitching();
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(historyCalls, 1);
  resolveHistory(envelope.release_history);
  await first;
  assert.deepStrictEqual(JSON.parse(await ctx.customerDownload('json').text()), envelope);
  const second = ctx.loadSwitching({ vendor: 'arista' });
  await new Promise((r) => setImmediate(r));
  assert.deepStrictEqual(
    JSON.parse(await ctx.customerDownload('json').text()),
    envelope,
    'pending filters preserve export',
  );
  resolveHistory({ ...envelope.release_history, generated_at: '2020-01-01T00:00:00Z' });
  await second;
  assert(vm.runInContext('switchingError', ctx).includes('rejected'));
  assert.deepStrictEqual(
    JSON.parse(await ctx.customerDownload('json').text()),
    envelope,
    'failed history preserves envelope',
  );
  vm.runInContext('view="matrix";comparisonMode="benchmark";render=()=>{};', ctx);
  listeners.hashchange();
  assert.strictEqual(
    vm.runInContext('view', ctx),
    'compare',
    'same-document hash opens Comparison',
  );
  assert.strictEqual(vm.runInContext('comparisonMode', ctx), 'customer');
  let unrelatedFetches = 0;
  ctx.fetch = async () => {
    unrelatedFetches++;
    throw Error('unrelated cohort read');
  };
  ctx.createStaticDelivery = async () => ({
    publication: envelope.publication,
    generated_at: envelope.generated_at,
    bootstrap: () => ({
      publication: envelope.publication,
      generated_at: envelope.generated_at,
      benchmark_cohort: { 'CVE-2024-6387': 'Synthetic' },
    }),
    switchingOverview: async () => envelope.study,
    switchingSelection: async () => envelope.study,
    switchingReleaseHistory: async () => envelope.release_history,
  });
  vm.runInContext(
    'data=undefined;switchingDelivery=null;selectedCves=null;view="compare";comparisonMode="customer";',
    ctx,
  );
  await ctx.load();
  await new Promise((r) => setImmediate(r));
  assert.strictEqual(
    unrelatedFetches,
    0,
    'cold customer startup never fetches benchmark metadata/state',
  );
  assert.strictEqual(
    vm.runInContext('selectedCves', ctx),
    null,
    'global benchmark selection preserved',
  );
  assert.strictEqual(vm.runInContext('cohortMode', ctx), 'benchmark');
  let benchmarkLoads = 0;
  ctx.load = async () => benchmarkLoads++;
  vm.runInContext('view="matrix";', ctx);
  renderApp();
  assert.strictEqual(
    benchmarkLoads,
    1,
    'normal navigation hydrates the preserved benchmark selection',
  );
  console.log(
    'Customer initial/same-document navigation and accepted-envelope export ownership passed',
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

// Exercise the actual operation/scoped/history functions with only root I/O gated.
// A second consumer must stop waiting without closing the first consumer's transport.
(async () => {
  const source = fs.readFileSync('infrastructure_impact/web/publication-v2.js', 'utf8'),
    operationStart = source.indexOf('  let operationId = 0;'),
    historyStart = source.indexOf('    let releaseHistoryPromise;');
  assert(operationStart >= 0 && historyStart >= 0);
  const helpers = source.slice(
      operationStart,
      source.indexOf('  async function* streamTokens', operationStart),
    ),
    history = source.slice(
      historyStart,
      source.indexOf('    return {\n      metadata:', historyStart),
    ),
    fixture = fixtures.cases[0].envelope;
  function gatedHistory() {
    let release,
      started,
      reads = 0,
      transportSignal;
    const gate = new Promise((resolve) => (release = resolve)),
      ready = new Promise((resolve) => (started = resolve)),
      ctx = {
        window: context.window,
        json: context.window.InfrastructureJSON,
        catalog: {
          publication: fixture.publication,
          generated_at: fixture.generated_at,
          roots: { 'switching-release-history.json': {} },
        },
        AbortController,
        Date,
        Promise,
        setTimeout,
        clearTimeout,
        field: async (name, path) => fixture.release_history[path[0]],
        materializeRoot: async (name, options) => {
          reads++;
          transportSignal = options.operation.signal;
          started();
          await options.operation.run(gate);
          return fixture.release_history;
        },
      };
    vm.createContext(ctx);
    vm.runInContext(helpers + history, ctx);
    return {
      load: (options) => ctx.switchingReleaseHistory(fixture.study, options),
      ready,
      release: () => release(),
      reads: () => reads,
      signal: () => transportSignal,
    };
  }
  async function promptly(promise) {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error('consumer waited for another caller')), 1000);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  for (const reason of ['abort', 'deadline']) {
    const reader = gatedHistory(),
      owner = reader.load({});
    await reader.ready;
    const controller = new AbortController();
    const waiting = reader.load(
      reason === 'abort' ? { signal: controller.signal } : { deadline: Date.now() + 25 },
    );
    const rejected = assert.rejects(() => waiting, reason === 'abort' ? /cancelled/ : /deadline/);
    if (reason === 'abort') controller.abort();
    try {
      await promptly(rejected);
      assert(!reader.signal().aborted, 'second consumer cannot abort the shared transport owner');
      assert.strictEqual(reader.reads(), 1, 'overlapping calls share the root read');
    } finally {
      reader.release();
      await owner;
    }
    assert.deepStrictEqual(
      clone(await reader.load({})),
      fixture.release_history,
      'cancelled consumer preserves valid cache',
    );
    assert.strictEqual(reader.reads(), 1, 'valid cache remains available');
  }
  const retry = gatedHistory(),
    controller = new AbortController();
  const failed = assert.rejects(() => retry.load({ signal: controller.signal }), /cancelled/);
  await retry.ready;
  controller.abort();
  await promptly(failed);
  retry.release();
  assert.deepStrictEqual(
    clone(await retry.load({})),
    fixture.release_history,
    'owner failure permits a fresh root read',
  );
  assert.strictEqual(retry.reads(), 2, 'failed shared transport is evicted');
  console.log(
    'Overlapping history abort/deadline isolation, valid cache and failed-owner retry passed',
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
