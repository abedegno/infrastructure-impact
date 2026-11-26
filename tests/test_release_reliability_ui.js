const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, URL, TextEncoder, TextDecoder, console };
vm.createContext(context);
for (const name of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'release-reliability',
]) {
  const file = `infrastructure_impact/web/${name}.js`;
  if (fs.existsSync(file)) vm.runInContext(fs.readFileSync(file, 'utf8'), context);
}
const R = context.window.InfrastructureReleaseReliability;
assert(R, 'release reliability browser interface is available');
assert(R.render(null).includes('unavailable'), 'missing generation root stays unavailable');
assert(R.render(null, { error: '<script>' }).includes('&lt;script&gt;'));
assert(
  R.render(null, { error: 'Retryable read failure' }).includes('reliability-retry'),
  'failed evidence reads offer a retry',
);
if (process.argv[2]) {
  const vectors = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  R.validate(vectors.report);
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(R.coverageReport(vectors.report))),
    vectors.coverage,
    'coverage JSON parity',
  );
  assert.strictEqual(R.coverageCSV(vectors.report), vectors.coverage_csv, 'coverage CSV parity');
  assert(R.render(vectors.report).includes('Coverage gaps by model'));
  assert(R.render(vectors.report).includes('reliability-coverage-json'));
  assert(!R.render(vectors.report).includes('<img src=x'), 'coverage model text is escaped');
  if (vectors.report.availability === 'available')
    assert(
      R.render(vectors.report).includes('reliability-review'),
      'review packet download is available',
    );
  assert.throws(() =>
    R.validate(vectors.report, { ...vectors.report, generated_at: '2000-01-01T00:00:00Z' }),
  );
  const selected = R.withUpgrades(vectors.report, vectors.upgrades);
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(selected)),
    vectors.selected,
    'Python/JS selected annotations',
  );
  assert.strictEqual(R.csvExport(selected), vectors.csv, 'Python/JS CSV parity');
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(vectors.report.annual)),
    JSON.parse(JSON.stringify(selected.annual)),
  );
  const html = R.render(selected);
  for (const text of [
    'Production eligible',
    'Denominator',
    'Research',
    'Independent human review pending',
    'reliability-json',
  ])
    assert(html.includes(text), text);
  assert(!html.includes('href="javascript:'), 'unsafe source URL cannot become a link');
  const steps = R.renderSteps(selected, vectors.upgrades.rows, vectors.upgrades.selection);
  assert(steps.includes('Model') || !selected.upgrade_annotations.length);
}
console.log('Release reliability browser tests passed');
if (process.argv[2]) {
  const v = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const copy = (value) => JSON.parse(JSON.stringify(value));
  let bad = copy(v.report);
  bad.annual[0].metrics.releases_shipped.observed_count = 999;
  assert.throws(() => R.validate(bad), /derived|facts/);
  bad = copy(v.report);
  bad.catalogue.sources[0].source_url = 'https://www.cisco.com@evil.example/x';
  bad.catalogue_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(bad.catalogue);
  assert.throws(() => R.validate(bad), /unsafe|source/);
  bad = copy(v.report);
  bad.catalogue.generated_at = '2099-01-01T00:00:00Z';
  bad.dataset_observed_at = bad.catalogue.generated_at;
  assert.throws(() => R.validate(bad), /future/);
  assert.throws(() =>
    R.withUpgrades(v.report, { ...v.upgrades, generated_at: '2000-01-01T00:00:00Z' }),
  );
  assert.throws(() => R.csvExport(v.selected, { max_bytes: 10 }), /budget|limit/i);
  const guarded = copy(v.report);
  guarded.limitations.push('=SUM(A1)', '\t@danger');
  assert(R.csvExport(guarded).includes("'=SUM(A1)"));
  assert(R.csvExport(guarded).includes("'\t@danger"));
  assert(R.renderSteps(v.selected, v.upgrades.rows, { different: true }).includes('unavailable'));
}
// Exercise the real app loader with late completion and mixed generation roots.
(async () => {
  if (!process.argv[2]) return;
  const v = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')),
    app = fs.readFileSync('infrastructure_impact/web/app.js', 'utf8'),
    source = app.slice(
      app.indexOf('function releaseReliabilityState('),
      app.indexOf('async function loadAnalysis('),
    );
  let finish,
    renders = 0;
  const delivery = {
      promise: Promise.resolve({
        publication: v.report.publication,
        generated_at: v.report.generated_at,
        releaseReliability: () =>
          new Promise((resolve) => {
            finish = resolve;
          }),
      }),
    },
    state = {
      window: context.window,
      reliabilityRoots: new WeakMap(),
      view: 'compare',
      comparisonMode: 'customer',
      renderComparison: () => {
        renders++;
      },
    };
  vm.createContext(state);
  vm.runInContext(source, state);
  const accepted = state.releaseReliabilityState(v.report, delivery);
  assert.strictEqual(accepted.report, null);
  await new Promise((resolve) => setImmediate(resolve));
  finish({ ...v.report, generated_at: '2000-01-01T00:00:00Z' });
  await new Promise((resolve) => setImmediate(resolve));
  assert.strictEqual(accepted.report, null, 'mixed-generation optional root is never accepted');
  assert(accepted.error.includes('rejected'));
  assert.strictEqual(
    state.releaseReliabilityState(v.report, delivery),
    accepted,
    'same delivery does not refetch',
  );
  assert.strictEqual(renders, 1);
  const old = state.releaseReliabilityState(v.report, {
    promise: Promise.resolve({
      publication: v.report.publication,
      generated_at: v.report.generated_at,
    }),
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.strictEqual(old.report, null, 'older root stays unavailable');
  assert.strictEqual(old.error, '');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
// Shared native-oracle vectors cover complete rates, partial scope and old roots.
for (const vector of JSON.parse(
  fs.readFileSync('tests/reliability-fixtures/release-reliability-vectors.json', 'utf8'),
)) {
  R.validate(vector.report);
  const report = R.withUpgrades(vector.report, vector.selected_upgrades);
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(report)),
    vector.expected,
    vector.name + ' JSON',
  );
  assert.strictEqual(R.csvExport(report), vector.csv, vector.name + ' CSV');
}
for (const vector of JSON.parse(
  fs.readFileSync('tests/reliability-fixtures/release-reliability-vectors.json', 'utf8'),
)) {
  const tampered = JSON.parse(JSON.stringify(vector.expected));
  const match = tampered.upgrade_annotations.flatMap((a) => a.matches)[0];
  if (match) {
    match.chronology = match.chronology === 'unknown' ? 'after_step' : 'unknown';
    assert.throws(() => R.validate(tampered), /annotation/);
  }
}
const nativeVectors = JSON.parse(
  fs.readFileSync('tests/reliability-fixtures/release-reliability-vectors.json', 'utf8'),
);
const availableVector = nativeVectors.find((v) => v.report.availability === 'available');
const unavailableVector = nativeVectors.find((v) => v.report.availability === 'unavailable');
const futureUpgrades = JSON.parse(JSON.stringify(availableVector.selected_upgrades));
futureUpgrades.rows[0].events[0].date = '2099-01-01';
assert.throws(() => R.withUpgrades(availableVector.report, futureUpgrades), /future|date/i);
for (const change of [
  (c) => {
    c.start = '2099-01-01';
  },
  (c) => {
    c.start = '2000-01-01';
  },
  (c) => {
    c.trains[0].vendor = 'unknown';
  },
  (c) => {
    c.trains.push(JSON.parse(JSON.stringify(c.trains[0])));
  },
  (c) => {
    c.trains[0].platforms = [];
  },
  (c) => {
    c.trains[0].base_pattern = '[';
  },
]) {
  const report = JSON.parse(JSON.stringify(unavailableVector.report));
  change(report.config);
  assert.throws(() => R.validate(report), /config|train|period|contract|regular|schema/i);
}
const presentation = R.render(availableVector.report);
assert(presentation.includes('class="reliability-train"'), 'each train has a compact summary');
assert(
  presentation.includes('class="reliability-metric-details"'),
  'full metric audit remains expandable',
);
const compactPresentation = presentation
  .replace(/<section class="reliability-coverage">[\s\S]*?<\/section>/, '')
  .replace(/<details\b[\s\S]*?<\/details>/g, '');
assert(
  !compactPresentation.includes('Rate unavailable: complete dated original'),
  'repeated audit reasons stay out of the main summary',
);
assert.strictEqual(
  (compactPresentation.match(/<tbody>/g) ?? []).length,
  availableVector.report.config.trains.length,
  'one summary table per configured train',
);
assert.strictEqual(
  (compactPresentation.match(/<tr>/g) ?? []).length,
  availableVector.report.annual.length + availableVector.report.config.trains.length,
  'one summary row per year plus train headers',
);
assert(
  presentation.includes('Original SHA-256') && presentation.includes('Excerpt SHA-256'),
  'source details preserve distinct capture fingerprints',
);
const futurePeriod = nativeVectors.find((v) => v.name.endsWith('future_year'));
assert(
  R.render(futurePeriod.report).includes('2024–2027'),
  'heading uses the accepted configured period',
);

for (const source of availableVector.report.catalogue.sources) {
  for (const value of [
    source.original_sha256,
    source.excerpt_sha256,
    source.retrieved_at,
    source.capture_kind,
  ])
    if (value !== null)
      assert(presentation.includes(value), 'source capture metadata is visible in details');
}
// Syntax validation applies even when a fact cannot enter any annual cohort or join.
for (const [section, mutate] of [
  [
    'releases',
    (f) => {
      f.version = f.train + '.NOT-A-RELEASE';
    },
  ],
  [
    'notices',
    (f) => {
      f.affected_releases = [f.train + '.NOT-A-RELEASE'];
    },
  ],
  [
    'notices',
    (f) => {
      f.fixed_releases = [
        {
          version: f.train + '.NOT-A-RELEASE',
          platforms_stated: f.platforms_stated,
          conditions: 'Source-stated conditions',
        },
      ];
    },
  ],
  [
    'statements',
    (f) => {
      f.version = f.train + '.NOT-A-RELEASE';
    },
  ],
]) {
  const report = JSON.parse(JSON.stringify(availableVector.report));
  const fact = report.catalogue[section][0];
  mutate(fact);
  report.catalogue_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(
    report.catalogue,
  );
  for (const item of report.review_packet)
    if (
      item.type === (section === 'notices' ? 'notice' : 'statement') &&
      item.index === 0 &&
      section !== 'releases'
    )
      item.fact = JSON.parse(JSON.stringify(fact));
  assert.throws(
    () => R.validate(report),
    /unsupported release identity/i,
    section + ' validates complete release literals',
  );
}

// Exercise the actual app download handlers, including accepted generation checks.
if (process.argv[2]) {
  const vectors = JSON.parse(fs.readFileSync(process.argv[2], 'utf8')),
    source = fs.readFileSync('infrastructure_impact/web/app.js', 'utf8'),
    start = source.indexOf(
      "    for (const kind of ['json', 'csv', 'review', 'coverage-json', 'coverage-csv'])",
    ),
    end = source.indexOf('  window.InfrastructureSwitchingView.mount(', start),
    handlers = new Map(),
    downloads = [],
    bodies = [],
    state = {
      window: context.window,
      reliabilityReport: vectors.report,
      accepted: vectors.report,
      reliabilityState: { report: vectors.report, error: '' },
      appJSON: context.window.InfrastructureJSON,
      $: (selector) => ({ addEventListener: (_, callback) => handlers.set(selector, callback) }),
      Blob: class {
        constructor(parts) {
          this.body = parts.join('');
        }
      },
      URL: {
        createObjectURL: (blob) => {
          bodies.push(blob.body);
          return 'blob:test';
        },
        revokeObjectURL: () => {},
      },
      document: {
        createElement: () => {
          const a = { click: () => downloads.push(a.download) };
          return a;
        },
      },
      setTimeout: (f) => f(),
      renderComparison: () => {},
    };
  assert(start >= 0 && end > start, 'real app handlers found');
  vm.runInNewContext(source.slice(start, end).replace(/\n  }\s*$/, ''), state);
  handlers.get('#reliability-coverage-json')();
  handlers.get('#reliability-coverage-csv')();
  assert.deepStrictEqual(JSON.parse(bodies[0]), vectors.coverage);
  assert.strictEqual(bodies[1], vectors.coverage_csv);
  assert(downloads.every((name) => name.startsWith('release-reliability-coverage-')));
  state.accepted = { ...vectors.report, generated_at: '2000-01-01T00:00:00Z' };
  handlers.get('#reliability-coverage-json')();
  assert.strictEqual(downloads.length, 2, 'mixed generation download rejected');
  assert(state.reliabilityState.error.includes('rejected'));
}
