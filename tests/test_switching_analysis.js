// Authored native-oracle vectors, no vendor parsing or full claim hydration.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, console, URL, TextEncoder, TextDecoder };
vm.createContext(context);
for (const name of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'customer-comparison',
  'switching-analysis',
])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
const A = context.window.InfrastructureSwitchingAnalysis,
  vectors = JSON.parse(fs.readFileSync('tests/fixtures/switching-analysis-vectors.json'));
for (const v of vectors.cases) {
  const selected = A.select(vectors.compiled, A.context(vectors.compiled, v.options));
  assert.deepStrictEqual(JSON.parse(JSON.stringify(selected)), v.expected, v.name + ' JSON');
  assert.strictEqual(
    A.csv(selected, { upgradesOnly: true }),
    v.upgrades_csv,
    v.name + ' upgrade CSV',
  );
  assert.strictEqual(A.csv(selected), v.analysis_csv, v.name + ' analysis CSV');
}
const changed = JSON.parse(JSON.stringify(vectors.compiled));
changed.requirements.requirements[0].target = '99.99.99';
assert.throws(() => A.select(changed, vectors.cases[0].context), /fingerprint/);
assert.strictEqual(A.select(null, vectors.cases[0].context).availability, 'unavailable');
const mixed = { ...vectors.cases[0].context, generated_at: '2026-11-14T00:00:00Z' };
assert.throws(() => A.select(vectors.compiled, mixed), /generation|identity|publication/i);
console.log('Native compact analysis JSON/CSV and absent/tampered/mixed generation parity passed');

assert.strictEqual(
  A.csv(vectors.numeric_csv.selected),
  vectors.numeric_csv.expected,
  'integral CVSS nested CSV',
);
for (const v of vectors.numeric_fingerprints)
  assert.strictEqual(
    context.window.InfrastructureSwitchingContracts.fingerprint(v.value),
    v.sha256,
    'numeric canonical identity',
  );
const html = A.render(vectors.cases[0].expected);
for (const text of [
  'Upgrade estimates',
  'Disclosure eras',
  'Per-model',
  'KEV',
  'analysis-family',
  'analysis-train',
  'analysis-year',
  'analysis-policy',
  'analysis-scenario',
  'Independent human review pending',
])
  assert(html.includes(text), text);
assert(A.render(null, { error: '<script>bad</script>' }).includes('&lt;script&gt;'));

// Execute the real acceptance function with delayed delivery and a new study sequence.
(async () => {
  const app = fs.readFileSync('infrastructure_impact/web/app.js', 'utf8');
  let finish;
  const study = vectors.cases[0].context,
    selected = vectors.cases[0].expected;
  const loader = {
    publication: study.publication,
    generated_at: study.generated_at,
    switchingAnalysis: () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  };
  const race = {
    window: context.window,
    data: { publication: study.publication, generated_at: study.generated_at },
    analysisSequence: 0,
    switchingSequence: 1,
    analysisLoading: false,
    analysisError: '',
    analysisReport: null,
    analysisStudy: null,
    view: 'compare',
    comparisonMode: 'switching',
    renderComparison: () => {},
  };
  vm.createContext(race);
  vm.runInContext(
    app.slice(app.indexOf('async function loadAnalysis('), app.indexOf('function studyOptions(')),
    race,
  );
  const pending = race.loadAnalysis(study, { promise: Promise.resolve(loader) });
  await new Promise(setImmediate);
  race.switchingSequence++;
  finish(selected);
  await pending;
  assert.strictEqual(race.analysisReport, null, 'late result must not replace accepted state');
  const next = race.loadAnalysis(study, {
    promise: Promise.resolve({ ...loader, switchingAnalysis: async () => selected }),
  });
  await next;
  assert.strictEqual(race.analysisReport, selected);
  const accepted = race.analysisReport;
  race.data = { publication: study.publication, generated_at: '2000-01-01T00:00:00Z' };
  await race.loadAnalysis(study, {
    promise: Promise.resolve({ ...loader, switchingAnalysis: async () => selected }),
  });
  assert.strictEqual(
    race.analysisReport,
    accepted,
    'mixed publication must retain accepted export object',
  );
  assert(race.analysisError.includes('rejected'));
  console.log('Real analysis acceptance awaits preserve selected generation and export object');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

for (const mutate of [
  (r) => {
    r.disclosure.pairs[0].claim_ids = ['f'.repeat(64)];
  },
  (r) => {
    r.requirements.requirements.pop();
    r.requirements.content_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(
      Object.fromEntries(Object.entries(r.requirements).filter(([k]) => k !== 'content_sha256')),
    );
  },
  (r) => {
    r.disclosure.observation_end = '2000-01-01';
  },
]) {
  const r = JSON.parse(JSON.stringify(vectors.compiled));
  mutate(r);
  r.content_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(
    Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'content_sha256')),
  );
  assert.throws(
    () => A.select(r, vectors.cases[0].context),
    /ownership|bounds|scenario|contract/,
    'rehashed child must still retain source ownership',
  );
}
assert.throws(() => A.validate(null), undefined, 'present null is malformed');
assert.throws(
  () => A.csv(vectors.cases[0].expected, { max_bytes: 100 }),
  /budget|limit|exceed/i,
  'typed CSV byte bound',
);
