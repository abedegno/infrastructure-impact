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

const misboundTarget = JSON.parse(JSON.stringify(vectors.compiled));
const targetRequirement = misboundTarget.requirements.requirements.find((r) => r.target !== null);
targetRequirement.target = '17.15.99';
misboundTarget.requirements.content_sha256 =
  context.window.InfrastructureSwitchingContracts.fingerprint(
    Object.fromEntries(
      Object.entries(misboundTarget.requirements).filter(([k]) => k !== 'content_sha256'),
    ),
  );
misboundTarget.content_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(
  Object.fromEntries(Object.entries(misboundTarget).filter(([k]) => k !== 'content_sha256')),
);
assert.throws(
  () => A.select(misboundTarget, vectors.cases[0].context),
  /target differs/,
  'rehashed target must match compiled alternatives',
);

for (const vector of vectors.numeric_cases)
  assert.strictEqual(
    A.csv(vector.selected),
    vector.expected,
    'exact fractional/exponent/signed-zero CSV tokens',
  );

for (const reference of [
  '0'.repeat(64),
  Object.keys(vectors.compiled.requirements.facts).find((k) =>
    Array.isArray(vectors.compiled.requirements.facts[k]),
  ),
]) {
  const r = JSON.parse(JSON.stringify(vectors.compiled));
  Object.values(r.claims)[0].source_ref = reference;
  r.content_sha256 = context.window.InfrastructureSwitchingContracts.fingerprint(
    Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'content_sha256')),
  );
  assert.throws(
    () => A.select(r, vectors.cases[0].context),
    /source reference/,
    'absent or wrongly typed pooled source',
  );
}
for (const requirement of vectors.compiled.requirements.requirements) {
  assert(!Object.hasOwn(requirement, 'source_ref'));
  assert(!Object.hasOwn(requirement, 'severity_facets_ref'));
}

const ownedInput = JSON.parse(JSON.stringify(vectors.compiled)),
  beforeOwnership = JSON.stringify(ownedInput),
  ownedOutput = A.select(ownedInput, A.context(ownedInput, {}));
ownedOutput.upgrades.requirements.kev_context.evaluated_at = 'changed-output-only';
const ownedFacet = ownedOutput.disclosure.pairs.flatMap((p) => p.severity)[0];
if (ownedFacet) ownedFacet.band = 'changed-output-only';
assert.strictEqual(
  JSON.stringify(ownedInput),
  beforeOwnership,
  'selected nested metadata/facets must not alias immutable compiled input',
);

{
  const C = context.window.InfrastructureSwitchingContracts,
    report = JSON.parse(JSON.stringify(vectors.compiled)),
    identity = JSON.parse(JSON.stringify(vectors.cases[0].context)),
    originalValidate = C.validate;
  let validations = 0;
  C.validate = (name, value, fragment) => {
    if (name === 'switching-analysis-v1.json' && fragment === '/$defs/compiled') validations++;
    return originalValidate(name, value, fragment);
  };
  try {
    assert.strictEqual(typeof A.prepare, 'function', 'prepared selector API');
    Object.freeze(report.requirements);
    const select = A.prepare(report, identity);
    assert(Object.isFrozen(report), 'compiled root is frozen');
    assert(Object.isFrozen(report.requirements.kev_context), 'even pre-frozen branches are deep');
    assert(Object.isFrozen(report.requirements.requirements[0].alternatives));
    identity.publication = { id: 'changed-external-identity' };
    identity.generated_at = '2000-01-01T00:00:00Z';

    for (const v of vectors.cases) {
      const selected = select(v.context);
      assert.deepStrictEqual(JSON.parse(JSON.stringify(selected)), v.expected, v.name);
      assert.strictEqual(A.csv(selected), v.analysis_csv, v.name + ' analysis CSV');
    }
    assert.throws(() => select(identity), /generation|identity|publication/i);
    assert.throws(
      () =>
        select({
          ...vectors.cases[0].context,
          selection: { ...vectors.cases[0].context.selection, effective_cve_ids: [] },
        }),
      /accepted cohort differs/,
    );
    const study = vectors.cases[0].context,
      selected = select(study);
    selected.upgrades.requirements.kev_context.evaluated_at = 'changed-output-only';
    selected.disclosure.pairs[0].source.source_locator = 'changed-output-only';
    assert.strictEqual(
      selected.upgrades.requirements.kev_context.evaluated_at,
      'changed-output-only',
    );
    assert.strictEqual(selected.disclosure.pairs[0].source.source_locator, 'changed-output-only');
    assert.deepStrictEqual(JSON.parse(JSON.stringify(select(study))), vectors.cases[0].expected);
    assert.strictEqual(
      validations,
      1,
      'one complete validation across accepted and rejected calls',
    );
    assert.throws(() => A.prepare(changed, study), /fingerprint/);
    assert.throws(() => A.prepare(null, study), undefined, 'present null is malformed');
    const accessor = JSON.parse(JSON.stringify(vectors.compiled));
    const publication = accessor.publication;
    Object.defineProperty(accessor, 'publication', { get: () => publication, enumerable: true });
    assert.throws(() => A.prepare(accessor, study), /owned JSON data/);
  } finally {
    C.validate = originalValidate;
  }
}

{
  const report = JSON.parse(JSON.stringify(vectors.compiled.requirements)),
    member = Object.values(report.members)[0],
    { vendor, cve_id: cve } = member,
    original = report.facts[member.source_ref];
  member.advisory_id = 'advisory:partition';
  function group(group_id, vendor, advisory_id, cve_ids) {
    return {
      group_id,
      vendor,
      advisory_id,
      cve_ids,
      product: null,
      product_ids: null,
      train_expression: null,
      disposition: 'affected',
      method: 'authored',
      source: original,
    };
  }
  report.source_groups = [
    group('first', vendor, member.advisory_id, [cve]),
    group('joined-key-collision', vendor, 'advisory', ['partition:' + cve]),
    group('other-vendor', 'aruba', member.advisory_id, [cve]),
    group('other-cve', vendor, member.advisory_id, ['CVE-2025-1234567']),
    group('last', vendor, member.advisory_id, ['CVE-2025-1234567', cve]),
  ];
  report.inference_groups = ['kept-second', 'unused', 'kept-first'].map((group_id) => ({
    group_id,
  }));
  const inferred = report.requirements.filter((r) => r.claim_id === member.claim_id);
  inferred[0].inference = { group_id: 'kept-first' };
  inferred[1].inference = { group_id: 'kept-second' };
  const selected = A.upgrades(report, vectors.cases[0].context).requirements;
  assert.strictEqual(
    JSON.stringify(selected.source_groups.map((g) => g.group_id)),
    '["first","last"]',
  );
  assert.strictEqual(
    JSON.stringify(selected.inference_groups.map((g) => g.group_id)),
    '["kept-second","kept-first"]',
  );
}

for (const vector of vectors.cases) {
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify([...A.detailedRows(vector.expected.upgrades)])),
    vector.detailed_rows,
    vector.name + ' exact detailed row inflation',
  );
}
for (const mutation of ['digest', 'missing', 'index', 'duplicate', 'unused']) {
  const report = JSON.parse(JSON.stringify(vectors.cases[0].expected.upgrades)),
    e = report.row_evidence;
  if (mutation === 'digest') e.member_order_sha256 = '0'.repeat(64);
  else if (mutation === 'missing') report.rows[0].affected_ref = '0'.repeat(64);
  else if (mutation === 'unused') e.affected['0'.repeat(64)] = [];
  else {
    const row = report.rows.find((r) => e.affected[r.affected_ref].length),
      values = e.affected[row.affected_ref];
    values.splice(
      0,
      values.length,
      ...(mutation === 'index' ? [e.member_count] : [values[0], values[0]]),
    );
    const key = context.window.InfrastructureSwitchingContracts.fingerprint({ items: values });
    e.affected[key] = values;
    row.affected_ref = key;
  }
  assert.throws(() => [...A.detailedRows(report)], undefined, 'selected evidence ' + mutation);
}
for (const vector of vectors.complete_kev.cases) {
  const compiled = vectors.complete_kev.compiled;
  const selected = A.reconciliation(compiled, A.context(compiled, vector.options).selection);
  assert.deepStrictEqual(
    JSON.parse(JSON.stringify(selected)),
    vector.expected,
    'complete-feed missing-record reconciliation',
  );
}
