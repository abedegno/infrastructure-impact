const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, console, TextEncoder };
vm.createContext(context);
for (const name of ['kev', 'switching-contracts', 'switching'])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
const data = JSON.parse(fs.readFileSync('tests/fixtures/switching-cases.json'));
const api = context.window.InfrastructureSwitching;
assert(api);
for (const c of data.comparison_cases) {
  const selected = JSON.parse(
    JSON.stringify(api.selectReport(data.comparison_base_report, c.options)),
  );
  delete selected.inputs;
  delete selected.definition;
  assert.deepStrictEqual(selected, c.expected, c.name);
}
console.log('Switching shared parity passed');
for (const c of data.severity_band_cases)
  assert.strictEqual(api.severityBand(c.version, c.value), c.band);
for (const value of [null, undefined])
  assert.throws(() => api.selectReport({ ...data.comparison_base_report, inputs: value }));
assert.throws(() =>
  api.selectReport({
    ...data.comparison_base_report,
    inputs: {
      ...data.comparison_base_report.inputs,
      evidence: {
        ...data.comparison_base_report.inputs.evidence,
        generated_at: '2025-01-01T00:00:00Z',
      },
    },
  }),
);
assert.deepStrictEqual(
  JSON.parse(
    JSON.stringify(
      api.selectReport(data.comparison_base_report, {
        cve_ids: [],
        evaluated_at: '2026-11-04T10:00:00Z',
      }).selection.effective_cve_ids,
    ),
  ),
  [],
);
const contracts = context.window.InfrastructureSwitchingContracts;
const { createHash } = require('crypto');
for (const value of [
  '',
  'a',
  'x'.repeat(55),
  'x'.repeat(56),
  'x'.repeat(64),
  'x'.repeat(1000),
  'é\u{10000}\ue000😀',
]) {
  assert.strictEqual(
    contracts.fingerprint(value),
    createHash('sha256').update(JSON.stringify(value)).digest('hex'),
  );
}
for (const change of [
  (report) => (report.definition.references[0].reviewed_at = '2026-11-03'),
  (report) => (report.inputs.evidence.schema_version = 999),
  (report) => (report.inputs.evidence.unrecognized_field = true),
  (report) => (report.inputs.kev.policy.unrecognized_field = true),
  (report) => (report.inputs.evidence.claims[0].publisher.unrecognized_field = true),
]) {
  const report = JSON.parse(JSON.stringify(data.comparison_base_report));
  change(report);
  assert.throws(() => api.selectReport(report));
}
console.log('Strict switching schema, definition hash and SHA-256 block/Unicode checks passed.');
const malformedSource = {
  ...data.comparison_base_report.inputs.evidence.claims[0].source,
  source_url: 'https://www.arista.com/[invalid-path]',
};
assert.throws(() =>
  contracts.validate('switching-evidence-v1.json', malformedSource, '/$defs/source'),
);

// Validation ownership: mutable callers cannot poison the retained source or skip
// the boundary check; accepted immutable reports share inputs across selections.
const caller = JSON.parse(JSON.stringify(data.comparison_base_report));
const prepared = api.prepareReport(caller);
assert(!Object.isFrozen(caller.inputs.evidence.claims[0]), 'caller keeps mutable ownership');
assert(Object.isFrozen(prepared.inputs.evidence.claims[0].source));
caller.inputs.evidence.claims[0].platform_bindings[0].model = '7500';
assert.throws(() => api.selectReport(caller));
assert.notStrictEqual(prepared.inputs.evidence.claims[0].platform_bindings[0].model, '7500');
const fullValidation = contracts.full;
let checks = 0;
contracts.full = (...args) => {
  checks++;
  return fullValidation(...args);
};
const firstSelection = api.selectReport(prepared, { vendor: 'arista' });
const nextSelection = api.selectReport(firstSelection, { scope_level: 'model_qualified' });
assert.strictEqual(checks, 0, 'owned immutable inputs are not revalidated');
assert.strictEqual(firstSelection.inputs, nextSelection.inputs, 'complete evidence shared');
assert(Object.isFrozen(nextSelection.rows[0].counts));
const tampered = { ...nextSelection, rows: [] };
assert.throws(() => api.selectReport(tampered), 'new object identity requires validation');
assert.strictEqual(checks, 1);
contracts.full = fullValidation;
console.log('Immutable study ownership, repeated selection and mutable-input rejection passed.');

// Only the owned JSON value is validated; caller serialization hooks cannot swap
// an unchecked value into the immutable cache after validation.
let serializationHookCalls = 0;
const hooked = Object.assign(
  Object.create({
    toJSON() {
      serializationHookCalls++;
      const changed = JSON.parse(JSON.stringify(data.comparison_base_report));
      changed.inputs.evidence.claims[0].conditions.push('unchecked condition');
      return changed;
    },
  }),
  data.comparison_base_report,
);
api.prepareReport(hooked);
assert.strictEqual(serializationHookCalls, 0, 'caller toJSON must not produce trusted data');
for (const value of [NaN, Infinity, -Infinity]) {
  const invalid = JSON.parse(JSON.stringify(data.comparison_base_report));
  invalid.inputs.evidence.claims[0].scores[0].value = value;
  assert.throws(
    () => api.prepareReport(invalid),
    'nonfinite scores rejected before copy normalization',
  );
  assert.throws(() => contracts.fingerprint({ value }));
}
(async () => {
  assert.strictEqual(typeof api.selectClaims, 'function', 'streamed reducer required');
  for (const c of data.comparison_cases) {
    const base = data.comparison_base_report;
    const selected = await api.selectClaims(
      base,
      base.inputs.evidence,
      base.inputs.kev,
      (async function* () {
        yield* base.inputs.evidence.claims;
      })(),
      c.options,
    );
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(selected)),
      JSON.parse(JSON.stringify(api.summary(api.selectReport(base, c.options)))),
      c.name,
    );
  }
  console.log('Streamed private projection query parity passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
(async () => {
  const vectors = JSON.parse(fs.readFileSync('tests/fixtures/publication-v2-query-vectors.json'));
  for (const c of vectors.cases) {
    const base = vectors.report;
    const selected = await api.selectClaims(
      base,
      base.inputs.evidence,
      base.inputs.kev,
      (async function* () {
        yield* base.inputs.evidence.claims;
      })(),
      { ...c.options, evaluated_at: c.evaluated_at },
    );
    assert.deepStrictEqual(JSON.parse(JSON.stringify(selected)), c.summary, c.name);
    assert.strictEqual(api.csvExport(selected), c.csv, c.name + ' CSV');
  }
  console.log('Publication v2 shared cross-language query JSON and CSV vectors passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
(async () => {
  const base = data.comparison_base_report,
    claim = JSON.parse(JSON.stringify(base.inputs.evidence.claims[0]));
  claim.product += ' tampered';
  await assert.rejects(
    () =>
      api.selectClaims(
        base,
        base.inputs.evidence,
        base.inputs.kev,
        (async function* () {
          yield claim;
        })(),
        {},
      ),
    /claim IDs/,
  );
  console.log('Streamed semantic identity validation passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
{
  const evidence = JSON.parse(fs.readFileSync('tests/fixtures/publication-v2-reviewed-link.json'));
  const validator = contracts.evidenceStream(evidence, data.comparison_base_report.definition);
  for (const claim of evidence.claims) validator.add(claim);
  validator.finish();
  const missing = contracts.evidenceStream(evidence, data.comparison_base_report.definition);
  for (const claim of evidence.claims.filter((c) => c.status !== 'fixed')) missing.add(claim);
  assert.throws(() => missing.finish(), /reviewed section/);
  console.log('Streamed reviewed-section cross-claim linkage passed');
}
