const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, console };
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
