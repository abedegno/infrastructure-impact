const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, console, TextEncoder };
vm.createContext(context);
for (const name of ['lossless-json', 'kev', 'switching-contracts', 'switching'])
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
  const base = data.comparison_base_report;
  for (const working_bytes of [1, 512000001])
    await assert.rejects(
      () =>
        api.selectClaims(
          base,
          base.inputs.evidence,
          base.inputs.kev,
          (async function* () {
            yield* base.inputs.evidence.claims;
          })(),
          {},
          { working_bytes },
        ),
      /budget/,
    );
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
(async () => {
  const base = data.comparison_base_report;
  await assert.rejects(
    () =>
      api.selectClaims(
        base,
        base.inputs.evidence,
        base.inputs.kev,
        (async function* () {
          yield* base.inputs.evidence.claims;
        })(),
        {},
        { max_bytes: 400 },
      ),
    /budget/,
  );
  const selected = api.summary(api.selectReport(base)),
    csv = api.csvExport(selected),
    bytes = Buffer.byteLength(csv);
  assert.strictEqual(api.csvExport(selected, { max_bytes: bytes }), csv);
  assert.throws(() => api.csvExport(selected, { max_bytes: bytes - 1 }), /budget/);
  vm.runInContext(
    `const originalStringify=JSON.stringify;JSON.stringify=(value,...rest)=>{if(value?.inputs)throw Error('full inputs serialization forbidden');return originalStringify(value,...rest);};`,
    context,
  );
  try {
    api.summary(base);
  } finally {
    vm.runInContext('JSON.stringify=originalStringify;', context);
  }
  console.log(
    'Projection/reducer limits, CSV exact allowance and no full-input summary clone passed',
  );
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

// Count allocations through the public API, without exporting validator internals.
{
  let errors = 0;
  const probe = {
    window: {},
    Error: (...args) => {
      errors++;
      return Error(...args);
    },
  };
  vm.createContext(probe);
  for (const name of ['lossless-json', 'switching-contracts'])
    vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), probe);
  const validator = probe.window.InfrastructureSwitchingContracts;
  const tokens = [null, true, -2, [0], [-1, 0], [-2, 'i', '123'], [-3, 'switching-evidence.json']];
  errors = 0;
  for (let i = 0; i < 50; i++)
    assert.strictEqual(validator.validate('publication-v2.json', tokens, '/$defs/tokens'), tokens);
  assert.strictEqual(errors, 0, 'valid token alternatives must not construct Error stacks');
  function invalid(name, value, fragment, message) {
    errors = 0;
    assert.throws(
      () => validator.validate(name, value, fragment),
      (error) =>
        error instanceof Error && error.message === 'Invalid switching contract: ' + message,
    );
    assert.strictEqual(errors, 1, 'only the public mismatch constructs an Error');
  }
  for (const value of [0, -1, [], [0, 1], [-1, -1], [-2, 'x', '1'], [-2, 'i', '01'], [-3, 'other']])
    invalid('publication-v2.json', value, '/$defs/token', 'oneOf');
  const evidence = 'switching-evidence-v1.json';
  const datePath = '/$defs/claim/properties/initial_published_at';
  for (const value of [null, '2024-02-29', '2024-02-29T12:34:56Z'])
    assert.strictEqual(validator.validate(evidence, value, datePath), value);
  invalid(evidence, '2023-02-29', datePath, 'anyOf');
  invalid(evidence, '2024-02-29T25:00:00Z', datePath, 'anyOf');

  // An isolated copy of the publicly exposed policy exercises every recursive
  // check edge under an alternative, including branches uncommon in fixtures.
  const defs = validator.policy.schemas['publication-v2.json'].$defs;
  defs.probeLeaf = { type: 'string', minLength: 1, maxLength: 1 };
  defs.probe = {
    anyOf: [
      { type: 'null' },
      {
        type: 'object',
        required: ['kind', 'values'],
        additionalProperties: false,
        propertyNames: { minLength: 1 },
        properties: {
          kind: { enum: ['text', 'number'] },
          values: { type: 'array', minItems: 1, items: { $ref: '#/$defs/probeLeaf' } },
          count: { type: 'integer', minimum: 0, maximum: 10 },
          extra: false,
        },
        allOf: [
          {
            if: { properties: { kind: { const: 'text' } } },
            then: { not: { required: ['count'] } },
            else: { required: ['count'] },
          },
        ],
      },
    ],
  };
  for (const value of [
    null,
    { kind: 'text', values: ['😀'] },
    { kind: 'number', values: ['é'], count: 10n },
  ]) {
    errors = 0;
    assert.strictEqual(validator.validate('publication-v2.json', value, '/$defs/probe'), value);
    assert.strictEqual(errors, 0);
  }
  for (const value of [
    { kind: 'text', values: ['ab'] },
    { kind: 'text', values: [1] },
    { kind: 'text', values: ['a'], count: 1 },
    { kind: 'number', values: ['a'] },
    { kind: 'number', values: ['a'], count: 11n },
    { kind: 'number', values: ['a'], count: 1.5 },
    { kind: 'text', values: ['a'], extra: true },
    { kind: 'text', values: ['a'], '': true },
  ])
    invalid('publication-v2.json', value, '/$defs/probe', 'anyOf');
  invalid('publication-v2.json', 'ab', '/$defs/probeLeaf', 'string constraint');
  invalid('publication-v2.json', {}, '/$defs/probe/anyOf/1', 'object fields');
  invalid(
    'publication-v2.json',
    { kind: 'text', values: ['a'], count: 1 },
    '/$defs/probe/anyOf/1',
    'not',
  );
  invalid(
    'publication-v2.json',
    { kind: 'number', values: ['a'] },
    '/$defs/probe/anyOf/1',
    'object fields',
  );
  defs.probeExtras = {
    anyOf: [
      { type: 'null' },
      { type: 'object', additionalProperties: { $ref: '#/$defs/probeLeaf' } },
    ],
  };
  invalid('publication-v2.json', { x: 'ab' }, '/$defs/probeExtras', 'anyOf');
  const visits = [];
  defs.probeOrder = {
    oneOf: [0, 1, 2].map((index) => ({
      get const() {
        visits.push(index);
        return index === 1 ? 1 : 2;
      },
    })),
  };
  assert.strictEqual(validator.validate('publication-v2.json', 1, '/$defs/probeOrder'), 1);
  assert.deepStrictEqual(
    visits,
    [0, 1, 2],
    'oneOf must continue probing every alternative in order',
  );
  invalid('publication-v2.json', 'x', '/$defs/probeOrder', 'oneOf');
  defs.probeCatch = {
    anyOf: [
      {
        get type() {
          throw new TypeError('probe failure');
        },
      },
      { type: 'null' },
    ],
  };
  assert.strictEqual(validator.validate('publication-v2.json', null, '/$defs/probeCatch'), null);
  invalid('publication-v2.json', 'x', '/$defs/probeCatch', 'anyOf');
  console.log(
    'Speculative schema probes allocate no Errors; public mismatches retain Error messages',
  );
}
