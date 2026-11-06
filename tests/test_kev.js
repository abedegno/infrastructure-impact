const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { selectReport } = require('../infrastructure_impact/web/kev.js');
const shared = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures/kev-selection-cases.json'), 'utf8'),
);
for (const test of shared.cases) {
  const before = JSON.stringify(test);
  const options = { kevOnly: test.kev_only, evaluatedAt: test.evaluated_at };
  if (test.expected.error) {
    assert.throws(
      () => selectReport(test.report, test.requested, options),
      (error) => error.code === test.expected.error,
      test.name,
    );
  } else {
    const selected = selectReport(test.report, test.requested, options);
    assert.equal(selected.source.availability, test.expected.availability, test.name);
    assert.deepEqual(selected.selection.membership, test.expected.membership, test.name);
    assert.deepEqual(
      selected.selection.effective_cve_ids,
      test.expected.effective_cve_ids,
      test.name,
    );
    assert.deepEqual(
      selected.selection.requested_cve_ids,
      Object.keys(test.expected.membership).sort(),
      test.name,
    );
    assert.equal(selected.evaluated_at, test.evaluated_at);
    if (test.report) {
      for (const key of Object.keys(test.report).filter(
        (key) => !['source', 'selection', 'evaluated_at'].includes(key),
      )) {
        assert.deepEqual(selected[key], test.report[key], test.name);
      }
      assert.deepEqual(
        { ...selected.source, availability: test.report.source.availability },
        test.report.source,
      );
      selected.entries['CVE-2024-6387'] && (selected.entries['CVE-2024-6387'].product = 'changed');
    } else {
      assert.equal(selected.publication, null);
      assert.equal(selected.source.configured, null);
      assert.equal(selected.source.enabled, null);
    }
  }
  assert.equal(JSON.stringify(test), before, test.name + ': immutable inputs');
}
const before = Date.now();
const current = selectReport(shared.base_report, []);
assert.ok(
  Date.parse(current.evaluated_at) >= before && Date.parse(current.evaluated_at) <= Date.now(),
);
assert.equal(current.generated_at, shared.base_report.generated_at);
assert.throws(() => selectReport(shared.base_report, [], { evaluatedAt: 'invalid' }));
const context = { window: {} };
vm.runInNewContext(
  fs.readFileSync(path.join(__dirname, '../infrastructure_impact/web/kev.js'), 'utf8'),
  context,
);
assert.equal(typeof context.window.InfrastructureKev.selectReport, 'function');
console.log(`${shared.cases.length} shared KEV cases and browser/default-time checks passed`);
