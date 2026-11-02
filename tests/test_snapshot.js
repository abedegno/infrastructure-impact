// Standalone synthetic selection/CSV harness; full adapter parity lives in pytest.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = { window: {}, Set, URL, Response, Blob };
vm.createContext(context);
for (const f of ['kev.js', 'research-dossiers.js', 'snapshot.js'])
  vm.runInContext(fs.readFileSync('infrastructure_impact/web/' + f, 'utf8'), context);
const plain = (v) => JSON.parse(JSON.stringify(v));
assert.strictEqual(context.window.InfrastructureKev.validateQuery([]), false);
assert.strictEqual(context.window.InfrastructureKev.validateQuery(['listed']), true);
for (const values of [[''], ['other'], ['listed', 'listed']])
  assert.throws(() => context.window.InfrastructureKev.validateQuery(values));
const cid = 'CVE-2024-6387',
  other = 'CVE-1999-999999';
const report = JSON.parse(
  fs.readFileSync('tests/fixtures/kev-selection-cases.json', 'utf8'),
).base_report;
const source = {
  vendors: { hpe: 'HPE' },
  all_cves: [cid, other],
  coverage: [],
  publication: report.publication,
  kev: report,
  records: [
    {
      vendor: 'hpe',
      cves: [cid],
      assessments: [
        { cve_id: cid, product: '=synthetic()', status: 'affected', scope: 'cve_specific' },
      ],
    },
  ],
};
for (const ids of [[cid], [other], []]) {
  const selected = context.selectSnapshot(source, ids, {
    kevOnly: true,
    evaluatedAt: report.generated_at,
  });
  const expected = ids.filter((id) => report.listed_cve_ids.includes(id));
  assert.deepStrictEqual(plain(selected.comparison.cohort), expected);
  assert.deepStrictEqual(plain(selected.kev.selection.requested_cve_ids), ids);
  assert.deepStrictEqual(plain(selected.all_cves), source.all_cves);
  assert(
    context
      .exportSnapshot(selected)
      .records.every((r) => r.assessments.every((a) => expected.includes(a.cve_id))),
  );
}
assert(
  context
    .snapshotCSV(context.selectSnapshot(source, [cid], { evaluatedAt: report.generated_at }))
    .includes("'=synthetic()"),
);
console.log(
  'Synthetic snapshot KEV scope, query contract, export isolation and CSV escaping passed.',
);
