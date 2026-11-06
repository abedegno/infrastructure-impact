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
const hostileSource = plain(source);
hostileSource.kev.entries[cid].requiredAction = '=WEBSERVICE("<script>")';
hostileSource.kev.entries[cid].forensicTriage = '<svg onload=alert(1)>';
const hostileSelection = context.selectSnapshot(hostileSource, [cid], {
  evaluatedAt: report.generated_at,
});
assert(
  context.snapshotCSV(hostileSelection).includes("'=WEBSERVICE"),
  'CISA action formulas are inert in CSV',
);
assert.strictEqual(
  context.exportSnapshot(hostileSelection).kev.entries[cid].requiredAction,
  '=WEBSERVICE("<script>")',
  'JSON preserves literal attributed source text',
);
// The old benchmark/global selectors must not silently narrow the independent study.
const studySummary = {
  representation: 'summary',
  selection: { requested_cve_ids: null },
  rows: [{ vendor: 'arista', cve_ids: ['CVE-2026-10001'] }],
};
const withStudy = { ...source, switching_comparison: studySummary };
for (const ids of [[cid], []]) {
  const selected = context.selectSnapshot(withStudy, ids, {
    kevOnly: true,
    evaluatedAt: report.generated_at,
  });
  assert.deepStrictEqual(plain(selected.switching_comparison), studySummary);
  assert.deepStrictEqual(plain(selected.switching_comparison.selection.requested_cve_ids), null);
}
console.log(
  'Synthetic snapshot KEV scope, query contract, export isolation and CSV escaping passed.',
);

// Installed adapter clicks honor the app's accepted state, including lazy history exports.
(async () => {
  const reads = [],
    clicks = [],
    downloads = [],
    blobs = new Map();
  const clock = Date.parse(report.generated_at);
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [clock]));
    }
  }
  class BlobURL extends URL {
    static createObjectURL(blob) {
      const id = 'blob:' + blobs.size;
      blobs.set(id, blob);
      return id;
    }
    static revokeObjectURL() {}
  }
  const document = {
    baseURI: 'https://example.test/',
    addEventListener(type, fn) {
      if (type === 'click') clicks.push(fn);
    },
    querySelector() {
      return {};
    },
    createElement() {
      return {
        click() {
          downloads.push({ name: this.download, blob: blobs.get(this.href) });
        },
      };
    },
  };
  const window = {
    fetch: async () => {
      throw Error('No network expected');
    },
  };
  const installed = {
    window,
    document,
    location: { origin: 'https://example.test' },
    URL: BlobURL,
    Response,
    Blob,
    Set,
    Date: Clock,
    setTimeout: () => {},
    createStaticDelivery: async () => async (ids, history) =>
      new Promise((resolve) => reads.push({ ids, history, resolve })),
  };
  vm.createContext(installed);
  for (const f of ['kev.js', 'research-dossiers.js', 'snapshot.js'])
    vm.runInContext(fs.readFileSync('infrastructure_impact/web/' + f, 'utf8'), installed);
  assert(
    installed.window.InfrastructureSnapshot?.commit,
    'adapter must accept explicit app commits',
  );
  const flush = async () => {
    for (let i = 0; i < 15; i++) await Promise.resolve();
  };
  const read = async (url, value) => {
    const pending = window.fetch(url);
    await flush();
    reads.at(-1).resolve(value);
    return (await pending).json();
  };
  const click = (id) =>
    clicks[0]({
      preventDefault() {},
      target: {
        closest() {
          return { id };
        },
      },
    });
  // Without app commits, rejected state intents still supersede pending states.
  const acceptedSource = {
    ...source,
    publication: { id: 'standalone-accepted' },
    kev: { ...report, publication: { id: 'standalone-accepted' } },
  };
  await read('/api/state?cves=' + cid, acceptedSource);
  const jsonClick = async () => {
    const pending = click('json-export');
    await flush();
    reads.at(-1).resolve({ changes: [{ synthetic: 'accepted-history' }] });
    await pending;
    return JSON.parse(await downloads.at(-1).blob.text());
  };
  const acceptedExport = await jsonClick();
  assert.strictEqual(acceptedExport.publication.id, 'standalone-accepted');
  assert.deepStrictEqual(acceptedExport.comparison.cohort, [cid]);
  assert.strictEqual(acceptedExport.kev.selection.membership[cid], 'listed');
  await click('csv-export');
  const acceptedCSV = await downloads.at(-1).blob.text();
  assert(acceptedCSV.includes('standalone-accepted'));
  for (const query of [
    'kev=invalid',
    'cves=invalid',
    'products=invalid',
    'start=2026-01-01&start=2026-02-01',
  ]) {
    const pending = window.fetch('/api/state?cves=' + cid + '&kev=listed');
    await flush();
    const held = reads.at(-1);
    const rejected = await window.fetch('/api/state?' + query);
    assert.strictEqual(rejected.status, 400);
    assert.deepStrictEqual(await rejected.json(), { error: 'Invalid request' });
    held.resolve({
      ...acceptedSource,
      publication: { id: 'standalone-obsolete' },
      kev: { ...report, publication: { id: 'standalone-obsolete' } },
    });
    assert.strictEqual((await pending).status, 200, 'older response is still returned to caller');
    assert.deepStrictEqual(await jsonClick(), acceptedExport);
    await click('csv-export');
    assert.strictEqual(await downloads.at(-1).blob.text(), acceptedCSV);
  }
  // Invalid export/report queries have no state intent and must not cancel it.
  for (const path of ['/api/export.json', '/api/export.csv', '/api/v1/kev']) {
    const id = 'accepted-after-' + path;
    const pending = window.fetch('/api/state?cves=' + cid);
    await flush();
    const held = reads.at(-1);
    assert.strictEqual((await window.fetch(path + '?kev=invalid')).status, 400);
    held.resolve({
      ...acceptedSource,
      publication: { id },
      kev: { ...report, publication: { id } },
    });
    assert.strictEqual((await pending).status, 200);
    assert.strictEqual((await jsonClick()).publication.id, id);
    await click('csv-export');
    assert((await downloads.at(-1).blob.text()).includes(id));
  }
  const app = window.InfrastructureSnapshot;
  app.commit(null, null);
  const a = await read('/api/state?cves=' + cid, source);
  app.commit(a, report);
  const delayed = click('json-export');
  await flush();
  assert.strictEqual(reads.at(-1).history, true);
  const history = reads.at(-1);
  const b = await read('/api/state?cves=' + other, {
    ...source,
    publication: { id: 'next-generation' },
  });
  app.commit(b, { ...report, publication: { id: 'next-generation' } });
  history.resolve({ changes: [{ synthetic: 'original-history' }] });
  await delayed;
  const exported = JSON.parse(await downloads.at(-1).blob.text());
  assert.strictEqual(
    exported.publication.id,
    source.publication.id,
    'delayed export captures click-time state',
  );
  assert.deepStrictEqual(exported.comparison.cohort, [cid]);
  assert.strictEqual(exported.changes[0].synthetic, 'original-history');
  // An adapter-successful response can still fail app validation; it must stay undownloadable.
  await read('/api/state?cves=' + cid, source);
  await click('csv-export');
  const csv = await downloads.at(-1).blob.text();
  assert(!csv.includes('=synthetic()'), 'CSV still uses accepted empty-record cohort');
  await click('kev-export');
  assert.strictEqual(
    JSON.parse(await downloads.at(-1).blob.text()).publication.id,
    'next-generation',
  );
  const pending = window.fetch('/api/export.json?cves=' + cid);
  await flush();
  reads.at(-1).resolve(source);
  assert.strictEqual((await (await pending).json()).comparison.cohort[0], cid);
  await click('kev-export');
  assert.strictEqual(
    JSON.parse(await downloads.at(-1).blob.text()).publication.id,
    'next-generation',
    'explicit query export cannot change accepted report',
  );
  console.log('Installed snapshot accepted-state commits and delayed click-time downloads passed.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
