// Python supplies a real synthetic publication and independently selected expectations.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = { window: {}, Set, Map, URL, Response, Blob };
vm.createContext(context);
const script = 'infrastructure_impact/web/research-dossiers.js';
assert(fs.existsSync(script), 'research dossier browser component must exist');
vm.runInContext(fs.readFileSync(script, 'utf8'), context);
const api = context.window.ResearchDossiers;
const plain = (x) => JSON.parse(JSON.stringify(x));
const esc = (x) =>
  String(x ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
const helpers = {
  esc,
  date: esc,
  link: (url, label) =>
    /^https?:\/\//.test(url) ? `<a href="${esc(url)}">${esc(label)}</a>` : esc(label),
};
const original = JSON.stringify(input.report);
for (const test of input.matrix) {
  assert.deepStrictEqual(plain(api.select(input.report, test.ids, test.vendor)), test.expected);
}
assert.strictEqual(api.select(null, []), null);
assert.throws(() => api.select(input.report, [], 'unknown'));
assert.throws(() => api.downloadPayload(input.report, 'absent-dossier-id'));
assert(api.render(null, null, helpers).includes('unavailable for this generation'));
assert(
  api
    .render(api.select(input.report, []), null, helpers)
    .includes('No dossier for the selected scope'),
);
const payload = api.downloadPayload(input.report, 'openssh-switching-6387');
assert.strictEqual(payload.dossiers.length, 1);
assert.deepStrictEqual(plain(payload.publication), input.report.publication);
assert.strictEqual(payload.generated_at, input.report.generated_at);
assert.strictEqual(payload.definition_sha256, input.report.definition_sha256);
assert.deepStrictEqual(plain(payload.limits), input.report.limits);
const hostile = '<img onerror=alert(1) src=x>';
const report = plain(input.report);
report.dossiers[0].comparison_targets[0].product = hostile;
report.dossiers[0].comparison_targets[0].statements[0].product = hostile;
report.dossiers[0].sources[0].source_url = 'javascript:alert(1)';
const html = api.render(report, report.dossiers[0].id, helpers);
assert(html.includes(esc(hostile)));
assert(!html.includes('<img'));
assert(!html.includes('href="javascript:'));
for (const label of [
  'Publisher date claims',
  'Local observations',
  'Publisher documentation history',
  'Evidence still needed',
  'Source fingerprints',
  'Declared target IDs',
  'Declared case IDs',
])
  assert(html.includes(label), label);
assert.strictEqual(
  api.downloadPayload(report, report.dossiers[0].id).dossiers[0].comparison_targets[0].product,
  hostile,
);
assert.strictEqual(JSON.stringify(input.report), original);

// Minimal browser surface: exercise real mount handlers and selected-generation downloads.
class Element {
  constructor() {
    this.value = '';
    this.dataset = {};
    this.listeners = {};
    this.nodes = {};
  }
  set innerHTML(html) {
    this.html = html;
    this.nodes = {};
    for (const id of ['dossier-select', 'dossier-download'])
      if (html.includes(`id="${id}"`)) this.nodes['#' + id] = new Element();
  }
  get innerHTML() {
    return this.html;
  }
  querySelector(s) {
    return this.nodes[s] || null;
  }
  addEventListener(type, fn) {
    this.listeners[type] = fn;
  }
}
const container = new Element(),
  downloads = [];
const options = { ...helpers, onDownload: (p) => downloads.push(plain(p)) };
api.mount(container, input.report, options);
container.querySelector('#dossier-select').value = 'fortiproxy-curl-38546';
container.querySelector('#dossier-select').listeners.change();
container.querySelector('#dossier-download').listeners.click();
assert.strictEqual(downloads.at(-1).dossiers[0].id, 'fortiproxy-curl-38546');
api.mount(container, input.report, options);
container.querySelector('#dossier-download').listeners.click();
assert.strictEqual(downloads.at(-1).dossiers[0].id, 'fortiproxy-curl-38546');
const next = api.select(input.report, ['CVE-2024-6387']);
next.publication.id = 'publication-B';
api.mount(container, next, options);
container.querySelector('#dossier-download').listeners.click();
assert.strictEqual(downloads.at(-1).dossiers[0].id, 'openssh-switching-6387');
assert.strictEqual(downloads.at(-1).publication.id, 'publication-B');
api.mount(container, null, options);
assert(!container.querySelector('#dossier-download'));

// Legacy snapshots are usable without the additive component script.
const legacy = { window: {}, Set, URL, Response, Blob };
vm.createContext(legacy);
vm.runInContext(fs.readFileSync('infrastructure_impact/web/snapshot.js', 'utf8'), legacy);
const old = plain(input.state);
delete old.research_dossiers;
assert(!Object.hasOwn(legacy.selectSnapshot(old, []), 'research_dossiers'));
vm.runInContext(fs.readFileSync('infrastructure_impact/web/snapshot.js', 'utf8'), context);
for (const test of input.matrix)
  assert.deepStrictEqual(
    plain(context.selectSnapshot(input.state, test.ids, { vendor: test.vendor }).research_dossiers),
    plain(api.select(input.state.research_dossiers, test.ids, test.vendor)),
  );

// Real app's overlapping loads: B resolves first, then stale A must not render/export.
(async () => {
  const nodes = new Map();
  const get = (s) => {
    if (!nodes.has(s)) nodes.set(s, new Element());
    return nodes.get(s);
  };
  const pending = [],
    blobs = [],
    revoked = [],
    anchors = [];
  const appURL = class extends URL {};
  appURL.createObjectURL = (blob) => {
    blobs.push(blob);
    return 'blob:synthetic';
  };
  appURL.revokeObjectURL = (url) => revoked.push(url);
  const app = {
    window: { ResearchDossiers: api },
    Set,
    URL: appURL,
    URLSearchParams,
    Blob,
    location: { origin: 'https://example.test' },
    setTimeout: (fn) => fn(),
    document: {
      baseURI: 'https://example.test/',
      querySelector: get,
      querySelectorAll: () => [],
      createElement: () => {
        const a = { click() {} };
        anchors.push(a);
        return a;
      },
    },
    fetch: () => new Promise((resolve) => pending.push(resolve)),
  };
  get('#cohort').value = 'all';
  vm.createContext(app);
  vm.runInContext(fs.readFileSync('infrastructure_impact/web/app.js', 'utf8'), app);
  vm.runInContext("view = 'casefiles'; load()", app);
  assert.strictEqual(pending.length, 2);
  const a = plain(input.state),
    b = plain(input.state);
  a.publication.id = 'publication-A';
  b.publication.id = 'publication-B';
  pending[1]({ ok: true, json: async () => b });
  await new Promise(setImmediate);
  const panel = get('#research-dossiers');
  assert(panel.innerHTML.includes('publication-B'));
  panel.querySelector('#dossier-download').listeners.click();
  pending[0]({ ok: true, json: async () => a });
  await new Promise(setImmediate);
  assert(panel.innerHTML.includes('publication-B'));
  assert(!panel.innerHTML.includes('publication-A'));
  panel.querySelector('#dossier-download').listeners.click();
  assert.strictEqual(blobs.length, 2);
  for (const blob of blobs)
    assert.strictEqual(JSON.parse(await blob.text()).publication.id, 'publication-B');
  assert.strictEqual(revoked.length, 2);
  assert(anchors.every((a) => a.download.endsWith('.json')));
  console.log(
    'Dossier selection, safe rendering, mount/download identity and stale-load isolation passed.',
  );
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
