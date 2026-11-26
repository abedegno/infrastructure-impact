'use strict';
const assert = require('node:assert/strict'),
  fs = require('node:fs'),
  path = require('node:path'),
  vm = require('node:vm'),
  crypto = require('node:crypto'),
  { Worker: Thread } = require('node:worker_threads'),
  directory = process.argv[2],
  read = (name) => fs.readFileSync(path.join(directory, name)),
  tag = read('index.html')
    .toString()
    .match(/<script [^>]*data-analysis-worker=[^>]+>/)?.[0];
assert(tag, 'missing immutable worker binding');
const asset = tag.match(/data-analysis-worker="([^"]+)"/)[1],
  origin = 'https://fixture.test',
  script = { src: origin + tag.match(/src="([^"]+)"/)[1], dataset: { analysisWorker: asset } },
  bundle = read('assets/' + asset).toString(),
  prefix = `const {parentPort} = require('node:worker_threads');
globalThis.crypto ||= require('node:crypto').webcrypto;
globalThis.self = globalThis;
self.postMessage = (msg, transfer) => parentPort.postMessage(msg, transfer);
parentPort.on('message', data => self.onmessage({data}));\n`;
let fault,
  terminated = 0,
  deliveries = 0,
  lastWorker;
class BrowserWorker {
  constructor(url) {
    assert.equal(String(url), origin + '/assets/' + asset);
    if (fault === 'startup') throw Error('fixture startup fault');
    const thread = (this.thread = new Thread(prefix + bundle, { eval: true }));
    lastWorker = this;
    thread.on('message', (data) => {
      if (fault === 'crash') return this.onerror({ message: 'fixture runtime fault' });
      if (fault === 'foreign') data.generation = 'different generation';
      this.onmessage?.({ data });
    });
    thread.on('error', (error) => this.onerror?.(error));
  }
  postMessage(data, list) {
    if (data.type === 'deliver') deliveries++;
    this.thread.postMessage(data, list);
  }
  terminate() {
    terminated++;
    this.thread.terminate();
  }
}
const context = {
  window: {},
  crypto: crypto.webcrypto,
  URL,
  TextEncoder,
  TextDecoder,
  DecompressionStream,
  Response,
  AbortController,
  structuredClone,
  setTimeout,
  clearTimeout,
  document: { currentScript: script, location: new URL(origin) },
  location: new URL(origin),
  Worker: BrowserWorker,
};
vm.createContext(context);
for (const name of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'customer-comparison',
  'switching-analysis',
  'publication-v2',
  'analysis-precomputed',
  'analysis-worker-client',
])
  vm.runInContext(read(name + '.js').toString(), context);
const {
    InfrastructureJSON: J,
    InfrastructureSwitchingAnalysis: A,
    InfrastructurePublicationV2: V,
  } = context.window,
  parse = (name) => J.parseStrict(read(name).toString()),
  catalog = parse('publication-v2.json'),
  index = parse('data/index.json'),
  source = parse('source.json'),
  study = A.context(source, { vendor: 'cisco' }),
  other = A.context(source, { vendor: 'aruba' }),
  expected = A.select(source, study),
  otherExpected = A.select(source, other),
  root = parse(catalog.roots['switching-analysis-selected.json'].path).data,
  manifest = parse('data/v2/' + root.logical.sha256 + '.json'),
  part = manifest.views[0].chunks[0].part.path,
  requests = [],
  fetchFile = async (name) => {
    requests.push(name);
    return new Response(read(name));
  },
  open = (fetch = fetchFile) => V.open(fetch, catalog, index),
  equal = (a, b) => assert.equal(J.stringify(a), J.stringify(b));
function deferred() {
  let resolve;
  return {
    promise: new Promise((r) => {
      resolve = r;
    }),
    resolve,
  };
}
async function main() {
  const reader = await open();
  try {
    const [first, second, otherReport, bytes] = await Promise.all([
      reader.switchingAnalysis(study),
      reader.switchingAnalysis(study),
      reader.switchingAnalysis(other),
      reader.switchingAnalysisExport(study, 'json'),
    ]);
    assert(deliveries >= 4, 'worker owns reads and exports');
    equal(first, expected);
    equal(otherReport, otherExpected);
    first.upgrades.rows.length = 0;
    equal(second, expected);
    assert.deepEqual(Buffer.from(bytes), Buffer.from(J.stringify(expected)));
    bytes.fill(0);
    for (const [format, body] of [
      ['json', J.stringify(expected)],
      ['csv', A.csv(expected)],
      ['upgrades-csv', A.csv(expected, { upgradesOnly: true })],
    ]) {
      assert.deepEqual(
        Buffer.from(await reader.switchingAnalysisExport(study, format)),
        Buffer.from(body),
      );
      if (Buffer.byteLength(body) >= manifest.views[0].decoded.bytes)
        await assert.rejects(
          reader.switchingAnalysisExport(study, format, { max_bytes: Buffer.byteLength(body) - 1 }),
          /budget/i,
        );
    }
    assert.equal(
      requests.filter((p) => p === part).length,
      1,
      'raw cache survives transfer and eviction',
    );
    assert.equal(await reader.switchingAnalysisExport(study, 'xml'), null);
    for (const opts of [{ cve_ids: [] }, { window: '2025' }])
      assert.equal(
        await reader.switchingAnalysisExport(
          A.context(source, { vendor: 'cisco', ...opts }),
          'json',
        ),
        null,
      );
    const invalid = structuredClone(study);
    invalid.definition.start_date = '2022-01-01';
    await assert.rejects(reader.switchingAnalysisExport(invalid, 'json'), /definition/i);
    await assert.rejects(reader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
  } finally {
    reader.dispose();
  }
  for (const mode of ['startup', 'crash', 'foreign']) {
    const fresh = await open();
    fault = mode;
    try {
      await assert.rejects(fresh.switchingAnalysis(study), /worker|generation|startup|runtime/i);
    } finally {
      fault = null;
    }
    equal(await fresh.switchingAnalysis(study), expected);
    fresh.dispose();
  }
  for (const survivors of [true, false]) {
    const entered = deferred(),
      release = deferred(),
      controller = new AbortController();
    let fetchSignal;
    const fresh = await open(async (name, options) => {
      if (name === part && !fetchSignal) {
        fetchSignal = options.signal;
        entered.resolve();
        await release.promise;
      }
      return fetchFile(name);
    });
    const leaving = fresh.switchingAnalysis(study, { signal: controller.signal });
    const keeper = survivors && fresh.switchingAnalysisExport(study, 'json');
    await entered.promise;
    const previous = lastWorker,
      before = terminated;
    controller.abort();
    await assert.rejects(leaving, /cancel/i);
    await new Promise((r) => setTimeout(r, 5));
    assert.equal(fetchSignal.aborted, !survivors);
    assert.equal(terminated > before, !survivors);
    release.resolve();
    if (keeper) assert.deepEqual(Buffer.from(await keeper), Buffer.from(J.stringify(expected)));
    else {
      previous.onmessage?.({ data: { type: 'result', id: 1, generation: 'stale' } });
      equal(await fresh.switchingAnalysis(study), expected);
    }
    fresh.dispose();
  }
  const broken = await open(async (name) =>
    name === part ? new Response('corrupt') : fetchFile(name),
  );
  await assert.rejects(broken.switchingAnalysisExport(study, 'json'), /fingerprint|size/i);
  broken.dispose();
  const legacy = await open();
  context.Worker = undefined;
  assert.equal(await legacy.switchingAnalysisExport(study, 'json'), null);
  equal(await legacy.switchingAnalysis(study), expected);
  legacy.dispose();
}
main().catch((err) => {
  console.error(err);
  process.exit(1);
});
