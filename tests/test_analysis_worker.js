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
  preparations = 0,
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
      if (fault === 'missing' && data.type === 'result') data.value = null;
      if (fault === 'silent') return;
      this.onmessage?.({ data });
    });
    thread.on('error', (error) => this.onerror?.(error));
  }
  postMessage(data, list) {
    if (data.type === 'deliver') deliveries++;
    if (data.type === 'prepare') preparations++;
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
    assert.equal(deliveries, 4, 'worker owns reads and exports');
    assert.equal(
      preparations,
      3,
      'a FIFO view replacement shares consecutive reads and evicts its predecessor',
    );
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
  for (const mode of ['startup', 'crash', 'foreign', 'missing']) {
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
  const mixed = await open(),
    callsBefore = preparations;
  const outcomes = await Promise.allSettled([
    mixed.switchingAnalysis(study, { max_bytes: 1 }),
    mixed.switchingAnalysis(study),
    mixed.switchingAnalysisExport(study, 'json'),
  ]);
  assert.equal(outcomes[0].status, 'rejected');
  assert.match(outcomes[0].reason.message, /budget/i);
  equal(outcomes[1].value, expected);
  assert.deepEqual(Buffer.from(outcomes[2].value), Buffer.from(J.stringify(expected)));
  assert.equal(preparations, callsBefore + 1);
  mixed.dispose();
  const tight = await V.open(fetchFile, catalog, index, { selected_bytes: 1 });
  await assert.rejects(
    tight.switchingAnalysisExport(study, 'csv', { max_bytes: 128000000 }),
    /budget/i,
  );
  tight.dispose();
  const idle = await open();
  const onIdle = deferred();
  context.setTimeout = (fn, ms) =>
    ms === 60000
      ? setTimeout(() => {
          fn();
          onIdle.resolve();
        }, 1)
      : setTimeout(fn, ms);
  const beforeIdle = terminated;
  await idle.switchingAnalysis(study);
  await onIdle.promise;
  assert(terminated > beforeIdle);
  context.setTimeout = setTimeout;
  equal(await idle.switchingAnalysis(study), expected);
  idle.dispose();
  const stalled = await open();
  fault = 'silent';
  await assert.rejects(
    stalled.switchingAnalysis(study, { deadline: Date.now() + 200 }),
    /deadline/i,
  );
  fault = null;
  equal(await stalled.switchingAnalysis(study), expected);
  stalled.dispose();
  const held = deferred(),
    release = deferred();
  const active = await open(async (name) => {
    if (name === part) {
      held.resolve();
      await release.promise;
    }
    return fetchFile(name);
  });
  const exportInProgress = active.switchingAnalysisExport(study, 'json');
  await held.promise;
  const beforeRetire = terminated;
  active.retireAnalysisWorker();
  assert.equal(terminated, beforeRetire, 'retirement preserves clicked exports');
  release.resolve();
  assert.deepEqual(Buffer.from(await exportInProgress), Buffer.from(J.stringify(expected)));
  assert(terminated > beforeRetire, 'retired sessions release promptly after their last result');
  const blocked = deferred();
  const abandoned = await open(async (name) => {
    if (name === part) {
      blocked.resolve();
      return new Promise(() => {});
    }
    return fetchFile(name);
  });
  const pending = abandoned.switchingAnalysis(study);
  await blocked.promise;
  abandoned.dispose();
  await assert.rejects(pending, /disposed|cancel/i);
  await assert.rejects(abandoned.switchingAnalysis(study), /disposed/i);
  await numericProtocol();
  const legacy = await open();
  context.Worker = undefined;
  assert.equal(await legacy.switchingAnalysisExport(study, 'json'), null);
  equal(await legacy.switchingAnalysis(study), expected);
  legacy.dispose();
}
// Exercise the worker boundary directly so a main-thread cohort or cap check
// cannot conceal a missing per-delivery check inside the retained worker.
async function numericProtocol() {
  const compiled = parse('numeric.json'),
    view = parse('numeric-manifest.json').views[0],
    study = A.context(compiled, view.options),
    expected = A.select(compiled, study),
    thread = new Thread(prefix + bundle, { eval: true }),
    generation = JSON.stringify([study.publication?.id, study.generated_at]),
    key = view.decoded.sha256;
  expected.upgrades.rows[0].start_version = '=SYNTHETIC("雪")';
  let sequence = 0;
  function call(type, fields, chunkKey) {
    const id = ++sequence;
    return new Promise((resolve, reject) => {
      function receive(data) {
        if (data.type === 'load') {
          const bytes = new Uint8Array(read(view.chunks[data.index].part.path));
          thread.postMessage(
            { type: 'chunk', id, key: chunkKey ?? data.key, generation, index: data.index, bytes },
            [bytes.buffer],
          );
          return;
        }
        thread.off('message', receive);
        if (data.type === 'error') reject(Error(data.message));
        else resolve(data.value);
      }
      thread.on('message', receive);
      thread.postMessage({ type, id, generation, key, study, max: 128000000, ...fields });
    });
  }
  try {
    await call('prepare', { view });
    const actual = await call('deliver', { format: 'report' });
    equal(actual, expected);
    assert.match(J.stringify(actual), /"revision_id":9007199254740997/);
    assert.match(J.stringify(actual), /"evidence_id":9007199254740999/);
    assert.match(J.stringify(actual), /"value":7\.5/);
    for (const [format, body] of [
      ['json', J.stringify(expected)],
      ['csv', A.csv(expected)],
      ['upgrades-csv', A.csv(expected, { upgradesOnly: true })],
    ]) {
      const bytes = await call('deliver', { format });
      assert.deepEqual(Buffer.from(bytes), Buffer.from(body));
    }
    assert.deepEqual(
      Buffer.from(await call('deliver', { format: 'csv' })),
      read('numeric-analysis.csv'),
    );
    const nativeUpgrades = read('numeric-upgrades.csv');
    assert(
      nativeUpgrades.includes(Buffer.from(`"'=SYNTHETIC(""雪"")"`)),
      'formula quoting and UTF-8 retained',
    );
    assert.deepEqual(
      Buffer.from(await call('deliver', { format: 'upgrades-csv' })),
      nativeUpgrades,
    );
    const forged = structuredClone(study);
    forged.definition.start_date = '2022-01-01';
    await assert.rejects(call('deliver', { format: 'report', study: forged }), /definition/i);
    await assert.rejects(call('deliver', { format: 'json', max: 1 }), /budget/i);
    await assert.rejects(call('deliver', { format: 'json', generation: 'other' }), /generation/i);
    const bad = structuredClone(view);
    bad.decoded.sha256 = '1'.repeat(64);
    await assert.rejects(call('prepare', { view: bad, key: bad.decoded.sha256 }), /fingerprint/i);
    await call('prepare', { view });
    equal(await call('deliver', { format: 'report' }), expected);
    await assert.rejects(call('prepare', { view }, '0'.repeat(64)), /unexpected.*chunk/i);
  } finally {
    await thread.terminate();
  }
}
main().catch((err) => {
  console.error(err);
  process.exit(1);
});
