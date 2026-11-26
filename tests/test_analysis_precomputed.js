'use strict';

const assert = require('node:assert/strict'),
  crypto = require('node:crypto'),
  fs = require('node:fs'),
  path = require('node:path'),
  vm = require('node:vm'),
  zlib = require('node:zlib');

const dir = process.argv[2],
  context = {
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
])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);

const {
  InfrastructureAnalysisPrecomputed: P,
  InfrastructureSwitchingAnalysis: A,
  InfrastructureJSON: J,
} = context.window;
const parse = (name) => J.parseStrict(fs.readFileSync(path.join(dir, name), 'utf8')),
  { compiled } = parse('source.json'),
  manifest = parse('selected.json'),
  load = async (descriptor) => fs.readFileSync(path.join(dir, descriptor.path)),
  sha = (raw) => crypto.createHash('sha256').update(raw).digest('hex');

async function main() {
  assert.deepEqual(P.validateManifest(manifest, compiled), manifest);
  for (const view of manifest.views) {
    const study = A.context(compiled, view.options),
      expected = A.select(compiled, study),
      prepared = await P.decodeSelected(view, study, load),
      selected = P.copySelected(prepared);
    assert.equal(J.stringifyBounded(selected), J.stringifyBounded(expected));
    assert.equal(A.csv(selected), A.csv(expected));
    assert.equal(A.csv(selected, { upgradesOnly: true }), A.csv(expected, { upgradesOnly: true }));
    assert.throws(() => P.prepareSelected(structuredClone(selected), study, 1), /budget/i);
    assert.throws(() => P.copySelected(prepared, prepared.bytes - 1), /budget/i);
    const changed = structuredClone(selected);
    changed.release_history.selection.effective_windows.push('other');
    assert.throws(() => P.prepareSelected(changed, study), /cohort/i);
    selected.upgrades.rows.length = 0;
    assert.equal(J.stringify(P.copySelected(prepared)), J.stringify(expected));
  }

  assert.throws(() => P.copySelected({ value: { bogus: true }, bytes: 1 }), /prepared/i);
  const view = manifest.views[0],
    study = A.context(compiled, view.options),
    first = await load(view.chunks[0].part);
  for (const mutate of [
    (wire) => wire.subarray(0, wire.length - 1),
    (wire) => {
      const copy = Buffer.from(wire);
      copy[copy.length - 8] ^= 1;
      return copy;
    },
    (wire) => Buffer.concat([wire, zlib.gzipSync(Buffer.alloc(0))]),
    (wire) => Buffer.concat([zlib.gzipSync(Buffer.alloc(0)), wire]),
    () => zlib.gzipSync(Buffer.alloc(view.decoded.bytes + 100000), { level: 6 }),
  ]) {
    const changed = structuredClone(view),
      raw = mutate(first),
      fingerprint = sha(raw);
    changed.chunks[0].part = {
      path: `data/v2/${fingerprint}.json.gz`,
      sha256: fingerprint,
      bytes: raw.length,
    };
    await assert.rejects(
      () => P.decodeSelected(changed, study, async () => raw),
      /gzip|decoded|budget/i,
    );
  }
  await checkLosslessCandidate();
  await readerLifecycle();
  console.log('Selected browser JSON, CSV, identity, bounds, gzip, and reader lifecycle passed');
}
async function checkLosslessCandidate() {
  const { compiled } = parse('numeric-source.json'),
    descriptor = parse('numeric-selected.json').views[0],
    study = A.context(compiled, descriptor.options),
    expected = A.select(compiled, study),
    actual = P.copySelected(await P.decodeSelected(descriptor, study, load));
  const text = J.stringify(actual);
  assert.match(text, /"revision_id":9007199254740997/);
  assert.match(text, /"evidence_id":9007199254740999/);
  assert.match(text, /"value":7\.5/);
  assert.equal(text, J.stringify(expected));
  assert.equal(A.csv(actual), A.csv(expected));
  assert.equal(A.csv(actual, { upgradesOnly: true }), A.csv(expected, { upgradesOnly: true }));

  // The first byte of the Unicode code point ends slice one. Leading JSON
  // whitespace keeps the fixture small while it crosses the production boundary.
  actual.model_coverage.interpretation = '❄';
  const payload = Buffer.from(J.stringify(actual)),
    raw = Buffer.concat([Buffer.alloc(3999999 - payload.indexOf('❄'), 32), payload]),
    chunks = [raw.subarray(0, 4000000), raw.subarray(4000000)],
    target = structuredClone(descriptor),
    wire = new Map();
  const digest = (bytes) => ({ bytes: bytes.length, sha256: sha(bytes) });
  target.decoded = digest(raw);
  target.chunks = chunks.map((chunk, i) => {
    const zipped = zlib.gzipSync(chunk, { level: 6 });
    zipped[9] = 255; // The writer uses the OS-neutral fixed gzip header.
    const path = `data/v2/${sha(zipped)}.json.gz`;
    wire.set(path, zipped);
    return { offset: i * 4000000, decoded: digest(chunk), part: { path, ...digest(zipped) } };
  });
  const prepared = await P.decodeSelected(target, study, async ({ path }) => wire.get(path));
  assert.equal(J.stringify(P.copySelected(prepared)), J.stringify(actual));
  const badOffset = structuredClone(target);
  badOffset.chunks[1].offset++;
  await assert.rejects(
    P.decodeSelected(badOffset, study, async () => assert.fail('no fetch')),
    /offset/i,
  );
  const badTotal = structuredClone(target);
  badTotal.decoded.sha256 = '0'.repeat(64);
  await assert.rejects(
    P.decodeSelected(badTotal, study, async ({ path }) => wire.get(path)),
    /fingerprint/i,
  );
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function readerLifecycle() {
  const dirPath = path.join(dir, 'preview'),
    read = (name) => fs.readFileSync(path.join(dirPath, name)),
    catalog = J.parseStrict(read('publication-v2.json').toString(), { transport: true }),
    index = J.parseStrict(read('data/index.json').toString(), { transport: true }),
    source = parse('preview-source.json'),
    rootName = P.ROOT,
    root = J.parseStrict(read(catalog.roots[rootName].path).toString()).data,
    sidecar = `data/v2/${root.logical.sha256}.json`,
    metadata = J.parseStrict(read(sidecar).toString(), { transport: true }),
    part = metadata.views[0].chunks[0].part.path,
    AContext = (vendor, selection = {}) => A.context(source, { vendor, ...selection }),
    study = AContext('cisco'),
    expected = J.stringify(A.select(source, study)),
    full = catalog.roots['switching-analysis.json'].path,
    tables = new Set([
      ...catalog.strings.map((x) => x.part.path),
      ...catalog.shapes.map((x) => x.part.path),
      ...Object.values(catalog.table_transports ?? {}).map((x) => x.path),
    ]),
    reads = [],
    fileFetch = async (name) => {
      reads.push(name);
      return new Response(read(name));
    },
    open = (fetch = fileFetch, limits = {}) =>
      context.window.InfrastructurePublicationV2.open(fetch, catalog, index, limits),
    assertReport = (result) => assert.equal(J.stringify(result), expected);

  const loader = await open();
  assert.equal(reads.length, 0, 'bootstrap is lazy');
  await assert.rejects(loader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
  assert(reads.includes(sidecar));
  assert(!reads.includes(part), 'lone small caller cannot fetch a selected chunk');
  const result = await loader.switchingAnalysis(study);
  assertReport(result);
  assert(reads.includes(part));
  assert(!reads.includes(full) && reads.every((name) => !tables.has(name)));
  result.upgrades.rows.splice(0);
  assertReport(await loader.switchingAnalysis(study));
  await assert.rejects(loader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
  const smallReader = await open(fileFetch, { selected_bytes: 1 });
  await assert.rejects(smallReader.switchingAnalysis(study, { max_bytes: 128000000 }), /budget/i);

  const decode = P.decodeSelected;
  let preparations = 0;
  P.decodeSelected = (...args) => {
    preparations++;
    return decode(...args);
  };
  try {
    const fresh = await open();
    await fresh.switchingAnalysis(study);
    await fresh.switchingAnalysis(study);
    await fresh.switchingAnalysis(AContext('aruba'));
    await fresh.switchingAnalysis(study);
    assert.equal(preparations, 3, 'only one prepared cohort survives replacement');
  } finally {
    P.decodeSelected = decode;
  }

  for (const smallFirst of [true, false]) {
    const fresh = await open(),
      small = () => fresh.switchingAnalysis(study, { max_bytes: 1 }),
      ordinary = () => fresh.switchingAnalysis(study),
      results = await Promise.allSettled(
        smallFirst ? [small(), ordinary()] : [ordinary(), small()],
      );
    assert.equal(results[smallFirst ? 0 : 1].status, 'rejected');
    assertReport(results[smallFirst ? 1 : 0].value);
  }

  function delayed() {
    const entered = deferred(),
      release = deferred(),
      aborted = deferred();
    let suspended = false,
      owner;
    return {
      entered: entered.promise,
      aborted: aborted.promise,
      release: release.resolve,
      wasAborted: () => owner?.aborted,
      fetch: async (name, { signal }) => {
        if (name === part && !suspended) {
          suspended = true;
          owner = signal;
          signal.addEventListener('abort', aborted.resolve, { once: true });
          entered.resolve();
          await release.promise;
        }
        return fileFetch(name);
      },
    };
  }
  for (const cancelFirst of [true, false]) {
    const delay = delayed(),
      fresh = await open(delay.fetch),
      controllers = [new AbortController(), new AbortController()],
      results = controllers.map((c) => fresh.switchingAnalysis(study, { signal: c.signal })),
      leaving = cancelFirst ? 0 : 1;
    await delay.entered;
    controllers[leaving].abort();
    await assert.rejects(results[leaving], /cancel/i);
    assert(!delay.wasAborted(), 'remaining waiter still owns transport');
    delay.release();
    assertReport(await results[1 - leaving]);
  }
  const serial = delayed(),
    serialReader = await open(serial.fetch);
  await assert.rejects(serialReader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
  const firstView = serialReader.switchingAnalysis(study);
  await serial.entered;
  const otherStudy = AContext('aruba'),
    otherController = new AbortController(),
    otherPart = metadata.views[1].chunks[0].part.path,
    beforeOther = reads.length;
  const otherView = serialReader.switchingAnalysis(otherStudy, { signal: otherController.signal });
  const otherOutcome = otherView.catch((error) => error);
  await new Promise((resolve) => setTimeout(resolve, 50));
  try {
    assert(
      !reads.slice(beforeOther).includes(otherPart),
      'one active decoded preparation at a time',
    );
  } finally {
    otherController.abort();
    serial.release();
  }
  assert.match((await otherOutcome).message, /cancel/i);
  assertReport(await firstView);
  assert.equal(
    J.stringify(await serialReader.switchingAnalysis(otherStudy)),
    J.stringify(A.select(source, otherStudy)),
  );

  const delay = delayed(),
    fresh = await open(delay.fetch),
    orphan = new AbortController();
  const pending = fresh.switchingAnalysis(study, { signal: orphan.signal });
  await delay.entered;
  orphan.abort();
  await assert.rejects(pending, /cancel/i);
  await delay.aborted;
  assertReport(await fresh.switchingAnalysis(study));
  delay.release();

  const interrupted = delayed(),
    timeoutReader = await open(interrupted.fetch);
  const outcome = assert.rejects(
    timeoutReader.switchingAnalysis(study, { deadline: Date.now() + 500 }),
    /deadline/i,
  );
  await interrupted.entered;
  await outcome;
  await interrupted.aborted;
  assertReport(await timeoutReader.switchingAnalysis(study));
  interrupted.release();

  const noChunk = await open(async (name) =>
    name === part ? new Response(null, { status: 404 }) : fileFetch(name),
  );
  const beforeFailure = reads.length;
  await assert.rejects(noChunk.switchingAnalysis(study), /part unavailable/i);
  assert(!reads.slice(beforeFailure).includes(full), 'corrupt advertised view fails closed');
  for (const selection of [{ cve_ids: [] }, { window: '2025' }]) {
    const fallbackStudy = AContext('cisco', selection);
    assert.equal(
      J.stringify(await loader.switchingAnalysis(fallbackStudy)),
      J.stringify(A.select(source, fallbackStudy)),
    );
  }
  context.DecompressionStream = undefined;
  try {
    const fallback = await open();
    assertReport(await fallback.switchingAnalysis(study));
    assert(reads.includes(full));
  } finally {
    context.DecompressionStream = DecompressionStream;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
