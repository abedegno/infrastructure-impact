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
  InfrastructureSwitchingContracts: C,
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
    first = await load(view.chunks[0].part),
    badCRC = Buffer.from(first);
  badCRC[badCRC.length - 8] ^= 1;
  for (const [wire, error] of [
    [first.subarray(0, first.length - 1), /truncated gzip|gzip Huffman/i],
    [badCRC, /invalid gzip output/i],
    [Buffer.concat([first, gzip(Buffer.alloc(0))]), /trailing gzip member/i],
    [Buffer.concat([gzip(Buffer.alloc(0)), first]), /trailing gzip member/i],
    [gzip(Buffer.alloc(view.decoded.bytes + 100000)), /decoded gzip byte budget/i],
  ]) {
    const changed = structuredClone(view);
    changed.chunks[0].part = wireDescriptor(wire);
    await assert.rejects(() => P.decodeSelected(changed, study, async () => wire), error);
  }
  for (const [raw, error] of [
    [Buffer.from([0x22, 0xc3, 0x28, 0x22]), /utf-8|encoding/i],
    [Buffer.from('{"x":1,"x":2}'), /lossless JSON/i],
  ]) {
    const [candidate, wire] = rawCandidate(view, raw);
    await assert.rejects(
      P.decodeSelected(candidate, study, async () => wire),
      error,
    );
  }
  await checkPreflightDeadline(view, study, first);
  await checkLosslessCandidate();
  await checkStandaloneValidation();
  await readerLifecycle();
  console.log('Selected browser JSON, CSV, identity, bounds, gzip, and reader lifecycle passed');
}
function gzip(raw) {
  const zipped = zlib.gzipSync(raw, { level: 6 });
  zipped[9] = 255;
  return zipped;
}
const digest = (raw) => ({ bytes: raw.length, sha256: sha(raw) });
const wireDescriptor = (raw) => ({ path: `data/v2/${sha(raw)}.json.gz`, ...digest(raw) });
function rawCandidate(view, raw, wire = gzip(raw)) {
  return [
    {
      ...view,
      decoded: digest(raw),
      chunks: [{ offset: 0, decoded: digest(raw), part: wireDescriptor(wire) }],
    },
    wire,
  ];
}
async function checkPreflightDeadline(view, study, valid) {
  const filler = Buffer.alloc(1000000).fill(Buffer.from([0, 0, 0, 255, 255])),
    wire = Buffer.concat([valid.subarray(0, 10), filler, valid.subarray(10)]),
    candidate = structuredClone(view);
  candidate.chunks[0].part = wireDescriptor(wire);
  let yieldObserved = false,
    platformStarted = false,
    expire;
  const deadline = new Promise((_, reject) => {
    expire = reject;
  });
  context.setTimeout = (callback, ms) => {
    yieldObserved = true;
    expire(Error('fixture owner deadline'));
    return setTimeout(callback, ms);
  };
  context.DecompressionStream = class {
    constructor() {
      platformStarted = true;
      throw Error('inflation started before checkpoint');
    }
  };
  try {
    await assert.rejects(
      P.decodeSelected(candidate, study, async () => wire, {
        run: (work) => Promise.race([work, deadline]),
      }),
      /owner deadline/i,
    );
    assert(yieldObserved && !platformStarted);
  } finally {
    context.setTimeout = setTimeout;
    context.DecompressionStream = DecompressionStream;
  }
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
  target.decoded = digest(raw);
  target.chunks = chunks.map((chunk, i) => {
    const zipped = gzip(chunk);
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

async function checkStandaloneValidation() {
  const view = manifest.views[0],
    study = A.context(compiled, view.options),
    selected = P.copySelected(await P.decodeSelected(view, study, load));
  const corrupt = [
    [(r) => r.disclosure.coverage.selected_affected_claims++, /disclosure/i],
    [(r) => (r.disclosure.pairs[0].date_period = 'unknown'), /disclosure/i],
    [(r) => r.model_coverage.models[0].counts.claims++, /model/i],
    [(r) => (r.kev_reconciliation.summary.state_counts.unknown = 999), /KEV/i],
    [(r) => (r.kev_reconciliation.entries[0].membership = 'unknown'), /KEV/i],
    [(r) => r.upgrades.rows[0].supported_event_count++, /event count/i],
  ];
  for (const [change, error] of corrupt) {
    const wrong = structuredClone(selected);
    change(wrong);
    assert.throws(() => P.prepareSelected(wrong, study), error);
  }
  for (const kind of ['facts', 'inference', 'source']) {
    const invalid = structuredClone(selected),
      r = invalid.upgrades.requirements;
    if (kind === 'facts') {
      const f = Object.values(r.facts).find((fact) => fact?.source_url);
      const unused = { ...f, source_locator: 'authored-unused' };
      r.facts[C.fingerprint(unused)] = unused;
    } else if (kind === 'inference') {
      const { group_id, ...g } = r.inference_groups[0];
      g.maximum_affected = '17.15.99';
      r.inference_groups.push({ ...g, group_id: C.fingerprint(g) });
    } else {
      r.source_groups[0].advisory_id = 'authored-unused';
    }
    const { content_sha256, ...unsigned } = r;
    r.content_sha256 = C.fingerprint(unsigned);
    assert.throws(() => P.prepareSelected(invalid, study), /reference closure/i);
  }
  const oldIdentity = {
    ...study,
    generated_at: '2020-12-31T00:00:00Z',
    observation_end: '2020-12-31',
  };
  assert.throws(
    () =>
      P.validateManifest(
        {
          ...manifest,
          generated_at: oldIdentity.generated_at,
          observation_end: oldIdentity.observation_end,
        },
        oldIdentity,
      ),
    /cutoff/i,
  );
  const forgedDefinition = structuredClone(study);
  forgedDefinition.definition.start_date = '2022-01-01';
  assert.throws(() => P.prepareSelected(selected, forgedDefinition), /definition/i);

  const wrong = structuredClone(selected),
    wrongStudy = structuredClone(study);
  for (const value of [
    wrong,
    wrong.upgrades,
    wrong.disclosure,
    wrong.model_coverage,
    wrong.kev_reconciliation,
    wrong.release_history,
    wrongStudy,
  ])
    value.selection.requested_vendor = 'cisco';
  assert.throws(() => P.prepareSelected(wrong, wrongStudy), /cohort/i);

  const getter = structuredClone(selected);
  let accessed = 0;
  Object.defineProperty(getter.model_coverage, 'interpretation', {
    enumerable: true,
    get() {
      accessed++;
      return 'borrowed';
    },
  });
  assert.throws(() => P.prepareSelected(getter, study), /accessor|owned JSON/i);
  assert.equal(accessed, 0);
  const badView = structuredClone(view);
  Object.defineProperty(badView.chunks[0], 'part', {
    enumerable: true,
    get() {
      accessed++;
      return view.chunks[0].part;
    },
  });
  await assert.rejects(P.decodeSelected(badView, study, load), /accessor|owned JSON/i);
  assert.equal(accessed, 0);
  const cyclic = structuredClone(selected);
  cyclic.model_coverage.loop = cyclic;
  assert.throws(() => P.prepareSelected(cyclic, study), /cyc/i);
  const large = structuredClone(view);
  large.unexpected = 'a'.repeat(2100000);
  await assert.rejects(P.decodeSelected(large, study, load), /budget|metadata/i);

  const borrowed = Buffer.from(await load(view.chunks[0].part));
  let writes = 0;
  const prepared = await P.decodeSelected(view, study, async () => borrowed, {
    run: async (promise) => {
      const value = await promise;
      if (++writes === 2) borrowed.fill(0);
      return value;
    },
  });
  assert.equal(J.stringify(P.copySelected(prepared)), J.stringify(selected));

  const original = parse('numeric-selected.json').views[0],
    expandedStudy = A.context(parse('numeric-source.json').compiled, original.options),
    report = P.copySelected(await P.decodeSelected(original, expandedStudy, load)),
    compact = report.upgrades.requirements,
    matching = Object.values(compact.members).find((member) =>
      compact.facts[member.severity_facets_ref].some((facet) => facet.value === 7.5),
    ),
    oldRef = matching.severity_facets_ref,
    facets = compact.facts[oldRef];
  facets[0].value = 0.000001;
  const newRef = C.fingerprint({ items: facets });
  for (const owner of Object.values(compact.members))
    if (owner.severity_facets_ref === oldRef) owner.severity_facets_ref = newRef;
  compact.facts[newRef] = facets;
  delete compact.facts[oldRef];
  compact.membership_sha256 = C.fingerprint(compact.members);
  const { content_sha256, ...unsigned } = compact;
  compact.content_sha256 = C.fingerprint(unsigned);
  const shortWire = Buffer.from(J.stringify(report).replace('"value":0.000001', '"value":1e-6')),
    [expanded, trip] = rawCandidate(original, shortWire),
    loadExpanded = async () => trip,
    accepted = await P.decodeSelected(expanded, expandedStudy, loadExpanded);
  assert(accepted.bytes > expanded.decoded.bytes);
  await assert.rejects(
    P.decodeSelected(expanded, expandedStudy, loadExpanded, {
      max_bytes: expanded.decoded.bytes,
    }),
    /budget/i,
  );
  assert.throws(() => P.copySelected(accepted, expanded.decoded.bytes), /budget/i);
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
