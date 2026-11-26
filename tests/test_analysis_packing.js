// Native-generated packed envelopes exercised through the portable v2 reader.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert'),
  path = require('path'),
  crypto = require('crypto');

const context = vm.createContext({
  window: {},
  console,
  URL,
  TextEncoder,
  TextDecoder,
  AbortController,
  setTimeout,
  clearTimeout,
  crypto: crypto.webcrypto,
});
for (const name of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'customer-comparison',
  'switching-analysis',
  'analysis-packing',
  'publication-v2',
]) {
  const file = `infrastructure_impact/web/${name}.js`;
  if (name !== 'analysis-packing' || fs.existsSync(file))
    vm.runInContext(fs.readFileSync(file, 'utf8'), context);
}
const {
  InfrastructureAnalysisPacking: P,
  InfrastructureSwitchingAnalysis: A,
  InfrastructureJSON: J,
  InfrastructureSwitchingContracts: C,
  InfrastructurePublicationV2: V,
} = context.window;
assert.strictEqual(typeof P?.prepare, 'function', 'packed preparation must be registered');

const dir = process.argv[2],
  fixture = J.parseStrict(fs.readFileSync(process.argv[3], 'utf8')),
  { rich, packed, exact, exact_packed, compiled, vector, vector_packed } = fixture;
function sameSelection(actual, expected) {
  assert.strictEqual(J.stringify(actual), J.stringify(expected));
  assert.strictEqual(A.csv(actual), A.csv(expected));
  assert.strictEqual(
    A.csv(actual, { upgradesOnly: true }),
    A.csv(expected, { upgradesOnly: true }),
  );
}
function clone(value) {
  return J.parseStrict(J.stringify(value));
}
function rehash(envelope) {
  const { content_sha256, ...rest } = envelope;
  envelope.content_sha256 = C.fingerprint(rest);
  return envelope;
}
const vectorStudy = A.context(vector, {}),
  vectorResult = A.select(vector, vectorStudy),
  vectorBudget = Math.max(
    vector_packed.source_logical_bytes,
    J.measure(vector),
    J.measure(vector_packed),
  );
assert(J.measure(vectorResult) > vectorBudget);
assert.throws(
  () => P.prepare(clone(vector_packed), vector, { max_bytes: vectorBudget })(vectorStudy),
  /byte budget/i,
  'standalone selection must charge its default output limit',
);
assert.throws(
  () => P.prepare(clone(vector_packed), vector)(vectorStudy, { max_bytes: vectorBudget }),
  /byte budget/i,
  'standalone selection must charge a narrowed output limit',
);

const {
    float_source: floatSource,
    float_packed: floatPacked,
    float_catalog: floatCatalog,
  } = fixture,
  floatStudy = A.context(floatSource, { vendor: 'cisco', cve_ids: [] });
sameSelection(
  P.prepare(clone(floatPacked), floatSource)(floatStudy),
  A.select(floatSource, floatStudy),
);
for (const [old, alternate] of [
  ['publication', String.raw`\u0070ublication`],
  ['1e-05', '0.00001'],
  ['café', String.raw`caf\u00e9`],
]) {
  const bad = clone(floatPacked),
    text = bad.skeleton_json.join(''),
    modified = text.replace(old, alternate);
  assert.notStrictEqual(modified, text);
  bad.skeleton_json = [modified];
  bad.source_logical_bytes += Buffer.byteLength(modified) - Buffer.byteLength(text);
  assert.throws(() => P.prepare(rehash(bad), floatSource), /JSON/i);
}

const richSelect = A.prepare(rich),
  select = P.prepare(clone(packed), rich);
for (const vendor of [null, 'cisco', 'aruba', 'arista'])
  for (const scope_level of ['os_family', 'model_qualified'])
    for (const window of ['all', 'pre', 'post', 'undated', '2024', '2025', '2026'])
      for (const cve_ids of [null, [], ['CVE-2026-7473']]) {
        const study = A.context(rich, { vendor, scope_level, window, cve_ids });
        sameSelection(select(study), richSelect(study));
      }
const fullStudy = A.context(exact, {});
sameSelection(P.prepare(exact_packed, exact)(fullStudy), A.select(exact, fullStudy));
const richStudy = A.context(rich, { vendor: 'cisco' });
const writable = select(richStudy);
writable.disclosure.pairs[0].claim_ids.push('changed');
sameSelection(select(richStudy), richSelect(richStudy));
assert.throws(
  () => select({ ...richStudy, observation_end: '2024-01-01' }),
  /identity|observation/i,
);
assert.throws(
  () => P.prepare(clone(packed), rich, { max_bytes: packed.source_logical_bytes - 1 }),
  /byte budget/i,
);

for (const [mutate, error] of [
  [(p) => p.values_json.push(['"unused pool entry"']), /closure/i],
  [(p) => p.values_json.push(p.values_json[0]), /duplicate/i],
  [(p) => p.layouts.push(p.layouts[0]), /duplicate/i],
  [(p) => p.layouts[0].push(p.layouts[0][0]), /layout/i],
  [(p) => p.tables.claims[0].pop(), /row/i],
  [(p) => p.tables.claims[0].push(0), /row/i],
  [(p) => (p.tables.claims[0][0] = true), /integer|index/i],
  [(p) => (p.tables.claims[0][0] = 9007199254740992), /integer|index/i],
  [(p) => (p.tables.claims[0][1] = p.layouts.length), /index/i],
  [(p) => (p.tables.claims[1] = p.tables.claims[0].slice()), /duplicate/i],
  [(p) => (p.counts.claims = 1), /counts/i],
  [(p) => (p.observation_end = '2030-01-01'), /identity/i],
  [(p) => (p.source_content_sha256 = '0'.repeat(64)), /fingerprint/i],
  [(p) => (p.source_logical_bytes = 1), /byte budget/i],
  [(p) => (p.values_json[0] = ['{"a":0,"a":1}']), /JSON/i],
  [(p) => (p.values_json[0] = ['1e9999']), /JSON/i],
  [(p) => (p.values_json[0] = [' "__proto__"']), /JSON/i],
  [(p) => (p.values_json[0] = ['"__proto__"']), /row key|byte budget/i],
]) {
  const bad = clone(packed);
  mutate(bad);
  assert.throws(() => P.prepare(rehash(bad), rich), error);
}
const accessor = clone(packed);
let accessed = false;
Object.defineProperty(accessor.tables.claims[0], '1', {
  get() {
    accessed = true;
    return 0;
  },
  enumerable: true,
});
assert.throws(() => P.prepare(accessor, rich), /owned JSON/i);
assert.strictEqual(accessed, false);
const inherited = clone(packed);
Object.setPrototypeOf(inherited.tables.claims[0], {
  get [Symbol.iterator]() {
    accessed = true;
    return Array.prototype[Symbol.iterator];
  },
});
assert.throws(() => P.prepare(inherited, rich), /owned JSON/i);
assert.strictEqual(accessed, false);
assert.strictEqual({}.polluted, undefined);

const bomb = clone(packed),
  bombRows = bomb.tables.requirements,
  cell = bombRows[0][1];
bomb.values_json[cell] = ('"' + 'a'.repeat(4_000_000) + '"').match(/.{1,65536}/gs);
for (const row of bombRows) row[1] = cell;
bomb.source_logical_bytes = 128000000;
assert(bombRows.length > 32);
assert.throws(() => P.prepare(rehash(bomb), rich), /byte budget/i);

const catalog = JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json'))),
  index = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json'))),
  name = 'switching-analysis-packed.json',
  legacy = 'switching-analysis.json',
  rootPath = catalog.roots[name].path,
  request = (part) => fs.readFileSync(path.join(dir, part.replace(/^\//, ''))),
  root = JSON.parse(request(rootPath)).data,
  metadataRangePath = root.ranges[0].path,
  study = A.context(compiled, { vendor: 'cisco', window: '2025' }),
  expected = A.select(compiled, study),
  reads = [];
async function fetch(part) {
  reads.push(part);
  const raw = request(part);
  return { ok: true, status: 200, arrayBuffer: async () => raw, text: async () => raw.toString() };
}
const open = (load = fetch, cat = catalog, limits) => V.open(load, cat, index, limits);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function pausedAt(target) {
  let enter, release, abort;
  const entered = new Promise((resolve) => (enter = resolve)),
    released = new Promise((resolve) => (release = resolve)),
    aborted = new Promise((resolve) => (abort = resolve));
  let once = true;
  return {
    entered,
    release,
    aborted,
    load: async (part, options) => {
      if (part === target && once) {
        once = false;
        options.signal.addEventListener('abort', abort, { once: true });
        enter();
        await released;
      }
      return fetch(part);
    },
  };
}

(async () => {
  const reader = await open();
  assert(!reads.includes(rootPath), 'packed analysis must remain lazy');
  sameSelection(await reader.switchingAnalysis(study), expected);
  assert(reads.includes(rootPath));
  assert(!reads.includes(catalog.roots[legacy].path));
  const all = A.context(compiled, {});
  sameSelection(await reader.switchingAnalysis(all), A.select(compiled, all));
  const warm = reads.length;
  sameSelection(await reader.switchingAnalysis(study), expected);
  assert.strictEqual(reads.length, warm);
  await assert.rejects(() => reader.switchingAnalysis(study, { max_bytes: 1 }), /byte budget/i);

  const advertised = clone(catalog);
  advertised.roots[name] = advertised.roots[legacy];
  await assert.rejects(
    () => open(fetch, advertised).then((r) => r.switchingAnalysis(study)),
    /root/i,
  );
  delete advertised.roots[name];
  sameSelection(await open(fetch, advertised).then((r) => r.switchingAnalysis(study)), expected);

  function authenticate(envelope, memory) {
    const raw = Buffer.from(JSON.stringify(envelope)),
      sha256 = crypto.createHash('sha256').update(raw).digest('hex'),
      part = { path: `data/v2/${sha256}.json`, sha256, bytes: raw.length };
    memory.set(part.path, raw);
    return part;
  }
  for (const [corrupt, error] of [
    [(bound) => (bound.logical_sha256 = '0'.repeat(64)), /range fingerprint/i],
    [(bound) => (bound.end_token = bound.first_token + 2), /source byte range/i],
    [
      (bound) => {
        bound.first_token = 0;
        bound.end_token = 1;
      },
      /source byte token/i,
    ],
    [
      (bound, entries) =>
        Object.assign(bound, entries.find((entry) => entry.path[0] === 'schema_version').range),
      /source byte metadata/i,
    ],
  ]) {
    const memory = new Map(),
      malformed = clone(catalog),
      rootEnvelope = JSON.parse(request(rootPath)),
      rangeEnvelope = JSON.parse(request(metadataRangePath));
    corrupt(
      rangeEnvelope.data.find((entry) => entry.path[0] === 'source_logical_bytes').range,
      rangeEnvelope.data,
    );
    rootEnvelope.data.ranges[0] = authenticate(rangeEnvelope, memory);
    malformed.roots[name] = authenticate(rootEnvelope, memory);
    const reader = await open(async (part) => {
      const raw = memory.get(part);
      return raw ? { ok: true, arrayBuffer: async () => raw } : fetch(part);
    }, malformed);
    await assert.rejects(() => reader.switchingAnalysis(study), error);
  }

  const cap = J.measure(compiled) - 1,
    tail = root.pages.at(-1).part.path;
  assert(root.logical.bytes < cap, 'the compressed envelope alone fits the caller budget');
  assert(root.pages.length > 2, 'metadata and later token work must be independent');
  const start = reads.length,
    bounded = await open(fetch, catalog, { selected_bytes: cap });
  await assert.rejects(() => bounded.switchingAnalysis(study, { max_bytes: 128000000 }), /budget/i);
  const tablePaths = new Set([...catalog.strings, ...catalog.shapes].map((p) => p.part.path));
  assert(!reads.slice(start).includes(tail), 'source size rejects before loading later tokens');
  assert(
    !reads.slice(start).some((part) => tablePaths.has(part)),
    'source size rejects before loading the global dictionaries',
  );
  await assert.rejects(() => reader.switchingAnalysis(study, { max_bytes: cap }), /budget/i);
  for (const smallFirst of [true, false]) {
    const fresh = await open(),
      small = () => fresh.switchingAnalysis(study, { max_bytes: cap }),
      large = () => fresh.switchingAnalysis(study),
      results = await Promise.allSettled(smallFirst ? [small(), large()] : [large(), small()]);
    assert.match(results[smallFirst ? 0 : 1].reason.message, /byte budget/i);
    sameSelection(results[smallFirst ? 1 : 0].value, expected);
  }

  const floatCap = floatPacked.source_logical_bytes,
    requestedFloatBytes = J.measure(floatSource);
  assert(J.measure(floatPacked) <= floatCap);
  assert(requestedFloatBytes > floatCap);
  const prepare = A.prepare;
  let preparations = 0;
  A.prepare = (...args) => {
    preparations++;
    return prepare(...args);
  };
  try {
    const narrow = await open(fetch, floatCatalog);
    await assert.rejects(
      () => narrow.switchingAnalysis(floatStudy, { max_bytes: floatCap }),
      /budget/i,
    );
    assert.strictEqual(preparations, 0, 'an unadmitted lone caller cannot prepare compiled rows');
    const floatExpected = A.select(floatSource, floatStudy);
    for (const smallFirst of [true, false]) {
      const fresh = await open(fetch, floatCatalog),
        small = () => fresh.switchingAnalysis(floatStudy, { max_bytes: floatCap }),
        large = () => fresh.switchingAnalysis(floatStudy),
        before = preparations,
        results = await Promise.allSettled(smallFirst ? [small(), large()] : [large(), small()]);
      assert.match(results[smallFirst ? 0 : 1].reason.message, /byte budget/i);
      sameSelection(results[smallFirst ? 1 : 0].value, floatExpected);
      assert.strictEqual(preparations, before + 1, 'only admitted requests prepare compiled rows');
    }
  } finally {
    A.prepare = prepare;
  }

  // Exercise the lower metadata range and shared prepared root work. Both
  // waiter orders must work, even when one caller aborts during the fetch.
  for (const target of [metadataRangePath, root.pages.at(-1).part.path])
    for (const cancelledFirst of [true, false]) {
      const gate = pausedAt(target),
        reader = await open(gate.load),
        controller = new AbortController(),
        cancelled = () => reader.switchingAnalysis(study, { signal: controller.signal }),
        healthy = () => reader.switchingAnalysis(study),
        first = cancelledFirst ? cancelled() : healthy();
      const firstResult = Promise.allSettled([first]);
      await gate.entered;
      const second = cancelledFirst ? healthy() : cancelled();
      const secondResult = Promise.allSettled([second]);
      controller.abort();
      gate.release();
      const [a] = await firstResult,
        [b] = await secondResult;
      assert.strictEqual((cancelledFirst ? a : b).status, 'rejected');
      const accepted = cancelledFirst ? b : a;
      assert.strictEqual(accepted.status, 'fulfilled');
      sameSelection(accepted.value, expected);
    }

  const gate = pausedAt(metadataRangePath),
    last = await open(gate.load),
    controller = new AbortController(),
    abandoned = assert.rejects(
      () => last.switchingAnalysis(study, { signal: controller.signal }),
      /cancelled/i,
    );
  await gate.entered;
  controller.abort();
  await abandoned;
  try {
    await Promise.race([
      gate.aborted,
      sleep(3000).then(() => {
        throw Error('Last packed waiter left metadata fetch running');
      }),
    ]);
  } finally {
    gate.release();
  }
  sameSelection(await last.switchingAnalysis(study), expected);

  for (const target of [metadataRangePath, root.pages.at(-1).part.path]) {
    let transient = true;
    const retry = await open(async (part) => {
      if (part === target && transient) {
        transient = false;
        return { ok: false, status: 503 };
      }
      return fetch(part);
    });
    await assert.rejects(() => retry.switchingAnalysis(study));
    assert.strictEqual(transient, false, 'the first call reached the 503 response');
    sameSelection(await retry.switchingAnalysis(study), expected);
  }
  console.log('Packed browser parity, expansion bounds, fallback, limits and lifecycle passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
