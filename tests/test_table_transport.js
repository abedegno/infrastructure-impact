/* Browser transport regressions: real published envelopes, gzip bytes and bounded streams. */
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const os = require('os');
const child = require('child_process');
const crypto = require('crypto');
const zlib = require('zlib');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'table-transport-browser-'));
const clone = (value) => JSON.parse(JSON.stringify(value));
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
function descriptor(raw, gzip = false) {
  const sha256 = hash(raw);
  return { path: `data/v2/${sha256}.json${gzip ? '.gz' : ''}`, sha256, bytes: raw.length };
}
function context(decompress = DecompressionStream) {
  const scope = {
    window: {},
    TextEncoder,
    TextDecoder,
    crypto: crypto.webcrypto,
    AbortController,
    console,
    setTimeout,
    clearTimeout,
    ReadableStream,
    // Expanded output must always use a bounded stream reader.
    Response: class extends Response {
      arrayBuffer() {
        throw Error('expanded gzip must not be buffered without a bound');
      }
    },
  };
  if (decompress) scope.DecompressionStream = decompress;
  vm.createContext(scope);
  for (const name of ['lossless-json', 'switching-contracts', 'publication-v2'])
    vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), scope);
  return scope.window.InfrastructurePublicationV2;
}
(async () => {
  // The synthetic public test dataset is deliberately the only publisher input.
  const dir = child
    .execFileSync(
      process.env.PYTHON || (fs.existsSync('.venv/bin/python') ? '.venv/bin/python' : 'python3'),
      [
        '-c',
        `import sys
sys.path.insert(0,'tests')
from test_static_delivery import dataset
from infrastructure_impact.application.publication import publish
print(publish(dataset(),sys.argv[1],publication_format='v2'))`,
        temporary,
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    )
    .trim();
  const base = JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json')));
  const identity = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json')));
  const assets = new Map();
  const catalog = clone(base);
  catalog.table_transports = {};
  for (const entry of [...catalog.strings, ...catalog.shapes]) {
    const raw = fs.readFileSync(path.join(dir, entry.part.path));
    const gzip = zlib.gzipSync(raw, { mtime: 0 });
    const transport = descriptor(gzip, true);
    catalog.table_transports[entry.part.path] = transport;
    assets.set(transport.path, gzip);
  }
  const first = catalog.strings[0].part;
  const firstTransport = catalog.table_transports[first.path];
  const fetcher =
    (reads = [], overrides = new Map()) =>
    async (name) => {
      reads.push(name);
      const raw = overrides.get(name) ?? assets.get(name) ?? fs.readFileSync(path.join(dir, name));
      return new Response(raw);
    };
  const api = context();
  // Advertised table bytes are bounded at open, before fetching or parsing tables.
  // These descriptors require no large allocation; repeated paths still count per row.
  function metadataCatalog({
    overflow = false,
    repeated = false,
    combined = false,
    partial = false,
  } = {}) {
    const metadata = clone(catalog);
    const parts = Array.from({ length: 16 + Number(overflow) }, (_, index) => ({
      ...descriptor(Buffer.from(String(repeated && index < 16 ? 0 : index))),
      bytes: index < 16 ? 8000000 : 1,
    }));
    const split = combined ? 8 : parts.length;
    for (const [kind, group] of [
      ['strings', parts.slice(0, split)],
      ['shapes', parts.slice(split)],
    ])
      metadata[kind] = group.map((part, first) => ({ part, first, count: 1 }));
    metadata.table_transports = {};
    for (const [index, part] of (partial ? parts.slice(0, 1) : parts).entries())
      if (!Object.hasOwn(metadata.table_transports, part.path))
        metadata.table_transports[part.path] = descriptor(Buffer.from(`compressed ${index}`), true);
    return metadata;
  }
  for (const options of [{}, { partial: true }, { repeated: true }, { combined: true }]) {
    for (const implementation of [api, context(null)]) {
      const reads = [];
      await assert.rejects(
        () =>
          implementation.open(
            fetcher(reads),
            metadataCatalog({ ...options, overflow: true }),
            identity,
          ),
        /table decoded byte budget/,
      );
      assert.deepStrictEqual(reads, [], 'aggregate table rejection precedes fetch');
      await implementation.open(fetcher(reads), metadataCatalog(options), identity);
      assert.deepStrictEqual(reads, [], 'exactly 128 MB of advertised tables may open');
    }
  }
  for (const absent of [false, true]) {
    const legacy = metadataCatalog({ overflow: true });
    if (absent) delete legacy.table_transports;
    else legacy.table_transports = {};
    const reads = [];
    await api.open(fetcher(reads), legacy, identity);
    assert.deepStrictEqual(reads, [], 'legacy aggregate metadata behavior is retained');
  }
  const reads = [];
  const reader = await api.open(fetcher(reads), catalog, identity);
  const tables = await reader.getTables();
  assert(tables[0].length > 0);
  assert(reads.includes(firstTransport.path), 'supported browser must fetch declared gzip');
  assert(!reads.includes(first.path), 'gzip success must avoid duplicate raw transfer');
  assert.strictEqual(
    reader.cacheBytes(),
    [...catalog.strings, ...catalog.shapes].reduce((sum, entry) => sum + entry.part.bytes, 0),
    'cache charges decoded table bytes',
  );
  await reader.getTables();
  assert.strictEqual(reads.length, Object.keys(catalog.table_transports).length);

  const publishedReads = [];
  assert(Object.keys(base.table_transports).length > 0, 'real publisher emits gzip table sidecars');
  const published = await api.open(fetcher(publishedReads), base, identity);
  assert.deepStrictEqual(clone(await published.getTables()), clone(tables));
  for (const [rawPath, transport] of Object.entries(base.table_transports)) {
    assert(publishedReads.includes(transport.path), 'real published sidecar is used');
    assert(!publishedReads.includes(rawPath));
  }

  // Removing transport support must retain all existing verified raw behavior.
  const legacyReads = [];
  const fallback = await context(null).open(fetcher(legacyReads), catalog, identity);
  assert.deepStrictEqual(clone(await fallback.getTables()), clone(tables));
  assert(legacyReads.includes(first.path));
  assert(!legacyReads.includes(firstTransport.path));
  const old = clone(catalog);
  delete old.table_transports;
  const oldReader = await api.open(fetcher(), old, identity);
  assert.deepStrictEqual(clone(await oldReader.getTables()), clone(tables));
  const fallbackBad = await context(null).open(
    fetcher([], new Map([[first.path, Buffer.from('bad')]])),
    catalog,
    identity,
  );
  await assert.rejects(() => fallbackBad.getTables(), /part size|fingerprint/);

  // Schema plus semantic validation must reject malformed/non-table/duplicate bindings at open.
  for (const [name, mutate] of [
    [
      'unknown table',
      (c) => {
        c.table_transports['data/v2/' + '0'.repeat(64) + '.json'] = firstTransport;
      },
    ],
    [
      'stale binding',
      (c) => {
        c.strings[0].part = c.shapes[0].part;
      },
    ],
    [
      'root binding',
      (c) => {
        c.table_transports[c.roots['snapshot.json'].path] = firstTransport;
      },
    ],
    [
      'duplicate gzip',
      (c) => {
        c.table_transports[c.shapes[0].part.path] = firstTransport;
      },
    ],
    [
      'raw path',
      (c) => {
        c.table_transports[first.path] = first;
      },
    ],
    [
      'newline gzip path',
      (c) => {
        c.table_transports[first.path].path += '\n';
      },
    ],
    [
      'wrong hash path',
      (c) => {
        c.table_transports[first.path].sha256 = '0'.repeat(64);
      },
    ],
    [
      'extra descriptor key',
      (c) => {
        c.table_transports[first.path].encoding = 'gzip';
      },
    ],
    [
      'zero bytes',
      (c) => {
        c.table_transports[first.path].bytes = 0;
      },
    ],
    [
      'oversize bytes',
      (c) => {
        c.table_transports[first.path].bytes = 8000001;
      },
    ],
    [
      'fractional bytes',
      (c) => {
        c.table_transports[first.path].bytes = 1.5;
      },
    ],
    [
      'map array',
      (c) => {
        c.table_transports = [];
      },
    ],
    [
      'map null',
      (c) => {
        c.table_transports = null;
      },
    ],
  ]) {
    const bad = clone(catalog);
    mutate(bad);
    await assert.rejects(() => api.open(fetcher(), bad, identity), undefined, name);
    await assert.rejects(
      () => context(null).open(fetcher(), bad, identity),
      undefined,
      name + ' without gzip support',
    );
  }

  async function rejectTransport(name, gzip, expected, mutate = () => {}, implementation = api) {
    const bad = clone(catalog);
    const transport = descriptor(gzip, true);
    bad.table_transports[first.path] = transport;
    mutate(bad, transport);
    const reads = [];
    const reader = await implementation.open(
      fetcher(reads, new Map([[transport.path, gzip]])),
      bad,
      identity,
    );
    await assert.rejects(() => reader.getTables(), expected, name);
    assert(
      !reads.includes(first.path),
      name + ' cannot fall back after declared transport failure',
    );
    assert.strictEqual(reader.cacheBytes(), 0, name + ' cannot cache invalid decoded bytes');
  }
  await rejectTransport(
    'encoded fingerprint',
    Buffer.from(assets.get(firstTransport.path)),
    /fingerprint/,
    (_c, d) => {
      d.bytes++;
    },
  );
  // Reject the first oversized encoded chunk without waiting for EOF or decoding.
  let encodedCancellations = 0,
    encodedSlots = 0,
    decoderConstructions = 0;
  const oversizedReads = [];
  class UnexpectedDecoder {
    constructor() {
      decoderConstructions++;
      throw Error('oversized encoded bytes must not reach decompression');
    }
  }
  const oversized = await context(UnexpectedDecoder).open(
    async (name) => {
      oversizedReads.push(name);
      return {
        ok: true,
        body: new ReadableStream(
          {
            start(controller) {
              controller.enqueue(new Uint8Array(firstTransport.bytes + 1));
              // Remain open: a reader that misses the bound cannot finish.
            },
            cancel() {
              encodedCancellations++;
              return new Promise(() => {});
            },
          },
          { highWaterMark: 0 },
        ),
      };
    },
    catalog,
    identity,
    {
      fetch_timeout_ms: 100,
      requestSlots: {
        acquire: async () => {
          encodedSlots++;
        },
        release: () => {
          encodedSlots--;
        },
      },
    },
  );
  await assert.rejects(() => oversized.getTables(), /part size/);
  assert.strictEqual(encodedCancellations, 1, 'oversized response reader is cancelled');
  assert.strictEqual(encodedSlots, 0, 'unsettled cancellation releases the request slot');
  assert.strictEqual(decoderConstructions, 0, 'encoded bound is enforced before decompression');
  assert.deepStrictEqual(oversizedReads, [firstTransport.path], 'no raw fallback is requested');
  assert.strictEqual(oversized.cacheBytes(), 0);

  const corrupt = Buffer.from(assets.get(firstTransport.path));
  corrupt[Math.floor(corrupt.length / 2)] ^= 1;
  const encodedMismatch = await api.open(
    fetcher([], new Map([[firstTransport.path, corrupt]])),
    catalog,
    identity,
  );
  await assert.rejects(() => encodedMismatch.getTables(), /fingerprint/);
  await rejectTransport('malformed gzip', corrupt);
  await rejectTransport('truncated gzip', assets.get(firstTransport.path).subarray(0, -4));
  await rejectTransport(
    'decoded hash',
    zlib.gzipSync(Buffer.alloc(first.bytes, 32)),
    /fingerprint/,
  );
  await rejectTransport('decoded underflow', zlib.gzipSync(Buffer.from('[]')), /fingerprint|size/);
  await rejectTransport(
    'decoded overflow',
    zlib.gzipSync(Buffer.alloc(first.bytes + 1000000, 32)),
    /size|gzip/,
  );
  await rejectTransport(
    'trailing garbage',
    Buffer.concat([assets.get(firstTransport.path), Buffer.from('extra')]),
  );
  await rejectTransport(
    'concatenated overflow',
    Buffer.concat([assets.get(firstTransport.path), zlib.gzipSync('extra')]),
    // Native decoders may reject the additional member before our size check.
    (error) => error.name === 'TypeError' || /size|gzip/.test(error.message),
  );
  class RejectedDecoder {
    constructor() {
      return new TransformStream({
        transform() {
          throw new TypeError('native decompression rejected');
        },
      });
    }
  }
  await rejectTransport(
    'native decoder rejection',
    assets.get(firstTransport.path),
    (error) => error instanceof TypeError && error.message === 'native decompression rejected',
    undefined,
    context(RejectedDecoder),
  );

  const unavailableReads = [];
  const unavailable = await api.open(
    async (name) => {
      unavailableReads.push(name);
      return new Response(null, { status: 404 });
    },
    catalog,
    identity,
  );
  await assert.rejects(() => unavailable.getTables(), /part unavailable/);
  assert.deepStrictEqual(unavailableReads, [firstTransport.path]);

  // A stalled decoder must release slots and permit retry even if cancel never settles.
  let cancellations = 0,
    releases = 0,
    slots = 0,
    attempts = 0,
    onDecoderStarted;
  async function withinWatchdog(promise) {
    let watchdog;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          watchdog = setTimeout(() => reject(Error('operation watchdog expired')), 1000);
        }),
      ]);
    } finally {
      clearTimeout(watchdog);
    }
  }
  class StalledDecoder {
    constructor(format) {
      if (attempts++) return new DecompressionStream(format);
      this.writable = new WritableStream();
      this.readable = new ReadableStream();
      this.readable.getReader = () => ({
        read: () => new Promise(() => {}),
        cancel: () => {
          cancellations++;
          return new Promise(() => {});
        },
        releaseLock: () => {
          releases++;
        },
      });
      onDecoderStarted?.();
    }
  }
  const stalled = await context(StalledDecoder).open(fetcher(), catalog, identity, {
    requestSlots: {
      acquire: async () => {
        slots++;
      },
      release: () => {
        slots--;
      },
    },
  });
  const abort = new AbortController();
  const decoderStarted = new Promise((resolve) => {
    onDecoderStarted = resolve;
  });
  const pending = stalled.getTables({ signal: abort.signal });
  pending.catch(() => {});
  try {
    await withinWatchdog(decoderStarted);
  } finally {
    onDecoderStarted = undefined;
    abort.abort();
  }
  await assert.rejects(() => pending, /cancelled/);
  assert.strictEqual(slots, 0);
  assert.strictEqual(cancellations, 1);
  assert.strictEqual(releases, 1);
  assert.deepStrictEqual(clone(await stalled.getTables()), clone(tables));

  attempts = 0;
  const timeout = await context(StalledDecoder).open(fetcher(), catalog, identity, {
    fetch_timeout_ms: 20,
  });
  await assert.rejects(() => timeout.getTables(), /deadline/);
  assert.strictEqual(timeout.cacheBytes(), 0);
  attempts = cancellations = releases = 0;
  const deadline = await context(StalledDecoder).open(fetcher(), catalog, identity, {
    requestSlots: {
      acquire: async () => {
        slots++;
      },
      release: () => {
        slots--;
      },
    },
  });
  await assert.rejects(
    withinWatchdog(deadline.getTables({ deadline: Date.now() + 20 })),
    // The operation's own timer may fire just before the Date.now() boundary.
    /deadline|cancelled/,
  );
  // A busy runner can hit the deadline before constructing the decoder.
  assert(attempts <= 1, 'operation deadline cannot retry the decoder');
  assert.strictEqual(cancellations, attempts, 'operation deadline cancels any decoder reader');
  assert.strictEqual(releases, attempts, 'operation deadline releases any decoder reader lock');
  assert.strictEqual(slots, 0, 'operation deadline releases the request slot');
  assert.strictEqual(deadline.cacheBytes(), 0, 'operation deadline cannot cache stalled bytes');
  console.log('Browser gzip table transport, fallback, integrity, bounds and cancellation passed');
})()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(() => fs.rmSync(temporary, { recursive: true, force: true }));
