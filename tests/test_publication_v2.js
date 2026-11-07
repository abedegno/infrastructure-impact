const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const context = {
  window: {},
  TextEncoder,
  TextDecoder,
  crypto: require('crypto').webcrypto,
  AbortController,
  console,
  setTimeout,
  clearTimeout,
};
vm.createContext(context);
vm.runInContext(fs.readFileSync('infrastructure_impact/web/lossless-json.js', 'utf8'), context);
assert.strictEqual(
  typeof context.window.InfrastructureJSON.parseStrict,
  'function',
  'strict parser required',
);
for (const raw of JSON.parse(fs.readFileSync('tests/fixtures/publication-v2-codec-vectors.json'))
  .invalid_json)
  assert.throws(() => context.window.InfrastructureJSON.parseStrict(raw));
vm.runInContext(fs.readFileSync('infrastructure_impact/web/publication-v2.js', 'utf8'), context);
const api = context.window.InfrastructurePublicationV2,
  vectors = JSON.parse(fs.readFileSync('tests/fixtures/publication-v2-codec-vectors.json'));
(async () => {
  for (const v of vectors.valid) {
    for (const encoding of ['logical', 'ascii'])
      assert.strictEqual(
        await api.decodeTokens(v.tokens, v.strings, v.shapes, { serialization: encoding }),
        v[encoding],
        v.name,
      );
  }
  for (const v of vectors.invalid)
    await assert.rejects(() => api.decodeTokens(v.tokens, v.strings, v.shapes), undefined, v.name);
  await assert.rejects(() => api.decodeTokens([[-1, 10000000]], [], [], { max_bytes: 100 }));
  await assert.rejects(() =>
    api.decodeTokens([-2], ['🚀'], [], { max_bytes: 10, serialization: 'ascii' }),
  );
  await assert.rejects(() => api.decodeTokens([null], [], [], { deadline: 0 }));
  console.log('Publication v2 shared codec vectors and bounds passed');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
// Consume an actual Python-published generation (optional path supplied by integration).
(async () => {
  const path = require('path'),
    os = require('os'),
    child = require('child_process');
  let temporary;
  const dir =
    process.argv[2] ||
    (() => {
      temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'publication-v2-browser-'));
      return child
        .execFileSync(
          process.env.PYTHON ||
            (fs.existsSync('.venv/bin/python') ? '.venv/bin/python' : 'python3'),
          [
            '-c',
            `import json,sys
sys.path.insert(0,'tests')
from test_static_delivery import dataset
from infrastructure_impact.application.publication import publish
data=dataset()
data['research']['switching_input']=json.load(open('tests/fixtures/switching-cases.json'))['evidence']
print(publish(data,sys.argv[1],publication_format='v2'))`,
            temporary,
          ],
          { encoding: 'utf8' },
        )
        .trim();
    })();
  try {
    for (const name of ['kev', 'switching-contracts', 'switching', 'current-evidence', 'delivery'])
      vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
    const reads = [];
    const fetch = async (name) => {
      reads.push(name);
      const raw = fs.readFileSync(path.join(dir, name.replace(/^\//, '')));
      return { ok: true, arrayBuffer: async () => raw, text: async () => raw.toString() };
    };
    const index = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json'))),
      catalog = JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json')));
    const reader = await api.open(fetch, catalog, index);
    assert.strictEqual(reads.length, 0, 'open metadata only');
    await assert.rejects(
      () => reader.runtimeSnapshot({ cohort: [Object.keys(index.cohorts)[0]] }),
      /cohort runtime requires static delivery/,
    );
    assert.strictEqual(
      reads.length,
      0,
      'missing cohort capability rejects before reading any full root',
    );
    const overview = await reader.switchingOverview(index.generated_at);
    assert.strictEqual(overview.representation, 'switching-overview');
    assert(
      !reads.includes(catalog.roots['switching-evidence.json'].path),
      'overview does not open full evidence root',
    );
    const defaultBytes = [...new Set(reads)].reduce(
      (n, name) => n + fs.statSync(path.join(dir, name)).size,
      0,
    );
    assert(defaultBytes <= 20000000, 'actual default reads fit budget');
    const fixture = JSON.parse(fs.readFileSync('tests/fixtures/switching-cases.json'));
    let streamed = '';
    for await (const chunk of reader.streamRoot('switching-evidence.json')) streamed += chunk;
    assert.deepStrictEqual(
      JSON.parse(streamed),
      JSON.parse(
        context.window.InfrastructureJSON.stringify(
          await reader.materializeRoot('switching-evidence.json'),
        ),
      ),
    );
    const sourcePage = await reader.switchingDetails(overview, { kind: 'sources', limit: 25 });
    assert(sourcePage.items.length <= 25);
    const diagnosticPage = await reader.switchingDetails(overview, {
      kind: 'diagnostics',
      limit: 25,
    });
    assert(diagnosticPage.items.length <= 25);
    await assert.rejects(() =>
      reader.switchingDetails(JSON.parse(JSON.stringify(overview)), { kind: 'sources', limit: 25 }),
    );
    const full = await reader.materializeRoot('switching-comparison.json');
    for (const c of fixture.comparison_cases) {
      const got = await reader.switchingSelection(
        c.options,
        c.options.evaluated_at ?? index.generated_at,
      );
      const expected = context.window.InfrastructureSwitching.summary(
        context.window.InfrastructureSwitching.selectReport(full, {
          ...c.options,
          evaluated_at: c.options.evaluated_at ?? index.generated_at,
        }),
      );
      assert.deepStrictEqual(
        JSON.parse(JSON.stringify(got)),
        JSON.parse(JSON.stringify(expected)),
        c.name,
      );
    }
    const loader = await context.createStaticDelivery(fetch, '');
    assert(loader.switchingSelection);
    assert.strictEqual(
      (await loader.switchingOverview(index.generated_at)).representation,
      'switching-overview',
    );
    const cohort = await loader([Object.keys(index.cohorts)[0]]);
    assert(Array.isArray(cohort.records));
    assert(cohort.counts);
    const bootstrap = JSON.parse(fs.readFileSync(path.join(dir, index.bootstrap.path))).data;
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(cohort.counts)),
      bootstrap.counts,
      'narrow cohort retains complete global context counts',
    );
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(cohort.benchmark_cohort)),
      bootstrap.benchmark_cohort,
      'narrow cohort preserves complete benchmark denominator',
    );
    const staleOverview = await reader.switchingOverview('2027-12-01T00:00:00Z');
    const staleSummary = context.window.InfrastructureSwitching.summary(
      context.window.InfrastructureSwitching.selectReport(full, {
        evaluated_at: '2027-12-01T00:00:00Z',
      }),
    );
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(staleOverview.rows.map((r) => r.kev))),
      JSON.parse(JSON.stringify(staleSummary.rows.map((r) => r.kev))),
    );
    const { createHash } = require('crypto'),
      overlay = new Map();
    function altered(descriptor, change) {
      const value = JSON.parse(fs.readFileSync(path.join(dir, descriptor.path)));
      change(value);
      const raw = Buffer.from(JSON.stringify(value));
      const sha256 = createHash('sha256').update(raw).digest('hex');
      const result = { path: `data/v2/${sha256}.json`, sha256, bytes: raw.length };
      overlay.set(result.path, raw);
      return result;
    }
    const virtualFetch = async (name) => {
      const raw = overlay.get(name) || fs.readFileSync(path.join(dir, name));
      return { ok: true, arrayBuffer: async () => raw };
    };
    const large = JSON.parse(JSON.stringify(catalog));
    large.roots['runtime-snapshot'] = altered(
      large.roots['runtime-snapshot'],
      (v) => (v.data.logical.bytes = 128000001),
    );
    const largeReader = await api.open(virtualFetch, large, index);
    await largeReader.switchingOverview(index.generated_at);
    await assert.rejects(() => largeReader.runtimeSnapshot(), /selected byte budget/);
    assert((await largeReader.runtimeSnapshot({ fields: ['counts'] })).counts);
    const tampered = JSON.parse(JSON.stringify(catalog));
    tampered.roots['switching-evidence.json'] = altered(
      tampered.roots['switching-evidence.json'],
      (v) => v.data.pages[0].decoded_upper_bound++,
    );
    const badReader = await api.open(virtualFetch, tampered, index);
    await assert.rejects(
      () => badReader.materializeRoot('switching-evidence.json'),
      /page decoded bound/,
    );
    const mixed = JSON.parse(JSON.stringify(catalog));
    mixed.strings[0].part = altered(
      mixed.strings[0].part,
      (v) => (v.publication.id = 'f'.repeat(32)),
    );
    const mixedReader = await api.open(virtualFetch, mixed, index);
    await assert.rejects(() => mixedReader.getTables(), /mixed generation/);
    let active = 0,
      peak = 0;
    const throttled = await api.open(
      async (name) => {
        active++;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 2));
        const result = await virtualFetch(name);
        active--;
        return result;
      },
      catalog,
      index,
      { cache_bytes: 30000 },
    );
    await Promise.all(
      Object.values(catalog.roots)
        .slice(0, 30)
        .map((d) => throttled.read(d, 'root')),
    );
    assert(peak <= 6);
    assert(throttled.cacheBytes() <= 30000);
    const firstPage = await reader.switchingDetails(overview, { kind: 'sources', limit: 1 });
    if (firstPage.next_cursor) {
      const nextOverview = await reader.switchingOverview('2027-12-01T00:00:00Z');
      await assert.rejects(
        () =>
          reader.switchingDetails(nextOverview, {
            kind: 'claims',
            cursor: firstPage.next_cursor,
            limit: 1,
          }),
        /cursor generation/,
      );
    }
    console.log(
      'Actual Python v2 publication browser overview, root, selection, paging, tamper and bound checks passed',
    );
  } finally {
    if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
for (const v of vectors.materialization ?? [])
  (async () => {
    const value = context.window.InfrastructureJSON.parseStrict(
      await api.decodeTokens([v.token], [], []),
    );
    if (v.kind === 'float') {
      assert.strictEqual(typeof value, 'number');
      assert.strictEqual(Object.is(value, -0), v.negative_zero);
    } else assert.strictEqual(String(value), v.integer_decimal);
  })().catch((e) => {
    console.error(e);
    process.exitCode = 1;
  });

(async () => {
  await assert.rejects(
    () =>
      api.decodeTokens(
        {
          [Symbol.asyncIterator]() {
            return {
              next() {
                return new Promise(() => {});
              },
            };
          },
        },
        [],
        [],
        { deadline: Date.now() + 5 },
      ),
    /deadline/,
  );
  const signal = new AbortController();
  signal.abort();
  await assert.rejects(
    () => api.decodeTokens([null], [], [], { signal: signal.signal }),
    /cancelled/,
  );
  const options = { root: 'switching-comparison.json', aliases: () => [-2], max_bytes: 20 };
  await assert.rejects(
    () =>
      api.decodeTokens(
        [[0], [1], [-3, 'switching-evidence.json']],
        ['x'.repeat(100)],
        [['inputs'], ['evidence']],
        options,
      ),
    /budget/,
  );
  await assert.rejects(
    () =>
      api.decodeTokens([-2], [String.fromCharCode(127)], [], {
        serialization: 'ascii',
        max_bytes: 4,
      }),
    /budget/,
  );
  console.log('Streaming cancellation, deadline and shared alias budget passed');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
