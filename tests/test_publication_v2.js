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
    let transferred = 0;
    const fetch = async (name) => {
      reads.push(name);
      const raw = fs.readFileSync(path.join(dir, name.replace(/^\//, '')));
      transferred += raw.length;
      return { ok: true, arrayBuffer: async () => raw, text: async () => raw.toString() };
    };
    const index = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json'))),
      catalog = JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json')));
    // Raw-descriptor mutation cases exercise legacy catalogs; test_table_transport.js covers gzip.
    delete catalog.table_transports;
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
    assert(transferred <= 20000000, 'actual direct overview transfers fit synthetic budget');
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
    assert(catalog.switching.detail_indexes, 'publisher emits separate detail indexes');
    const contracts = context.window.InfrastructureSwitchingContracts;
    const detailEnvelope = {
      schema_version: 2,
      publication: catalog.publication,
      generated_at: catalog.generated_at,
      kind: 'detail_index',
      data: [{ ordinal: 0, range: catalog.switching.diagnostics }],
    };
    contracts.envelope(detailEnvelope, 'detail_index');
    for (const [field, value] of [
      ['schema_version', 1],
      ['publication', { id: 'bad', advisory_schema_version: 2 }],
      ['generated_at', 42],
      ['kind', 'strings'],
      ['data', [{ ordinal: -1 }]],
      ['extra', true],
    ]) {
      const broken = { ...detailEnvelope, [field]: value };
      assert.throws(() => contracts.validate('publication-v2.json', broken, '/$defs/envelope'));
      assert.throws(() => contracts.envelope(broken, 'detail_index'));
    }
    assert.throws(() => contracts.envelope(detailEnvelope, 'unknown'));
    const originalValidate = contracts.validate;
    contracts.validate = (name, value, fragment) => {
      assert.notStrictEqual(fragment, '/$defs/envelope', 'dispatch envelope by exact kind');
      return originalValidate(name, value, fragment);
    };
    let sourcePage;
    try {
      sourcePage = await reader.switchingDetails(overview, { kind: 'sources', limit: 25 });
    } finally {
      contracts.validate = originalValidate;
    }
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
    const originalSelectClaims = context.window.InfrastructureSwitching.selectClaims;
    context.window.InfrastructureSwitching.selectClaims = () => {
      throw Error('default selection must use the published comparison');
    };
    try {
      const selected = await reader.switchingSelection({}, index.generated_at);
      const expected = context.window.InfrastructureSwitching.summary(
        context.window.InfrastructureSwitching.selectReport(full, {
          evaluated_at: index.generated_at,
        }),
      );
      assert.deepStrictEqual(
        JSON.parse(JSON.stringify(selected)),
        JSON.parse(JSON.stringify(expected)),
      );
      for (const evaluated_at of [index.generated_at, '2027-12-01T00:00:00Z'])
        for (const vendor of ['cisco', 'aruba', 'arista']) {
          const narrowReads = [],
            narrow = await api.open(
              async (name) => {
                narrowReads.push(name);
                return fetch(name);
              },
              catalog,
              index,
            ),
            actual = await narrow.switchingSelection({ vendor, cve_ids: null }, evaluated_at),
            native = context.window.InfrastructureSwitching.summary(
              context.window.InfrastructureSwitching.selectReport(full, { vendor, evaluated_at }),
            );
          assert.deepStrictEqual(
            JSON.parse(JSON.stringify(actual)),
            JSON.parse(JSON.stringify(native)),
          );
          assert.strictEqual(
            context.window.InfrastructureSwitching.csvExport(actual),
            context.window.InfrastructureSwitching.csvExport(native),
          );
          assert(!narrowReads.includes(catalog.roots['switching-evidence.json'].path));
          for (const chunk of catalog.switching.detail_indexes.sources)
            assert(
              narrowReads.filter((name) => name === chunk.part.path).length <= 1,
              'intersected Source chunk fetched once',
            );
          assert(Object.isFrozen(actual) && Object.isFrozen(actual.rows));
          await assert.rejects(() => narrow.switchingDetails(selected, { kind: 'sources' }));
        }
    } finally {
      context.window.InfrastructureSwitching.selectClaims = originalSelectClaims;
    }
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
    transferred = 0;
    const loader = await context.createStaticDelivery(fetch, '');
    await loader();
    assert(loader.switchingSelection);
    assert.strictEqual(
      (await loader.switchingOverview(index.generated_at)).representation,
      'switching-overview',
    );
    assert(
      transferred <= 20000000,
      'actual facade default includes every index/catalog/bootstrap/cohort/current-evidence/overview transfer',
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
      const value = JSON.parse(
        overlay.get(descriptor.path) || fs.readFileSync(path.join(dir, descriptor.path)),
      );
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
    // All review fixtures remain content-addressed, generation-bound envelopes.
    function part(kind, data) {
      const raw = Buffer.from(
        JSON.stringify({
          schema_version: 2,
          publication: index.publication,
          generated_at: index.generated_at,
          kind,
          data,
        }),
      );
      const sha256 = createHash('sha256').update(raw).digest('hex'),
        d = { path: `data/v2/${sha256}.json`, sha256, bytes: raw.length };
      overlay.set(d.path, raw);
      return d;
    }
    function wireRoot(name, tokens, text, cost, ranges = []) {
      return part('root', {
        name,
        token_count: tokens.length,
        logical: {
          bytes: Buffer.byteLength(text),
          sha256: createHash('sha256').update(text).digest('hex'),
        },
        pages: [
          {
            part: part('tokens', tokens),
            first_token: 0,
            count: tokens.length,
            decoded_upper_bound: cost,
          },
        ],
        ranges: ranges.length ? [part('ranges', ranges)] : [],
      });
    }
    function bound(name, first, end, text) {
      return {
        root: name,
        first_token: first,
        end_token: end,
        logical_bytes: Buffer.byteLength(text),
        logical_sha256: createHash('sha256').update(text).digest('hex'),
      };
    }
    const membershipRoot = 'switching-row-sources.json',
      originalMembership = await reader.materializeRoot(membershipRoot),
      seedStrings = catalog.strings.flatMap(
        (d) => JSON.parse(fs.readFileSync(path.join(dir, d.part.path))).data,
      ),
      seedShapes = catalog.shapes.flatMap(
        (d) => JSON.parse(fs.readFileSync(path.join(dir, d.part.path))).data,
      );
    function membershipCatalog(change, floatPath = null) {
      const value = JSON.parse(JSON.stringify(originalMembership)),
        result = JSON.parse(JSON.stringify(catalog)),
        strings = [...seedStrings],
        shapes = [...seedShapes],
        tokens = [];
      change(value);
      function encode(v, path = []) {
        if (v === null || typeof v === 'boolean') tokens.push(v);
        else if (typeof v === 'number') {
          const fractional = JSON.stringify(path) === JSON.stringify(floatPath),
            raw = String(v) + (fractional ? '.0' : '');
          tokens.push([-2, fractional ? 'f' : 'i', raw]);
          return raw;
        } else if (typeof v === 'string') {
          let i = strings.indexOf(v);
          if (i < 0) {
            i = strings.length;
            strings.push(v);
          }
          tokens.push(-i - 2);
        } else if (Array.isArray(v)) {
          tokens.push([-1, v.length]);
          return '[' + v.map((x, i) => encode(x, [...path, i])).join(',') + ']';
        } else {
          const keys = Object.keys(v);
          let i = shapes.findIndex((s) => JSON.stringify(s) === JSON.stringify(keys));
          if (i < 0) {
            i = shapes.length;
            shapes.push(keys);
          }
          tokens.push([i]);
          return (
            '{' +
            keys.map((k) => JSON.stringify(k) + ':' + encode(v[k], [...path, k])).join(',') +
            '}'
          );
        }
        return JSON.stringify(v);
      }
      const text = encode(value);
      result.roots[membershipRoot] = wireRoot(
        membershipRoot,
        tokens,
        text,
        Buffer.byteLength(text),
      );
      result.strings = [{ first: 0, count: strings.length, part: part('strings', strings) }];
      result.shapes = [{ first: 0, count: shapes.length, part: part('shapes', shapes) }];
      delete result.table_transports;
      return result;
    }
    for (const floatPath of [
      ['schema_version'],
      ['sources_count'],
      ['rows', 0, 'row_ordinal'],
      ['rows', 2, 'source_ordinals', 0],
      ['sources_range', 'first_token'],
    ]) {
      const broken = await api.open(
        virtualFetch,
        membershipCatalog(() => {}, floatPath),
        index,
      );
      await assert.rejects(
        () => broken.switchingSelection({ vendor: 'arista' }, index.generated_at),
        undefined,
        'float kind at ' + JSON.stringify(floatPath),
      );
    }
    for (const change of [
      (v) => {
        v.schema_version = true;
      },
      (v) => {
        v.publication.id = '0'.repeat(32);
      },
      (v) => {
        v.generated_at = '2025-01-01T00:00:00Z';
      },
      (v) => {
        v.definition_sha256 = '0'.repeat(64);
      },
      (v) => {
        v.observation_end = '2025-01-01';
      },
      (v) => {
        v.sources_count++;
      },
      (v) => {
        v.sources_count = true;
      },
      (v) => {
        v.sources_range.logical_sha256 = '0'.repeat(64);
      },
      (v) => {
        v.rows[0].row_id = 'arista:os_family:all';
      },
      (v) => {
        v.rows[0].row_ordinal = 1;
      },
      (v) => {
        v.rows[0].published_row_sha256 = '0'.repeat(64);
      },
      (v) => {
        v.rows[2].claim_membership_sha256 = '0'.repeat(64);
      },
      (v) => {
        v.rows.pop();
      },
      (v) => {
        v.rows.push(v.rows[0]);
      },
      (v) => {
        v.extra = true;
      },
      ...[[true], [-1], [0, 0], [1, 0], [9007199254740992], [originalMembership.sources_count]].map(
        (values) => (v) => {
          v.rows[2].source_ordinals = values;
        },
      ),
    ]) {
      const brokenCatalog = membershipCatalog(change),
        broken = await api.open(virtualFetch, brokenCatalog, index);
      await assert.rejects(() =>
        broken.switchingSelection({ vendor: 'arista' }, index.generated_at),
      );
      delete brokenCatalog.switching.detail_indexes;
      const noDetails = await api.open(virtualFetch, brokenCatalog, index);
      await assert.rejects(() =>
        noDetails.switchingSelection({ vendor: 'arista' }, index.generated_at),
      );
    }
    for (const change of [
      (v) => {
        v.data[0].ordinal++;
      },
      (v) => {
        v.data[0].range.logical_sha256 = '0'.repeat(64);
      },
      (v) => {
        v.data[0].range.end_token++;
      },
    ]) {
      const brokenCatalog = JSON.parse(JSON.stringify(catalog));
      for (const chunk of brokenCatalog.switching.detail_indexes.sources)
        chunk.part = altered(chunk.part, change);
      const broken = await api.open(virtualFetch, brokenCatalog, index);
      await assert.rejects(() => broken.switchingSelection({}, index.generated_at));
    }
    const oldCatalog = JSON.parse(JSON.stringify(catalog));
    delete oldCatalog.roots[membershipRoot];
    const oldReader = await api.open(virtualFetch, oldCatalog, index);
    assert.deepStrictEqual(
      JSON.parse(
        JSON.stringify(
          await oldReader.switchingSelection({ vendor: 'arista' }, index.generated_at),
        ),
      ),
      JSON.parse(
        JSON.stringify(
          context.window.InfrastructureSwitching.summary(
            context.window.InfrastructureSwitching.selectReport(full, {
              vendor: 'arista',
              evaluated_at: index.generated_at,
            }),
          ),
        ),
      ),
    );
    let retryOnce = true;
    const retryReader = await api.open(
      async (name) => {
        if (name === catalog.roots[membershipRoot].path && retryOnce) {
          retryOnce = false;
          throw Error('transient metadata failure');
        }
        return virtualFetch(name);
      },
      catalog,
      index,
    );
    await assert.rejects(
      () => retryReader.switchingSelection({ vendor: 'arista' }, index.generated_at),
      /transient/,
    );
    await retryReader.switchingSelection({ vendor: 'arista' }, index.generated_at);
    const cancelledSelection = new AbortController();
    cancelledSelection.abort();
    await assert.rejects(
      () =>
        retryReader.switchingSelection({ vendor: 'arista' }, index.generated_at, {
          signal: cancelledSelection.signal,
        }),
      /cancel/,
    );
    await retryReader.switchingSelection({ vendor: 'arista' }, index.generated_at);
    const tinyWorking = await api.open(virtualFetch, catalog, index, { working_bytes: 1 });
    await assert.rejects(
      () => tinyWorking.switchingSelection({ vendor: 'arista' }, index.generated_at),
      /budget/,
    );
    const transportCatalog = JSON.parse(JSON.stringify(catalog));
    const transportRoot = transportCatalog.roots['snapshot.json'];
    const floatRaw = Buffer.from(
      fs
        .readFileSync(path.join(dir, transportRoot.path), 'utf8')
        .replace('"first_token":0', '"first_token":0.0'),
    );
    const floatHash = createHash('sha256').update(floatRaw).digest('hex');
    transportCatalog.roots['snapshot.json'] = {
      path: `data/v2/${floatHash}.json`,
      sha256: floatHash,
      bytes: floatRaw.length,
    };
    overlay.set(transportCatalog.roots['snapshot.json'].path, floatRaw);
    const floatReader = await api.open(virtualFetch, transportCatalog, index);
    await assert.rejects(() => floatReader.materializeRoot('snapshot.json'), /transport/);
    const short = JSON.parse(JSON.stringify(catalog));
    short.strings = [];
    short.shapes = [];
    short.roots['snapshot.json'] = altered(
      wireRoot('snapshot.json', [null], 'null', 4),
      (v) => (v.data.logical.bytes = 1),
    );
    const shortReader = await api.open(virtualFetch, short, index);
    let emitted = '';
    await assert.rejects(async () => {
      for await (const chunk of shortReader.streamRoot('snapshot.json')) emitted += chunk;
    }, /canonical byte budget/);
    assert.strictEqual(emitted, '', 'no bytes beyond declared length escape root reader');
    let aborted = false;
    const stalled = await api.open(
      (name, { signal }) => {
        signal.addEventListener('abort', () => (aborted = true), { once: true });
        return new Promise(() => {});
      },
      short,
      index,
    );
    await assert.rejects(async () => {
      for await (const chunk of stalled.streamRoot('snapshot.json', { deadline: Date.now() + 5 })) {
      }
    }, /deadline|cancelled/);
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert(aborted, 'operation deadline aborts metadata fetch');
    const comparisonCatalog = JSON.parse(JSON.stringify(short));
    comparisonCatalog.shapes = [
      { part: part('shapes', [['inputs'], ['evidence']]), first: 0, count: 2 },
    ];
    comparisonCatalog.roots['switching-evidence.json'] = wireRoot(
      'switching-evidence.json',
      [null],
      'null',
      4,
    );
    comparisonCatalog.roots['switching-comparison.json'] = wireRoot(
      'switching-comparison.json',
      [[0], [1], [-3, 'switching-evidence.json']],
      '{"inputs":{"evidence":null}}',
      25,
    );
    const evidenceMeta = JSON.parse(
      overlay.get(comparisonCatalog.roots['switching-evidence.json'].path),
    ).data;
    let bodyAborted = false,
      bodyCancelled = false,
      bodyReleased = false;
    const pendingBody = await api.open(
      async (name, { signal }) => {
        if (name !== evidenceMeta.pages[0].part.path) return virtualFetch(name);
        signal.addEventListener('abort', () => (bodyAborted = true), { once: true });
        return {
          ok: true,
          body: {
            getReader: () => ({
              read: () => new Promise(() => {}),
              cancel: async () => {
                bodyCancelled = true;
              },
              releaseLock: () => {
                bodyReleased = true;
              },
            }),
          },
        };
      },
      comparisonCatalog,
      index,
    );
    await assert.rejects(async () => {
      for await (const chunk of pendingBody.streamRoot('switching-comparison.json', {
        deadline: Date.now() + 200,
      })) {
      }
    }, /deadline|cancelled/);
    await new Promise((resolve) => setTimeout(resolve, 5));
    assert(
      bodyAborted && bodyCancelled && bodyReleased,
      'nested alias body aborts, cancels and releases on operation deadline',
    );

    const fieldsCatalog = JSON.parse(JSON.stringify(catalog)),
      textValue = 'x'.repeat(60),
      quoted = JSON.stringify(textValue),
      fieldText = JSON.stringify({ a: textValue, b: textValue });
    fieldsCatalog.strings = [{ part: part('strings', [textValue]), first: 0, count: 1 }];
    fieldsCatalog.shapes = [{ part: part('shapes', [['a', 'b']]), first: 0, count: 1 }];
    fieldsCatalog.roots['runtime-snapshot'] = wireRoot(
      'runtime-snapshot',
      [[0], -2, -2],
      fieldText,
      Buffer.byteLength(fieldText),
      [
        { path: ['a'], range: bound('runtime-snapshot', 1, 2, quoted) },
        { path: ['b'], range: bound('runtime-snapshot', 2, 3, quoted) },
      ],
    );
    const fieldReader = await api.open(virtualFetch, fieldsCatalog, index, { selected_bytes: 100 });
    assert.strictEqual((await fieldReader.runtimeSnapshot({ fields: ['a'] })).a, textValue);
    await assert.rejects(() => fieldReader.runtimeSnapshot({ fields: ['a', 'b'] }), /budget/);
    const pageCatalog = JSON.parse(JSON.stringify(catalog)),
      sourceValue = 'x'.repeat(400),
      sourceText = JSON.stringify([{ value: sourceValue }, { value: sourceValue }]);
    delete pageCatalog.switching.detail_indexes; // Legacy whole-array fixtures exercise fallback.
    pageCatalog.strings = [{ part: part('strings', [sourceValue]), first: 0, count: 1 }];
    pageCatalog.shapes = [{ part: part('shapes', [['value']]), first: 0, count: 1 }];
    pageCatalog.roots['review-page'] = wireRoot(
      'review-page',
      [[-1, 2], [0], -2, [0], -2],
      sourceText,
      Buffer.byteLength(sourceText),
    );
    pageCatalog.roots['review-kev'] = wireRoot('review-kev', [null], 'null', 4);
    pageCatalog.switching.kev = bound('review-kev', 0, 1, 'null');
    pageCatalog.switching.overview = altered(
      pageCatalog.switching.overview,
      (v) => (v.data.detail_ranges.sources = bound('review-page', 0, 5, sourceText)),
    );
    const pageReader = await api.open(virtualFetch, pageCatalog, index, { selected_bytes: 800 }),
      pageOverview = await pageReader.switchingOverview(index.generated_at);
    await pageReader.switchingDetails(pageOverview, { kind: 'sources', limit: 1 });
    await assert.rejects(
      () => pageReader.switchingDetails(pageOverview, { kind: 'sources', limit: 2 }),
      /budget/,
    );
    // R1: excluded diagnostics remain independently bounded, not page-budgeted.
    const filteredCatalog = JSON.parse(JSON.stringify(pageCatalog));
    function diagnostic(vendor, domain) {
      const value = {
        vendor,
        advisory_id: 'synthetic',
        source_url: `https://www.${domain}/synthetic`,
        source: {
          source_url: `https://www.${domain}/synthetic`,
          source_sha256: 'a'.repeat(64),
          retrieved_at: '2026-11-04T12:00:00Z',
          source_locator: '',
        },
        cve_id: null,
        product_id: null,
        context: 'source_only_unclassified',
        state: 'unavailable',
        issues: [],
        attempts: [],
      };
      value.source.source_locator = 'x'.repeat(
        671 -
          context.window.InfrastructureJSON.measure({
            items: [value],
            next_cursor: null,
            total: 1,
          }),
      );
      return value;
    }
    const selectedDiagnostic = diagnostic('arista', 'arista.com'),
      excludedDiagnostic = diagnostic('cisco', 'cisco.com');
    const diagnosticValues = [selectedDiagnostic, excludedDiagnostic],
      diagnosticText = JSON.stringify(diagnosticValues);
    context.window.InfrastructureSwitchingContracts.validate(
      'switching-evidence-v1.json',
      diagnosticValues,
      '/properties/score_availability',
    );
    const atoms = [],
      layouts = [],
      diagnosticTokens = [];
    function encodeDiagnostic(value) {
      if (value === null || typeof value === 'boolean') diagnosticTokens.push(value);
      else if (typeof value === 'string') {
        let atom = atoms.indexOf(value);
        if (atom < 0) {
          atom = atoms.length;
          atoms.push(value);
        }
        diagnosticTokens.push(-atom - 2);
      } else if (Array.isArray(value)) {
        diagnosticTokens.push([-1, value.length]);
        for (const child of value) encodeDiagnostic(child);
      } else {
        const keys = Object.keys(value);
        let shape = layouts.findIndex((entry) => JSON.stringify(entry) === JSON.stringify(keys));
        if (shape < 0) {
          shape = layouts.length;
          layouts.push(keys);
        }
        diagnosticTokens.push([shape]);
        for (const key of keys) encodeDiagnostic(value[key]);
      }
    }
    encodeDiagnostic(diagnosticValues);
    filteredCatalog.strings = [{ part: part('strings', atoms), first: 0, count: atoms.length }];
    filteredCatalog.shapes = [{ part: part('shapes', layouts), first: 0, count: layouts.length }];
    filteredCatalog.roots['filtered-diagnostics'] = wireRoot(
      'filtered-diagnostics',
      diagnosticTokens,
      diagnosticText,
      Buffer.byteLength(diagnosticText),
    );
    filteredCatalog.switching.diagnostics = bound(
      'filtered-diagnostics',
      0,
      diagnosticTokens.length,
      diagnosticText,
    );
    filteredCatalog.switching.overview = altered(filteredCatalog.switching.overview, (v) => {
      v.data.selection.effective_vendors = ['arista'];
    });
    const filteredReader = await api.open(virtualFetch, filteredCatalog, index, {
        selected_bytes: 1000,
      }),
      filteredOverview = await filteredReader.switchingOverview(index.generated_at);
    const filteredPage = await filteredReader.switchingDetails(filteredOverview, {
      kind: 'diagnostics',
      limit: 25,
    });
    assert.strictEqual(context.window.InfrastructureJSON.measure(filteredPage), 671);
    assert.deepStrictEqual(JSON.parse(JSON.stringify(filteredPage.items)), [selectedDiagnostic]);
    assert.strictEqual(
      context.window.InfrastructureJSON.measure({
        items: [excludedDiagnostic],
        next_cursor: null,
        total: 1,
      }),
      671,
    );
    assert(context.window.InfrastructureJSON.measure(excludedDiagnostic) > 1000 - 671);

    // Optional detail metadata skips the excluded vendor's token page entirely.
    const savedTokens = diagnosticTokens.slice();
    diagnosticTokens.length = 0;
    encodeDiagnostic(selectedDiagnostic);
    const selectedTokenCount = diagnosticTokens.length;
    diagnosticTokens.length = 0;
    diagnosticTokens.push(...savedTokens);
    const detailRows = [
      {
        ordinal: 0,
        vendor: 'arista',
        range: bound(
          'filtered-diagnostics',
          1,
          1 + selectedTokenCount,
          JSON.stringify(selectedDiagnostic),
        ),
      },
      {
        ordinal: 1,
        vendor: 'cisco',
        range: bound(
          'filtered-diagnostics',
          1 + selectedTokenCount,
          savedTokens.length,
          JSON.stringify(excludedDiagnostic),
        ),
      },
    ];
    const excludedTokens = part('tokens', savedTokens.slice(1 + selectedTokenCount)),
      indexedCatalog = JSON.parse(JSON.stringify(filteredCatalog)),
      indexedRoot = JSON.parse(overlay.get(indexedCatalog.roots['filtered-diagnostics'].path)).data;
    indexedRoot.pages = [
      {
        part: part('tokens', savedTokens.slice(0, 1)),
        first_token: 0,
        count: 1,
        decoded_upper_bound: 3,
      },
      {
        part: part('tokens', savedTokens.slice(1, 1 + selectedTokenCount)),
        first_token: 1,
        count: selectedTokenCount,
        decoded_upper_bound: Buffer.byteLength(JSON.stringify(selectedDiagnostic)),
      },
      {
        part: excludedTokens,
        first_token: 1 + selectedTokenCount,
        count: savedTokens.length - 1 - selectedTokenCount,
        decoded_upper_bound: Buffer.byteLength(JSON.stringify(excludedDiagnostic)),
      },
    ];
    indexedCatalog.roots['filtered-diagnostics'] = part('root', indexedRoot);
    indexedCatalog.switching.detail_indexes = {
      sources: [],
      diagnostics: [
        {
          first: 0,
          count: 2,
          vendors: { arista: 1, cisco: 1 },
          part: part('detail_index', detailRows),
        },
      ],
    };
    const indexedReader = await api.open(
      async (name, options) => {
        assert.notStrictEqual(
          name.replace(/^\//, ''),
          excludedTokens.path,
          'requested diagnostic page must not fetch excluded item tokens',
        );
        return virtualFetch(name, options);
      },
      indexedCatalog,
      index,
      { selected_bytes: 1000 },
    );
    const indexedOverview = await indexedReader.switchingOverview(index.generated_at),
      indexedPage = await indexedReader.switchingDetails(indexedOverview, {
        kind: 'diagnostics',
        limit: 25,
      });
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(indexedPage)),
      JSON.parse(JSON.stringify(filteredPage)),
    );

    // Multiple metadata chunks retain native order and exact filtered totals.
    function indexedArray(name, values, kind) {
      diagnosticTokens.length = 0;
      diagnosticTokens.push([-1, values.length]);
      const rows = [],
        pages = [
          {
            part: part('tokens', [[-1, values.length]]),
            first_token: 0,
            count: 1,
            decoded_upper_bound: values.length + 1,
          },
        ];
      for (let ordinal = 0; ordinal < values.length; ordinal++) {
        const first = diagnosticTokens.length,
          value = values[ordinal];
        encodeDiagnostic(value);
        const end = diagnosticTokens.length,
          text = JSON.stringify(value);
        rows.push({
          ordinal,
          range: bound(name, first, end, text),
          ...(kind === 'diagnostics' ? { vendor: value.vendor } : {}),
        });
        pages.push({
          part: part('tokens', diagnosticTokens.slice(first, end)),
          first_token: first,
          count: end - first,
          decoded_upper_bound: Buffer.byteLength(text),
        });
      }
      const text = JSON.stringify(values),
        whole = bound(name, 0, diagnosticTokens.length, text),
        chunks = [];
      for (let first = 0; first < rows.length; first += 7) {
        const slice = rows.slice(first, first + 7),
          vendors = {};
        if (kind === 'diagnostics')
          for (const row of slice) vendors[row.vendor] = (vendors[row.vendor] || 0) + 1;
        chunks.push({ first, count: slice.length, vendors, part: part('detail_index', slice) });
      }
      return {
        whole,
        chunks,
        pages,
        root: part('root', {
          name,
          token_count: diagnosticTokens.length,
          logical: { bytes: whole.logical_bytes, sha256: whole.logical_sha256 },
          pages,
          ranges: [],
        }),
      };
    }
    const manyDiagnostics = Array.from({ length: 63 }, (_, i) => ({
        vendor: i < 7 || i % 2 === 0 ? 'cisco' : 'arista',
        unknown: ['🚀', String(i)],
      })),
      manySources = Array.from({ length: 63 }, (_, i) => ({
        source: String(i),
        unknown: ['🚀', String(i)],
      }));
    const diagnosticsIndex = indexedArray('page-diagnostics', manyDiagnostics, 'diagnostics'),
      sourcesIndex = indexedArray('page-sources', manySources, 'sources'),
      manyCatalog = JSON.parse(JSON.stringify(indexedCatalog));
    manyCatalog.roots['page-diagnostics'] = diagnosticsIndex.root;
    manyCatalog.roots['page-sources'] = sourcesIndex.root;
    manyCatalog.strings = [{ part: part('strings', atoms), first: 0, count: atoms.length }];
    manyCatalog.shapes = [{ part: part('shapes', layouts), first: 0, count: layouts.length }];
    manyCatalog.switching.diagnostics = diagnosticsIndex.whole;
    manyCatalog.switching.detail_indexes = {
      sources: sourcesIndex.chunks,
      diagnostics: diagnosticsIndex.chunks,
    };
    manyCatalog.switching.overview = altered(manyCatalog.switching.overview, (value) => {
      value.data.detail_ranges.sources = sourcesIndex.whole;
    });
    const forbidden = new Set([
      diagnosticsIndex.chunks[0].part.path,
      ...diagnosticsIndex.pages
        .slice(1)
        .filter((_, i) => manyDiagnostics[i].vendor === 'cisco')
        .map((page) => page.part.path),
    ]);
    const manyReader = await api.open(
        async (name, options) => {
          assert(
            !forbidden.has(name.replace(/^\//, '')),
            'excluded vendor chunks and items stay unread',
          );
          return virtualFetch(name, options);
        },
        manyCatalog,
        index,
        { selected_bytes: 10000 },
      ),
      manyOverview = await manyReader.switchingOverview(index.generated_at),
      legacyManyCatalog = JSON.parse(JSON.stringify(manyCatalog));
    delete legacyManyCatalog.switching.detail_indexes;
    const legacyManyReader = await api.open(virtualFetch, legacyManyCatalog, index, {
        selected_bytes: 10000,
      }),
      legacyManyOverview = await legacyManyReader.switchingOverview(index.generated_at);
    for (const kind of ['diagnostics', 'sources']) {
      const wanted =
        kind === 'sources'
          ? manySources
          : manyDiagnostics.filter((value) => value.vendor === 'arista');
      const seen = [];
      let cursor = null;
      do {
        const request = { kind, cursor, limit: 25 },
          actual = await manyReader.switchingDetails(manyOverview, request),
          legacy = await legacyManyReader.switchingDetails(legacyManyOverview, request);
        assert.strictEqual(
          context.window.InfrastructureJSON.stringify(actual),
          context.window.InfrastructureJSON.stringify(legacy),
        );
        assert.strictEqual(actual.total, wanted.length);
        seen.push(...actual.items);
        cursor = actual.next_cursor;
      } while (cursor !== null);
      assert.deepStrictEqual(JSON.parse(JSON.stringify(seen)), wanted);
    }

    // R2: unresolved cancel must not retain a request slot or poison metadata.
    let unblockCodecCancel;
    const codecCancel = new Promise((resolve) => (unblockCodecCancel = resolve));
    let metadataAttempts = 0,
      metadataReleases = 0,
      slots = 0;
    const recoveringReader = await api.open(
      async (name) => {
        metadataAttempts++;
        if (metadataAttempts === 1)
          return {
            ok: true,
            body: {
              getReader: () => ({
                read: () => new Promise(() => {}),
                cancel: () => codecCancel,
                releaseLock: () => metadataReleases++,
              }),
            },
          };
        return virtualFetch(name);
      },
      short,
      index,
      {
        requestSlots: {
          acquire: async () => {
            slots++;
          },
          release: () => {
            slots--;
          },
        },
      },
    );
    try {
      await assert.rejects(async () => {
        for await (const chunk of recoveringReader.streamRoot('snapshot.json', {
          deadline: Date.now() + 20,
        })) {
        }
      }, /deadline|cancelled/);
      await new Promise((resolve) => setTimeout(resolve, 5));
      assert.strictEqual(
        metadataReleases,
        1,
        'unsettled cancellation still releases metadata reader',
      );
      assert.strictEqual(slots, 0, 'unsettled cancellation still releases request slots');
      await assert.rejects(async () => {
        for await (const chunk of recoveringReader.streamRoot('snapshot.json', {
          deadline: Date.now() + 200,
        })) {
        }
      }, /canonical byte budget/);
      assert(metadataAttempts >= 2, 'retry fetches fresh metadata after unresolved cancel');
    } finally {
      unblockCodecCancel();
    }

    let unblockFacadeCancel;
    const facadeCancel = new Promise((resolve) => (unblockFacadeCancel = resolve));
    const firstCohort = Object.keys(index.cohorts).find((id) => index.cohorts[id].length),
      blockedPart = index.cohorts[firstCohort][0].path;
    let facadeAttempts = 0,
      facadeReleases = 0,
      blockFacade = true;
    const recoveringFacade = await context.createStaticDelivery(async (name) => {
      if (name === blockedPart) {
        facadeAttempts++;
        if (blockFacade)
          return {
            ok: true,
            body: {
              getReader: () => ({
                read: () => new Promise(() => {}),
                cancel: () => facadeCancel,
                releaseLock: () => facadeReleases++,
              }),
            },
          };
      }
      return fetch(name);
    }, '');
    try {
      let timer;
      const failed = await Promise.race([
        recoveringFacade
          .runtimeSnapshot({
            cohort: [firstCohort],
            fields: ['records'],
            deadline: Date.now() + 20,
          })
          .then(
            () => ({ success: true }),
            (error) => ({ error }),
          ),
        new Promise((resolve) => {
          timer = setTimeout(() => resolve({ stuck: true }), 200);
        }),
      ]);
      clearTimeout(timer);
      assert(!failed.stuck, 'facade cleanup cannot await an unsettled cancel');
      assert.match(failed.error.message, /deadline|cancelled/);
      assert.strictEqual(facadeReleases, 1);
      blockFacade = false;
      assert(
        Array.isArray(
          (await recoveringFacade.runtimeSnapshot({ cohort: [firstCohort], fields: ['records'] }))
            .records,
        ),
      );
      assert(facadeAttempts >= 2, 'facade retry starts a fresh transfer');
    } finally {
      unblockFacadeCancel();
    }
    const rejectingBody = (label) => ({
      ok: true,
      body: {
        getReader: () => ({
          read: async () => {
            throw Error('original ' + label + ' read failure');
          },
          cancel: async () => {
            throw Error('cleanup cancellation rejection');
          },
          releaseLock: () => {},
        }),
      },
    });
    const rejectingCodec = await api.open(async () => rejectingBody('codec'), short, index);
    await assert.rejects(async () => {
      for await (const chunk of rejectingCodec.streamRoot('snapshot.json')) {
      }
    }, /original codec read failure/);
    const rejectingFacade = await context.createStaticDelivery(
      async (name) => (name === blockedPart ? rejectingBody('facade') : fetch(name)),
      '',
    );
    await assert.rejects(
      () => rejectingFacade.runtimeSnapshot({ cohort: [firstCohort], fields: ['records'] }),
      /original facade read failure/,
    );
    await new Promise((resolve) => setTimeout(resolve, 0)); // unhandled cancel rejection would fail Node
    console.log('Filtered fitting page and unsettled cancellation retry regressions passed');
    const cohortFields = ['counts', 'vendors'],
      singleMax = Math.max(
        ...cohortFields.map((k) =>
          context.window.InfrastructureJSON.measure({ [k]: bootstrap[k] }),
        ),
      );
    await assert.rejects(
      () =>
        loader.runtimeSnapshot({
          cohort: [Object.keys(index.cohorts)[0]],
          fields: cohortFields,
          max_bytes: singleMax,
        }),
      /budget/,
    );
    const cohortParts = [
      ...new Map(
        Object.values(index.cohorts)
          .flat()
          .map((d) => [d.path, d]),
      ).values(),
    ];
    if (cohortParts.length > 1)
      await assert.rejects(
        () =>
          loader.runtimeSnapshot({
            cohort: Object.keys(index.cohorts),
            fields: ['records'],
            max_bytes: Math.max(...cohortParts.map((d) => d.bytes)) + 160,
          }),
        /budget/,
      );
    console.log(
      'Actual Python v2 publication plus aggregate/declaration/underlying cancellation review regressions passed',
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
// Review regressions: cost before allocation and close owned token cursors.
(async () => {
  assert.strictEqual(
    typeof context.window.InfrastructureJSON.measure,
    'function',
    'bounded JSON cost pass',
  );
  assert.throws(
    () => context.window.InfrastructureJSON.measure({ a: [1, 2, 3] }, null, 2, 20),
    /budget/,
  );
  const value = { a: [1, 2, 3] },
    compact = context.window.InfrastructureJSON.measure(value);
  assert(compact < 20);
  assert.throws(
    () => context.window.InfrastructureJSON.stringifyBounded(value, null, 2, 20),
    /budget/,
  );
  let closed = false;
  async function* owned() {
    try {
      yield -2;
      yield null;
    } finally {
      closed = true;
    }
  }
  await assert.rejects(() => api.decodeTokens(owned(), ['abcdef'], [], { max_bytes: 3 }), /budget/);
  assert(closed, 'overflow closes owned iterator');
  let emitted = '';
  try {
    for await (const chunk of api.streamTokens([null], [], [], { canonical_bytes: 1 }))
      emitted += chunk;
  } catch {}
  assert.strictEqual(emitted, '', 'declared canonical length checked before yield');
  console.log('Review cost, canonical allowance and iterator cleanup regressions passed');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
(async () => {
  const json = context.window.InfrastructureJSON;
  for (const value of [
    { a: ['é', '🚀', '"', '\n', '\ud800'] },
    [null, undefined, 1n],
    {},
    { nested: { a: 1 } },
  ])
    for (const gap of ['', 2, '•'])
      assert.strictEqual(
        json.measure(value, null, gap),
        Buffer.byteLength(json.stringify(value, null, gap)),
      );
  const pool = json.requestPool();
  for (let i = 0; i < 6; i++) await pool.acquire();
  const controller = new AbortController(),
    pending = pool.acquire(controller.signal);
  controller.abort();
  await assert.rejects(() => pending, /cancelled/);
  for (let i = 0; i < 6; i++) pool.release();
  await pool.acquire();
  pool.release();
  let outerClosed = false,
    aliasClosed = false;
  async function* parent() {
    try {
      yield [0];
      yield [1];
      yield [-3, 'switching-evidence.json'];
    } finally {
      outerClosed = true;
    }
  }
  async function* alias() {
    try {
      yield -2;
      yield null;
    } finally {
      aliasClosed = true;
    }
  }
  await assert.rejects(
    () =>
      api.decodeTokens(parent(), ['a'.repeat(100)], [['inputs'], ['evidence']], {
        root: 'switching-comparison.json',
        aliases: () => alias(),
        max_bytes: 30,
      }),
    /budget/,
  );
  assert(outerClosed && aliasClosed, 'failure closes parent and alias iterators');
  let returned = false;
  async function* early() {
    try {
      yield [-1, 1];
      yield null;
    } finally {
      returned = true;
    }
  }
  for await (const chunk of api.streamTokens(early(), [], [])) break;
  assert(returned, 'consumer return closes nested owned iterator');
  console.log('Exact JSON costing, queued cancellation and alias/consumer finalization passed');
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
{
  const json = context.window.InfrastructureJSON;
  for (const raw of [
    ...[
      '{"record_index":0.0}',
      '{"first_token":1e0}',
      '[[-1,1.0]]',
      '{"first_token":9007199254740992}',
    ],
    ...vectors.invalid_transport_json,
  ])
    assert.throws(() => json.parseStrict(raw, { transport: true }), /transport/);
  assert.strictEqual(json.parseStrict('1.0'), 1, 'logical floats remain supported');
  assert.strictEqual(
    json.parseStrict('{"schema_version":2,"data":{"value":1.0}}', {
      transport: (path) => path[0] !== 'data',
    }).data.value,
    1,
  );
  console.log('Raw fractional/exponent transport lexeme rejection passed');
}

// Completed reads must not retain reactions on an operation-long pending promise.
(async () => {
  let peak = 0;
  class TrackedPromise extends Promise {
    constructor(executor) {
      const state = { settled: false, subscriptions: 0 };
      super((resolve, reject) =>
        executor(
          (value) => {
            state.settled = true;
            resolve(value);
          },
          (error) => {
            state.settled = true;
            reject(error);
          },
        ),
      );
      this.trackedState = state;
    }
    then(...args) {
      if (!this.trackedState.settled) peak = Math.max(peak, ++this.trackedState.subscriptions);
      return super.then(...args);
    }
  }
  let activeWaiters = 0,
    peakWaiters = 0;
  class TrackedSet extends Set {
    add(value) {
      if (typeof value === 'function' && !this.has(value)) {
        activeWaiters++;
        peakWaiters = Math.max(peakWaiters, activeWaiters);
      }
      return super.add(value);
    }
    delete(value) {
      if (typeof value === 'function' && this.has(value)) activeWaiters--;
      return super.delete(value);
    }
    clear() {
      for (const value of this) this.delete(value);
    }
  }
  const timers = new Set();
  const isolated = {
    ...context,
    window: {},
    Promise: TrackedPromise,
    Set: TrackedSet,
    setTimeout(fn, delay) {
      const timer = setTimeout(() => {
        timers.delete(timer);
        fn();
      }, delay);
      timers.add(timer);
      return timer;
    },
    clearTimeout(timer) {
      timers.delete(timer);
      clearTimeout(timer);
    },
  };
  vm.createContext(isolated);
  for (const name of ['lossless-json', 'publication-v2'])
    vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), isolated);
  const isolatedApi = isolated.window.InfrastructurePublicationV2;
  for (const count of [32, 2048]) {
    peak = 0;
    let result = '';
    for await (const chunk of isolatedApi.streamTokens(
      [[-1, count], ...Array(count).fill(null)],
      [],
      [],
    ))
      result += chunk;
    assert.strictEqual(result, '[' + Array(count).fill('null').join(',') + ']');
    assert(peak <= 4, `${count} completed reads retained ${peak} subscriptions on one promise`);
    assert(peakWaiters <= 1, 'completed reads release cancellation registrations');
    assert.strictEqual(activeWaiters, 0);
    assert.strictEqual(timers.size, 0, 'completed operation clears its timer');
  }
  const pendingRead = (options = {}, failImmediately = false) => {
    let resolve, reject;
    const read = new TrackedPromise((yes, no) => {
      resolve = yes;
      reject = no;
      if (failImmediately) no(Error('already rejected read'));
    });
    const stream = isolatedApi.streamTokens(
      { [Symbol.asyncIterator]: () => ({ next: () => read }) },
      [],
      [],
      options,
    );
    return { stream, result: stream.next(), resolve, reject };
  };
  for (const ordering of ['reject-abort', 'abort-reject', 'reject-microtask-abort']) {
    const owner = new AbortController();
    const pending = pendingRead({ signal: owner.signal });
    const original = Error('original rejection before cancellation');
    if (ordering === 'abort-reject') owner.abort();
    pending.reject(original);
    if (ordering === 'reject-microtask-abort') await Promise.resolve();
    owner.abort();
    await assert.rejects(
      () => pending.result,
      (error) =>
        ordering === 'abort-reject' ? /cancelled/.test(error.message) : error === original,
      ordering,
    );
    assert.strictEqual(activeWaiters, 0);
  }
  const controller = new AbortController();
  let externalListeners = 0;
  const addListener = controller.signal.addEventListener.bind(controller.signal),
    removeListener = controller.signal.removeEventListener.bind(controller.signal);
  controller.signal.addEventListener = (...args) => {
    externalListeners++;
    return addListener(...args);
  };
  controller.signal.removeEventListener = (...args) => {
    externalListeners--;
    return removeListener(...args);
  };
  const first = pendingRead({ signal: controller.signal });
  const second = pendingRead({ signal: controller.signal });
  assert.strictEqual(activeWaiters, 2, 'concurrent operations own independent active reads');
  controller.abort();
  controller.abort();
  await Promise.all([
    assert.rejects(() => first.result, /cancelled/),
    assert.rejects(() => second.result, /cancelled/),
  ]);
  assert.strictEqual(activeWaiters, 0, 'abort clears all active registrations');
  assert.strictEqual(timers.size, 0, 'abort closes both operation timers');
  assert.strictEqual(externalListeners, 0, 'close removes external abort listeners');
  first.reject(Error('late rejected read'));
  second.resolve({ value: null, done: false });
  await first.stream.return();
  await first.stream.return();
  const failure = Error('original failed read');
  const failed = pendingRead();
  failed.reject(failure);
  await assert.rejects(
    () => failed.result,
    (error) => error === failure,
  );
  assert.strictEqual(activeWaiters, 0, 'failed read unregisters');
  const alreadyAborted = pendingRead({ signal: controller.signal }, true);
  await assert.rejects(() => alreadyAborted.result, /cancelled/);
  const expired = pendingRead({ deadline: 0 }, true);
  await assert.rejects(() => expired.result, /deadline/);
  assert.strictEqual(
    await isolatedApi.decodeTokens(
      [[0], [1], [-3, 'switching-evidence.json']],
      [],
      [['inputs'], ['evidence']],
      { root: 'switching-comparison.json', aliases: () => [[-1, 2], null, null] },
    ),
    '{"inputs":{"evidence":[null,null]}}',
  );
  assert.strictEqual(activeWaiters, 0, 'nested alias completion releases registrations');
  // Move the clock past the deadline while an input read is awaiting settlement.
  let now = Date.now();
  isolated.Date = class extends Date {
    static now() {
      return now;
    }
  };
  // A fulfilled final read must still check cancellation/deadline in the next reaction.
  for (const ordering of ['abort-before', 'abort-after', 'deadline-before', 'deadline-after']) {
    const owner = new AbortController();
    let finish,
      reads = 0;
    const done = new TrackedPromise((resolve) => {
      finish = resolve;
    });
    const stream = isolatedApi.streamTokens(
      {
        [Symbol.asyncIterator]: () => ({
          next: () => (reads++ === 0 ? TrackedPromise.resolve({ value: null, done: false }) : done),
        }),
      },
      [],
      [],
      { signal: owner.signal, deadline: now + 10000 },
    );
    assert.strictEqual((await stream.next()).value, 'null');
    const result = stream.next();
    const interrupt = () => {
      if (ordering.startsWith('abort')) owner.abort();
      else now += 10001;
    };
    if (ordering.endsWith('before')) interrupt();
    finish({ done: true });
    if (ordering.endsWith('after')) queueMicrotask(interrupt);
    await assert.rejects(() => result, ordering.startsWith('abort') ? /cancelled/ : /deadline/);
    assert.strictEqual(activeWaiters, 0);
    assert.strictEqual(timers.size, 0);
  }
  const overdue = pendingRead({ deadline: now + 10000 });
  now += 10001;
  overdue.resolve({ value: null, done: false });
  await assert.rejects(() => overdue.result, /deadline/);
  assert.strictEqual(activeWaiters, 0);
  assert.strictEqual(timers.size, 0);
  await new Promise((resolve) => setTimeout(resolve, 0));
  console.log(
    'Completed token reads retain bounded pending-promise subscriptions and active waiters',
  );
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
