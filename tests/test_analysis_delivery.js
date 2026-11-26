// Native-generated vendor envelopes against the complete public oracle.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert'),
  child = require('child_process');
const context = { window: {}, console, URL, TextEncoder, TextDecoder };
vm.createContext(context);
for (const name of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'customer-comparison',
  'switching-analysis',
])
  vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
const A = context.window.InfrastructureSwitchingAnalysis;
const vectors = JSON.parse(fs.readFileSync('tests/fixtures/switching-analysis-vectors.json'));
const envelopes = JSON.parse(
  child.execFileSync(
    '.venv/bin/python',
    [
      '-c',
      `import json
from infrastructure_impact.application.analysis_delivery import project_vendor, VENDORS
v=json.load(open('tests/fixtures/switching-analysis-vectors.json'))
print(json.dumps({k:project_vendor(v['compiled'],k) for k in VENDORS}))`,
    ],
    { encoding: 'utf8', env: { ...process.env, TZ: 'UTC' } },
  ),
);
for (const [vendor, envelope] of Object.entries(envelopes)) {
  const select = A.prepareVendor(envelope, vectors.compiled);
  assert(Object.isFrozen(envelope.payload.requirements));
  for (const c of vectors.cases) {
    const study = A.context(vectors.compiled, { ...c.options, vendor });
    const actual = select(study),
      expected = A.select(vectors.compiled, study);
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(actual)),
      JSON.parse(JSON.stringify(expected)),
    );
    assert.strictEqual(A.csv(actual), A.csv(expected));
    assert.strictEqual(
      A.csv(actual, { upgradesOnly: true }),
      A.csv(expected, { upgradesOnly: true }),
    );
  }
  assert.throws(() => select(A.context(vectors.compiled, {})), /vendor/i);
}
const changed = JSON.parse(JSON.stringify(envelopes.cisco));
changed.payload.requirements.requirements[0].target = '99.99.99';
assert.throws(() => A.prepareVendor(changed, vectors.compiled), /fingerprint/i);
console.log('Vendor projection exact JSON and both CSV exports passed');

(async () => {
  const os = require('os'),
    path = require('path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-vendor-'));
  try {
    child.execFileSync(
      '.venv/bin/python',
      [
        '-c',
        `import json,sys
sys.path.insert(0,'tests')
from test_static_delivery import dataset
from infrastructure_impact.application import publication
x=dataset()
x['publication']={'id':'a'*32,'advisory_schema_version':2}
x['current_evidence']['publication']=x['publication']
x['research']['switching_input']=json.load(open('tests/fixtures/switching-cases.json'))['evidence']
p=publication.public_projection(x,publication_format='v2',include_switching_analysis=True)
publication.write_bundle(sys.argv[1],p,publication_format='v2',analysis_vendor_delivery=True)`,
        dir,
      ],
      { env: { ...process.env, TZ: 'UTC' }, stdio: ['ignore', 'pipe', 'pipe'] },
    );
    Object.assign(context, {
      crypto: require('crypto').webcrypto,
      AbortController,
      setTimeout,
      clearTimeout,
    });
    vm.runInContext(
      fs.readFileSync('infrastructure_impact/web/publication-v2.js', 'utf8'),
      context,
    );
    const catalog = JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json'))),
      index = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json'))),
      reads = [];
    const fetch = async (name) => {
      reads.push(name);
      const raw = fs.readFileSync(path.join(dir, name.replace(/^\//, '')));
      return {
        ok: true,
        status: 200,
        arrayBuffer: async () => raw,
        text: async () => raw.toString(),
      };
    };
    const open = (cat) => context.window.InfrastructurePublicationV2.open(fetch, cat, index);
    const loader = await open(catalog),
      overview = await loader.switchingOverview();
    const manifestName = 'switching-analysis-delivery.json',
      vendorName = 'switching-analysis-vendor-cisco.json',
      fullName = 'switching-analysis.json';
    assert(!reads.includes(catalog.roots[manifestName].path), 'bootstrap remains lazy');
    const fullNative = JSON.parse(
      child.execFileSync(
        '.venv/bin/python',
        [
          '-c',
          `import json,sys
from infrastructure_impact.application.publication_reader import PublicationReader
r=PublicationReader(sys.argv[1]);print(json.dumps(r.materialize_range(r.ranges('switching-analysis.json')[()])))`,
          dir,
        ],
        { encoding: 'utf8', env: { ...process.env, TZ: 'UTC' } },
      ),
    );
    const study = A.context(fullNative, { vendor: 'cisco', window: '2025' });
    const selected = await loader.switchingAnalysis(study);
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(selected)),
      JSON.parse(JSON.stringify(A.select(fullNative, study))),
    );
    assert(
      reads.includes(catalog.roots[manifestName].path),
      'explicit vendor reads delivery manifest',
    );
    assert(reads.includes(catalog.roots[vendorName].path), 'explicit vendor reads projection');
    assert(!reads.includes(catalog.roots[fullName].path), 'vendor avoids full root');
    const after = reads.length;
    await loader.switchingAnalysis(study);
    assert.strictEqual(reads.length, after, 'repeat preparation is cached');
    await assert.rejects(() => loader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
    const missing = JSON.parse(JSON.stringify(catalog));
    delete missing.roots[vendorName];
    const bad = await open(missing);
    await assert.rejects(() => bad.switchingAnalysis(study), /root|vendor|delivery/i);
    const legacy = JSON.parse(JSON.stringify(catalog));
    delete legacy.roots[manifestName];
    const fallback = await open(legacy);
    assert.deepStrictEqual(
      JSON.parse(JSON.stringify(await fallback.switchingAnalysis(study))),
      JSON.parse(JSON.stringify(selected)),
    );
    const all = await loader.switchingAnalysis(A.context(fullNative, {}));
    assert.strictEqual(all.availability, 'available');
    assert(reads.includes(catalog.roots[fullName].path), 'all vendors retains legacy full root');
    const cases = [
      [
        'ceiling',
        async () => {
          for (const cat of [catalog, legacy]) {
            const bounded = await context.window.InfrastructurePublicationV2.open(
              fetch,
              cat,
              index,
              { selected_bytes: 1 },
            );
            await assert.rejects(
              () => bounded.switchingAnalysis(study, { max_bytes: 128000000 }),
              /budget/i,
            );
          }
          await assert.rejects(() => loader.switchingAnalysis(study, { max_bytes: 1 }), /budget/i);
        },
      ],
      [
        'cutoff',
        async () => {
          const mixed = { ...study, observation_end: '2025-01-05' };
          await assert.rejects(
            () => loader.switchingAnalysis(mixed),
            /observation|identity|cutoff/i,
          );
          await assert.rejects(
            () => fallback.switchingAnalysis(mixed),
            /observation|identity|cutoff/i,
          );
          assert.throws(() => A.select(fullNative, mixed), /observation|identity|cutoff/i);
        },
      ],
      [
        'budget-race',
        async () => {
          for (const smallFirst of [true, false]) {
            const fresh = await open(catalog),
              small = () => fresh.switchingAnalysis(study, { max_bytes: 1 }),
              ordinary = () => fresh.switchingAnalysis(study),
              results = await Promise.allSettled(
                smallFirst ? [small(), ordinary()] : [ordinary(), small()],
              );
            assert.strictEqual(results[smallFirst ? 0 : 1].status, 'rejected');
            assert.strictEqual(
              results[smallFirst ? 1 : 0].status,
              'fulfilled',
              'one request budget must not reject another caller',
            );
          }
        },
      ],
      [
        'last-waiter',
        async () => {
          let enter,
            release,
            observeAbort,
            paused = false;
          const entered = new Promise((r) => {
              enter = r;
            }),
            gate = new Promise((r) => {
              release = r;
            }),
            aborted = new Promise((r) => {
              observeAbort = r;
            }),
            delayed = async (name, options) => {
              if (name === catalog.roots[manifestName].path && !paused) {
                paused = true;
                options.signal.addEventListener('abort', observeAbort, { once: true });
                enter();
                await gate;
              }
              return fetch(name, options);
            },
            fresh = await context.window.InfrastructurePublicationV2.open(delayed, catalog, index),
            controller = new AbortController(),
            result = fresh.switchingAnalysis(study, { signal: controller.signal }).then(
              () => 'fulfilled',
              () => 'rejected',
            );
          await entered;
          controller.abort();
          assert.strictEqual(await result, 'rejected');
          let timer;
          try {
            await Promise.race([
              aborted,
              new Promise((_, reject) => {
                timer = setTimeout(() => reject(Error('Last waiter left transport running')), 5000);
              }),
            ]);
          } finally {
            clearTimeout(timer);
            release();
          }
          assert.strictEqual((await fresh.switchingAnalysis(study)).availability, 'available');
        },
      ],
      [
        'transport-retry',
        async () => {
          let failed = false;
          const transient = async (name, options) => {
              if (name === catalog.roots[manifestName].path && !failed) {
                failed = true;
                return { ok: false, status: 503 };
              }
              return fetch(name, options);
            },
            fresh = await context.window.InfrastructurePublicationV2.open(
              transient,
              catalog,
              index,
            );
          await assert.rejects(() => fresh.switchingAnalysis(study), /part unavailable/i);
          assert.strictEqual((await fresh.switchingAnalysis(study)).availability, 'available');
        },
      ],
      [
        'cancel-race',
        async () => {
          for (const pausedPath of [
            catalog.roots[manifestName].path,
            catalog.roots[vendorName].path,
          ]) {
            let enter,
              release,
              paused = false;
            const entered = new Promise((r) => {
                enter = r;
              }),
              gate = new Promise((r) => {
                release = r;
              }),
              delayed = async (name, options) => {
                if (name === pausedPath && !paused) {
                  paused = true;
                  enter();
                  await gate;
                }
                return fetch(name, options);
              },
              fresh = await context.window.InfrastructurePublicationV2.open(
                delayed,
                catalog,
                index,
              ),
              controller = new AbortController(),
              first = fresh.switchingAnalysis(study, { signal: controller.signal });
            // Attach rejection handlers before cancellation to avoid an artificial unhandled rejection.
            const firstResult = first.then(
              () => 'fulfilled',
              () => 'rejected',
            );
            await entered;
            const otherStudy =
                pausedPath === catalog.roots[manifestName].path
                  ? A.context(fullNative, { vendor: 'aruba' })
                  : study,
              second = fresh.switchingAnalysis(otherStudy),
              both = Promise.allSettled([first, second]);
            controller.abort();
            release();
            const results = await both;
            assert.strictEqual(await firstResult, 'rejected');
            assert.strictEqual(
              results[1].status,
              'fulfilled',
              'one cancelled waiter must not cancel the healthy caller',
            );
            assert.strictEqual((await fresh.switchingAnalysis(study)).availability, 'available');
          }
        },
      ],
    ];
    for (const [name, run] of cases)
      if (!process.env.REVIEW_CASE || process.env.REVIEW_CASE === name) await run();

    console.log(
      'Opt-in vendor lazy transport, cache, budgets and absent-manifest compatibility passed',
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});

// Caller-owned hashes cannot replace the manifest's native closure commitment.
{
  const C = context.window.InfrastructureSwitchingContracts;
  const hash = (v) => C.fingerprint(v);
  const rehash = (v) => {
    delete v.content_sha256;
    v.content_sha256 = hash(v);
  };
  const empty = JSON.parse(JSON.stringify(envelopes.aruba));
  // The authored vectors may contain Aruba facts, so use an independently
  // well-formed vendor payload and relabel it to exercise explicit domain guards.
  empty.vendor = 'cisco';
  rehash(empty);
  assert.throws(
    () =>
      A.prepareVendor(empty, vectors.compiled, {
        content_sha256: envelopes.cisco.content_sha256,
        source_content_sha256: envelopes.cisco.source_content_sha256,
        counts: envelopes.cisco.counts,
      }),
    /advertised|vendor/i,
  );
  const bad = JSON.parse(JSON.stringify(envelopes.cisco));
  bad.counts.claims++;
  rehash(bad);
  assert.throws(() => A.prepareVendor(bad, vectors.compiled), /counts/i);
  const getters = JSON.parse(JSON.stringify(envelopes.cisco));
  Object.defineProperty(getters, 'payload', {
    get() {
      throw Error('getter executed');
    },
    enumerable: true,
  });
  assert.throws(() => A.prepareVendor(getters, vectors.compiled), /owned JSON data/i);
}

// Nonempty authored coverage for every vendor, source/inference groups, full
// release history and mapped/unmapped KEV entries (the older vectors are sparse).
{
  const rich = JSON.parse(
    child.execFileSync(
      '.venv/bin/python',
      [
        '-c',
        `import json,sys
sys.path.insert(0,'tests')
from test_analysis_delivery import rich_source
from infrastructure_impact.application.analysis_delivery import project_vendor,VENDORS
full=rich_source()
print(json.dumps(dict(full=full,envelopes={v:project_vendor(full,v) for v in VENDORS})))`,
      ],
      { encoding: 'utf8', env: { ...process.env, TZ: 'UTC' }, maxBuffer: 16000000 },
    ),
  );
  const fullSelect = A.prepare(rich.full);
  for (const [vendor, envelope] of Object.entries(rich.envelopes)) {
    const select = A.prepareVendor(envelope, rich.full);
    for (const scope_level of ['os_family', 'model_qualified'])
      for (const window of ['all', 'pre', 'post', 'undated', '2021', '2024', '2025', '2026'])
        for (const cve_ids of [null, [], ['CVE-2026-7473']]) {
          const study = A.context(rich.full, { vendor, scope_level, window, cve_ids }),
            actual = select(study),
            expected = fullSelect(study);
          assert.deepStrictEqual(
            JSON.parse(JSON.stringify(actual)),
            JSON.parse(JSON.stringify(expected)),
          );
          assert.strictEqual(A.csv(actual), A.csv(expected));
          assert.strictEqual(
            A.csv(actual, { upgradesOnly: true }),
            A.csv(expected, { upgradesOnly: true }),
          );
        }
  }
  console.log(
    'Rich vendor closure JSON/two-CSV parity includes history, source/inference groups and global unmapped KEV',
  );
}
