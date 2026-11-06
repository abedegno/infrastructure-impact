// Literal identity and strict generation contracts, including older browser fallback.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const { webcrypto, createHash } = require('crypto');
const web = 'infrastructure_impact/web/';
function context() {
  const c = {
    window: {},
    URL,
    Response,
    Blob,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    crypto: webcrypto,
  };
  vm.createContext(c);
  for (const f of [
    'lossless-json.js',
    'switching-contracts.js',
    'current-evidence.js',
    'kev.js',
    'research-dossiers.js',
    'delivery.js',
    'snapshot.js',
  ])
    if (fs.existsSync(web + f)) vm.runInContext(fs.readFileSync(web + f, 'utf8'), c);
  return c;
}
function fixture() {
  const publication = { id: 'a'.repeat(32), advisory_schema_version: 2 },
    generated_at = '2026-11-06T00:00:00Z';
  const target = {
    vendor: 'arista',
    advisory_id: 'EXCLUDED',
    revision_id: 9007199254740993n,
    source_url: 'https://example.test/alternate',
    sha256: 'b'.repeat(64),
  };
  const policy = {
    vendor: 'arista',
    policy_id: 'reviewed',
    version: '1',
    fingerprint: 'c'.repeat(64),
    reason_text: 'Reviewed representation scope conflict',
  };
  const decision = {
    decision_id: 'd'.repeat(64),
    vendor: 'arista',
    policy_id: 'reviewed',
    policy_version: '1',
    policy_fingerprint: policy.fingerprint,
    target_key: 'e'.repeat(64),
    disposition: 'excluded_from_current',
    reason: 'reviewed_representation_scope_conflict',
    reason_text: policy.reason_text,
    target,
    proofs: [
      {
        source_url: 'https://example.test/primary',
        source_sha256: 'f'.repeat(64),
        evidence_id: 1,
        source_observed_at: generated_at,
        locator: 'Synthetic proof',
      },
    ],
  };
  const report = {
    schema_version: 1,
    availability: 'available',
    publication,
    generated_at,
    policies: [policy],
    decisions: [decision],
    issues: [],
    counts: { current: 0, excluded: 1, retained_total: 1 },
  };
  const record = {
    ...target,
    cves: ['CVE-2023-5501'],
    assessments: [
      {
        cve_id: 'CVE-2023-5501',
        product: '=OLD()',
        status: 'affected',
        scope: 'cve_specific',
        versions: [],
        remediations: [],
      },
    ],
  };
  return {
    publication,
    generated_at,
    current_evidence: report,
    retained_advisories: [
      {
        record,
        decision_id: decision.decision_id,
        target_key: decision.target_key,
        record_scope: 'retained_latest_excluded',
      },
    ],
    records: [],
    vendors: { arista: 'Arista' },
    all_cves: [],
    benchmark_cohort: { 'CVE-2023-5501': 'Synthetic' },
    coverage: [],
    changes: [],
    timeline: { events: [] },
    scorecards: { vendors: [] },
  };
}
function bundle(s) {
  const json = context().window.InfrastructureJSON;
  const files = new Map(),
    identity = { schema_version: 1, publication: s.publication, generated_at: s.generated_at };
  const part = (data) => {
    const raw = json.stringify({ ...identity, data }) + '\n',
      sha256 = createHash('sha256').update(raw).digest('hex'),
      path = 'data/' + sha256 + '.json';
    files.set('/' + path, raw);
    return { path, sha256, bytes: Buffer.byteLength(raw) };
  };
  const { retained_advisories, current_evidence, ...common } = s;
  common.current_evidence_version = 1;
  common.retained_index = retained_advisories.map((w) => ({
    decision_id: w.decision_id,
    vendor: w.record.vendor,
    cves: w.record.cves,
    assessments: w.record.assessments.map((a) => ({
      cve_id: a.cve_id,
      product: a.product,
      status: a.status,
      search_text: a.product,
    })),
  }));
  const retained = part(retained_advisories),
    report = part(current_evidence);
  const index = {
    ...identity,
    bootstrap: part(common),
    cohorts: { 'CVE-2023-5501': [] },
    changes: [],
    full: { path: 'snapshot.json', sha256: 'a'.repeat(64), bytes: 1 },
    current_evidence: {
      schema_version: 1,
      report,
      retained: [
        {
          decision_ids: [current_evidence.decisions[0].decision_id],
          cve_ids: ['CVE-2023-5501'],
          part: retained,
        },
      ],
    },
  };
  files.set('/data/index.json', json.stringify(index));
  return { files, index, report, retained };
}
function rewriteBootstrap(b, mutate) {
  const json = context().window.InfrastructureJSON;
  const value = json.parse(b.files.get('/' + b.index.bootstrap.path));
  mutate(value.data);
  const raw = json.stringify(value) + '\n',
    sha256 = createHash('sha256').update(raw).digest('hex');
  b.index.bootstrap = { path: 'data/' + sha256 + '.json', sha256, bytes: Buffer.byteLength(raw) };
  b.files.set('/' + b.index.bootstrap.path, raw);
  b.files.set('/data/index.json', json.stringify(b.index));
}
module.exports = { context, fixture, bundle, rewriteBootstrap };
if (require.main === module) {
  const c = context(),
    api = c.window.InfrastructureCurrentEvidence;
  assert(api, 'current-evidence validator must be available');
  const json = c.window.InfrastructureJSON;
  const source = json.parse(json.stringify(fixture()));
  assert.strictEqual(source.retained_advisories[0].record.revision_id, 9007199254740993n);
  assert(json.stringify(json.clone(source)).includes('9007199254740993'));
  for (const token of ['1.0', '1e0', '9007199254740993.0'])
    assert.throws(() => json.parse('{"revision_id":' + token + '}'), /identity/i);
  for (const revision of [true, 1, '9007199254740993', 9007199254740992n]) {
    const bad = json.clone(source);
    bad.retained_advisories[0].record.revision_id = revision;
    assert.throws(() => api.validatePartition(bad), /identity|target/i);
  }
  api.validatePartition(source);
  const unicode = json.clone(source);
  unicode.current_evidence.decisions[0].proofs = ['\ue000', '😀'].map((locator) => ({
    ...unicode.current_evidence.decisions[0].proofs[0],
    locator,
  }));
  c.validateCurrentEvidence(unicode.current_evidence, unicode.publication, unicode.generated_at);
  const dossier = {
    vendors: { arista: 'Arista' },
    dossiers: [
      {
        id: 'synthetic',
        cve_id: 'CVE-2023-5501',
        scope: {},
        comparison_targets: [],
        disclosure_context: [],
        evidence_gaps: [],
        sources: [{ id: 'source', vendor: 'arista', evidence_id: 9007199254740993n }],
        chronology: { events: [{ source_id: 'source' }] },
      },
    ],
  };
  assert.strictEqual(
    c.window.ResearchDossiers.select(dossier, ['CVE-2023-5501']).dossiers[0].sources[0].evidence_id,
    9007199254740993n,
  );
  assert(
    json
      .stringify(c.window.ResearchDossiers.downloadPayload(dossier, 'synthetic'))
      .includes('9007199254740993'),
  );
  const chosen = c.selectRetainedSnapshot(source, ['CVE-2023-5501'], { vendor: 'arista' });
  const exported = c.exportRetainedSnapshot(chosen);
  assert.strictEqual(exported.records.length, 1);
  assert.strictEqual(exported.records[0].assessments[0].record_scope, 'retained_latest_excluded');
  assert(c.retainedSnapshotCSV(chosen).includes("'=OLD()"));
  assert(
    !json
      .stringify(c.exportSnapshot({ ...source, comparison: { cohort: ['CVE-2023-5501'] } }))
      .includes('=OLD()'),
  );
  assert.strictEqual(
    c.exportRetainedSnapshot(c.selectRetainedSnapshot(source, [])).records.length,
    0,
  );
  function test_mixed_generation_decision_report_is_rejected() {
    const bad = json.clone(source);
    bad.current_evidence.publication.id = '0'.repeat(32);
    assert.throws(
      () => c.validateCurrentEvidence(bad.current_evidence, bad.publication, bad.generated_at),
      /generation|publication/i,
    );
  }
  test_mixed_generation_decision_report_is_rejected();
  for (const mutate of [
    (s) => (s.retained_advisories = []),
    (s) => (s.retained_advisories[0].decision_id = '0'.repeat(64)),
    (s) => (s.current_evidence.decisions[0].target.revision_id = true),
    (s) => (s.current_evidence.extra = true),
  ]) {
    const bad = json.clone(source);
    mutate(bad);
    assert.throws(() => api.validatePartition(bad));
  }
  // No dependency on reviver context.source or JSON.rawJSON: older engines use the same parser.
  const fallback = context();
  vm.runInContext('JSON.rawJSON = undefined', fallback);
  assert.strictEqual(
    fallback.window.InfrastructureJSON.parse('{"revision_id":9007199254740993}').revision_id,
    9007199254740993n,
  );
  (async () => {
    for (const fault of ['missing-marker', 'marker-version', 'marker-null', 'capability-version']) {
      const b = bundle(json.clone(source)),
        requests = [];
      if (fault === 'capability-version') {
        b.index.current_evidence.schema_version = 2;
        b.files.set('/data/index.json', json.stringify(b.index));
      } else
        rewriteBootstrap(b, (common) => {
          if (fault === 'missing-marker') delete common.current_evidence_version;
          else common.current_evidence_version = fault === 'marker-null' ? null : 2;
        });
      const load = await c.createStaticDelivery(async (path) => {
        requests.push(path);
        return new Response(b.files.get(path));
      }, '/');
      await assert.rejects(() => load([]), undefined, fault + ' must reject before report load');
      assert(!requests.includes('/' + b.report.path), fault + ' must fail before reading report');
      assert(!requests.includes('/' + b.retained.path), 'marker failure must not hydrate records');
    }
    for (const fault of [
      'route-omission',
      'route-misrouting',
      'missing-summary',
      'duplicate-summary',
      'unknown-summary-decision',
      'summary-vendor',
      'summary-cve',
      'duplicate-summary-cve',
      'oversized-summary',
    ]) {
      const b = bundle(json.clone(source)),
        requests = [];
      if (fault.startsWith('route-')) {
        b.index.current_evidence.retained[0].cve_ids =
          fault === 'route-omission' ? [] : ['CVE-2024-6858'];
        b.files.set('/data/index.json', json.stringify(b.index));
      } else
        rewriteBootstrap(b, (common) => {
          if (fault === 'missing-summary') common.retained_index = [];
          if (fault === 'duplicate-summary') common.retained_index.push(common.retained_index[0]);
          if (fault === 'unknown-summary-decision')
            common.retained_index[0].decision_id = '0'.repeat(64);
          if (fault === 'summary-vendor') common.retained_index[0].vendor = 'cisco';
          if (fault === 'summary-cve') common.retained_index[0].cves = ['CVE-2024-6858'];
          if (fault === 'duplicate-summary-cve')
            common.retained_index[0].cves.push('CVE-2023-5501');
          if (fault === 'oversized-summary')
            common.retained_index = Array(1001).fill(common.retained_index[0]);
        });
      const load = await c.createStaticDelivery(async (path) => {
        requests.push(path);
        return new Response(b.files.get(path));
      }, '/');
      await assert.rejects(() => load([]), undefined, fault + ' must fail before routing');
      await assert.rejects(
        () => load.retained(['CVE-2023-5501']),
        undefined,
        fault + ' must not return an empty success',
      );
      assert(
        !requests.includes('/' + b.retained.path),
        'routing validation must preserve lazy record loading',
      );
    }
    for (const fault of [
      null,
      'missing',
      'digest',
      'generation',
      'omission',
      'reference',
      'decision-reference',
      'retained-generation',
      'retained-omission',
    ]) {
      let s = json.clone(source);
      if (fault === 'generation') s.current_evidence.generated_at = '2026-11-05T00:00:00Z';
      if (fault === 'reference') s.retained_advisories[0].target_key = '0'.repeat(64);
      if (fault === 'decision-reference') s.retained_advisories[0].decision_id = '0'.repeat(64);
      if (fault === 'retained-omission') s.retained_advisories = [];
      const b = bundle(s);
      if (fault === 'retained-generation') {
        const raw = b.files
          .get('/' + b.retained.path)
          .replace(s.generated_at, '2026-11-05T00:00:00Z');
        const sha256 = createHash('sha256').update(raw).digest('hex');
        const part = { path: 'data/' + sha256 + '.json', sha256, bytes: Buffer.byteLength(raw) };
        b.index.current_evidence.retained[0].part = part;
        b.files.set('/' + part.path, raw);
        b.files.set('/data/index.json', json.stringify(b.index));
      }
      if (fault === 'omission') {
        b.index.current_evidence.retained = [];
        b.files.set('/data/index.json', json.stringify(b.index));
      }
      const requests = [];
      const fetch = async (path) => {
        requests.push(path);
        let raw = b.files.get(path);
        if (path === '/' + b.report.path && fault === 'missing')
          return new Response('', { status: 404 });
        if (path === '/' + b.report.path && fault === 'digest') raw += ' ';
        return new Response(raw ?? '', { status: raw === undefined ? 404 : 200 });
      };
      const load = await c.createStaticDelivery(fetch, '/');
      if (fault)
        await assert.rejects(async () => {
          await load(['CVE-2023-5501']);
          await load.retained(['CVE-2023-5501']);
        });
      else {
        const first = await load(['CVE-2023-5501']);
        assert(!requests.includes('/' + b.retained.path), 'default load must remain lazy');
        first.retained_advisories = await load.retained(['CVE-2023-5501']);
        assert.strictEqual(first.retained_advisories[0].record.revision_id, 9007199254740993n);
        first.retained_advisories[0].record.revision_id = 'mutated';
        const second = await load(['CVE-2023-5501']);
        second.retained_advisories = await load.retained(['CVE-2023-5501']);
        assert.strictEqual(second.retained_advisories[0].record.revision_id, 9007199254740993n);
        assert.strictEqual(requests.length, new Set(requests).size);
      }
    }
    const installed = context(),
      apiBundle = bundle(json.clone(source));
    installed.window.fetch = async (path) =>
      new Response(apiBundle.files.get(path) ?? '', {
        status: apiBundle.files.has(path) ? 200 : 404,
      });
    installed.document = { baseURI: 'https://example.test/', addEventListener() {} };
    installed.location = { origin: 'https://example.test' };
    vm.runInContext(fs.readFileSync(web + 'snapshot.js', 'utf8'), installed);
    for (const endpoint of [
      '/api/v1/current-evidence',
      '/api/v1/retained-advisories?format=json',
    ]) {
      const get = await installed.window.fetch(endpoint);
      const text = await get.text();
      const head = await installed.window.fetch(endpoint, { method: 'HEAD' });
      assert.strictEqual(head.status, 200);
      assert.strictEqual(await head.text(), '');
      assert.strictEqual(Number(head.headers.get('Content-Length')), Buffer.byteLength(text));
      assert(text.includes('9007199254740993'));
      assert.strictEqual((await installed.window.fetch(endpoint, { method: 'POST' })).status, 405);
    }
    const empty = bundle(json.clone(source));
    const emptyLoad = await c.createStaticDelivery(
      async (path) =>
        new Response(empty.files.get(path) ?? '', { status: empty.files.has(path) ? 200 : 404 }),
      '/',
    );
    assert.strictEqual(
      (await emptyLoad([])).records.length,
      0,
      'empty selection must not hydrate the archive',
    );
    delete empty.index.current_evidence;
    empty.files.set('/data/index.json', json.stringify(empty.index));
    const missingCapability = await c.createStaticDelivery(
      async (path) => new Response(empty.files.get(path)),
      '/',
    );
    await assert.rejects(() => missingCapability([]), /capability/);
    const legacyCommon = { ...fixture() };
    delete legacyCommon.current_evidence;
    delete legacyCommon.retained_advisories;
    const legacy = bundle(json.clone(source));
    const bootstrapRaw =
      json.stringify({
        schema_version: 1,
        publication: source.publication,
        generated_at: source.generated_at,
        data: legacyCommon,
      }) + '\n';
    const digest = createHash('sha256').update(bootstrapRaw).digest('hex');
    legacy.index.bootstrap = {
      path: 'data/' + digest + '.json',
      sha256: digest,
      bytes: Buffer.byteLength(bootstrapRaw),
    };
    delete legacy.index.current_evidence;
    legacy.files.set('/' + legacy.index.bootstrap.path, bootstrapRaw);
    legacy.files.set('/data/index.json', json.stringify(legacy.index));
    const legacyLoad = await c.createStaticDelivery(
      async (path) => new Response(legacy.files.get(path)),
      '/',
    );
    assert.strictEqual((await legacyLoad([])).current_evidence.counts.excluded, null);
    const noBigInt = context();
    vm.runInContext('BigInt=undefined', noBigInt);
    assert.throws(
      () => noBigInt.window.InfrastructureJSON.parse('{"revision_id":9007199254740993}'),
      /unsupported/,
    );
    console.log('current evidence identity/transport contracts passed');
  })().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
