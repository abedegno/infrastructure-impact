// Verify actual published browser code using public inputs only. No native DB or credentials.
// node checks/switching_browser_acceptance.cjs PUBLIC_DIR PROOF_DIR [BASE_PATH] [OUTPUT_JSON]
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
const crypto = require('crypto');
const publicDir = path.resolve(process.argv[2]);
const proofDir = path.resolve(process.argv[3]);
const base = (process.argv[4] || '/infrastructure-impact').replace(/\/$/, '');
const output = process.argv[5] || path.join(proofDir, 'browser-verification.json');
const start = Date.now();
const sha = (value) => crypto.createHash('sha256').update(value).digest('hex');
(async () => {
  const proof = JSON.parse(fs.readFileSync(path.join(proofDir, 'proof.json')));
  assert.strictEqual(proof.analysis_json.path, 'selected-analysis.json');
  const expectedRaw = fs.readFileSync(path.join(proofDir, 'selected-analysis.json'));
  assert.strictEqual(expectedRaw.length, proof.analysis_json.bytes);
  assert.strictEqual(sha(expectedRaw), proof.analysis_json.sha256);
  const expected = JSON.parse(expectedRaw);
  assert.deepStrictEqual(expected.publication, proof.publication);
  assert.strictEqual(expected.generated_at, proof.generated_at);
  const context = {
    window: {},
    TextEncoder,
    TextDecoder,
    URL,
    AbortController,
    crypto: crypto.webcrypto,
    console,
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
    'delivery',
  ])
    vm.runInContext(fs.readFileSync(path.join(publicDir, name + '.js'), 'utf8'), context);
  const reads = [];
  let fetchedBytes = 0;
  const fetch = async (name) => {
    const url = new URL(String(name), 'https://candidate.invalid');
    assert.strictEqual(url.origin, 'https://candidate.invalid', 'no external network');
    let relative = decodeURIComponent(url.pathname);
    if (base && relative.startsWith(base + '/')) relative = relative.slice(base.length);
    relative = relative.replace(/^\//, '');
    const file = path.resolve(publicDir, relative);
    assert(file.startsWith(publicDir + path.sep), 'candidate path containment');
    reads.push(relative);
    if (!fs.existsSync(file)) return { ok: false, status: 404 };
    assert(!fs.lstatSync(file).isSymbolicLink(), 'no candidate symlink');
    const raw = fs.readFileSync(file);
    fetchedBytes += raw.length;
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => raw,
      text: async () => raw.toString(),
    };
  };
  const manifest = JSON.parse(fs.readFileSync(path.join(publicDir, 'publication-v2.json')));
  const descriptor = manifest.roots['switching-analysis.json'];
  assert(descriptor, 'selected profile must publish optional root');
  const loader = await context.createStaticDelivery(fetch, base ? base + '/' : '');
  assert(!reads.includes(descriptor.path), 'bootstrap stays lazy');
  const study = await loader.switchingOverview();
  assert(!reads.includes(descriptor.path), 'default study stays lazy');
  const defaultBytes = fetchedBytes;
  loader.switchingClaims = () => {
    throw Error('forbidden full claim hydration');
  };
  loader.switchingReport = () => {
    throw Error('forbidden full report hydration');
  };
  const actual = await loader.switchingAnalysis(study);
  assert.strictEqual(actual.availability, 'available');
  assert(reads.includes(descriptor.path), 'explicit analysis fetches its root');
  const serialized = JSON.stringify(actual);
  assert.deepStrictEqual(JSON.parse(serialized), expected, 'full native/browser selected JSON');
  const A = context.window.InfrastructureSwitchingAnalysis;
  const analysisCsv = A.csv(actual);
  const upgradesCsv = A.csv(actual, { upgradesOnly: true });
  const checked = {};
  for (const [key, value] of [
    ['analysis_csv', analysisCsv],
    ['upgrades_csv', upgradesCsv],
  ]) {
    const raw = Buffer.from(value, 'utf8');
    assert.strictEqual(raw.length, proof[key].bytes, key + ' byte count');
    assert.strictEqual(sha(raw), proof[key].sha256, key + ' exact hash');
    checked[key] = { bytes: raw.length, sha256: sha(raw) };
  }
  const html = A.render(actual);
  for (const text of [
    'Upgrade estimates',
    'Disclosure eras',
    'Per-model',
    'Independent human review pending',
  ])
    assert(html.includes(text), 'actual analysis render: ' + text);
  const result = {
    verifier_sha256: sha(fs.readFileSync(__filename)),
    status: 'passed',
    publication: actual.publication,
    generated_at: actual.generated_at,
    profile: proof.profile,
    full_selected_json_structural_parity: true,
    csv: checked,
    bootstrap_and_study_analysis_lazy: true,
    full_claim_hydration: false,
    analysis_render_contract: true,
    visual_browser_review_completed: false,
    default_fetch_bytes: defaultBytes,
    total_fetch_bytes: fetchedBytes,
    read_count: reads.length,
    elapsed_seconds: (Date.now() - start) / 1000,
    peak_resident_bytes: process.resourceUsage().maxRSS * 1024,
  };
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result));
})().catch((error) => {
  // Only sanitized public artifacts are read; no source bodies or private values in errors.
  console.error(error.stack);
  process.exitCode = 1;
});
