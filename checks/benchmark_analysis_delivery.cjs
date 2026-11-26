// Run once per fresh process against a locally cached public v2 publication.
// Usage: node checks/benchmark_analysis_delivery.cjs WEB DIR LABEL OUT CONTEXTS
// Reports metadata and export fingerprints; never writes into its input trees.
const fs = require('fs'),
  vm = require('vm'),
  path = require('path'),
  crypto = require('crypto');
const [web, dir, mode, out, contexts] = process.argv.slice(2);
if (!contexts) throw Error('web dir label out contexts required');
const inputDir = fs.realpathSync(dir),
  webDir = fs.realpathSync(web),
  output = path.join(fs.realpathSync(path.dirname(path.resolve(out))), path.basename(out));
if (
  fs.existsSync(output) ||
  [inputDir, webDir].some((d) => output === d || output.startsWith(d + path.sep))
)
  throw Error('Output must be new and outside input directories');
const read = (n) => {
  const target = fs.realpathSync(path.resolve(inputDir, n));
  if (!target.startsWith(inputDir + path.sep) || fs.statSync(target).size > 8000000)
    throw Error('Public part path or byte bound');
  return fs.readFileSync(target);
};
global.window = global;
for (const n of [
  'lossless-json',
  'kev',
  'switching-contracts',
  'switching',
  'customer-comparison',
  'switching-analysis',
  'analysis-packing',
  'publication-v2',
]) {
  const file = path.join(web, n + '.js');
  if (fs.existsSync(file))
    vm.runInThisContext(fs.readFileSync(file, 'utf8'), { filename: n + '.js' });
}
const J = InfrastructureJSON,
  A = InfrastructureSwitchingAnalysis;
const result = {
  mode,
  kind: 'matched_sequential_fresh_node_process_cached_public_parts',
  publication: null,
  node: process.version,
  platform: process.platform,
  requests: 0,
  received_bytes: 0,
  phases: {},
  outputs: {},
};
const fetch = async (n) => {
  const b = read(n);
  result.requests++;
  result.received_bytes += b.length;
  return new Response(b);
};
const parse = (n) => J.parseStrict(read(n).toString('utf8'));
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const timed = async (name, f) => {
  const start = performance.now(),
    v = await f();
  result.phases[name] = {
    seconds: (performance.now() - start) / 1000,
    requests: result.requests,
    received_bytes: result.received_bytes,
    rss_bytes: process.memoryUsage().rss,
    peak_resident_bytes: process.resourceUsage().maxRSS * 1024,
  };
  console.log(name, JSON.stringify(result.phases[name]));
  return v;
};
(async () => {
  const index = parse('data/index.json'),
    descriptor = index.publication_v2,
    catalogBytes = read(descriptor.path),
    catalogSha = sha(catalogBytes);
  if (catalogBytes.length !== descriptor.bytes || catalogSha !== descriptor.sha256)
    throw Error('Catalog descriptor fingerprint or size mismatch');
  const catalog = J.parseStrict(catalogBytes.toString('utf8')),
    packed = Object.hasOwn(catalog.roots, 'switching-analysis-packed.json');
  if ((mode === 'baseline' && packed) || (mode === 'packed' && !packed))
    throw Error('Catalog analysis roots do not match the requested ' + mode + ' variant');
  result.publication = index.publication;
  result.generated_at = index.generated_at;
  result.catalog_sha256 = catalogSha;
  result.catalog_analysis_roots = Object.keys(catalog.roots)
    .filter((name) => name === 'switching-analysis.json' || name.startsWith('switching-analysis-'))
    .sort();
  const reader = await timed('open', () => InfrastructurePublicationV2.open(fetch, catalog, index));
  if (fs.statSync(contexts).size > 2000000) throw Error('Study contexts byte bound');
  const studies = J.parseStrict(fs.readFileSync(contexts, 'utf8'));
  for (const [name, study] of Object.entries(studies)) {
    const selected = await timed(name, () => reader.switchingAnalysis(study));
    // Identical serializers, intentionally outside timed selection.
    result.outputs[name] = {
      selected_sha256: sha(J.stringify(selected)),
      analysis_csv_sha256: sha(A.csv(selected)),
      upgrades_csv_sha256: sha(A.csv(selected, { upgradesOnly: true })),
      rows: selected.upgrades.rows.length,
    };
  }
  result.peak_resident_bytes = process.resourceUsage().maxRSS * 1024;
  fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { flag: 'wx' });
  console.log('DONE', out);
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
