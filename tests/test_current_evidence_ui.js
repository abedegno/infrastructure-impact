// Real app acceptance/rollback and retained-only search with literal publisher text.
const fs = require('fs'),
  assert = require('assert');
const { browser } = require('./helpers/ui-browser.js');
const { context, fixture } = require('./test_current_evidence.js');
const c = context(),
  json = c.window.InfrastructureJSON;
const base = JSON.parse(fs.readFileSync('tests/fixtures/kev-selection-cases.json')).base_report;
function state(id = 'a'.repeat(32)) {
  const s = json.clone(fixture());
  s.publication.id = id;
  s.current_evidence.publication.id = id;
  s.counts = { advisories: 0, evidence_snapshots: 2 };
  s.kev = { ...base, publication: s.publication };
  s.kev.generated_at = s.generated_at;
  s.kev.evaluated_at = s.generated_at;
  s.kev = c.window.InfrastructureKev.selectReport(s.kev, ['CVE-2023-5501'], {
    evaluatedAt: s.generated_at,
  });
  s.comparison = { cohort: ['CVE-2023-5501'] };
  s.research_dossiers = { vendors: s.vendors, dossiers: [] };
  return s;
}
(async () => {
  const b = browser(true);
  async function respond(request, s) {
    request.resolve(new Response(json.stringify(s)));
    await b.settle();
  }
  await respond(b.requests[0], state());
  await respond(b.requests[1], state());
  assert(b.nodes.get('#summary').innerHTML.includes('Retained total'), 'retained totals visible');
  assert(
    b.nodes.get('#matrix-results').innerHTML.includes('retained-results'),
    'excluded-only results link',
  );
  assert(!b.nodes.get('#matrix-results').innerHTML.includes('class="badge unaffected"'));
  b.evaluate(
    `data.retained_index=[{vendor:'arista',cves:['CVE-2023-5501'],assessments:[{cve_id:'CVE-2023-5501',product:'=OLD()',status:'affected',search_text:'=OLD() version-only'}]}]; const savedRetained=data.retained_advisories; delete data.retained_advisories; matrixQuery='version-only'; render()`,
  );
  assert(
    b.nodes.get('#matrix-results').innerHTML.includes('retained-results'),
    'version-only search must link retained evidence without hydrating records',
  );
  b.evaluate("data.retained_advisories=savedRetained; matrixQuery=''; render()");
  const before = b.evaluate('data'),
    href = b.nodes.get('#json-export').href;
  async function test_mixed_generation_decision_report_is_rejected() {
    b.evaluate('load()');
    const bad = state('b'.repeat(32));
    bad.current_evidence.publication = { id: 'c'.repeat(32), advisory_schema_version: 2 };
    await respond(b.requests.at(-1), bad);
    assert.strictEqual(b.evaluate('data'), before);
    assert.strictEqual(b.nodes.get('#json-export').href, href);
    assert(b.nodes.get('#feedback').textContent.includes('last accepted'));
  }
  await test_mixed_generation_decision_report_is_rejected();
  b.evaluate('view="retained"; render()');
  assert(b.nodes.get('#view').innerHTML.includes('excluded_from_current'));
  assert(b.nodes.get('#view').innerHTML.includes('9007199254740993'));
  await b.nodes.get('#retained-json-export').click();
  await b.settle();
  const download = await b.downloads.at(-1).blob.text();
  assert(download.includes('9007199254740993'));
  assert(download.includes('retained_latest_excluded'));
  await b.nodes.get('#json-export').click();
  await b.settle();
  assert(!(await b.downloads.at(-1).blob.text()).includes('=OLD()'));
  // Stale successful responses cannot overwrite a later accepted publication/download scope.
  b.evaluate('load()');
  const older = b.requests.at(-1);
  b.evaluate('load()');
  const newer = b.requests.at(-1);
  await respond(newer, state('e'.repeat(32)));
  await respond(older, state('d'.repeat(32)));
  assert.strictEqual(b.evaluate('data.publication.id'), 'e'.repeat(32));
  b.evaluate('load()');
  const legacy = state('f'.repeat(32));
  delete legacy.current_evidence;
  delete legacy.retained_advisories;
  await respond(b.requests.at(-1), legacy);
  assert.strictEqual(b.evaluate('data.current_evidence.counts.excluded'), null);
  assert(b.nodes.get('#summary').innerHTML.includes('Unavailable'));
  console.log('current evidence UI acceptance/rollback passed');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
