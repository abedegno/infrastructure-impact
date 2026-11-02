// Synthetic browser contracts: publisher text stays inert and selection commits atomically.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert');
const web = 'infrastructure_impact/web/';
const base = JSON.parse(fs.readFileSync('tests/fixtures/kev-selection-cases.json')).base_report;
const clone = (value) => JSON.parse(JSON.stringify(value));
const cid = 'CVE-2024-6387',
  other = 'CVE-2025-1234',
  outside = 'CVE-2099-99999';
const kev = require('../' + web + 'kev.js');
const report = kev.selectReport(base, [cid, other, outside], { evaluatedAt: base.generated_at });
assert.strictEqual(typeof kev.renderContext, 'function', 'KEV context renderer must exist');
const listed = kev.renderContext(report, cid);
for (const label of [
  'KEV listed',
  'CISA',
  '2026-11-02',
  'Date added',
  '2026-11-01',
  'Due date',
  '2026-11-22',
  'Required action',
  'Ransomware',
  'Unknown',
  'Forensic triage',
  'Novel publisher triage value',
])
  assert(listed.includes(label), label);
assert(listed.includes('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"'));
const unknown = kev.selectReport(report, [cid], { evaluatedAt: '2026-11-04T00:00:01Z' });
const historical = kev.renderContext(unknown, cid);
assert(historical.includes('KEV unknown'));
assert(/historical/i.test(historical));
assert(!historical.includes('>KEV listed<'));
const arbitrary = kev.renderContext(report, outside);
assert(arbitrary.includes('KEV listed'));
assert(arbitrary.includes('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"'));
assert(!arbitrary.includes('Synthetic service'));
assert(!arbitrary.includes('Required action'));
const hostile = clone(report);
hostile.entries[cid].product = '<img src=x onerror=alert(1)>';
hostile.entries[cid].requiredAction = '=WEBSERVICE("<script>")';
hostile.entries[cid].forensicTriage = '<svg onload=alert(1)>';
hostile.source.catalogue_url = 'javascript:alert(1)';
const inert = kev.renderContext(hostile, cid);
assert(inert.includes('&lt;img'));
assert(inert.includes('=WEBSERVICE(&quot;&lt;script&gt;&quot;)'));
assert(!/<img|<svg|<script|href="javascript:/.test(inert));
assert.strictEqual(hostile.entries[cid].requiredAction, '=WEBSERVICE("<script>")');

// A small DOM boundary double; real app, KEV selector and dossier mount run unchanged.
function browser() {
  const nodes = new Map(),
    downloads = [],
    requests = [],
    blobs = new Map(),
    documentClicks = [];
  let blobId = 0,
    now = Date.parse(base.generated_at);
  const decode = (value) =>
    value
      .replaceAll('&quot;', '"')
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&amp;', '&');
  class Element {
    constructor(tag = '', attrs = '') {
      this.tagName = tag.toUpperCase();
      this.listeners = {};
      this.dataset = {};
      this.attrs = {};
      for (const m of attrs.matchAll(/([\w-]+)(?:="([^"]*)")?/g))
        this.attrs[m[1]] = decode(m[2] || '');
      this.id = this.attrs.id || '';
      this.value = this.attrs.value || '';
      this.checked = Object.hasOwn(this.attrs, 'checked');
      this.disabled = Object.hasOwn(this.attrs, 'disabled');
      this.hidden = Object.hasOwn(this.attrs, 'hidden');
      this.href = this.attrs.href || '';
      this.download = this.attrs.download || '';
      this.ownerDocument = document;
      if (this.attrs['data-view']) this.dataset.view = this.attrs['data-view'];
    }
    set innerHTML(html) {
      this.html = html;
      parse(html, this);
    }
    get innerHTML() {
      return this.html || '';
    }
    set textContent(text) {
      this.text = String(text);
    }
    get textContent() {
      return this.text || '';
    }
    addEventListener(type, handler) {
      (this.listeners[type] ||= []).push(handler);
    }
    setAttribute(key, value) {
      this.attrs[key] = value;
    }
    removeAttribute(key) {
      delete this.attrs[key];
    }
    querySelector(selector) {
      return document.querySelector(selector);
    }
    focus() {
      document.activeElement = this;
    }
    close() {}
    showModal() {}
    click() {
      if (this.download && this.href.startsWith('blob:'))
        downloads.push({ name: this.download, blob: blobs.get(this.href) });
      return this.fire('click');
    }
    closest(selector) {
      return selector.split(',').includes('#' + this.id) ? this : null;
    }
    fire(type) {
      const event = {
        target: this,
        preventDefault() {},
        stopPropagation() {},
        stopImmediatePropagation() {},
      };
      const handlers = [];
      for (let e = this; e; e = e.parentElement) handlers.push(...(e.listeners[type] || []));
      if (type === 'click') handlers.push(...documentClicks);
      return Promise.all(handlers.map((fn) => fn(event)));
    }
  }
  const document = {
    baseURI: 'https://example.test/',
    activeElement: null,
    querySelector(selector) {
      return nodes.get(selector) || null;
    },
    querySelectorAll(selector) {
      return selector === '[data-view]' ? [...nodes.values()].filter((n) => n.dataset.view) : [];
    },
    createElement(tag) {
      return new Element(tag);
    },
    addEventListener(type, fn) {
      if (type === 'click') documentClicks.push(fn);
    },
  };
  function parse(html, parent = null) {
    for (const m of html.matchAll(
      /<(input|select|button|section|div|span|a|dialog|option)\b([^>]*)>/g,
    )) {
      const e = new Element(m[1], m[2]);
      e.parentElement = parent;
      if (e.id) nodes.set('#' + e.id, e);
      if (e.dataset.view) nodes.set('[data-view="' + e.dataset.view + '"]', e);
      if (m[1] === 'option' && e.value === 'benchmark')
        nodes.set('#cohort option[value="benchmark"]', e);
    }
    for (const m of html.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g)) {
      const id = /id="([^"]+)"/.exec(m[1]);
      const selected =
        /<option\b[^>]*value="([^"]*)"[^>]*selected/.exec(m[2]) ||
        /<option\b[^>]*value="([^"]*)"/.exec(m[2]);
      if (id && selected) nodes.get('#' + id[1]).value = decode(selected[1]);
    }
  }
  parse(fs.readFileSync(web + 'index.html', 'utf8'));
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now]));
    }
    static now() {
      return now;
    }
  }
  class BlobURL extends URL {
    static createObjectURL(blob) {
      const url = 'blob:' + ++blobId;
      blobs.set(url, blob);
      return url;
    }
    static revokeObjectURL() {}
  }
  const window = {};
  const context = {
    window,
    document,
    location: { origin: 'https://example.test' },
    URL: BlobURL,
    URLSearchParams,
    Blob,
    Response,
    Date: Clock,
    Set,
    Map,
    console,
    setTimeout: () => {},
  };
  context.fetch = window.fetch = (url) =>
    new Promise((resolve, reject) => requests.push({ url, resolve, reject }));
  vm.createContext(context);
  context.createStaticDelivery = async () => async () => ({ changes: [] });
  for (const file of ['kev.js', 'research-dossiers.js', 'snapshot.js'])
    vm.runInContext(fs.readFileSync(web + file, 'utf8'), context);
  vm.runInContext(fs.readFileSync(web + 'app.js', 'utf8'), context);
  const evaluate = (code) => vm.runInContext(code, context);
  return {
    nodes,
    requests,
    downloads,
    context,
    evaluate,
    advance(ms) {
      now += ms;
    },
    async settle() {
      for (let i = 0; i < 15; i++) await Promise.resolve();
    },
  };
}
function state(id, requested = [cid], kevOnly = false) {
  const result = {
    generated_at: base.generated_at,
    publication: { id, advisory_schema_version: 2 },
    benchmark_cohort: { [cid]: 'Synthetic service' },
    all_cves: [cid, other],
    vendors: { hpe: 'HPE' },
    counts: { advisories: 1, evidence_snapshots: 1 },
    records: [
      {
        vendor: 'hpe',
        cves: [cid],
        title: id,
        source_format: 'synthetic',
        warnings: [],
        notes: [],
        assessments: [
          { cve_id: cid, product: id, status: 'affected', scope: 'cve_specific', versions: [] },
        ],
      },
    ],
    comparison: { cohort: kevOnly ? requested.filter((c) => c === cid) : requested },
    kev: kev.selectReport(
      { ...clone(base), publication: { id, advisory_schema_version: 2 } },
      requested,
      { kevOnly, evaluatedAt: base.generated_at },
    ),
    research_dossiers: { vendors: { hpe: 'HPE' }, dossiers: [] },
  };
  return result;
}
async function success(browser, request, value) {
  request.resolve(new Response(JSON.stringify(value)));
  await browser.settle();
}
async function checkDownloads(b, id) {
  for (const selector of ['#json-export', '#csv-export', '#kev-export']) {
    const before = b.downloads.length;
    await b.nodes.get(selector).click();
    await b.settle();
    assert.strictEqual(b.downloads.length, before + 1, selector + ' must capture accepted content');
    const text = await b.downloads.at(-1).blob.text();
    if (selector === '#csv-export' && b.evaluate('data.comparison.cohort.length') === 0)
      assert.strictEqual(
        text.split('\r\n').length,
        1,
        'empty accepted cohort exports only CSV header',
      );
    else assert(text.includes(id), selector + ' must keep accepted publication');
    if (selector === '#kev-export') {
      const expected = {
        ...clone(base),
        publication: { id, advisory_schema_version: 2 },
        selection: {
          requested_cve_ids: [cid, other],
          effective_cve_ids: [cid, other],
          kev_only: false,
          membership: { [cid]: 'listed', [other]: 'not_listed' },
        },
      };
      assert.deepStrictEqual(
        JSON.parse(text),
        expected,
        'report download is the untouched synthetic published report',
      );
    }
  }
}
(async () => {
  const b = browser();
  assert(b.nodes.has('#kev-only'), 'KEV filter control must exist');
  const html = fs.readFileSync(web + 'index.html', 'utf8');
  assert(
    /<label[^>]*for="kev-only"/.test(html),
    'checkbox has explicit keyboard label association',
  );
  assert(html.includes('KEV-listed only'));
  await success(b, b.requests[0], state('initial'));
  // Initial benchmark discovery is allowed to issue a second selected fetch.
  if (b.requests.length > 1) await success(b, b.requests[1], state('initial'));
  assert(
    b.nodes.get('#matrix-results').innerHTML.includes('KEV listed'),
    'Product impact includes KEV context',
  );
  assert(b.nodes.get('#kev-status').innerHTML.includes('2026-11-02'));
  await checkDownloads(b, 'initial');
  const apply = (cve, enabled) => {
    b.nodes.get('#cohort').value = 'custom';
    b.nodes.get('#custom-cves').value = cve;
    b.nodes.get('#kev-only').checked = enabled;
    return b.nodes.get('#apply').fire('click');
  };
  apply(cid, true);
  const older = b.requests.at(-1);
  apply(other, true);
  const failed = b.requests.at(-1);
  failed.resolve(new Response('{"error":"kev_unavailable"}', { status: 503 }));
  await b.settle();
  assert(/503|unavailable/i.test(b.nodes.get('#feedback').textContent));
  await success(b, older, state('obsolete', [cid], true));
  assert(b.nodes.get('#matrix-results').innerHTML.includes('initial'));
  assert.strictEqual(
    b.nodes.get('#kev-only').checked,
    false,
    'rejected filter restores committed controls',
  );
  assert.strictEqual(b.nodes.get('#cohort').value, 'benchmark');
  await checkDownloads(b, 'initial');
  apply(cid, false);
  const slow = b.requests.at(-1);
  apply(other, true);
  const latest = b.requests.at(-1);
  assert(latest.url.includes('kev=listed'));
  await success(b, latest, state('latest', [other], true));
  assert(
    /No KEV-listed CVEs match/.test(b.nodes.get('#view').innerHTML),
    'fresh empty selection is explicit',
  );
  await success(b, slow, state('too-late'));
  assert.strictEqual(b.evaluate('data.publication.id'), 'latest');
  assert.strictEqual(b.nodes.get('#kev-only').checked, true);
  assert.strictEqual(b.nodes.get('#custom-cves').value, other);
  await checkDownloads(b, 'latest');
  b.advance(36 * 3600000 + 1);
  const count = b.requests.length;
  b.evaluate('render()');
  await b.settle();
  assert(
    /503|unavailable/i.test(b.nodes.get('#feedback').textContent),
    'render rechecks expired KEV selection',
  );
  assert.strictEqual(b.evaluate('data.publication.id'), 'latest');
  apply(cid, true);
  const expired = b.requests.at(-1);
  if (b.requests.length > count) await success(b, expired, state('expired', [cid], true));
  assert(/503|unavailable/i.test(b.nodes.get('#feedback').textContent));
  assert.strictEqual(b.evaluate('data.publication.id'), 'latest');
  await checkDownloads(b, 'latest');

  // Catalogue membership remains visible for selected CVEs with no local evidence.
  const withoutAssessment = browser();
  await success(withoutAssessment, withoutAssessment.requests[0], state('context-initial'));
  await success(withoutAssessment, withoutAssessment.requests.at(-1), state('context-initial'));
  const applyWithoutAssessment = (cve, only) => {
    withoutAssessment.nodes.get('#cohort').value = 'custom';
    withoutAssessment.nodes.get('#custom-cves').value = cve;
    withoutAssessment.nodes.get('#kev-only').checked = only;
    withoutAssessment.nodes.get('#apply').fire('click');
  };
  const noEvidenceState = (id, cve, only = false) => {
    const selectedState = state(id, [cve], only);
    selectedState.comparison.cohort = [cve];
    selectedState.records = [];
    selectedState.counts.advisories = 0;
    return selectedState;
  };
  applyWithoutAssessment(outside, true);
  await success(
    withoutAssessment,
    withoutAssessment.requests.at(-1),
    noEvidenceState('outside-listed', outside, true),
  );
  const outsideMarkup = withoutAssessment.nodes.get('#matrix-results').innerHTML;
  assert(
    outsideMarkup.includes(`<code>${outside}</code>`),
    'matrix exposes selected CVE membership without an assessment row',
  );
  assert(outsideMarkup.includes('KEV listed'));
  assert(
    outsideMarkup.includes('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"'),
  );
  assert(outsideMarkup.includes('2026-11-02T12:00:00Z'));
  assert(outsideMarkup.includes('0 product/version statements'));
  assert(/no local product assessment/i.test(outsideMarkup));
  assert(!outsideMarkup.includes('Required action'));
  assert(!outsideMarkup.includes('Synthetic service'));
  assert(!outsideMarkup.includes('No KEV-listed CVEs match'));
  assert(withoutAssessment.nodes.get('#feedback').textContent.includes('1 selected CVEs'));
  await withoutAssessment.nodes.get('#json-export').click();
  await withoutAssessment.settle();
  const outsideExport = JSON.parse(await withoutAssessment.downloads.at(-1).blob.text());
  assert.strictEqual(outsideExport.publication.id, 'outside-listed');
  assert.deepStrictEqual(outsideExport.comparison.cohort, [outside]);
  assert.deepStrictEqual(outsideExport.kev.selection.effective_cve_ids, [outside]);
  assert.strictEqual(outsideExport.kev.selection.membership[outside], 'listed');
  assert.deepStrictEqual(outsideExport.records, []);
  await withoutAssessment.nodes.get('#csv-export').click();
  assert.strictEqual(
    (await withoutAssessment.downloads.at(-1).blob.text()).split('\r\n').length,
    1,
  );
  await withoutAssessment.nodes.get('#kev-export').click();
  const outsideReport = JSON.parse(await withoutAssessment.downloads.at(-1).blob.text());
  assert.strictEqual(outsideReport.publication.id, 'outside-listed');
  assert(outsideReport.listed_cve_ids.includes(outside));
  assert(!Object.hasOwn(outsideReport.entries, outside), 'outside detailed metadata stays absent');
  applyWithoutAssessment(other, false);
  await success(
    withoutAssessment,
    withoutAssessment.requests.at(-1),
    noEvidenceState('outside-not-listed', other),
  );
  const notListedMarkup = withoutAssessment.nodes.get('#matrix-results').innerHTML;
  assert(notListedMarkup.includes(`<code>${other}</code>`));
  assert(notListedMarkup.includes('KEV not listed'));
  assert(!notListedMarkup.includes('Required action'));
  assert.strictEqual(withoutAssessment.evaluate('data.publication.id'), 'outside-not-listed');
  applyWithoutAssessment(outside, false);
  await success(
    withoutAssessment,
    withoutAssessment.requests.at(-1),
    noEvidenceState('outside-historical', outside),
  );
  withoutAssessment.advance(36 * 3600000 + 1);
  withoutAssessment.evaluate('render()');
  const historicalOutside = withoutAssessment.nodes.get('#matrix-results').innerHTML;
  assert(historicalOutside.includes(`<code>${outside}</code>`));
  assert(historicalOutside.includes('KEV unknown'));
  assert(historicalOutside.includes('Retained listed membership is historical.'));
  assert(!historicalOutside.includes('>KEV listed<'));
  assert(!historicalOutside.includes('Required action'));
  applyWithoutAssessment(outside, false);
  const failedOutside = noEvidenceState('outside-unavailable', outside);
  failedOutside.kev.source.latest_attempt.outcome = 'error';
  failedOutside.kev.source.latest_attempt.error_code = 'HTTP_503';
  await success(withoutAssessment, withoutAssessment.requests.at(-1), failedOutside);
  assert(withoutAssessment.nodes.get('#matrix-results').innerHTML.includes('KEV unknown'));
  assert(
    withoutAssessment.nodes
      .get('#matrix-results')
      .innerHTML.includes('Retained listed membership is historical.'),
  );
  assert(withoutAssessment.nodes.get('#kev-status').innerHTML.includes('failed'));

  // A filtered matrix must reevaluate even when only its local product search renders.
  const m = browser();
  await success(m, m.requests[0], state('matrix'));
  await success(m, m.requests.at(-1), state('matrix'));
  m.nodes.get('#kev-only').checked = true;
  m.nodes.get('#apply').fire('click');
  await success(m, m.requests.at(-1), state('matrix', [cid], true));
  m.advance(36 * 3600000 + 1);
  await m.nodes.get('#product-search').fire('input');
  assert(
    /503|unavailable/i.test(m.nodes.get('#feedback').textContent),
    'local matrix render rechecks KEV freshness',
  );
  assert.strictEqual(
    m.evaluate('data.kev.source.availability'),
    'available',
    'expired render preserves accepted selection',
  );

  // Dossier context follows the selected CVE while evidence downloads retain their schema.
  const d = browser();
  const dossierState = state('dossiers', [cid, outside]);
  dossierState.benchmark_cohort[outside] = 'Synthetic arbitrary CVE';
  const dossier = (id, cve_id) => ({
    id,
    cve_id,
    scope: { build_target_ids: [], case_ids: [] },
    comparison_targets: [],
    disclosure_context: [],
    sources: [],
    evidence_gaps: [],
    chronology: { publisher_claims: [], local_observations: [], documentation_claims: [] },
  });
  dossierState.research_dossiers = {
    vendors: { hpe: 'HPE' },
    dossiers: [dossier('first', cid), dossier('second', outside)],
  };
  await success(d, d.requests[0], dossierState);
  await success(d, d.requests.at(-1), dossierState);
  d.evaluate("view='casefiles'; render()");
  assert(d.nodes.get('#dossier-kev-context').innerHTML.includes('KEV listed'));
  assert(d.nodes.get('#dossier-kev-context').innerHTML.includes('Required action'));
  const selector = d.nodes.get('#dossier-select');
  selector.value = 'second';
  selector.focus();
  await selector.fire('change');
  assert(d.nodes.get('#dossier-kev-context').innerHTML.includes('KEV listed'));
  assert(!d.nodes.get('#dossier-kev-context').innerHTML.includes('Required action'));
  assert.strictEqual(d.context.document.activeElement, d.nodes.get('#dossier-select'));
  await d.nodes.get('#dossier-download').click();
  const dossierExport = JSON.parse(await d.downloads.at(-1).blob.text());
  assert.deepStrictEqual(dossierExport.dossiers, [dossier('second', outside)]);
  assert(!Object.hasOwn(dossierExport, 'kev'), 'dossier evidence schema remains unchanged');
  d.advance(36 * 3600000 + 1);
  d.evaluate('render()');
  assert(d.nodes.get('#dossier-kev-context').innerHTML.includes('KEV unknown'));
  assert(/historical/i.test(d.nodes.get('#dossier-kev-context').innerHTML));

  // The child target change listener runs before parent bubbling handlers. Reject
  // expiry before that child can replace visible evidence or its download closure.
  const expiredDossier = browser();
  const filteredDossierState = clone(dossierState);
  filteredDossierState.kev = kev.selectReport(dossierState.kev, [cid, outside], {
    kevOnly: true,
    evaluatedAt: base.generated_at,
  });
  filteredDossierState.comparison.cohort = [cid, outside];
  await success(expiredDossier, expiredDossier.requests[0], dossierState);
  await success(expiredDossier, expiredDossier.requests.at(-1), dossierState);
  expiredDossier.nodes.get('#kev-only').checked = true;
  expiredDossier.nodes.get('#apply').fire('click');
  await success(expiredDossier, expiredDossier.requests.at(-1), filteredDossierState);
  expiredDossier.evaluate("view='casefiles'; render()");
  const acceptedContext = expiredDossier.nodes.get('#dossier-kev-context').innerHTML;
  assert(acceptedContext.includes('Follow the synthetic test action.'));
  assert(
    acceptedContext.includes('href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"'),
  );
  expiredDossier.advance(36 * 3600000 + 1);
  const rejectedSelector = expiredDossier.nodes.get('#dossier-select');
  rejectedSelector.value = 'second';
  rejectedSelector.focus();
  await rejectedSelector.fire('change');
  assert(/503|unavailable/i.test(expiredDossier.nodes.get('#feedback').textContent));
  assert.strictEqual(
    expiredDossier.nodes.get('#dossier-select').value,
    'first',
    'expired dossier selection preserves accepted CVE',
  );
  const acceptedPanel = expiredDossier.nodes.get('#research-dossiers').innerHTML;
  assert(acceptedPanel.includes(`<h3>${cid}</h3>`));
  assert(!acceptedPanel.includes(`<h3>${outside}</h3>`));
  assert.strictEqual(
    expiredDossier.nodes.get('#dossier-kev-context').innerHTML,
    acceptedContext,
    'rejection preserves the accepted source and action context',
  );
  assert.strictEqual(
    expiredDossier.context.document.activeElement,
    expiredDossier.nodes.get('#dossier-select'),
  );
  await expiredDossier.nodes.get('#dossier-download').click();
  const acceptedDossierExport = JSON.parse(await expiredDossier.downloads.at(-1).blob.text());
  assert.deepStrictEqual(
    acceptedDossierExport.dossiers,
    [dossier('first', cid)],
    'rejected dossier change keeps accepted evidence JSON',
  );
  assert(!Object.hasOwn(acceptedDossierExport, 'kev'));

  const c = browser(),
    comparisonState = state('comparison');
  comparisonState.comparison_eligibility = {
    period: { start: '2026-01-01', end: '2026-11-02' },
    product_selection: {},
    vendors: [],
    cohort: [cid],
    product_group: '',
  };
  comparisonState.product_groups = {
    groups: [{ id: 'networking', name: 'Networking' }],
    vendors: [],
  };
  await success(c, c.requests[0], comparisonState);
  await success(c, c.requests.at(-1), comparisonState);
  c.evaluate("view='compare';render()");
  c.nodes.get('#comparison-group').value = 'networking';
  c.nodes.get('#comparison-group').fire('change');
  assert(c.requests.at(-1).url.includes('group=networking'));
  c.requests.at(-1).resolve(new Response('{}', { status: 503 }));
  await c.settle();
  assert.strictEqual(
    c.nodes.get('#comparison-group').value,
    '',
    'rejected comparison scope restores its visible controls',
  );
  assert.deepStrictEqual(clone(c.evaluate('comparisonSelection')), {});
  // Legacy reports remain absent, without synthesizing a downloadable publication report.
  const legacy = state('legacy');
  delete legacy.kev;
  const l = browser();
  await success(l, l.requests[0], legacy);
  await success(l, l.requests.at(-1), legacy);
  assert(l.nodes.get('#kev-export').hidden);
  assert(l.nodes.get('#kev-status').innerHTML.includes('report unavailable'));
  assert(l.nodes.get('#matrix-results').innerHTML.includes('KEV unknown'));
  console.log(
    'KEV rendering, attribution, inert publisher text, controls, expiry and atomic UI downloads passed.',
  );
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
