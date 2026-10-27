const $ = (s) => document.querySelector(s);
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
const date = (v) => {
  if (!v) return 'Not supplied';
  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return esc(v) + ' (date only)';
  if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(v))
    return esc(v.replace('T', ' ')) + ' (publisher timezone unspecified)';
  const d = new Date(v);
  return isNaN(d)
    ? esc(v)
    : d.toLocaleString('en-GB', { timeZone: 'UTC', dateStyle: 'medium', timeStyle: 'short' }) +
        ' UTC';
};
const link = (url, label) => {
  try {
    if (window.snapshotMode) url = url.replace(/^\/api\/(evidence|changes)\/(\d+)$/, '/$1/$2.json');
    if (window.snapshotMode && url.startsWith('/'))
      url = new URL('.', document.baseURI).pathname + url.slice(1);
    const u = new URL(url, location.origin);
    if (!['https:', 'http:'].includes(u.protocol)) return esc(label);
    return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗</a>`;
  } catch {
    return esc(label);
  }
};
const badge = (s) => `<span class="badge ${esc(s)}">${esc(s.replaceAll('_', ' '))}</span>`;
const reference = ['CVE-2026-109618', 'CVE-2026-109619', 'CVE-2021-44228', 'CVE-2023-48795'];
let data,
  view = 'matrix',
  rows = [],
  shown = 150,
  matrixCve = 'CVE-2026-109618',
  matrixVendor = '',
  matrixStatus = '',
  matrixQuery = '';
let benchmark = [];
let selectedCves = null;
let comparisonSelection = {},
  comparisonScopeVendor = '';
function selected() {
  return new Set(data.comparison.cohort);
}
function name(v) {
  return data.vendors[v] || v;
}
function claims() {
  const cohort = selected();
  return data.records.flatMap((r) =>
    r.assessments.filter((a) => cohort.has(a.cve_id)).map((a) => ({ a, r })),
  );
}
function stats() {
  const c = data.counts;
  $('#summary').innerHTML = [
    ['Advisories', c.advisories],
    ['CVEs in cohort', data.comparison.cohort.length],
    [
      'Vendors collected',
      data.record_vendors?.length ?? new Set(data.records.map((r) => r.vendor)).size,
    ],
    ['Evidence snapshots', c.evidence_snapshots],
  ]
    .map(([l, n]) => `<div><strong>${n}</strong><span>${l}</span></div>`)
    .join('');
}
let loadSequence = 0;
async function load() {
  const sequence = ++loadSequence;
  $('#feedback').textContent = 'Loading evidence…';
  try {
    const params = new URLSearchParams();
    params.set('view', view);
    if (selectedCves) params.set('cves', selectedCves.join(','));
    if (comparisonSelection.start) params.set('start', comparisonSelection.start);
    if (comparisonSelection.end) params.set('end', comparisonSelection.end);
    if (comparisonSelection.group) params.set('group', comparisonSelection.group);
    if (comparisonSelection.products)
      params.set('products', JSON.stringify(comparisonSelection.products));
    const suffix = params.size ? '?' + params.toString() : '';
    const response = await fetch('/api/state' + suffix);
    if (!response.ok) throw Error('Could not load the evidence store');
    const loaded = await response.json();
    if (sequence !== loadSequence) return;
    data = loaded;
    benchmark = Object.keys(data.benchmark_cohort);
    if (selectedCves === null && $('#cohort').value === 'benchmark') {
      selectedCves = benchmark;
      return load();
    }
    const option = document.querySelector('#cohort option[value="benchmark"]');
    option.textContent = `Benchmark · ${benchmark.length} CVEs / ${new Set(Object.values(data.benchmark_cohort)).size} components`;
    const ageHours = (Date.now() - new Date(data.generated_at).getTime()) / 3600000;
    if (ageHours > 36)
      $('#feedback').textContent = 'Stale publication: collection needs attention.';
    stats();
    render();
    $('#json-export').href = window.snapshotMode
      ? new URL('snapshot.json', document.baseURI).href
      : '/api/export.json' + suffix;
    $('#csv-export').href = window.snapshotMode
      ? new URL('impact.csv', document.baseURI).href
      : '/api/export.csv' + suffix;
  } catch (e) {
    if (sequence !== loadSequence) return;
    $('#feedback').textContent = e.message;
  }
}
function render() {
  document.querySelectorAll('[data-view]').forEach((b) => {
    if (b.dataset.view === view) b.setAttribute('aria-current', 'page');
    else b.removeAttribute('aria-current');
  });
  $('#feedback').textContent =
    `${Date.now() - new Date(data.generated_at).getTime() > 36 * 3600000 ? 'STALE DATA · ' : ''}${data.comparison.cohort.length} selected CVEs · ${data.counts.advisories} imported advisories · ${window.snapshotMode ? 'snapshot collected' : 'last loaded'} ${date(data.generated_at)}`;
  ({
    matrix: renderMatrix,
    compare: renderComparison,
    coverage: renderCoverage,
    review: renderReview,
    changes: renderChanges,
    sources: renderSources,
    catalogue: renderCatalogue,
    gaps: renderVendorGaps,
    casefiles: renderCasefiles,
    families: renderFamilies,
    readiness: renderReadiness,
    productcohorts: renderProductCohorts,
    disclosurereview: renderDisclosureReview,
    fixleads: renderFixLeads,
    studies: renderComponentStudies,
    scorecards: renderScorecards,
    timeline: renderTimeline,
    correction: renderCorrection,
    validation: renderValidation,
  })[view]();
}
function renderMatrix() {
  $('#view').innerHTML =
    `<div class="section-heading"><div><h2>Product impact matrix</h2><p>Vendor statements stay attached to their products, versions, and source scope.</p></div></div><div class="matrix-filters"><label>CVE<select id="matrix-cve"><option value="">All CVEs in cohort</option>${data.comparison.cohort.map((c) => `<option ${c === matrixCve ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select></label><label>Vendor<select id="matrix-vendor"><option value="">All vendors</option>${Object.entries(
      data.vendors,
    )
      .map(
        ([v, n]) =>
          `<option value="${v}" ${v === matrixVendor ? 'selected' : ''}>${esc(n)}</option>`,
      )
      .join(
        '',
      )}</select></label><label>Assessment<select id="matrix-status"><option value="">All states</option>${['affected', 'partially_mitigated', 'unaffected', 'investigating', 'fixed', 'conflicting', 'unknown'].map((s) => `<option value="${s}" ${s === matrixStatus ? 'selected' : ''}>${s}</option>`).join('')}</select></label><label class="grow">Find product<input type="search" id="product-search" value="${esc(matrixQuery)}" placeholder="Catalyst, EOS, Panorama…"></label></div><div class="notice">Shared bulletin = the vendor supplied a common product table for multiple CVEs. Draft source documents are labelled and excluded from vendor comparison counts.</div><div id="matrix-results"></div>`;
  if (matrixCve && !selected().has(matrixCve)) {
    $('#matrix-cve').value = '';
    matrixCve = '';
  }
  $('#matrix-cve').addEventListener('change', (e) => {
    matrixCve = e.target.value;
    shown = 150;
    matrixRows();
  });
  $('#matrix-vendor').addEventListener('change', (e) => {
    matrixVendor = e.target.value;
    shown = 150;
    matrixRows();
  });
  $('#matrix-status').addEventListener('change', (e) => {
    matrixStatus = e.target.value;
    shown = 150;
    matrixRows();
  });
  $('#product-search').addEventListener('input', (e) => {
    matrixQuery = e.target.value;
    shown = 150;
    matrixRows();
  });
  matrixRows();
}
function matrixRows() {
  rows = claims().filter(
    ({ a, r }) =>
      (!matrixCve || a.cve_id === matrixCve) &&
      (!matrixVendor || r.vendor === matrixVendor) &&
      (!matrixStatus || a.status === matrixStatus) &&
      `${a.product} ${JSON.stringify(a.versions)} ${a.product_context?.map((x) => x[1]).join(' ')}`
        .toLowerCase()
        .includes(matrixQuery.toLowerCase()),
  );
  $('#matrix-results').innerHTML =
    `<p class="count">${rows.length} product/version statements · showing ${Math.min(shown, rows.length)}</p><div class="table-wrap"><table><thead><tr><th>Vendor / CVE</th><th>Product & version scope</th><th>Assessment</th><th>Remediation evidence</th><th>Source</th></tr></thead><tbody>${rows
      .slice(0, shown)
      .map(
        ({ a, r }, i) =>
          `<tr><td>${esc(name(r.vendor))}<br><code>${esc(a.cve_id)}</code></td><td><strong>${esc(a.product_family || a.product)}</strong>${a.product_family ? `<small>${esc(a.product)}</small>` : ''}${a.versions?.length ? `<div class="versions">${a.versions.map((v) => esc(v.expression || `${v.version} ${v.status || ''}${v.lessThan ? ' · below ' + v.lessThan : ''}${v.lessThanOrEqual ? ' · through ' + v.lessThanOrEqual : ''}`)).join('<br>')}</div>` : ''}${publisherScope(a)}${r.document_status === 'draft' ? '<span class="draft">DRAFT SOURCE</span>' : ''}</td><td>${badge(a.status)}<small>${a.scope === 'bulletin_shared' ? 'Shared bulletin' : 'CVE-specific statement'}</small></td><td>${fixSummary(a)}</td><td><button class="text-button" data-detail="${i}">View evidence ↗</button><small>${esc(r.source_format)}</small></td></tr>`,
      )
      .join(
        '',
      )}</tbody></table></div>${!rows.length ? '<p class="empty">No matching assessment in the collected dataset. This does not establish that the product is unaffected.</p>' : ''}${rows.length > shown ? '<button id="more">Show 150 more statements</button>' : ''}`;
  $('#more')?.addEventListener('click', () => {
    shown += 150;
    matrixRows();
  });
  document
    .querySelectorAll('[data-detail]')
    .forEach((b) => b.addEventListener('click', () => detail(rows[Number(b.dataset.detail)])));
}
function publisherScope(a) {
  const contexts = (a.exposure || []).filter(
    (c) => c.category?.startsWith('publisher_') && c.details,
  );
  if (!contexts.length) return '';
  return `<details><summary>Publisher scope and configuration</summary><p>Read these conditions with the product and version statement. Advisory-wide solutions and workarounds are context, not independently verified product fix availability.</p>${contexts.map((c) => `<p><strong>${esc(c.category.replace('publisher_', '').replaceAll('_', ' '))}</strong></p><pre>${esc(c.details)}</pre>`).join('')}</details>`;
}
function fixSummary(a) {
  if (a.status === 'unaffected')
    return '<span class="muted">No remediation required by this assessment</span>';
  const fixes = (a.remediations || []).filter((r) => !['not_a_fix'].includes(r.availability));
  if (!fixes.length) return '<span class="muted">No fix availability assessment</span>';
  return fixes
    .slice(0, 3)
    .map(
      (f) =>
        `${badge(f.availability || 'unknown')}<small>${esc((f.details || '').slice(0, 130))}${(f.details || '').length > 130 ? '…' : ''}</small>`,
    )
    .join('');
}
function detail({ a, r }) {
  $('#detail-body').innerHTML =
    `<div class="eyebrow">${esc(name(r.vendor))} / ${esc(a.cve_id)}</div><h2>${esc(a.product)}</h2>${badge(a.status)} <span class="muted">${esc(a.scope)}</span><p>${esc(r.title)}</p><div class="evidence-links">${link(r.advisory_url || r.source_url, 'Vendor advisory')} ${r.advisory_url && r.advisory_url !== r.source_url ? link(r.source_url, 'Captured source') : ''} ${link('/api/evidence/' + r.evidence_id, window.snapshotMode ? 'Evidence fingerprint JSON' : 'Archived evidence JSON')}</div><dl><dt>Published by vendor</dt><dd>${date(r.published_at)}</dd><dt>Updated by vendor</dt><dd>${date(r.updated_at)}</dd><dt>Source first captured</dt><dd>${date(r.source_observed_at)}</dd><dt>Normalized revision</dt><dd>${date(r.observed_at)}</dd><dt>Adapter fingerprint</dt><dd>${esc(r.adapter_version)}</dd><dt>Document status</dt><dd>${esc(r.document_status)}</dd><dt>Evidence locator</dt><dd>${esc(a.evidence_locator)}</dd></dl>${r.warnings.map((w) => `<p class="notice">${esc(w)}</p>`).join('')}<h3>Exact version / platform statement</h3><pre>${esc(JSON.stringify({ versions: a.versions, context: a.product_context, relationship: a.relationship, source_statuses: a.source_statuses }, null, 2))}</pre><h3>Remediations and exposure</h3><pre>${esc(JSON.stringify({ remediations: a.remediations, exposure: a.exposure }, null, 2))}</pre><details><summary>Vendor notes and score scenarios</summary><pre>${esc(JSON.stringify({ notes: r.notes.filter((n) => !n.cve_id || n.cve_id === a.cve_id), metrics: r.metrics }, null, 2))}</pre></details><p class="fingerprint">SHA-256 ${esc(r.sha256)}</p>`;
  $('#detail').showModal();
}
function comparisonCoverage(v) {
  const s = v.source_coverage;
  return `<details><summary>Product scope and evidence gaps</summary><p>Scope: ${esc(v.product_scope.mode.replaceAll('_', ' '))}. ${esc(v.product_scope.labels.join('; ') || 'No products selected')}.</p><p>Declared families are context, not a verified inventory: ${esc(v.product_scope.declared_families.join('; ') || 'Not declared')}.</p><p>${esc(s.history_scope)}</p>${s.archives.map((a) => `<p>${link(a.source_url, 'Archive source')} · ${a.documents.done} processed documents; ${a.documents.pending} pending; ${a.documents.error} failed. ${esc((a.observed_scopes || []).join('; '))}</p>`).join('')}${s.errors.map((e) => `<p>${link(e.source_url, 'Source gap')} · ${esc(e.error_code || 'collection error')} · checked ${date(e.checked_at)}</p>`).join('')}<ul>${s.known_gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul><p>Rate and timing blockers: ${esc(v.eligibility.reason_codes.map((r) => r.replaceAll('_', ' ')).join('; '))}.</p></details>`;
}
function renderComparison() {
  const c = data.comparison_eligibility;
  if (!c?.period) {
    $('#view').innerHTML = '<p>Comparison eligibility is unavailable for this publication.</p>';
    return;
  }
  const vendor = comparisonScopeVendor || Object.keys(data.vendors)[0];
  const labelContext = productLabelContext(data, vendor);
  const available = window.snapshotMode
    ? productLabels(data, vendor)
    : [
        ...new Set(
          data.records
            .filter((r) => r.vendor === vendor && r.document_status !== 'draft')
            .flatMap((r) => r.assessments.map((a) => a.product)),
        ),
      ].sort();
  const labels = Object.hasOwn(c.product_selection, vendor) ? c.product_selection[vendor] : [];
  const paired = c.vendors.flatMap((v) =>
    v.cases.flatMap((row) =>
      row.publication_observations.map((p) => ({ ...p, vendor: v.name, cve_id: row.cve_id })),
    ),
  );
  const sampleNumber = (v, key) =>
    v.eligibility.descriptive_counts_usable ? v.counts[key] : 'Unavailable';
  $('#view').innerHTML =
    `<h2>Scoped vendor evidence comparison</h2><p>One reporting period and CVE cohort, with an explicit product scope and collection limits for every vendor.</p><div class="notice">${esc(c.method)}</div><div class="matrix-filters"><label>Published from<input type="date" id="comparison-start" value="${esc(c.period.start)}" min="1900-01-01" max="${esc(data.generated_at.slice(0, 10))}"></label><label>Published through<input type="date" id="comparison-end" value="${esc(c.period.end)}" min="1900-01-01" max="${esc(data.generated_at.slice(0, 10))}"></label><label>Product group<select aria-label="Product group" id="comparison-group"><option value="">All retained product roles</option>${(data.product_groups?.groups || []).map((g) => `<option value="${esc(g.id)}" ${g.id === c.product_group ? 'selected' : ''}>${esc(g.name)}</option>`).join('')}</select></label><button id="comparison-period">Apply period</button><button id="comparison-download">Download scoped comparison JSON</button></div><details><summary>Product grouping coverage and rules</summary><p>Taxonomy ${esc(c.taxonomy_version)}. Roles group source statements; they do not establish equivalent devices, a complete inventory, or comparable vendor rates. Version leaves inherit only a retained named family. Shared routing/switching OS statements are kept separate from platform-specific groups. Exact product selections intersect the chosen group.</p><p>${link('/product-groups.json', 'Download grouping coverage and source-linked rules')}</p><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Mapped statements</th><th>Unmapped / ambiguous</th><th>Unresolved publisher labels</th></tr></thead><tbody>${(data.product_groups?.vendors || []).map((v) => `<tr><td>${esc(name(v.vendor))}</td><td>${v.mapped_statements} / ${v.statement_count}</td><td>${v.unmapped_statements} / ${v.ambiguous_statements}</td><td><details><summary>${v.unresolved_labels.length} labels</summary>${v.unresolved_labels.map((p) => `<p>${esc(p)}</p>`).join('')}</details></td></tr>`).join('')}</tbody></table></div><p>Grouping coverage above uses all retained non-draft statements, across dates and CVEs. The comparison below uses the selected period and cohort.</p></details><details id="comparison-product-scope"><summary>Choose exact products per vendor</summary><p>Unset vendors include all retained product labels. These labels do not establish equivalent product portfolios. Select up to 20 labels for a vendor; an empty selection gives no usable sample. Publisher family names are display context. A shared label still selects every matching statement, including other families or statements without family context.</p><label>Scope vendor<select aria-label="Scope vendor" id="comparison-scope-vendor">${Object.entries(
      data.vendors,
    )
      .map(
        ([id, name]) =>
          `<option value="${esc(id)}" ${id === vendor ? 'selected' : ''}>${esc(name)}</option>`,
      )
      .join(
        '',
      )}</select></label><label>Publisher product labels<select aria-label="Publisher product labels" id="comparison-products" multiple size="6">${available.map((label) => `<option value="${esc(label)}" title="${esc(productLabelDisplay(label, labelContext))}" ${labels.includes(label) ? 'selected' : ''}>${esc(productLabelDisplay(label, labelContext))}</option>`).join('')}</select></label><p>Current scope: ${Object.hasOwn(c.product_selection, vendor) ? labels.length + ' selected labels' : 'All retained labels'}.</p><button id="comparison-scope-apply">Use selected labels</button><button id="comparison-scope-clear">Use all retained labels for this vendor</button></details><p><strong>Shared period: ${esc(c.period.start)} through ${esc(c.period.end)}, inclusive.</strong> ${c.cohort.length} selected CVEs. Explicit means CVE-specific; affected includes partial mitigation. Counts overlap across products. Fixed statements do not establish earlier affectedness.</p><div class="table-wrap"><table class="comparison-table"><thead><tr><th>Vendor / scope</th><th>CVEs with a statement</th><th>Explicit affected</th><th>Shared affected</th><th>Explicit unaffected</th><th>Fixed</th><th>Unknown / missing evidence</th><th>Eligibility and collection</th></tr></thead><tbody>${c.vendors.map((v) => `<tr><td><strong>${esc(v.name)}</strong><small>${v.product_scope.labels.length} retained labels · ${esc(v.product_scope.mode.replaceAll('_', ' '))}</small>${comparisonCoverage(v)}</td><td>${v.counts.cves_with_statement} / ${v.counts.cohort_size}<small>${v.counts.advisories_in_period} advisories in period</small><small>Excluded: ${v.excluded_advisories.outside_period} outside period; ${v.excluded_advisories.unusable_publication_date} undated or timezone unspecified; ${v.excluded_advisories.draft} draft; ${v.excluded_advisories.future_timestamp} future timestamps.</small></td><td>${sampleNumber(v, 'explicit_affected')}</td><td>${sampleNumber(v, 'shared_affected')}</td><td>${sampleNumber(v, 'explicit_unaffected')}</td><td>${sampleNumber(v, 'fixed')}<small>Prior affectedness not inferred</small></td><td>${v.counts.unknown} explicit unknown<small>${v.counts.no_statement} no product statement in period/scope</small><small>${v.counts.no_cve_specific_exposure_assessment} without a CVE-specific affected/unaffected assessment</small></td><td>${v.eligibility.descriptive_counts_usable ? 'Qualified sample counts' : 'No usable sample'}<small>Vendor rates, first-disclosure and fix timing suppressed</small><small>${v.source_coverage.errors.length} retained source errors; ${v.source_coverage.configured_urls} configured URLs; ${v.source_coverage.stale_or_unchecked_urls} stale/unchecked</small><small>${v.source_coverage.backfill_pending} pending queue items; ${v.source_coverage.backfill_failed} failed queue items</small></td></tr>`).join('')}</tbody></table></div><h3>Timing eligibility</h3><p>First-disclosure and fix-delay metrics are unavailable. Individual CVE statement dates, complete disclosure history, independent fix availability and exact product/CVE linkage have not been verified. A planned release, fixed-only statement or release listing cannot supply those missing facts.</p><details><summary>Inspect paired publication metadata (${paired.length} observations)</summary><p>Each offset compares the publisher's initial document timestamp with upstream CVE publication. It does not date the CVE statement, establish first disclosure, measure response time, or date a fix. Date-only values and timestamps without a timezone produce no numeric offset. Conflicting statements and missing source fingerprints suppress paired observations. Showing up to 200 rows.</p><div class="table-wrap"><table><thead><tr><th>Vendor / CVE</th><th>Advisory date</th><th>Upstream date</th><th>Metadata offset</th><th>Sources and fingerprints</th></tr></thead><tbody>${paired
      .slice(0, 200)
      .map(
        (p) =>
          `<tr><td>${esc(p.vendor)}<small>${esc(p.cve_id)}</small></td><td>${date(p.advisory_date)}</td><td>${date(p.upstream_date)}</td><td>≈ ${(p.offset_seconds / 86400).toFixed(2)} days</td><td>${link(p.advisory_source, 'Advisory')} · ${link(p.upstream_source, 'Upstream')}<small>${esc(p.advisory_sha256 || 'Advisory fingerprint unavailable')}</small><small>${esc(p.upstream_sha256 || 'Upstream fingerprint unavailable')}</small></td></tr>`,
      )
      .join(
        '',
      )}</tbody></table></div></details><details><summary>Inspect CVE states and missing timing inputs</summary>${c.vendors.map((v) => `<h4>${esc(v.name)}</h4>${v.cases.map((row) => `<p><code>${esc(row.cve_id)}</code> · ${esc(row.statuses.join(', ') || 'No product statement in period/scope')} · ${esc(row.timing_reasons.map((r) => r.replaceAll('_', ' ')).join('; ') || 'Paired document metadata only; disclosure and fix timing suppressed')}.</p>`).join('')}`).join('')}</details>`;
  $('#comparison-period').addEventListener('click', () => {
    const start = $('#comparison-start'),
      end = $('#comparison-end');
    if (
      !start.value ||
      !end.value ||
      !start.reportValidity() ||
      !end.reportValidity() ||
      start.value > end.value
    ) {
      $('#feedback').textContent =
        'Choose an ordered reporting period no later than this publication.';
      return;
    }
    comparisonSelection = { ...comparisonSelection, start: start.value, end: end.value };
    load();
  });
  $('#comparison-group').addEventListener('change', (e) => {
    comparisonSelection = { ...comparisonSelection, group: e.target.value || null };
    load();
  });
  $('#comparison-scope-vendor').addEventListener('change', (e) => {
    comparisonScopeVendor = e.target.value;
    renderComparison();
    $('#comparison-product-scope').open = true;
  });
  $('#comparison-scope-apply').addEventListener('click', () => {
    const selected = [...$('#comparison-products').selectedOptions].map((o) => o.value);
    const products = { ...c.product_selection, [vendor]: selected };
    if (selected.length > 20 || new Blob([JSON.stringify(products)]).size > 4096) {
      $('#feedback').textContent =
        'Select up to 20 labels per vendor and keep the full selection below 4 KB.';
      return;
    }
    comparisonSelection = { ...comparisonSelection, products };
    load();
  });
  $('#comparison-scope-clear').addEventListener('click', () => {
    const products = { ...c.product_selection };
    delete products[vendor];
    comparisonSelection = { ...comparisonSelection, products };
    load();
  });
  $('#comparison-download').addEventListener('click', () => {
    const url = URL.createObjectURL(
      new Blob(
        [
          JSON.stringify(
            { ...c, publication: data.publication, generated_at: data.generated_at },
            null,
            2,
          ),
        ],
        { type: 'application/json' },
      ),
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = 'comparison-eligibility.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
}

function renderReview() {
  const reviewSignals = data.signals.filter(
    (s) => !s.cve_id || s.cve_id.split(/[,\s]+/).some((c) => selected().has(c)),
  );
  $('#view').innerHTML =
    `<h2>Disclosure evidence review</h2><p>Investigate observable disclosure patterns. These signals do not establish intent or prove that a vendor concealed a vulnerability.</p><div class="review-types"><article><h3>Fix before a collected advisory</h3><p>Requires reviewed release evidence and a specific CVE, product, and fixed-version link. A future ETA is insufficient.</p></article><article><h3>CVE added in a later revision</h3><p>Compares locally observed source revisions. Parser changes are tracked separately.</p></article><article><h3>Security change without a CVE</h3><p>Flags security language in collected release notes lacking CVE references. It may describe hardening or an issue without a CVE.</p></article></div><div class="notice">Release-note collection must be configured per product. ${data.research.release_documents.length} release-note documents, ${(data.research.release_assets || []).length} dated release listings and ${data.research.fix_candidates.length} independently registered fix candidates are collected across the dataset. Signals below follow the selected cohort. No comprehensive release-note or binary analysis has been performed. Zero signals means no qualifying evidence in this dataset.</div>${publisherHistoryMarkup(data.publisher_history?.documents)}<h3>Independent release-listing metadata</h3><p>These records identify builds, platforms, publisher dates and artifact checksums. They do not establish CVE applicability, historical availability or download entitlement.</p><div class="table-wrap"><table><thead><tr><th>Product / build</th><th>Platforms</th><th>Publisher date</th><th>Publisher artifact SHA-256</th><th>Source</th></tr></thead><tbody>${(data.research.release_assets || []).map((a) => `<tr><td>${esc(a.product)}<small>${esc(a.version)}</small></td><td>${esc(a.platforms.join(', '))}</td><td>${esc(a.reported_published_at)}</td><td><code>${esc(a.artifact_sha256)}</code></td><td>${link(a.source_url, 'Listing')}</td></tr>`).join('')}</tbody></table></div><div class="signal-list">${reviewSignals.map((s) => `<article><div class="eyebrow">${esc(name(s.vendor))} / ${esc(s.confidence)}</div><h3>${esc(s.kind.replaceAll('_', ' '))}</h3><p>${esc(s.product || '')} ${esc(s.cve_id || '')}</p><p>${esc(s.explanation)}</p>${s.excerpt ? `<blockquote>${esc(s.excerpt)}</blockquote>` : ''}${s.released_at ? `<p>${s.confidence === 'unverified_release_date_candidate' ? 'Reported firmware date' : 'Reviewed release date'}: ${date(s.released_at)} · advisory: ${date(s.advisory_date)}</p>` : ''}${link(s.source_url, 'Evidence source')}${s.kind === 'reported_firmware_date_predates_bulletin' ? `<p>${link('/research/hpe-timing-investigation.txt', 'Read investigation record')}</p>` : ''}${s.details ? `<pre>${esc(JSON.stringify(s.details, null, 2))}</pre>` : ''}</article>`).join('') || '<p class="empty">No qualifying disclosure signals collected. No claim about hidden exposure can be made.</p>'}</div>`;
}
function renderChanges() {
  $('#view').innerHTML =
    `<h2>Observed source changes</h2><p>Changes are detected between local snapshots. Vendor-supplied historical timelines are retained in the evidence; they are not treated as observations made by this collector.</p>${data.changes.map((c) => `<article class="change"><div class="eyebrow">${date(c.observed_at)} · ${esc(name(c.vendor))}</div><h3>${esc(c.advisory_id)}</h3>${badge(c.kind)}<details><summary>Inspect changes</summary>${link('/api/changes/' + c.id, 'Complete archived diff')}<pre>${esc(JSON.stringify(c.details, null, 2))}</pre></details></article>`).join('') || '<p class="empty">No changes observed yet. Run the collector again after sources update.</p>'}`;
}
let healthVendor = '',
  healthResult = 'attention';
function renderSources() {
  const collector = data.collector || {},
    run = collector.last_run,
    schedule = collector.schedule || {};
  const delivery = collector.hosted_auto_publication
    ? 'Data publications update this service automatically; code deployment is separate.'
    : 'This hosted static copy requires a separate publishing step.';
  const scheduleText = schedule.installed
    ? `${['container_worker', 'github_actions'].includes(schedule.kind) ? 'Service collection' : 'Local collection'}: ${esc(schedule.local_time)} (${esc(schedule.timezone)}). ${['container_worker', 'github_actions'].includes(schedule.kind) ? 'Runs in the collector service.' : 'Requires this Mac and user session; sleeping runs may be deferred.'}`
    : 'No installed collection schedule recorded.';
  const collectorSummary = `<div class="notice">${scheduleText} ${delivery} ${run ? `Last pass: ${esc(run.outcome)} · finished ${date(run.finished_at)} · ${run.failures} failed source check${run.failures === 1 ? '' : 's'}.` : 'No completed pipeline receipt collected.'}</div>`;
  const checks = data.health || [];
  const attention = (h) =>
    Boolean(h.error_code) || !['ok', 'not_applicable', 'reprocessed'].includes(h.outcome);
  const outcomes = [...new Set(checks.map((h) => h.outcome))].sort();
  const vendors = [...new Set(checks.map((h) => h.vendor))].sort();
  const visible = checks
    .filter((h) => !healthVendor || h.vendor === healthVendor)
    .filter((h) =>
      healthResult === 'attention'
        ? attention(h)
        : healthResult === 'all' || h.outcome === healthResult,
    )
    .sort(
      (a, b) =>
        Number(attention(b)) - Number(attention(a)) ||
        String(b.checked_at).localeCompare(String(a.checked_at)) ||
        a.source_url.localeCompare(b.source_url),
    );
  const controls = `<div class="matrix-filters"><label>Vendor<select id="health-vendor"><option value="">All retained vendors and references</option>${vendors.map((v) => `<option value="${esc(v)}" ${healthVendor === v ? 'selected' : ''}>${esc(name(v))}</option>`).join('')}</select></label><label>Source result<select id="health-result"><option value="attention" ${healthResult === 'attention' ? 'selected' : ''}>Needs attention</option><option value="all" ${healthResult === 'all' ? 'selected' : ''}>All retained results</option>${outcomes.map((o) => `<option value="${esc(o)}" ${healthResult === o ? 'selected' : ''}>${esc(o.replaceAll('_', ' '))}</option>`).join('')}</select></label></div><p role="status">Showing ${visible.length} of ${checks.length} retained source URL checks. ${checks.filter(attention).length} need attention across all vendors and references. Filters affect this table only; counts describe latest retained attempts, not just the last pass.</p>`;

  $('#view').innerHTML =
    `<h2>Collection history and coverage</h2>${collectorSummary}<p>Latest attempt per source URL, including historical attempts from earlier configurations. A failed fetch does not imply a missing vendor disclosure.</p><div class="notice">${Object.keys(data.vendors).length} vendors are on the installed roster. Collection coverage varies by configured feeds, indexes, curated documents and plugin capabilities. Article shells, empty CSAF envelopes and parse failures remain gaps. This is not a complete portfolio scan. Reprocessed means retained bytes were parsed again; it is not a new successful HTTP check.</div>${controls}<div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Result</th><th>Checked</th><th>Source / collection scope</th></tr></thead><tbody>${visible.map((h) => `<tr><td>${esc(name(h.vendor))}</td><td>${badge(h.outcome)}${h.error_code ? `<small>${esc(h.error_code.replaceAll('_', ' '))}</small>` : ''}</td><td>${date(h.checked_at)}</td><td>${link(h.source_url, 'Source')}<small>${esc(h.details)}</small></td></tr>`).join('') || '<tr><td colspan="4">No retained checks match these filters. This does not establish complete collection or absence of vendor impact.</td></tr>'}</tbody></table></div>${sourceSelectionMarkup(data.source_audit || {})}`;
  $('#health-vendor').addEventListener('change', (e) => {
    healthVendor = e.target.value;
    renderSources();
  });
  $('#health-result').addEventListener('change', (e) => {
    healthResult = e.target.value;
    renderSources();
  });
}
document.querySelectorAll('[data-view]').forEach((b) =>
  b.addEventListener('click', () => {
    view = b.dataset.view;
    if (data) {
      if (window.snapshotMode) load();
      else render();
    }
  }),
);
$('#cohort').addEventListener('change', (e) => {
  $('#custom-cves').disabled = e.target.value !== 'custom';
});
$('#apply').addEventListener('click', () => {
  const mode = $('#cohort').value;
  selectedCves =
    mode === 'benchmark'
      ? benchmark
      : mode === 'reference'
        ? reference
        : mode === 'custom'
          ? $('#custom-cves')
              .value.toUpperCase()
              .split(/[\s,]+/)
              .filter(Boolean)
          : null;
  if (
    selectedCves &&
    (!selectedCves.length || selectedCves.some((c) => !/^CVE-\d{4}-\d{4,}$/.test(c)))
  ) {
    $('#feedback').textContent = 'Enter valid CVE identifiers separated by commas.';
    return;
  }
  load();
});
$('#close-detail').addEventListener('click', () => $('#detail').close());
load();

function renderCoverage() {
  const states = {
    assessment_available: ['●', 'Assessment available'],
    advisory_located_no_resolved_assessment: ['◐', 'Advisory located; assessment unresolved'],
    advisory_reference_located: ['◐', 'Reference located; content unavailable'],
    index_checked_no_match: ['—', 'No match in searched index/reference scope'],
    source_unavailable: ['!', 'Source check incomplete'],
    not_checked: ['?', 'Not checked'],
  };
  const vendors = Object.keys(data.vendors),
    ids = data.comparison.cohort;
  $('#view').innerHTML =
    `<h2>What has actually been checked?</h2><p>Each cell separates available product evidence from collection gaps. “No match” refers only to the stated search scope; it does not mean the vendor is unaffected.</p><div class="table-wrap"><table><thead><tr><th>CVE / component</th>${vendors.map((v) => `<th>${esc(name(v))}</th>`).join('')}</tr></thead><tbody>${ids
      .map(
        (cid) =>
          `<tr><td><code>${esc(cid)}</code><small>${esc(data.benchmark_cohort[cid] || 'Custom cohort')}</small></td>${vendors
            .map((v) => {
              const i = data.coverage.findIndex((c) => c.vendor === v && c.cve_id === cid);
              const c = data.coverage[i];
              const [symbol, label] = states[c?.state] || states.not_checked;
              return `<td><button class="coverage-cell ${esc(c?.state || 'not_checked')}" data-coverage="${i}" title="${esc(label)}" aria-label="${esc(name(v) + ' ' + cid + ': ' + label)}">${symbol}</button></td>`;
            })
            .join('')}</tr>`,
      )
      .join(
        '',
      )}</tbody></table></div><p class="notice">● Product assessment · ◐ Advisory/reference without resolved assessment · — No match in checked scope · ! Check incomplete · ? Not checked. The declared benchmark is a purposive sample, not a representative security ranking.</p>`;
  document.querySelectorAll('[data-coverage]').forEach((b) =>
    b.addEventListener('click', () => {
      const c = data.coverage[Number(b.dataset.coverage)];
      if (!c) return;
      $('#detail-body').innerHTML =
        `<h2>${esc(name(c.vendor))} / ${esc(c.cve_id)}</h2>${badge(c.state)}<h3>Located advisories</h3>${c.advisory_sources.map((u) => `<p>${link(u, 'Primary source')}</p>`).join('') || '<p>No advisory imported for this pair.</p>'}<h3>Search scope and provenance</h3>${c.checks.map((x) => `<article><p>${esc(x.scope)}</p>${badge(x.outcome)}<p>Checked ${date(x.checked_at)} · ${link(x.source_url, 'Searched source')}</p></article>`).join('') || '<p>No persisted index check. Any available evidence comes from individually collected documents.</p>'}`;
      $('#detail').showModal();
    }),
  );
}

function renderCorrection() {
  $('#view').innerHTML =
    `<h2>Prepare a correction</h2><p>Attach a primary source and a precise product/version statement. This form saves a proposal to your device; it does not submit data or change the evidence store.</p><form id="correction-form"><div class="matrix-filters"><label>Vendor<select name="vendor">${Object.entries(
      data.vendors,
    )
      .map(([v, n]) => `<option value="${v}">${esc(n)}</option>`)
      .join(
        '',
      )}</select></label><label>CVE<input name="cve_id" required pattern="CVE-[0-9]{4}-[0-9]{4,}" placeholder="CVE-2024-6387"></label><label>Product and versions<input name="product" required maxlength="300"></label><label>Primary source URL<input name="source_url" required type="url" placeholder="https://vendor.example/advisory"></label></div><label>Suggested correction and evidence<textarea name="explanation" required rows="5" maxlength="5000" placeholder="Quote the relevant table row or describe the missing product scope, with a source locator."></textarea></label><p>Keep personal data and confidential support material out of the proposal. A maintainer must review source evidence before any assessment changes.</p><button type="submit">Download correction proposal</button><p id="correction-status" role="status"></p></form>`;
  $('#correction-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const proposal = {
      schema_version: 1,
      kind: 'assessment_correction',
      snapshot_generated_at: data.generated_at,
      created_at: new Date().toISOString(),
      ...Object.fromEntries(new FormData(e.target)),
    };
    if (!/^https:\/\//.test(proposal.source_url)) {
      $('#correction-status').textContent = 'Use an HTTPS primary source URL.';
      return;
    }
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(proposal, null, 2)], { type: 'application/json' }),
    );
    const a = document.createElement('a');
    a.href = url;
    a.download = 'impact-correction-' + proposal.cve_id + '.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    $('#correction-status').textContent = 'Proposal downloaded. No submission has been made.';
  });
}

function renderCatalogue() {
  const catalogue = data.catalogue;
  const evaluation = data.benchmark;
  const evaluated = evaluation
    ? `<p class="notice">${evaluation.passed}/${evaluation.total} declared mapping expectations matched. Global extraction precision is not estimated. ${link('/benchmark.json', 'Evaluation details')}</p>`
    : '';

  $('#view').innerHTML =
    `<h2>Vendor coverage catalogue</h2>${evaluated}${sourceAuditMarkup()}<p>Product families and exact source boundaries. Freshness describes successful collection checks, not the date a vendor last updated an advisory.</p>${(catalogue?.vendors || []).map((v) => `<article><h3>${esc(v.name)} · ${badge(v.freshness)}</h3><p>${esc(v.product_families.join('; '))}</p><p>${esc(v.history_scope)}</p><p>Expected cadence: ${v.cadence_hours} hours · Stale after ${v.stale_after_hours} hours · Last successful check: ${date(v.last_successful_check)} · ${v.current_source_errors} source error${v.current_source_errors === 1 ? '' : 's'}</p><ul>${v.known_gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul><details><summary>${v.sources.length} configured sources</summary>${v.sources.map((s) => `<p>${esc(s.role)} · ${link(s.url, 'Official source')}</p>`).join('')}</details></article>`).join('')}`;
}

let scoreVendor = '',
  timelineVendor = '',
  timelineCve = '',
  timelineLimit = 80;
function renderScorecards() {
  const cards = data.scorecards?.vendors || [];
  $('#view').innerHTML =
    `<h2>Vendor evidence scorecards</h2><p>Compare documented CVE states within this cohort. Counts overlap across products and version branches; they do not measure the proportion of a vendor’s estate affected.</p><div class="notice">No product-portfolio or installed-base denominator is available. Missing statements and failed collection remain gaps. Source health below covers configured URLs, not a complete vendor scan.</div><label>Vendor<select id="score-vendor"><option value="">All vendors</option>${cards.map((c) => `<option value="${esc(c.vendor)}" ${scoreVendor === c.vendor ? 'selected' : ''}>${esc(c.name)}</option>`).join('')}</select></label><div class="scorecard-grid">${cards
      .filter((c) => !scoreVendor || c.vendor === scoreVendor)
      .map(
        (c) =>
          `<article class="vendor-scorecard"><div class="eyebrow">${c.cohort_size} selected CVEs · ${c.configured_sources.length} configured source URLs</div><h3>${esc(c.name)}</h3><div class="scorecard-counts">${['affected', 'unaffected', 'investigating', 'fixed'].map((s) => `<div><strong>${c.status_counts[s]}</strong><span>${esc(s)}</span></div>`).join('')}<div><strong>${c.explicit_unknown}</strong><span>explicit unknown</span></div><div><strong>${c.without_statement}</strong><span>no product statement</span></div></div><p>${c.with_statement}/${c.cohort_size} CVEs have a product statement. Partial mitigation: ${c.status_counts.partially_mitigated}; conflicting: ${c.status_counts.conflicting}; recommendation-only claims: ${c.status_counts.recommended}.</p><p>Source checks: ${
            Object.entries(c.source_outcomes)
              .map(([k, v]) => `${v} ${esc(k.replaceAll('_', ' '))}`)
              .join(' · ') || 'No configured sources'
          } · ${c.stale_sources} stale checks.</p>${c.additional_source_errors?.length ? `<details><summary>${c.additional_source_errors.length} other source errors</summary><p>Discovered or historical URLs outside the configured-source denominator. Review scope and dates in Collection health.</p>${c.additional_source_errors.map((h) => `<p>${link(h.source_url, 'Source')} · ${date(h.checked_at)} · ${esc(h.error_code || 'collection error')}</p>`).join('')}</details>` : ''}<details><summary>Coverage and known gaps</summary><p>${esc(c.history_scope)}</p><p>${esc(c.product_families.join(', '))}</p><ul>${c.known_gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul>${c.configured_sources.map((s) => `<p>${link(s.source_url, 'Configured source')} · ${badge(s.outcome)} ${s.stale ? '· stale' : ''}${s.error_code ? `<small>${esc(s.error_code.replaceAll('_', ' '))}</small>` : ''}</p>`).join('')}</details><details><summary>CVE and product evidence</summary>${c.cases.map((e) => `<div class="scorecard-case"><strong>${esc(e.cve_id)}</strong><p>${e.statuses.map(badge).join(' ') || 'No product statement'} · ${esc(e.coverage_state.replaceAll('_', ' '))}</p><p>${e.product_labels.length} product labels · ${e.cve_specific_statements} CVE-specific / ${e.shared_bulletin_statements} shared-bulletin statements.</p>${e.statement_count ? `<button class="score-products" data-vendor="${esc(c.vendor)}" data-cve="${esc(e.cve_id)}">Inspect products and versions</button>` : ''}</div>`).join('')}</details></article>`,
      )
      .join('')}</div><p>${esc(data.scorecards?.method || '')}</p>`;
  $('#score-vendor').addEventListener('change', (e) => {
    scoreVendor = e.target.value;
    renderScorecards();
  });
  document.querySelectorAll('.score-products').forEach((b) =>
    b.addEventListener('click', () => {
      matrixVendor = b.dataset.vendor;
      matrixCve = b.dataset.cve;
      matrixStatus = '';
      matrixQuery = '';
      shown = 150;
      view = 'matrix';
      render();
    }),
  );
}
function renderTimeline() {
  const document = data.timeline || { events: [] };
  if (timelineCve && !selected().has(timelineCve)) timelineCve = '';
  const events = document.events.filter(
    (e) =>
      (!timelineVendor || e.vendor === timelineVendor) &&
      (!timelineCve || e.cve_id === timelineCve),
  );
  $('#view').innerHTML =
    `<h2>Evidence timeline</h2><p>Ordered by when this collector observed revisions. Publisher publication, update and reported fix dates are separate claims, shown inside each event. A first observation can occur years after publication.</p><div class="matrix-filters"><label>Vendor<select id="timeline-vendor"><option value="">All vendors</option>${Object.entries(
      data.vendors,
    )
      .map(
        ([v, n]) =>
          `<option value="${esc(v)}" ${timelineVendor === v ? 'selected' : ''}>${esc(n)}</option>`,
      )
      .join(
        '',
      )}</select></label><label>CVE<select id="timeline-cve"><option value="">All selected CVEs</option>${data.comparison.cohort.map((c) => `<option ${timelineCve === c ? 'selected' : ''}>${esc(c)}</option>`).join('')}</select></label></div><div class="notice">${document.history_truncated ? `History is truncated to ${document.revision_limit} retained revisions. ` : ''}${document.events_truncated ? `Events are truncated to ${document.event_limit}. ` : ''}Parser reinterpretations and source-view switches are labelled separately from source changes. No event establishes intent, first-ever disclosure, or verified historical fix availability.</div><p>${events.length} events in this selection; showing ${Math.min(events.length, timelineLimit)}.</p><div class="evidence-timeline">${
      events
        .slice(0, timelineLimit)
        .map(
          (e) =>
            `<article class="change"><div class="eyebrow">Observed ${date(e.observed_at)} · ${esc(name(e.vendor))} · ${esc(e.cve_id)}</div><h3>${esc(e.advisory_id)}</h3>${badge(e.kind)} ${e.document_status === 'draft' ? badge('draft') : ''}<p>${e.reference_present ? e.statuses.map(badge).join(' ') || 'CVE reference without a product statement' : 'CVE reference absent in this revision; no unaffectedness inferred.'} · ${e.product_count} product labels</p>${e.cve_reference_added ? '<p>CVE reference added between observed source revisions; earlier disclosures may exist.</p>' : ''}<details><summary>Publisher dates and source evidence</summary><dl><dt>Publisher publication date</dt><dd>${date(e.publisher_published_at)}</dd><dt>Publisher update date</dt><dd>${date(e.publisher_updated_at)}</dd><dt>Publisher reported fix date · ${esc(e.publisher_fix_date_scope.replaceAll('_', ' '))}</dt><dd>${date(e.publisher_reported_fix_date)}</dd></dl>${e.previous_statuses ? `<p>Previously retained states across this document’s products and versions: ${e.previous_statuses.map(badge).join(' ') || 'No product statement'}.</p>` : ''}<p>A reported fix date does not verify availability or applicability for every product in this document.</p><p>${link(e.source_url, 'Publisher source')} · revision ${e.revision_id} · evidence ${e.evidence_id}</p><code>${esc(e.source_sha256)}</code><p>Changed fields: ${esc(e.change_fields.join(', ') || 'No scoped semantic change recorded')}</p></details></article>`,
        )
        .join('') ||
      '<p class="empty">No retained revision events for this selection. This does not establish absence of a vendor disclosure.</p>'
    }</div>${events.length > timelineLimit ? '<button id="timeline-more">Show more events</button>' : ''}`;
  $('#timeline-vendor').addEventListener('change', (e) => {
    timelineVendor = e.target.value;
    timelineLimit = 80;
    renderTimeline();
  });
  $('#timeline-cve').addEventListener('change', (e) => {
    timelineCve = e.target.value;
    timelineLimit = 80;
    renderTimeline();
  });
  $('#timeline-more')?.addEventListener('click', () => {
    timelineLimit += 80;
    renderTimeline();
  });
}

function archiveProgress(audit) {
  const archives = audit.vendors.flatMap((v) =>
    (v.archives || []).map((a) => ({ ...a, name: v.name })),
  );
  if (!archives.length) return '<p>No historical collection sources configured.</p>';
  return `<h4>Resumable historical collection</h4><p>Counts cover links discovered from configured sources. Publisher dates describe the processed advisories; they do not prove historical download availability. Queue exhaustion does not establish full vendor coverage.</p><div class="table-wrap"><table><thead><tr><th>Source / scope</th><th>Pages processed</th><th>Documents processed</th><th>Pending / failed documents</th><th>Retained parser recovery</th><th>Publisher date range</th></tr></thead><tbody>${archives.map((a) => `<tr><td>${link(a.source_url, a.name)}<small>${esc(a.kind)} · ${a.page_limit} pages / ${a.document_limit} documents per pass</small>${(a.observed_scopes || []).length ? `<details><summary>Observed listing scope</summary>${a.observed_scopes.map((scope) => `<p>${esc(scope)}</p>`).join('')}</details>` : ''}</td><td>${a.pages.done}<small>${a.pages.pending} pending; ${a.pages.error} failed</small></td><td>${a.documents.done} / ${a.discovered_documents} discovered<small>${a.documents.not_applicable} non-CVE notices</small></td><td>${a.documents.pending} / ${a.documents.error}<small>${a.exhausted_errors} exhausted retries across pages/documents; ${a.discovery_link_gaps} missing or rejected links</small></td><td>${parserReplayMarkup(a.parser_replays)}</td><td>${a.publisher_date_range.earliest ? `${date(a.publisher_date_range.earliest)} – ${date(a.publisher_date_range.latest)}` : 'Not established'}<small>${a.current_records_without_usable_publisher_date || 0} current records without usable publisher dates</small><small>${a.known_queue_exhausted ? 'Known queue exhausted' : 'Collection incomplete'}; portfolio completeness not established</small></td></tr>`).join('')}</tbody></table></div>`;
}

function archiveSourceReviews(audit) {
  const reviews = audit.vendors.filter((v) => v.archive_source_review);
  if (!reviews.length) return '';
  return `<details><summary>Archive source decisions and access limits</summary>${reviews
    .map((v) => {
      const r = v.archive_source_review;
      return `<h4>${esc(v.name)} · ${esc(r.status.replaceAll('_', ' '))}</h4><p>Configured here: ${r.configured ? 'Yes' : 'No'}</p><p>${link(r.source_url, 'Reviewed official source')} · reviewed ${esc(r.reviewed_at)}</p><p>${esc(r.scope)}</p><ul>${r.limitations.map((limit) => `<li>${esc(limit)}</li>`).join('')}</ul><p>${esc(r.review_method)}</p>${r.evidence.map((e) => `<p>${link(e.source_url, 'Retained review response')} · first retained ${date(e.first_retained_at)}<small>${esc(e.sha256)}</small></p>`).join('')}`;
    })
    .join('')}</details>`;
}

function sourceAuditMarkup() {
  const audit = data.source_audit;
  if (!audit) return '';
  return `<h3>Retained source scope audit</h3><p>Current feed/index response sizes, exact-URL retention and extracted product records. Retained bytes do not establish successful extraction. Historical queue progress is reported separately below; current feed windows do not establish full archive coverage. ${link('/source-audit.json', 'Audit JSON')}</p>${archiveProgress(audit)}${archiveSourceReviews(audit)}<details><summary>Product-label and source-error audit</summary>${audit.vendors.map((v) => `<h4>${esc(v.name)}</h4><p>${v.observed_product_labels_count} observed product labels; these are not an exhaustive family inventory. Declared families: ${esc(v.declared_product_families.join('; ') || 'Not declared')}.</p>${v.source_errors.map((h) => `<p>${link(h.source_url, 'Failed source')} · ${esc(h.error_code || 'collection error')} · ${date(h.checked_at)}</p>`).join('') || '<p>No errors in the latest retained source checks; this does not establish complete coverage.</p>'}`).join('')}</details><div class="table-wrap"><table><thead><tr><th>Vendor / discovery</th><th>Entries in retained response</th><th>Linked documents retained</th><th>Current product advisory records matching links</th><th>Pagination / archive scope</th></tr></thead><tbody>${audit.vendors.map((v) => (v.feeds.length ? v.feeds.map((f) => `<tr><td><strong>${esc(v.name)}</strong><small>${esc(f.kind)} · ${esc(f.evidence_state.replaceAll('_', ' '))}</small></td><td>${f.entry_count ?? 'Unknown'}<small>Default feed sample: ${f.configured_limit}${f.index_benchmark_limit ? `; benchmark index cap: ${f.index_benchmark_limit}` : ''}</small></td><td>${f.raw_documents_retained ?? 'Not applicable to record API'}${f.unique_links !== null ? ` / ${f.unique_links} listed links` : ''}</td><td>${f.product_advisories_current ?? 'Not computed for record API'}</td><td>${f.next_pages.length} advertised next links; pagination ${f.pagination_followed ? 'followed in the historical queue' : 'not followed'}. Portfolio completeness not established.<details><summary>Retained response evidence</summary><p>${link(f.source_url, 'Official source')} · first retained ${date(f.source_observed_at)} · latest check ${esc(f.latest_check_outcome)}</p><code>${esc(f.source_sha256 || 'No retained fingerprint')}</code>${(f.recorded_search_scopes || []).map((scope) => `<p>${esc(scope)}</p>`).join('')}${f.next_pages.map((u) => `<p>${link(u, 'Advertised next page')}</p>`).join('')}</details></td></tr>`).join('') : `<tr><td>${esc(v.name)}</td><td colspan="4">No configured discovery feed. ${v.pinned_documents} pinned documents; ${v.release_documents} release documents. Portfolio completeness not established.</td></tr>`)).join('')}</tbody></table></div>`;
}
function renderCasefiles() {
  const files = data.casefiles?.cases || [];
  $('#view').innerHTML =
    `<h2>Disclosure research case files</h2><p>Reviewable questions with linked source fingerprints, chronology limits and alternative explanations. Exposure evidence and disclosure chronology are separate.</p><div class="notice">Every initial case has incomplete evidence. Source leads are not verified release availability, and no case establishes intentional concealment. ${link('/casefiles.json', 'All case files')}</div>${files.map((c) => `<article class="change"><div class="eyebrow">${esc(name(c.vendor))} · ${esc(c.selected_cve_ids.join(', '))}</div><h3>${esc(c.question)}</h3>${badge(c.status)}<p>${esc(c.product_scope)}</p><p>Retained publisher product statement: ${c.exposure.publisher_statement_retained ? 'Yes' : 'No'} · ${c.exposure.observed_statuses.map(badge).join(' ') || 'Unresolved in this dataset'}. Prior affectedness is not inferred from a fixed-release statement.</p><h4>Retained evidence</h4>${c.evidence.map((e) => `<p>${link(e.source_url, 'Publisher document')} · evidence ${e.evidence_id}<small>Published ${date(e.publisher_published_at)} · reported fix date ${date(e.publisher_reported_fix_date)}</small><code>${esc(e.source_sha256)}</code></p>`).join('') || '<p>No matching retained publisher evidence for this case.</p>'}${c.reported_date_gaps.map((g) => `<p>Reported date difference: ${g.days} days. ${esc(g.basis)}</p>`).join('')}${caseChronology(c)}<h4>Evidence still needed</h4><ul>${c.missing_evidence.map((g) => `<li>${esc(g)}</li>`).join('')}</ul><h4>Release-source leads</h4>${c.release_source_leads.map((u) => `<p>${link(u, 'Official source lead')} · availability not verified</p>`).join('') || '<p>No independent release-source lead registered.</p>'}<h4>Alternative explanations</h4><ul>${c.alternative_explanations.map((a) => `<li>${esc(a)}</li>`).join('')}</ul><details><summary>Traceability and review scope</summary><p>${c.timeline_event_ids.length} linked local timeline events${c.timeline_links_truncated ? ' (bounded list)' : ''}. ${c.research_record ? link('/' + c.research_record, 'Investigation record') : ''}</p><p>${esc(c.review_method)} · ${esc(c.reviewed_at)}</p><p>Independent release availability: not verified. Earliest disclosure: not established.</p></details></article>`).join('') || '<p class="empty">No registered case files match this cohort. No exposure or disclosure conclusion follows.</p>'}`;
}

function publisherHistoryMarkup(documents) {
  if (!documents?.length) return '';
  return `<h3>Publisher-reported documentation history</h3><p>These dates come from current change logs, not historical captures. They do not establish firmware availability, first disclosure or intent.</p>${documents
    .map(
      (d) =>
        `<article><h4>${esc(d.product)} ${esc(d.version || '')}</h4><p>${badge(d.state)} · ${link(d.source_url, 'Publisher change log')}</p><code>${esc(d.source_sha256)}</code><ul>${d.events
          .filter((e) => !e.cve_ids.length || e.cve_ids.some((id) => selected().has(id)))
          .map(
            (e) =>
              `<li>${esc(e.publisher_date)} · ${esc(e.kind.replaceAll('_', ' '))} · ${esc(e.cve_ids.filter((id) => selected().has(id)).join(', '))}</li>`,
          )
          .join('')}</ul></article>`,
    )
    .join('')}`;
}

function caseChronology(c) {
  return `${publisherHistoryMarkup(c.publisher_document_histories)}${(c.reported_documentation_offsets || []).map((o) => `<p>${esc(o.cve_id)}: the publisher reports adding the reference ${o.days} days after the initial document entry (${esc(o.initial_document_date)} → ${esc(o.reference_added_date)}). ${esc(o.basis)}</p>`).join('')}${(c.earlier_dated_vendor_documents || []).map((d) => `<h4>Earlier-dated vendor advisory candidate</h4><p>${link(d.source_url, 'Related vendor advisory')} · ${esc(d.publisher_published_at)} · ${esc(d.date_basis.replaceAll('_', ' '))}</p><p>${esc(d.interpretation)}</p><p>Source product labels: ${esc(d.product_labels.join('; '))}. Platform and version qualifiers require source review.</p><code>${esc(d.source_sha256)}</code>`).join('')}`;
}

function renderValidation() {
  const report = data.extraction_validation;
  if (!report) {
    $('#view').innerHTML = '<p>Source validation report unavailable.</p>';
    return;
  }
  $('#view').innerHTML =
    `<h2>Extraction validation</h2><p>${report.passed} raw-byte passes and ${report.scope_matches || 0} reviewed-section matches with changed raw sources, out of ${report.total} assertions across ${report.vendors.length} vendors and ${report.source_documents} source documents. This report covers the whole review sample, independently of the selected CVE cohort.</p><div class="notice"><strong>Independent human review pending.</strong> ${esc(report.review_method)}. Global precision is not estimated. Changed sources remain visible; only explicitly reviewed section digests can corroborate unchanged article content.</div><p>${esc(report.sample_strategy)}</p><p>${link('/extraction-validation.json', 'Full validation report')} · ${link('/review-packet.json', 'Blind independent-review packet')}</p><details><summary>Review method and limitations</summary><ul>${report.limitations.map((s) => `<li>${esc(s)}</li>`).join('')}</ul><p>The blind packet withholds expected labels and parser output. A reviewer should read the official sources and complete the packet before consulting this report.</p></details><div class="table-wrap"><table><thead><tr><th>Vendor / CVE</th><th>Source-led expectation</th><th>Current extraction</th><th>Source and review basis</th></tr></thead><tbody>${report.cases.map((c) => `<tr><td>${esc(name(c.vendor))}<small>${esc(c.cve_id)}</small></td><td>${badge(c.expected_status)}<small>${esc(c.product_pattern)}</small>${c.remediation_availability ? `<small>Remediation: ${esc(c.remediation_availability)}</small>` : ''}</td><td>${badge(c.outcome)}<small>${esc(c.observed_statuses.join(', ') || 'No reviewed matching claim')}</small></td><td>${link(c.source_url, 'Official source')}<small>${esc(c.source_locator)}</small><p>${esc(c.rationale)}</p><details><summary>Reviewed and current fingerprints</summary><code>${esc(c.source_sha256)}</code>${c.current_source_fingerprints.map((h) => `<code>${esc(h)}</code>`).join('')}</details></td></tr>`).join('')}</tbody></table></div>`;
}

let gapVendor = '',
  gapFilter = '';
function renderVendorGaps() {
  const report = data.vendor_gaps;
  if (!report) {
    $('#view').innerHTML = '<p>Vendor gap report unavailable.</p>';
    return;
  }
  const rows = report.vendors.filter(
    (v) =>
      (!gapVendor || v.vendor === gapVendor) &&
      (!gapFilter ||
        (gapFilter === 'sources' && v.source_error_count) ||
        (gapFilter === 'review' && v.review_unresolved.length) ||
        (gapFilter === 'notices' && v.without_cve_advisories)),
  );
  $('#view').innerHTML =
    `<h2>Vendor coverage and review gaps</h2><p>Whole-publication status, independent of the selected CVE cohort. A clean row does not establish complete coverage or a more secure vendor.</p><div class="notice">${esc(report.method)}</div><div class="matrix-filters"><label>Vendor<select id="gap-vendor"><option value="">All vendors</option>${report.vendors.map((v) => `<option value="${esc(v.vendor)}" ${gapVendor === v.vendor ? 'selected' : ''}>${esc(v.name)}</option>`).join('')}</select></label><label>Show<select id="gap-filter">${[
      ['', 'All gaps and coverage'],
      ['sources', 'Source errors'],
      ['review', 'Unresolved review assertions'],
      ['notices', 'Notices without CVE identifiers'],
    ]
      .map(
        ([id, label]) =>
          `<option value="${id}" ${gapFilter === id ? 'selected' : ''}>${label}</option>`,
      )
      .join(
        '',
      )}</select></label></div><p>${link('/vendor-gaps.json', 'Download coverage and gap report')}</p>${renderCoverageMatrix(rows)}<h3>Collection and review gaps</h3><div class="table-wrap"><table><thead><tr><th>Vendor / source scope</th><th>Retained documents</th><th>Collection and archive gaps</th><th>Source-led review</th></tr></thead><tbody>${rows.map((v) => `<tr><td><strong>${esc(v.name)}</strong>${badge(v.freshness)}<small>${v.configured_sources} configured sources; portfolio completeness not established</small></td><td>${v.advisories} advisories<small>${v.metadata_only_advisories} metadata-only; ${v.without_cve_advisories} without CVE identifiers</small>${v.without_cve_sources.map((s) => `<p>${link(s.source_url, s.title)}<small>Security review lead; no CVE/product exposure inferred</small></p>`).join('')}</td><td>${v.source_error_count} latest retained URL errors<small>${v.archive_pending} queued; ${v.archive_failed} failed archive items</small><details><summary>Inspect source gaps</summary>${v.source_errors.map((e) => `<p>${link(e.source_url, 'Source')} · ${esc(e.error_code.replaceAll('_', ' '))}<small>${date(e.checked_at)}</small></p>`).join('') || '<p>No errors in retained URL checks. This does not prove a complete archive.</p>'}${v.source_errors_truncated ? '<p>List bounded to 100; total count shown above.</p>' : ''}</details></td><td>${v.review_total} sampled assertions<small>${v.review_raw_passes} raw-byte passes; ${v.review_section_matches} reviewed-section matches; ${v.review_unresolved.length} unresolved</small><small>Independent human review pending</small><details><summary>Inspect unresolved assertions</summary>${v.review_unresolved.map((c) => `<p>${esc(c.cve_id)} · ${esc(c.outcome.replaceAll('_', ' '))} · ${link(c.source_url, 'Source')}</p>`).join('') || '<p>No unresolved assertions in this sample; global accuracy is not estimated.</p>'}</details></td></tr>`).join('')}</tbody></table></div>${!rows.length ? '<p class="empty">No vendors match this filter in the current publication.</p>' : ''}`;
  $('#gap-vendor').addEventListener('change', (e) => {
    gapVendor = e.target.value;
    renderVendorGaps();
  });
  $('#gap-filter').addEventListener('change', (e) => {
    gapFilter = e.target.value;
    renderVendorGaps();
  });
}

function renderCoverageMatrix(rows) {
  return `<h3>Evidence coverage matrix</h3><p>Publisher dates describe retained documents, including reposted notices. They do not establish when a vendor first disclosed a vulnerability. Configured feeds and parser capabilities do not prove complete product coverage.</p><div class="table-wrap"><table><thead><tr><th>Vendor and declared scope</th><th>Feeds and source routes</th><th>Archive depth</th><th>Retained formats and dates</th><th>Layout and access gaps</th></tr></thead><tbody>${rows
    .map((v) => {
      const c = v.coverage;
      if (!c) return '';
      return `<tr><td><strong>${esc(v.name)}</strong><small>${esc(c.declared_history_scope)}</small><details><summary>Products and declared limits</summary><p>${c.declared_product_families.map(esc).join('; ')}</p>${c.declared_gaps.map((g) => `<p>${esc(g)}</p>`).join('')}</details></td><td><details><summary>${c.configured_sources.length} configured routes</summary>${c.configured_sources.map((s) => `<p>${link(s.source_url, s.kind)} · ${esc(s.role.replaceAll('_', ' '))}${s.per_pass_limit === null ? '' : ` · ${s.per_pass_limit} documents per pass`}</p>`).join('')}</details><small>Capabilities: ${c.capabilities.map(esc).join(', ') || 'Not declared'}</small></td><td>${c.archives.map((a) => `<p>${link(a.source_url, a.kind)}<small>${a.pages.done} pages processed; ${a.pages.pending} pages pending; ${a.pages.error} pages failed; ${a.documents.done} documents retained; ${a.documents.pending} pending; ${a.documents.error} failed</small><small>Budget: ${a.page_limit} pages / ${a.document_limit} documents per pass. Known queue ${a.known_queue_exhausted ? 'exhausted' : 'not exhausted'}; portfolio completeness not established.</small></p>`).join('') || '<p>No enabled archive source.</p>'}</td><td>${c.observed_formats.map((f) => `<small>${esc(f.format)}: ${f.advisories}</small>`).join('') || 'No normalized documents'}<small>Publisher dates: ${date(c.publisher_date_range.earliest)} to ${date(c.publisher_date_range.latest)}</small><small>${c.documents_without_publisher_date} without a usable publisher date</small></td><td>${c.unsupported_sources} unsupported or invalid source URLs<small>${c.access_blocked_sources} access-blocked source URLs; ${c.other_error_sources} other or unclassified errors</small><small>Latest retained checks; successful layouts do not establish all layouts are supported.</small></td></tr>`;
    })
    .join('')}</tbody></table></div>`;
}

let familyVendor = '',
  familyUnknown = false;
function renderFamilies() {
  const report = data.family_completeness;
  if (!report) {
    $('#view').innerHTML = '<p>Family evidence report unavailable.</p>';
    return;
  }
  const rows = report.families.filter(
    (f) =>
      (!familyVendor || f.vendor === familyVendor) &&
      (!familyUnknown ||
        f.state === 'unknown' ||
        f.train_references.some((t) => t.state === 'unknown')),
  );
  $('#view').innerHTML =
    `<h2>Product-family evidence completeness</h2><div class="notice">${esc(report.method)}</div><div class="matrix-filters"><label>Vendor<select id="family-vendor"><option value="">All vendors</option>${Object.entries(
      data.vendors,
    )
      .map(
        ([v, n]) =>
          `<option value="${esc(v)}" ${v === familyVendor ? 'selected' : ''}>${esc(n)}</option>`,
      )
      .join(
        '',
      )}</select></label><label><input id="family-unknown" type="checkbox" ${familyUnknown ? 'checked' : ''}> Show unknown families or selected train references</label></div><p>${link('/family-completeness.json', 'Download family evidence report')}</p><div class="table-wrap"><table><thead><tr><th>Family</th><th>Retained statements</th><th>Selected release-line references</th><th>Evidence and unresolved scope</th></tr></thead><tbody>${rows
      .map(
        (f) =>
          `<tr><td><strong>${esc(name(f.vendor))} · ${esc(f.name)}</strong>${badge(f.state.replaceAll('_', ' '))}<small>Inventory completeness not established</small></td><td>${f.advisories} advisories; ${f.cves} CVEs<small>${f.explicit_statements} CVE-specific; ${f.shared_statements} shared-scope statements</small><small>${Object.entries(
            f.statuses,
          )
            .map(([s, n]) => `${esc(s)}: ${n}`)
            .join(
              '; ',
            )}</small></td><td>${f.train_references.map((t) => `<small>${esc(t.train)}: ${esc(t.state)} (${t.statements} statements)</small>`).join('') || 'No selected train expectations declared'}<small>A reference does not establish full train coverage.</small></td><td>${f.version_scope_unresolved} statements without usable version scope<small>${f.vendor_source_errors} vendor-wide source errors; family attribution unresolved</small><details><summary>Retained publisher sources</summary>${f.evidence.map((e) => `<p>${link(e.source_url, 'Source')}<small>Publisher ${date(e.publisher_date)}; captured ${date(e.observed_at)}</small><code>${esc(e.source_sha256)}</code></p>`).join('') || '<p>No matching retained family evidence. This does not mean unaffected.</p>'}</details></td></tr>`,
      )
      .join('')}</tbody></table></div><p>Unmapped statements: ${Object.entries(
      report.unmapped_statements,
    )
      .map(([v, n]) => `${esc(name(v))}: ${n}`)
      .join('; ')}. Mixed platform classes and unreviewed product names remain unresolved.</p>`;
  $('#family-vendor').addEventListener('change', (e) => {
    familyVendor = e.target.value;
    renderFamilies();
  });
  $('#family-unknown').addEventListener('change', (e) => {
    familyUnknown = e.target.checked;
    renderFamilies();
  });
}

function renderReadiness() {
  const report = data.comparison_readiness;
  if (!report) {
    $('#view').innerHTML = '<p>Comparison readiness unavailable.</p>';
    return;
  }
  $('#view').innerHTML =
    `<h2>Vendor comparison readiness</h2><div class="notice">${esc(report.method)}</div><p>${esc(report.cohort_design)} These plans use their predeclared cohort regardless of the browser cohort selector.</p><p>${link('/comparison-readiness.json', 'Download predeclared cohort plans')}</p>${report.plans
      .map(
        (p) =>
          `<article class="change"><h3>${esc(p.name)}</h3>${badge(p.state)}${
            p.protocol
              ? `<details><summary>Comparison protocol and confounders</summary>${Object.entries(
                  p.protocol,
                )
                  .map(
                    ([k, v]) =>
                      `<p><strong>${esc(k.replaceAll('_', ' '))}</strong>: ${esc(Array.isArray(v) ? v.join('; ') : v)}</p>`,
                  )
                  .join('')}</details>`
              : ''
          }<p>${p.cohort.length} common CVEs; ${esc(p.period.start)} to ${esc(p.period.end)}. Latest retained statements grouped by initial advisory date; not an as-of history.</p><p>${p.requirements.map((r) => `${esc(r.code.replaceAll('_', ' '))}: ${esc(r.state)}`).join(' · ')}</p><div class="table-wrap"><table><thead><tr><th>Family</th><th>Explicit case assessments</th><th>Gaps</th><th>Readiness blockers</th></tr></thead><tbody>${p.members.map((m) => `<tr><td>${esc(name(m.vendor))} · ${esc(m.name)}</td><td>${m.explicit_cases} of ${p.cohort.length} reference cases<small>Evidence cells, not a vulnerability rate.</small></td><td>${m.unknown_or_unresolved_cases} unknown, shared-only or unresolved<small>${m.undated_statements_excluded} undated statements excluded</small></td><td>${m.reason_codes.map((r) => `<small>${esc(r.replaceAll('_', ' '))}</small>`).join('')}<details><summary>Inspect common CVE cells</summary>${m.cases.map((c) => `<p>${esc(c.cve_id)} · ${esc(c.state.replaceAll('_', ' '))} · ${c.statuses.map(esc).join(', ') || 'No statement'}</p>${(c.evidence || []).map((e) => `<p>${link(e.source_url, e.product)} · ${esc(e.status)} / ${esc(e.scope)}<small>${esc(e.period_state)} · publisher ${date(e.publisher_date_claim)} · captured ${date(e.observed_at)}</small><small>${e.platforms.map(esc).join('; ')} ${e.version_scope.map(esc).join('; ')} · ${esc(e.evidence_locator || 'No locator supplied')}</small><code>${esc(e.source_sha256)}</code></p>`).join('')}${c.evidence_truncated ? '<p>Evidence examples truncated to twenty statements.</p>' : ''}`).join('')}</details></td></tr>`).join('')}</tbody></table></div></article>`,
      )
      .join('')}`;
}

function renderComponentSource(source) {
  const history = source.retrieval_history;
  const references =
    Object.entries(source.components)
      .map(([component, versions]) => `${esc(component)}: ${versions.map(esc).join(', ')}`)
      .join('; ') || 'No explicit component-version references in reviewed sections.';
  const alignment =
    source.latest_retrieval_matches_analyzed_snapshot === null
      ? 'no logged check'
      : source.latest_retrieval_matches_analyzed_snapshot
        ? 'yes'
        : 'no; review collection health';
  const checks =
    history && history.logged_checks > 0
      ? `<p>${history.logged_checks} successful check${history.logged_checks === 1 ? '' : 's'} logged; ${history.distinct_fingerprints} raw fingerprint${history.distinct_fingerprints === 1 ? '' : 's'}; ${history.same_as_previous_checks} same as previous; ${history.http_304_checks} HTTP 304.</p>
       <p><small>Logging began ${date(history.first_logged_check_at)}; latest ${date(history.last_logged_check_at)}. Latest logged retrieval matches this analyzed snapshot: ${alignment}.</small></p>
       <details><summary>Inspect retrieval checks</summary>${history.checks.map((check) => `<p>${date(check.checked_at)} · HTTP ${check.http_status} · ${esc(check.content_state.replaceAll('_', ' '))}<small>${esc(check.source_sha256)}</small></p>`).join('')}${history.checks_truncated ? '<p>Latest twelve checks shown.</p>' : ''}<p>${esc(history.method)}</p></details>`
      : '<p><small>No retrieval checks have been logged for this source; earlier checks remain unknown.</small></p>';
  return `<article class="change"><h4>${esc(name(source.vendor))} · ${esc(source.product)}</h4>
    <p>${source.snapshots} retained revision${source.snapshots === 1 ? '' : 's'} shown (up to two) · ${esc(source.analysis_state.replaceAll('_', ' '))}</p>
    <p>${esc(source.component_scope || 'Patch and deployment scope unverified.')}</p>
    <p>${references}</p>${checks}
    <p>${link(source.source_url, 'Component/release source')} · analyzed capture ${date(source.current_evidence.observed_at)}</p>
    <code>${esc(source.current_evidence.source_sha256)}</code></article>`;
}

function renderFixLeads() {
  const report = data.fix_leads;
  if (!report) {
    $('#view').innerHTML = '<p>Fix-lead report unavailable.</p>';
    return;
  }
  $('#view').innerHTML =
    `<h2>Potential security-fix investigation leads</h2><div class="notice">${esc(report.method)}</div><p>${link('/fix-leads.json', 'Download dated leads and analysis gaps')}</p>${report.leads.map((l) => `<article class="change"><div class="eyebrow">${esc(name(l.vendor))} · ${esc(l.kind.replaceAll('_', ' '))}</div><h3>${esc(l.product)}</h3>${badge(l.state.replaceAll('_', ' '))}<p>${esc(l.details)}</p><p>${l.cve_ids.map(esc).join(', ') || 'No CVE linkage established'}${l.component ? ` · ${esc(l.component)}` : ''}</p><h4>Dated retained evidence</h4>${l.evidence.map((e) => `<p>${link(e.source_url, 'Publisher source')}<small>Local observation ${date(e.observed_at)}; publisher date claim ${date(e.publisher_date_claim)}</small><code>${esc(e.source_sha256)}</code></p>`).join('')}<h4>Alternative explanations</h4><ul>${l.alternative_explanations.map((a) => `<li>${esc(a)}</li>`).join('')}</ul><h4>Evidence still needed</h4><ul>${l.missing_evidence.map((a) => `<li>${esc(a)}</li>`).join('')}</ul><p>Concealment: not established. No prior product exposure or public fix availability inferred.</p></article>`).join('') || '<p>No leads established from the currently eligible sources. This does not establish absence of security fixes.</p>'}<h3>Component references and source gaps</h3><p>Distinct retained content revisions are counted below. Repeated unchanged checks do not create a new revision. Different product branches are never treated as before/after snapshots. Successful HTTP checks are logged separately from content revisions; logging does not reconstruct earlier availability or establish parser validity.</p>${report.sources.map(renderComponentSource).join('')}<details><summary>${report.analysis_gaps.length} analysis gaps</summary>${report.analysis_gaps.map((g) => `<p>${esc(name(g.vendor))} · ${link(g.source_url, 'Source')} · ${esc(g.reason.replaceAll('_', ' '))}</p>`).join('')}</details>`;
}

function renderComponentStudies() {
  const report = data.component_studies;
  if (!report) {
    $('#view').innerHTML = '<p>Component study report unavailable for this publication.</p>';
    return;
  }
  const labels = {
    unknown_no_retained_family_assessment: 'No family assessment retained',
    vendor_reference_without_family_assessment: 'Vendor reference; family unresolved',
    shared_bulletin_only: 'Shared bulletin only',
    scope_requires_review: 'Scope requires review',
    explicit_affected_statement: 'Affected statement',
    explicit_partial_mitigation_statement: 'Partial mitigation statement',
    explicit_unaffected_statement: 'Unaffected statement',
    fixed_statement_without_prior_exposure_inference: 'Fixed statement; prior exposure unknown',
    assessment_unresolved: 'Assessment unresolved',
  };
  $('#view').innerHTML =
    `<h2>Component reference studies</h2><div class="notice">${esc(report.method)}</div><p>${link('/component-studies.json', 'Download frozen enrollment, evidence and source drift')}</p>${report.studies
      .map((study) => {
        const reference = study.reference_status;
        const source = reference.source;
        const excluded = study.candidate_reviews.filter(
          (candidate) => candidate.enrollment === 'excluded',
        );
        return `<article class="change"><div class="eyebrow">${esc(study.component)} · ${esc(study.cohort_version)}</div><h3>${esc(study.name)}</h3><p>${study.included_cves.length} enrolled CVEs · ${excluded.length} explicit exclusions · ${study.members.length} selected product families. Independent human review pending.</p><p>Registry publication window: ${esc(study.period.start)} to ${esc(study.period.end)}. Current retained vendor statements are shown; this is not a historical exposure reconstruction.</p><p>${esc(study.design)}</p><details><summary>Enrollment rule, scope and fingerprint</summary><p>${esc(study.selection_rule)}</p><p>Frozen ${date(study.frozen_at)} · ${link(study.baseline_source_url, 'Official registry query')}</p><p>Current family matcher: ${esc(study.family_catalogue_version)}. Matcher refinements are separate from frozen CVE enrollment.</p><code>${esc(study.family_scope_sha256)}</code><p>Cohort fingerprint</p><code>${esc(study.cohort_sha256)}</code><p>Baseline response fingerprint</p><code>${esc(study.baseline_source_sha256)}</code><p>Registry mappings do not prove a shipped dependency, enabled service or appliance affectedness. NVD publication dates are publisher metadata claims. This candidate catalogue may omit upstream vulnerabilities.</p></details><h4>Current reference check</h4><p>${esc(reference.state.replaceAll('_', ' '))}. Enrollment stays frozen when the source changes.</p>${source ? `<p>${link(source.source_url, 'Official reference source')} · retained ${date(source.source_observed_at)}; latest collection ${date(source.collection?.checked_at)} · ${esc(source.collection?.outcome || 'No collection check retained')}${source.collection?.error_code ? ` · ${esc(source.collection.error_code)}` : ''}</p><code>${esc(source.source_sha256)}</code>` : '<p>The frozen baseline is recorded, but this vault has no independently collected current reference response.</p>'}${reference.added_candidates.length || reference.removed_candidates.length || reference.changed_candidates.length ? `<p>Added candidates: ${esc(reference.added_candidates.join(', ') || 'None')}. Removed candidates: ${esc(reference.removed_candidates.join(', ') || 'None')}. Changed candidate semantics: ${esc(reference.changed_candidates.join(', ') || 'None')}. Review is required before any enrollment revision.</p>` : ''}<h4>Vendor family statements</h4><p>Every label describes retained publisher evidence. Unknown cells remain unknown. Different affected and unaffected branches require scope review. Open a cell for literal product and version references; configuration prerequisites require the linked source.</p><div class="table-wrap"><table><thead><tr><th>CVE / variant qualification</th>${study.members.map((member) => `<th>${esc(name(member.vendor))}<small>${esc(member.name)}</small></th>`).join('')}</tr></thead><tbody>${study.included_cves
          .map((cid) => {
            const candidate = study.candidate_reviews.find((row) => row.cve_id === cid);
            return `<tr><th>${esc(cid)}<small>${esc(candidate.role.replaceAll('_', ' '))}</small><small>${esc(candidate.variant_scope.replaceAll('_', ' '))}</small></th>${study.members
              .map((member) => {
                const cell = study.cells.find(
                  (row) => row.cve_id === cid && row.family_id === member.id,
                );
                if (!cell) return '<td>Vendor unavailable in this publication</td>';
                return `<td>${esc(labels[cell.state] || cell.state)}${cell.evidence.length ? `<details><summary>${cell.statements} publisher statement${cell.statements === 1 ? '' : 's'}</summary>${cell.evidence.map((evidence) => `<p><strong>${esc(evidence.product)}</strong> · ${esc(evidence.status)} · ${esc(evidence.scope.replaceAll('_', ' '))}</p><p>${esc(evidence.platforms.join('; ') || 'Platform equivalence unverified')}</p><p>Literal versions: ${esc(JSON.stringify(evidence.versions))}</p><p>Product context: ${esc(JSON.stringify(evidence.product_context))}</p><p>${esc(evidence.evidence_locator || 'Review the original product section')}. Exposure context retained by parser: ${evidence.exposure_context_present ? 'yes; review source prerequisites' : 'not supplied; prerequisites remain unverified'}.</p><p>${link(evidence.source_url, evidence.advisory_id)} · publisher date ${date(evidence.publisher_published_at)} · retained ${date(evidence.source_observed_at)}</p><code>${esc(evidence.source_sha256)}</code>`).join('')}${cell.evidence_truncated ? '<p>Latest dataset order bounded to twelve statements; count includes all matching statements.</p>' : ''}<p>Product-build equivalence and deployment exposure are not verified.</p></details>` : ''}</td>`;
              })
              .join('')}</tr>`;
          })
          .join(
            '',
          )}</tbody></table></div><details><summary>${excluded.length} excluded candidates and their reasons</summary>${excluded.map((candidate) => `<p>${esc(candidate.cve_id)} · ${esc(candidate.role)} · ${esc(candidate.reason.replaceAll('_', ' '))}</p>`).join('')}<p>Exclusion defines this service study's scope; it does not establish vendor unaffectedness.</p></details><h4>Comparison prerequisites</h4><ul>${study.blockers.map((blocker) => `<li>${esc(blocker)}</li>`).join('')}</ul><p>Affectedness rates are suppressed. Vendor ranking and intentional concealment are not established.</p></article>`;
      })
      .join('')}`;
}

function sourceSelectionMarkup(audit) {
  const selections = audit.source_selections || [];
  if (!selections.length) return '';
  return `<h3>Reviewed publisher representation choices</h3><p>The selected source supplies normalized statements. Alternate captures remain linked for review. Counts describe statements, not unique products or exposure rates.</p>${selections.map((selection) => `<article class="change"><h4>${esc(name(selection.vendor))} · ${link(selection.requested_url, 'Requested advisory')}</h4><p>${esc(selection.reason)}</p><p>Selection logged ${date(selection.selected_at)}.</p>${selection.views.map((source) => `<p><strong>${source.selected ? 'Selected' : 'Alternative'}: ${esc(source.source_format)}</strong> · ${source.normalized_statements} normalized statements · ${link(source.source_url, 'Publisher representation')}</p><p><small>Capture ${date(source.source_observed_at)} · parser ${esc(source.adapter_version)}</small></p><code>${esc(source.source_sha256)}</code>`).join('')}${selection.unavailable.map((issue) => `<p>Alternative unavailable: ${link(issue.source_url, 'Publisher representation')} · ${esc(issue.error_code)}. The validated selected source remains retained; review collection health for the failed check.</p>`).join('')}</article>`).join('')}`;
}

function parserReplayMarkup(report) {
  if (!report || !report.attempts) return 'No parser replays logged; earlier activity unknown';
  return `${report.recovered} recovered; ${report.not_applicable} outside scope<small>${report.still_unsupported} still unsupported; ${report.not_retained} not retained</small><details><summary>${report.attempts} logged offline attempts</summary><p>${esc(report.method)}</p>${report.examples.map((item) => `<p>${link(item.requested_url, 'Retained source')} · ${esc(item.outcome.replaceAll('_', ' '))}<small>Processed ${date(item.checked_at)} · parser ${esc(item.parser_version)}</small></p>${item.source_sha256 ? `<p>Capture ${date(item.source_observed_at)}</p><code>${esc(item.source_sha256)}</code>` : '<p>Selected capture metadata unavailable for this attempt.</p>'}${item.error_code ? `<p>${esc(item.error_code)}</p>` : ''}`).join('')}${report.examples_truncated ? '<p>Latest ten attempts shown.</p>' : ''}</details>`;
}

function renderProductCohorts() {
  const report = data.product_cohorts;
  if (!report) {
    $('#view').innerHTML = '<p>Product cohorts unavailable for this publication.</p>';
    return;
  }
  $('#view').innerHTML =
    `<h2>Product cohorts</h2><div class="notice">${esc(report.method)}</div><p>${link('/product-cohorts.json', 'Download product scopes and source coverage')}</p><p>${esc(report.definition.design)}</p><details><summary>Scope version and fingerprint</summary><p>${esc(report.definition.version)}</p><code>${esc(report.definition.definition_sha256)}</code></details><h3>Component evidence by vendor</h3><p>These counts describe retained source references. They do not measure component inventory completeness or vendor security.</p><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Sources with component references</th><th>Analyzed release sources</th><th>Vendor source errors</th></tr></thead><tbody>${report.component_source_coverage.map((r) => `<tr><td>${esc(name(r.vendor))}</td><td>${r.sources_with_component_references}</td><td>${r.analyzed_sources}</td><td>${r.source_errors}</td></tr>`).join('')}</tbody></table></div>${report.cohorts
      .map(
        (c) =>
          `<article class="change"><h3>${esc(c.name)}</h3><p>Research period: ${esc(c.period.start)} to ${esc(c.period.end)}. ${c.selected_scope_units} selected product scopes; confirmed build denominator unavailable. Comparisons blocked.</p>${c.units
            .map((r) => {
              const t = r.target;
              return `<details><summary>${esc(name(r.vendor))} · ${esc(r.name)}${t.release_train ? ` · ${esc(t.release_train)}` : ''}</summary><p>Targets: firmware build ${esc(t.firmware_build || 'unspecified')}; hardware ${esc(t.hardware_model || 'unspecified')}; deployment ${esc(t.deployment || 'unspecified')}. ${esc(t.service.name)} enabled: ${t.service.enabled === null ? 'unknown' : t.service.enabled ? 'targeted enabled' : 'targeted disabled'}. Support window: ${esc(t.support_window ? `${t.support_window.start} to ${t.support_window.end}` : 'unknown')}.</p><h4>Bound component references</h4>${r.component_evidence.map((e) => `<p>${link(e.source_url, 'Publisher source')} · retained ${date(e.observed_at)}</p><p>${esc(e.component_scope)}</p><p>${esc(JSON.stringify(e.components))}</p><p>${esc(e.locators.join('; '))}</p><code>${esc(e.source_sha256)}</code><p>Latest successful retrieval matches analyzed snapshot: ${e.latest_retrieval_matches_analyzed_snapshot === null ? 'unknown' : e.latest_retrieval_matches_analyzed_snapshot ? 'yes' : 'no; source review needed'}.</p>`).join('') || '<p>No component reference is bound to this product scope. Other products from the same vendor cannot fill this gap.</p>'}${r.source_checks.map((s) => `<p>${link(s.source_url, 'Source check')} · ${esc(s.outcome)} · ${date(s.checked_at)}${s.error_code ? ` · ${esc(s.error_code)}` : ''}</p>`).join('')}<h4>Still needed</h4><ul>${r.missing_dimensions.map((m) => `<li>${esc(m.replaceAll('_', ' '))}</li>`).join('')}</ul><p>Targets define research scope; they are not verified product facts. No affectedness rate is calculated.</p></details>`;
            })
            .join('')}</article>`,
      )
      .join('')}`;
}

function renderDisclosureReview() {
  const report = data.disclosure_review;
  if (!report) {
    $('#view').innerHTML = '<p>Disclosure review unavailable for this publication.</p>';
    return;
  }
  $('#view').innerHTML =
    `<h2>Disclosure review queue</h2><div class="notice">${esc(report.method)}</div><p>${link('/disclosure-review.json', 'Download investigation queue')}</p>${report.leads_truncated ? '<p>Lead list is bounded; additional candidates may be omitted.</p>' : ''}${report.cases.map((c) => `<article class="change"><div class="eyebrow">${esc(name(c.vendor))} · ${esc(c.kind.replaceAll('_', ' '))}</div><h3>${esc(c.product)}</h3><p>${esc(c.details)}</p><p>${esc(c.cve_ids.join(', ') || 'CVE linkage not established')}</p><p>Next: ${esc(c.next_action.replaceAll('_', ' '))}. Independent review pending.</p>${c.evidence.map((e) => `<p>${link(e.source_url, 'Retained source')} · captured ${date(e.observed_at)} · publisher date claim ${date(e.publisher_date_claim)}</p><code>${esc(e.source_sha256)}</code>`).join('')}<h4>Earlier-document counter-evidence</h4>${c.earlier_document_counter_evidence.map((e) => `<p>${link(e.source_url, 'Earlier-dated publisher document')} · publisher date claim ${date(e.publisher_date_claim)}</p><code>${esc(e.source_sha256)}</code><p>This date claim does not establish historical availability.</p>`).join('') || '<p>No related earlier document is linked here. This is not an exhaustive search for earlier disclosure.</p>'}<h4>Evidence gates</h4><ul>${c.checklist.map((q) => `<li>${esc(q.question)} <strong>Not established by this queue.</strong></li>`).join('')}</ul><h4>Alternative explanations</h4><ul>${c.alternative_explanations.map((a) => `<li>${esc(a)}</li>`).join('')}</ul><p>Concealment is not established.</p></article>`).join('') || '<p>No eligible leads in this publication. This does not establish absence of undocumented security changes.</p>'}`;
}
