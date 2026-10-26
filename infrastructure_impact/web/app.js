const $ = (s) => document.querySelector(s);
const esc = (v) =>
  String(v ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
  );
const date = (v) => {
  if (!v) return 'Not supplied';
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
    ['Vendors collected', new Set(data.records.map((r) => r.vendor)).size],
    ['Evidence snapshots', c.evidence_snapshots],
  ]
    .map(([l, n]) => `<div><strong>${n}</strong><span>${l}</span></div>`)
    .join('');
}
async function load() {
  $('#feedback').textContent = 'Loading evidence…';
  try {
    const suffix = selectedCves ? '?cves=' + encodeURIComponent(selectedCves.join(',')) : '';
    const response = await fetch('/api/state' + suffix);
    if (!response.ok) throw Error('Could not load the evidence store');
    data = await response.json();
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
    scorecards: renderScorecards,
    timeline: renderTimeline,
    correction: renderCorrection,
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
          `<tr><td>${esc(name(r.vendor))}<br><code>${esc(a.cve_id)}</code></td><td><strong>${esc(a.product_family || a.product)}</strong>${a.product_family ? `<small>${esc(a.product)}</small>` : ''}${a.versions?.length ? `<div class="versions">${a.versions.map((v) => esc(v.expression || `${v.version} ${v.status || ''}${v.lessThan ? ' · below ' + v.lessThan : ''}${v.lessThanOrEqual ? ' · through ' + v.lessThanOrEqual : ''}`)).join('<br>')}</div>` : ''}${r.document_status === 'draft' ? '<span class="draft">DRAFT SOURCE</span>' : ''}</td><td>${badge(a.status)}<small>${a.scope === 'bulletin_shared' ? 'Shared bulletin' : 'CVE-specific statement'}</small></td><td>${fixSummary(a)}</td><td><button class="text-button" data-detail="${i}">View evidence ↗</button><small>${esc(r.source_format)}</small></td></tr>`,
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
function renderComparison() {
  const c = data.comparison;
  $('#view').innerHTML =
    `<h2>Compare the same CVE cohort</h2><p>These counts describe imported evidence. They cannot establish which vendor is inherently more secure.</p><div class="notice">${esc(c.method)} ${c.draft_advisories_excluded} draft advisory documents excluded.</div><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Assessed / selected CVEs</th><th>Any affected / partially mitigated product</th><th>Any unaffected product</th><th>Investigating</th><th>Fixed versions reported</th><th>No assessment in dataset</th></tr></thead><tbody>${c.vendors.map((v) => `<tr><td><strong>${esc(v.name)}</strong>${v.has_imported_advisories ? '' : '<small>No imported advisory</small>'}</td><td>${v.assessed_cves} / ${v.cohort_size}</td><td><strong class="amber">${v.affected_cves}</strong><small>${v.explicit_affected_cves} CVE-specific · ${v.shared_bulletin_affected_cves} shared-bulletin (may overlap)</small></td><td>${v.unaffected_cves}</td><td>${v.investigating_cves}</td><td>${v.fixed_cves}</td><td>${v.no_assessment_in_dataset}</td></tr>`).join('')}</tbody></table></div><details class="method" open><summary>How to interpret vendor comparisons</summary><ul>${c.limitations.map((l) => `<li>${esc(l)}</li>`).join('')}</ul><p>These are overlapping CVE counts, not product totals or percentages of a vendor’s estate. A vendor can have affected and unaffected products for the same CVE. Missing sources remain missing data.</p></details><h3>Dated advisory observations</h3><p>Earliest dated advisory in this sample relative to upstream CVE publication. This is not vendor response time from private notification, and earlier disclosures may exist.</p><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>CVE</th><th>Calendar-day difference</th><th>Evidence</th></tr></thead><tbody>${data.delays.map((d) => `<tr><td>${esc(name(d.vendor))}</td><td><code>${esc(d.cve_id)}</code></td><td>${d.days}</td><td>${link(d.advisory_source, 'Vendor')} · ${link(d.upstream_source, 'Upstream')}</td></tr>`).join('')}</tbody></table></div>${!data.delays.length ? '<p class="empty">No comparable upstream publication dates have been collected for this cohort.</p>' : ''}`;
}
function renderReview() {
  const reviewSignals = data.signals.filter(
    (s) => !s.cve_id || s.cve_id.split(/[,\s]+/).some((c) => selected().has(c)),
  );
  $('#view').innerHTML =
    `<h2>Disclosure evidence review</h2><p>Investigate observable disclosure patterns. These signals do not establish intent or prove that a vendor concealed a vulnerability.</p><div class="review-types"><article><h3>Fix before a collected advisory</h3><p>Requires reviewed release evidence and a specific CVE, product, and fixed-version link. A future ETA is insufficient.</p></article><article><h3>CVE added in a later revision</h3><p>Compares locally observed source revisions. Parser changes are tracked separately.</p></article><article><h3>Security change without a CVE</h3><p>Flags security language in collected release notes lacking CVE references. It may describe hardening or an issue without a CVE.</p></article></div><div class="notice">Release-note collection must be configured per product. ${data.research.release_documents.length} release-note documents, ${(data.research.release_assets || []).length} dated release listings and ${data.research.fix_candidates.length} independently registered fix candidates are collected across the dataset. Signals below follow the selected cohort. No comprehensive release-note or binary analysis has been performed. Zero signals means no qualifying evidence in this dataset.</div><h3>Independent release-listing metadata</h3><p>These records identify builds, platforms, publisher dates and artifact checksums. They do not establish CVE applicability, historical availability or download entitlement.</p><div class="table-wrap"><table><thead><tr><th>Product / build</th><th>Platforms</th><th>Publisher date</th><th>Publisher artifact SHA-256</th><th>Source</th></tr></thead><tbody>${(data.research.release_assets || []).map((a) => `<tr><td>${esc(a.product)}<small>${esc(a.version)}</small></td><td>${esc(a.platforms.join(', '))}</td><td>${esc(a.reported_published_at)}</td><td><code>${esc(a.artifact_sha256)}</code></td><td>${link(a.source_url, 'Listing')}</td></tr>`).join('')}</tbody></table></div><div class="signal-list">${reviewSignals.map((s) => `<article><div class="eyebrow">${esc(name(s.vendor))} / ${esc(s.confidence)}</div><h3>${esc(s.kind.replaceAll('_', ' '))}</h3><p>${esc(s.product || '')} ${esc(s.cve_id || '')}</p><p>${esc(s.explanation)}</p>${s.excerpt ? `<blockquote>${esc(s.excerpt)}</blockquote>` : ''}${s.released_at ? `<p>${s.confidence === 'unverified_release_date_candidate' ? 'Reported firmware date' : 'Reviewed release date'}: ${date(s.released_at)} · advisory: ${date(s.advisory_date)}</p>` : ''}${link(s.source_url, 'Evidence source')}${s.kind === 'reported_firmware_date_predates_bulletin' ? `<p>${link('/research/hpe-timing-investigation.txt', 'Read investigation record')}</p>` : ''}${s.details ? `<pre>${esc(JSON.stringify(s.details, null, 2))}</pre>` : ''}</article>`).join('') || '<p class="empty">No qualifying disclosure signals collected. No claim about hidden exposure can be made.</p>'}</div>`;
}
function renderChanges() {
  $('#view').innerHTML =
    `<h2>Observed source changes</h2><p>Changes are detected between local snapshots. Vendor-supplied historical timelines are retained in the evidence; they are not treated as observations made by this collector.</p>${data.changes.map((c) => `<article class="change"><div class="eyebrow">${date(c.observed_at)} · ${esc(name(c.vendor))}</div><h3>${esc(c.advisory_id)}</h3>${badge(c.kind)}<details><summary>Inspect changes</summary>${link('/api/changes/' + c.id, 'Complete archived diff')}<pre>${esc(JSON.stringify(c.details, null, 2))}</pre></details></article>`).join('') || '<p class="empty">No changes observed yet. Run the collector again after sources update.</p>'}`;
}
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
  const collectorSummary = `<div class="notice">${scheduleText} ${delivery} ${run ? `Last pass: ${esc(run.outcome)} · finished ${date(run.finished_at)} · ${run.failures} failed source checks.` : 'No completed pipeline receipt collected.'}</div>`;
  $('#view').innerHTML =
    `<h2>Collection history and coverage</h2>${collectorSummary}<p>Latest attempt per source URL, including historical attempts from earlier configurations. A failed fetch does not imply a missing vendor disclosure.</p><div class="notice">${Object.keys(data.vendors).length} vendors are on the installed roster. Collection coverage varies by configured feeds, indexes, curated documents and plugin capabilities. Article shells, empty CSAF envelopes and parse failures remain gaps. This is not a complete portfolio scan.</div><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Result</th><th>Checked</th><th>Source / collection scope</th></tr></thead><tbody>${data.health.map((h) => `<tr><td>${esc(name(h.vendor))}</td><td>${badge(h.outcome)}${h.error_code ? `<small>${esc(h.error_code.replaceAll('_', ' '))}</small>` : ''}</td><td>${date(h.checked_at)}</td><td>${link(h.source_url, 'Source')}<small>${esc(h.details)}</small></td></tr>`).join('')}</tbody></table></div>`;
}
document.querySelectorAll('[data-view]').forEach((b) =>
  b.addEventListener('click', () => {
    view = b.dataset.view;
    if (data) render();
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
    `<h2>Vendor coverage catalogue</h2>${evaluated}<p>Product families and exact source boundaries. Freshness describes successful collection checks, not the date a vendor last updated an advisory.</p>${(catalogue?.vendors || []).map((v) => `<article><h3>${esc(v.name)} · ${badge(v.freshness)}</h3><p>${esc(v.product_families.join('; '))}</p><p>${esc(v.history_scope)}</p><p>Expected cadence: ${v.cadence_hours} hours · Stale after ${v.stale_after_hours} hours · Last successful check: ${date(v.last_successful_check)} · ${v.current_source_errors} source error${v.current_source_errors === 1 ? '' : 's'}</p><ul>${v.known_gaps.map((g) => `<li>${esc(g)}</li>`).join('')}</ul><details><summary>${v.sources.length} configured sources</summary>${v.sources.map((s) => `<p>${esc(s.role)} · ${link(s.url, 'Official source')}</p>`).join('')}</details></article>`).join('')}`;
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
