/* Descriptive reader only. Selection and CSV semantics remain in switching.js. */
(() => {
  const esc = (v) =>
    String(v ?? '').replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
    );
  const text = (v) => esc(v == null ? 'unknown' : v);
  function link(url, label) {
    try {
      const u = new URL(url);
      if (u.protocol !== 'https:' || u.username || u.password)
        return esc(label) + ' (link unavailable)';
      return `<a href="${esc(u.href)}" target="_blank" rel="noopener noreferrer">${esc(label)} ↗</a>`;
    } catch {
      return esc(label) + ' (link unavailable)';
    }
  }
  const source = (s) =>
    s
      ? `<p>${link(s.source_url, 'Publisher source')} · retrieved ${text(s.retrieved_at)} · locator ${text(s.source_locator)}</p><p class="fingerprint">SHA-256 ${text(s.source_sha256)}</p>`
      : '<p>Source provenance unknown.</p>';
  const option = (value, label, chosen) =>
    `<option value="${esc(value)}"${value === chosen ? ' selected' : ''}>${esc(label)}</option>`;
  function controls(report) {
    const s = report?.selection ?? {
      scope_level: 'os_family',
      requested_vendor: null,
      requested_window: 'all',
    };
    const end = Number((report?.observation_end || '2026').slice(0, 4));
    const years = Array.from({ length: Math.max(0, end - 2020) }, (_, i) => String(2021 + i));
    return `<div class="matrix-filters switching-controls"><label for="switching-scope">Study scope<select id="switching-scope" aria-label="Study scope">${option('os_family', 'OS-family context', s.scope_level)}${option('model_qualified', 'Model-qualified subset', s.scope_level)}</select></label><label for="switching-vendor">Study vendor<select id="switching-vendor" aria-label="Study vendor">${[
      ['', 'All three vendors'],
      ['cisco', 'Cisco'],
      ['aruba', 'HPE Aruba Networking'],
      ['arista', 'Arista'],
    ]
      .map(([v, l]) => option(v, l, s.requested_vendor || ''))
      .join(
        '',
      )}</select></label><label for="switching-window">Study period<select id="switching-window" aria-label="Study period">${[['all', 'Full study'], ['pre', 'Before 2026-04-07'], ['post', 'From 2026-04-07'], ['undated', 'Unknown publication date'], ...years.map((y) => [y, y === String(end) ? y + ' (partial)' : y])].map(([v, l]) => option(v, l, s.requested_window)).join('')}</select></label><button id="switching-apply">Apply study selection</button><button id="switching-refresh">Re-evaluate KEV freshness</button></div>`;
  }
  function coverage(row) {
    return `<details><summary>Source observation windows · ${text(row.coverage.state)}</summary><p>Historical denominator: unknown. Source-window totals and errors describe retained collection runs, not historical period completeness. They cannot be allocated to a selected year.</p>${row.coverage.sources.map((s) => `<article class="switching-source"><p>${link(s.source_url, 'Collection source')} · observed ${text(s.observed_start)} through ${text(s.observed_end)} · ${text(s.state)}</p><p>Source-window reported total: ${text(s.total)} (not a selected-period denominator).</p><p>Issues: ${esc((s.issues || []).join('; ') || 'none recorded')}</p><pre>${esc(JSON.stringify(s.enumeration ?? { coverage_state: 'unknown' }, null, 2))}</pre></article>`).join('') || '<p>No source observation window is retained; coverage unknown.</p>'}</details>`;
  }
  function rowMarkup(r) {
    const c = r.counts;
    return `<article class="switching-row"><h3>${esc({ cisco: 'Cisco', aruba: 'HPE Aruba Networking', arista: 'Arista' }[r.vendor] || r.vendor)}</h3><p>${esc(r.scope_level)} · ${esc(r.window)} · ${esc(r.period_start)} through ${esc(r.period_end)} (UTC, inclusive)</p><div class="table-wrap"><table><caption>Distinct identities in this study selection</caption><thead><tr><th>Affected advisories</th><th>Affected CVEs</th><th>Observed advisories</th><th>Observed CVEs</th><th>Remediation-publication events</th></tr></thead><tbody><tr><td data-affected-advisories="${esc(c.affected_advisories)}">${esc(c.affected_advisories)}</td><td>${esc(c.affected_cves)}</td><td>${esc(c.advisories)}</td><td>${esc(c.cves)}</td><td>${esc(c.remediation_events)}<small>${esc(c.bundled_events)} bundled; ${esc(c.unbundled_publications)} unbundled</small></td></tr></tbody></table></div>${c.cves ? '' : '<p class="empty">No retained observations match this selection. Zero observations does not establish no exposure.</p>'}<p>Scoped draft advisories: ${esc(c.draft_advisories)} (excluded from impact totals). Drafts without family/model claims may be outside these rows; this is not a vendor-wide draft inventory.</p><p>Model-unspecified claims: ${esc(c.model_unresolved_claims)}. OS-family context does not prove applicability to a named model. A model-qualified zero does not establish no exposure.</p><p>Explicit conditional affected CVEs: ${esc(c.conditional_cves)}; conditionality unclassified CVEs: ${esc(c.conditionality_unclassified_cves)}. Null conditionality is unclassified. Generic conditions are context, not proof of prerequisites or deployed configuration.</p><h4>Provider-reported CVSS</h4><p>Structurally checked, not independently rescored. Version, provider, origin and preferred context stay separate; facets are nonadditive.</p><div class="table-wrap"><table><thead><tr><th>Version / provider / origin</th><th>Preferred</th><th>Band</th><th>Distinct affected CVEs</th></tr></thead><tbody>${r.severity.map((s) => `<tr><td>${text(s.version)} / ${text(s.provider)} / ${text(s.origin)}</td><td>${text(s.preferred)}</td><td>${esc(s.band)}</td><td>${esc(s.count)}</td></tr>`).join('') || '<tr><td colspan="4">Unknown / no scored affected CVEs in this selection</td></tr>'}</tbody></table></div><h4>Vendor advisory rating</h4><p>Advisory context, separate from CVSS; no conversion or ranking.</p>${r.vendor_severity.map((s) => `<p>${esc(s.rating)} · ${text(s.scheme)} · ${text(s.namespace)} · ${esc(s.count)} advisories</p>`).join('') || '<p>Vendor advisory rating not supplied in selected claims.</p>'}<p>KEV listed: ${esc(r.kev.listed_count)} / ${esc(r.kev.denominator)} documented affected CVEs. KEV unknown: ${esc(r.kev.unknown_count)}. Membership availability: ${esc(r.kev.availability)}. Catalogue membership does not establish product exposure.</p>${coverage(r)}<details><summary>Scoped status buckets and publication events</summary><p>Statuses retain their exact claim scope; fixed-only evidence does not prove earlier affectedness.</p><pre>${esc(JSON.stringify({ status_buckets: r.status_buckets, events: r.events, issues: r.issues }, null, 2))}</pre></details></article>`;
  }
  function claimMarkup(c) {
    return `<details><summary>${esc(c.cve_id)} · ${esc(c.advisory_id)} · ${esc(c.product)}</summary><p>Claim ${esc(c.claim_id)} · ${esc(c.scope_level)} · ${esc(c.status)} / ${esc(c.scope)}</p><p>Publisher identity: ${esc(c.publisher.id)} · Publisher revision label: ${text(c.publisher.sequence)} · status: ${text(c.publisher.status)}. Normalized revision: ${text(c.revision)}</p><p>Initial publication: ${text(c.initial_published_at)} · updated: ${text(c.updated_at)}</p>${source(c.source)}<pre>${esc(JSON.stringify({ family: c.family, named_platforms: c.named_platforms, platform_bindings: c.platform_bindings, version_expressions: c.version_expressions, conditional_affected: c.conditional_affected ?? null, conditions: c.conditions, remediations: c.remediations, bundle: c.bundle, scores: c.scores, issues: c.issues }, null, 2))}</pre></details>`;
  }
  function render(report, state = {}) {
    const title =
      '<h2>Campus/branch switching study</h2><p class="notice">Counts measure disclosure, not vendor security quality; higher disclosure can reflect more scrutiny.</p><p>Full study, independent of the 24-CVE benchmark and global CVE / KEV filters. Study controls apply only here.</p>';
    const status = state.loading
      ? '<p role="status">Loading switching study…' +
        (report ? ' Displaying the last accepted selection.' : '') +
        '</p>'
      : state.error
        ? `<p role="alert">${esc(state.error)}${report ? ' Displaying the last accepted selection.' : ''}</p>`
        : '';
    if (!report) return title + controls(null) + status;
    if (report.availability !== 'available')
      return (
        title +
        controls(report) +
        status +
        `<p>Study ${esc(report.definition.id)} · version ${esc(report.definition.version)}. Publication ${text(report.publication?.id)} · generated ${text(report.generated_at)}.</p><p class="empty">Switching study unavailable for this publication. Older publications may not contain study assets; missing evidence is unknown.</p>`
      );
    const selected = new Set(
      report.rows.flatMap((r) => [...r.claim_ids, ...r.events.flatMap((e) => e.claim_ids)]),
    );
    const claims = (report.inputs?.evidence.claims || []).filter((c) => selected.has(c.claim_id));
    return (
      title +
      controls(report) +
      status +
      `<p><strong>Study ${esc(report.definition.id)} · version ${esc(report.definition.version)}</strong> · ${esc(report.definition.start_date)} through ${esc(report.observation_end)}. Cutoff ${esc(report.definition.cutoff_date)} belongs to post. 2026 is partial; the observation-end year is partial.</p><p>Publication ${text(report.publication?.id)} · generated ${text(report.generated_at)} · evaluated ${text(report.evaluated_at)}</p><p class="fingerprint">Definition SHA-256 ${esc(report.selection.definition_sha256)}</p><p><button id="switching-json">Download accepted study JSON (complete inputs)</button> <button id="switching-csv">Download accepted study CSV summary</button></p><p class="notice">Sets are nonadditive across years, severity facets and OS-family/model-qualified scopes. Do not sum overlapping counts. Unequal declared model sets do not establish equivalent exposure.</p>${report.rows.map(rowMarkup).join('')}<details><summary>Method, target models and review limits</summary><p>${esc(report.method)}</p><p>Latest retained claims grouped by initial publication date. Remediation-publication events describe explicit publisher fix statements and bundle membership, not actual upgrades. No fix-delay estimate, vendor ranking, equivalence verdict, causal interpretation or automatic no-difference conclusion.</p><p>Independent human review pending. The separate 16-case switching validation set checks extraction behavior; the original global extraction set does not validate this study.</p><p>7050X3 has a broader data-center product role; inclusion does not establish equal campus exposures. Arista 750 is not 7500. Lifecycle, historical inventory and release-train coverage remain unresolved.</p>${report.definition.targets.map((t) => `<p>${esc(t.vendor)} / ${esc(t.family)}: ${esc(t.models.join(', '))} · ${esc(t.issues.join('; '))}</p>`).join('')}<h4>Declared target references</h4>${report.definition.references.map((r) => `<p>${link(r.source_url, r.id)} · ${esc(r.source_locator)} · reviewed ${esc(r.reviewed_at)}</p>`).join('')}</details><details><summary>Trace selected claims (${claims.length})</summary>${claims.map(claimMarkup).join('') || '<p>No retained claim matches these rows.</p>'}</details><details><summary>Score availability and source diagnostics</summary><p>These diagnostics retain source context and are not additional impact counts. Source-only unclassified records do not establish study applicability.</p><pre>${esc(
        JSON.stringify(
          (report.inputs?.evidence.score_availability || []).filter((s) =>
            report.selection.effective_vendors.includes(s.vendor),
          ),
          null,
          2,
        ),
      )}</pre></details><details><summary>Selected provenance (${report.sources.length})</summary>${report.sources.map(source).join('')}</details>`
    );
  }
  window.InfrastructureSwitchingView = { render };
})();
