// Buildless reader for the current publication's public, allowlisted report.
(() => {
  const clone = (value) => JSON.parse(JSON.stringify(value));
  function select(report, ids, vendor = null) {
    if (report == null) return null;
    if (vendor !== null && !Object.hasOwn(report.vendors, vendor))
      throw Error('Unknown dossier vendor');
    const selected = clone(report),
      cohort = new Set(ids);
    if (vendor !== null) selected.vendors = { [vendor]: selected.vendors[vendor] };
    selected.dossiers = selected.dossiers.filter((dossier) => {
      if (!cohort.has(dossier.cve_id)) return false;
      const targets = dossier.comparison_targets.filter(
        (row) => vendor === null || row.vendor === vendor,
      );
      const contexts = dossier.disclosure_context.filter(
        (row) => vendor === null || row.vendor === vendor,
      );
      if (vendor !== null && !targets.length && !contexts.length) return false;
      dossier.scope.selected_vendor = vendor;
      dossier.comparison_targets = targets;
      dossier.disclosure_context = contexts;
      const owners = new Set([
        ...targets.map((r) => 'target:' + r.target_id),
        ...contexts.map((r) => 'case:' + r.case_id),
      ]);
      dossier.evidence_gaps = dossier.evidence_gaps.filter((r) =>
        owners.has(r.owner_kind + ':' + r.owner_id),
      );
      const sources = dossier.sources.filter((r) => vendor === null || r.vendor === vendor);
      const sourceIds = new Set(sources.map((r) => r.id));
      dossier.chronology = Object.fromEntries(
        Object.entries(dossier.chronology).map(([key, rows]) => [
          key,
          rows.filter((r) => sourceIds.has(r.source_id)),
        ]),
      );
      const references = new Set();
      for (const target of targets) {
        target.statements.forEach((r) => references.add(r.source_id));
        target.fields.forEach((f) => f.evidence.forEach((r) => references.add(r.source_id)));
      }
      for (const context of contexts) {
        context.source_ids.forEach((id) => references.add(id));
        context.earlier_documents.forEach((r) => references.add(r.source_id));
        context.investigation?.source_ids.forEach((id) => references.add(id));
      }
      Object.values(dossier.chronology).forEach((rows) =>
        rows.forEach((r) => references.add(r.source_id)),
      );
      dossier.sources = sources.filter((r) => references.has(r.id));
      return true;
    });
    return selected;
  }
  function downloadPayload(report, selectedId) {
    const dossier = report?.dossiers.find((row) => row.id === selectedId);
    if (!dossier) throw Error('Dossier is absent from this report');
    return clone({ ...report, dossiers: [dossier] });
  }
  function render(report, selectedId, { esc, link, date }) {
    if (!report)
      return '<h3>CVE research dossier</h3><p class="empty">Research dossier unavailable for this generation.</p>';
    const dossier = report.dossiers.find((r) => r.id === selectedId) || report.dossiers[0];
    if (!dossier)
      return '<h3>CVE research dossier</h3><p class="empty">No dossier for the selected scope. No exposure or disclosure conclusion follows.</p>';
    const text = (v) =>
      esc(
        v === null || v === undefined
          ? 'Not supplied'
          : typeof v === 'object'
            ? JSON.stringify(v)
            : v,
      );
    const list = (rows, fn, empty = 'None retained; evidence remains unresolved.') =>
      rows.length
        ? `<ul>${rows.map((r) => `<li>${fn(r)}</li>`).join('')}</ul>`
        : `<p>${esc(empty)}</p>`;
    const refs = (ids) =>
      ids
        .map((id) => {
          const source = dossier.sources.find((r) => r.id === id);
          return source
            ? `${link(source.source_url, 'Retained source')} <code>${esc(id)}</code>`
            : 'Source reference unavailable';
        })
        .join(' · ');
    const locator = (v) => `<small>Locator: ${text(v)}</small>`;
    const check = (r) =>
      `<p>Source access observation: ${text(r.outcome)} · ${date(r.checked_at)}${r.error_code ? ` · ${text(r.error_code)}` : ''}${r.source_url ? ` · ${link(r.source_url, 'Checked source')}` : ''}. Retrieval does not establish historical availability or nondisclosure.</p>`;
    const statements = (rows) =>
      list(
        rows,
        (s) =>
          `<strong>${text(s.status)}</strong> · ${text(s.scope)}<p>${text(s.product)} · product ID ${text(s.product_id)} · family ${text(s.product_family)}</p><p>Product context: ${text(s.product_context)} · platforms: ${text(s.platforms)}</p><p>Version expressions: ${text(s.versions)}</p><p>Prerequisites: ${text(s.exposure)}</p><p>Fixes and branch qualifications: ${text(s.remediations)}</p>${locator(s.evidence_locator)}${refs([s.source_id])}`,
        'No exact retained statement. Evidence is unknown.',
      );
    const chronology = (rows) =>
      list(
        rows,
        (r) =>
          `${text(r.field || r.kind)} · ${text(r.value)} <strong>(${text(r.precision)})</strong>${r.precision === 'local_datetime' ? ' · publisher timezone unspecified' : ''}${r.kind && r.field ? ` · ${text(r.kind)}` : ''}${locator(r.locator)}${refs([r.source_id])}${r.event_id ? `<small>Event ${text(r.event_id)}</small>` : ''}${r.revision_id ? `<small>Revision ${text(r.revision_id)}</small>` : ''}${r.evidence_id ? `<small>Evidence ${text(r.evidence_id)}</small>` : ''}${r.history_truncated || r.events_truncated ? '<small>Bounded history; earlier observations may be absent.</small>' : ''}`,
      );
    const controls = `<div class="matrix-filters"><label for="dossier-select">CVE dossier</label><select id="dossier-select">${report.dossiers.map((r) => `<option value="${esc(r.id)}" ${r.id === dossier.id ? 'selected' : ''}>${esc(r.cve_id)}</option>`).join('')}</select><button id="dossier-download">Download selected dossier JSON</button></div>`;
    return `<h3>CVE research dossier</h3>${controls}<article class="research-dossier"><h3>${esc(dossier.cve_id)}</h3><p>Publication <code>${text(report.publication?.id)}</code> · generated ${date(report.generated_at)}</p><p>${text(report.method)}</p><h4>Declared comparison scope</h4><p>Role: ${text(dossier.scope.comparison_role)} · selected vendor: ${text(dossier.scope.selected_vendor || 'All declared members')}</p><p>Declared target IDs: ${text(dossier.scope.build_target_ids.join(', ') || 'No comparable build cohort declared')}</p><p>Declared case IDs: ${text(dossier.scope.case_ids.join(', '))}</p><p>${text(dossier.scope.selection_limitation)}</p><div class="notice">Fixed-only statements do not establish prior affectedness. Inventory, independent human review and historical release availability remain unverified. Earliest disclosure and intentional concealment are not established. Vendor rates and verified fix delays are not calculated.</div><h4>Comparison evidence</h4><div class="dossier-targets">${dossier.comparison_targets.map((t) => `<article><h5>${text(report.vendors[t.vendor] || t.vendor)} · ${text(t.product)} · ${text(t.firmware_build)}</h5><p>Target ${text(t.target_id)}</p>${statements(t.statements)}<h5>Evidence fields</h5>${list(t.fields, (f) => `${text(f.field)}: <strong>${text(f.state)}</strong> · ${text(f.value)}${f.evidence.map((e) => `${locator(e.locator)}<small>Captured ${date(e.observed_at)}</small>${refs([e.source_id])}`).join('')}`)}${check(t.source_check)}</article>`).join('') || '<p>No comparable build target in this selected subset. Disclosure context follows.</p>'}</div><h4>Publisher date claims</h4><p>Literal publisher values and precision; these do not establish first disclosure.</p>${chronology(dossier.chronology.publisher_claims)}<h4>Local observations</h4><p>Collector events and source revisions retain their original classifications.</p>${chronology(dossier.chronology.local_observations)}<h4>Publisher documentation history</h4><p>Publisher-reported document changes, not independently observed disclosure events.</p>${chronology(dossier.chronology.documentation_claims)}<h4>Disclosure context and counter-evidence</h4>${dossier.disclosure_context.map((c) => `<article><h5>${text(report.vendors[c.vendor] || c.vendor)} · ${text(c.question)}</h5><p>${text(c.case_id)} · ${text(c.status)} · ${text(c.product_scope)}</p>${refs(c.source_ids)}${c.investigation ? `<p>Source-bound assistant disposition: ${text(c.investigation.disposition)} · ${text(c.investigation.source_state)}</p><p>${text(c.investigation.summary)}</p><p>Review method: ${text(c.investigation.review_method)} · ${text(c.investigation.reviewed_at)}. Independent human review pending.</p><details><summary>Investigation search scope</summary><p>${text(c.investigation.search_scope)}</p>${list(c.investigation.remaining_evidence, text)}${list(c.investigation.uncollected_search_leads, (u) => `${link(u, 'Uncollected research lead')} · not retained availability evidence`)}</details>` : '<p>No source-bound assistant disposition retained.</p>'}<h5>Earlier-document counter-evidence</h5>${list(c.earlier_documents, (e) => `${text(e.publisher_published_at)} · ${text(e.date_basis)} · ${text(e.product_labels)}<p>${text(e.interpretation)}</p>${refs([e.source_id])}`)}${c.source_checks.map(check).join('')}<p>Release source state: ${text(c.release_source_state)}</p><h5>Missing evidence</h5>${list(c.missing_evidence, text)}<h5>Alternative explanations</h5>${list(c.alternative_explanations, text)}</article>`).join('')}<h4>Evidence still needed</h4>${list(dossier.evidence_gaps, (g) => `${text(g.owner_kind)} ${text(g.owner_id)} · ${text(g.field_or_question)}<p>Evidence sought: ${text(g.evidence_sought)} · access state: ${text(g.access_state)}</p>`)}<p>${link('https://github.com/abedegno/infrastructure-impact/blob/main/docs/BUILD_INVENTORY.md', 'Prepare inventory evidence')}</p><details><summary>Source fingerprints and definition identity</summary><p>Definition ${text(report.definition_version)}</p><code>${text(report.definition_sha256)}</code>${dossier.sources.map((s) => `<article><p>${link(s.source_url, s.source_url)}</p><p>Vendor ${text(s.vendor)} · source ID <code>${text(s.id)}</code></p><p>SHA-256 <code>${text(s.source_sha256)}</code></p><p>Locators: ${text(s.locators)}</p><p>Capture observations: ${text(s.observations)}</p><p>Parser ${text(s.adapter_version)} · revision ${text(s.revision_id)} · evidence ${text(s.evidence_id)}</p></article>`).join('')}<h5>Report limits</h5><pre>${text(report.limits)}</pre></details></article>`;
  }
  const selections = new WeakMap();
  function mount(container, report, helpers) {
    let id = selections.get(container);
    if (!report?.dossiers.some((r) => r.id === id)) id = report?.dossiers[0]?.id;
    const draw = () => {
      selections.set(container, id);
      container.innerHTML = render(report, id, helpers);
      const selector = container.querySelector('#dossier-select');
      if (selector) {
        selector.value = id;
        selector.addEventListener('change', () => {
          if (report.dossiers.some((r) => r.id === selector.value)) id = selector.value;
          draw();
        });
      }
      container
        .querySelector('#dossier-download')
        ?.addEventListener('click', () => helpers.onDownload(downloadPayload(report, id)));
    };
    draw();
  }
  window.ResearchDossiers = { select, render, downloadPayload, mount };
})();
