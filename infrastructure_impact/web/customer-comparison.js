/* Public customer facts; history never changes the study's affected denominator. */
(() => {
  const contracts = window.InfrastructureSwitchingContracts,
    policy = contracts.policy,
    switching = window.InfrastructureSwitching,
    json = window.InfrastructureJSON,
    clone = (v) => json.clone(v),
    equal = (a, b) => contracts.fingerprint(a) === contracts.fingerprint(b),
    sorted = (values) => [...new Set(values)].sort(),
    families = { cisco: 'cisco-iosxe', aruba: 'aruba-aoscx', arista: 'arista-eos' };
  function fail(message) {
    throw Error('Customer comparison: ' + message);
  }
  function counts(node) {
    for (const [kind, name] of [
      ['vendor_fixed', 'vendor_reported_fixed'],
      ['affected_scope_fix', 'affected_scope'],
    ]) {
      const ids = sorted(node.references.filter((r) => r.kind === kind).map((r) => r.cve_id));
      node[name + '_cve_ids'] = ids;
      node[name + '_cve_count'] = ids.length || null;
    }
    node.reported_release_dates = sorted(
      node.history.map((h) => h.reported_release_date).filter((d) => d !== null),
    );
  }
  function literal(vendor, expression) {
    if (vendor === 'aruba')
      return /^(?:AOS-CX )?(\d+\.\d+\.\d{4})(?:_aos-cx)?$/.exec(expression)?.[1] ?? null;
    if (vendor !== 'arista') return null;
    const simple = /^(\d+\.\d+\.\d+(?:\.\d+)?[FM]?)(?: and onwards)?\.?$/.exec(expression);
    if (simple) return simple[1];
    const train =
      /^(\d+\.\d+\.\d+(?:\.\d+)?[FM]?) and later releases? in the (\d+\.\d+)\.x train\.?$/.exec(
        expression,
      );
    return train && train[1].startsWith(train[2] + '.') ? train[1] : null;
  }
  function validateHistory(history, identity = history) {
    contracts.validate('switching-release-history-v1.json', history);
    contracts.identity(history, identity);
    const end = history.observation_end;
    if (
      switching.day(end) !== end ||
      end < policy.study_definition.start_date ||
      end > switching.day(history.generated_at)
    )
      fail('release observation end outside study or generation');
    if (
      history.definition_sha256 !== policy.definition_sha256 ||
      history.method !== policy.release_method
    )
      fail('release definition or method differs');
    const seen = new Set(),
      sourceMap = new Map();
    for (const s of history.sources) {
      if (sourceMap.has(s.source_id) || policy.release_sources[s.source_id] !== s.source_url)
        fail('unregistered or duplicate release source');
      if (s.availability === 'retained' && !(s.configured && s.enabled && s.retained))
        fail('retained release source is not enabled');
      sourceMap.set(s.source_id, s);
    }
    function contextSource(c) {
      const source = sourceMap.get(c.source_id);
      if (
        !source ||
        source.availability !== 'retained' ||
        c.source.source_url !== source.source_url ||
        c.source.source_sha256 !== source.retained.sha256 ||
        c.source.retrieved_at !== source.retained.source_observed_at
      )
        fail('release context source differs');
    }
    for (const node of history.releases) {
      if (
        node.family !== families[node.vendor] ||
        seen.has(node.release_id) ||
        node.release_id !==
          contracts.fingerprint({ vendor: node.vendor, family: node.family, version: node.version })
      )
        fail('release identity differs');
      seen.add(node.release_id);
      const checked = clone(node);
      counts(checked);
      if (!equal(checked, node)) fail('release counts or dates differ');
      node.history.forEach(contextSource);
      for (const ref of node.references) {
        contracts.official(ref.source.source_url, node.vendor);
        contracts.official(ref.claim_source.source_url, node.vendor);
        if (
          (ref.publisher_status || '').toLowerCase() === 'draft' ||
          literal(node.vendor, ref.expression) !== node.version
        )
          fail('ineligible release reference');
      }
    }
    for (const c of [...history.platform_support, ...history.bundles]) {
      if (c.source_id !== null) contextSource(c);
      else {
        if (c.vendor !== 'cisco') fail('only Cisco bundle context may omit release source');
        contracts.official(c.source.source_url, 'cisco');
      }
    }
    if (
      history.availability === 'unavailable' &&
      ['releases', 'bundles', 'platform_support', 'sources'].some((k) => history[k].length)
    )
      fail('unavailable history contains observations');
    return history;
  }
  function selectHistory(history, study) {
    const s = study.selection;
    if (s.definition_sha256 !== policy.definition_sha256)
      fail('study selection definition differs');
    let selected;
    if (history == null)
      selected = {
        schema_version: 1,
        publication: clone(study.publication),
        generated_at: study.generated_at,
        definition_sha256: policy.definition_sha256,
        observation_end: study.observation_end,
        availability: 'unavailable',
        releases: [],
        bundles: [],
        platform_support: [],
        sources: [],
        diagnostics: [],
        selection: null,
        coverage: {
          expected_releases: null,
          expected_advisories: null,
          completeness: 'not_established',
        },
        method: policy.release_method,
      };
    else {
      validateHistory(history, study);
      if (history.observation_end !== study.observation_end)
        fail('release and study observation bounds differ');
      selected = clone(history);
    }
    if (
      !['os_family', 'model_qualified'].includes(s.scope_level) ||
      s.effective_vendors.some((v) => !families[v])
    )
      fail('invalid release study scope');
    const [start, end] = switching.bounds(
        policy.study_definition,
        selected.observation_end,
        s.requested_window,
      ),
      cohorts = new Map(study.rows.map((r) => [r.vendor, new Set(r.affected_cve_ids)])),
      effective = new Set(s.effective_cve_ids);
    selected.releases = selected.releases
      .filter((n) => s.effective_vendors.includes(n.vendor))
      .filter((node) => {
        node.references = node.references.filter((ref) => {
          const date = switching.day(ref.initial_published_at);
          return (
            (ref.kind === 'vendor_fixed' ? effective : (cohorts.get(node.vendor) ?? new Set())).has(
              ref.cve_id,
            ) &&
            (s.scope_level === 'os_family' || ref.scope_level === 'model_qualified') &&
            (date === null ||
              (policy.study_definition.start_date <= date && date <= selected.observation_end)) &&
            switching.inWindow(date, start, end, s.requested_window)
          );
        });
        counts(node);
        return node.history.length || node.references.length;
      });
    for (const key of ['bundles', 'platform_support'])
      selected[key] = selected[key].filter((c) => s.effective_vendors.includes(c.vendor));
    selected.selection = clone(s);
    validateHistory(selected, study);
    return selected;
  }
  function validate(envelope) {
    contracts.validate('customer-comparison-v1.json', envelope);
    const study = envelope.study,
      history = envelope.release_history;
    contracts.identity(study, envelope);
    validateHistory(history, envelope);
    if (
      !equal(history.selection, study.selection) ||
      history.observation_end !== study.observation_end ||
      history.definition_sha256 !== study.selection.definition_sha256 ||
      contracts.fingerprint(study.definition) !== history.definition_sha256
    )
      fail('study and history selection differ');
    if (!equal(selectHistory(history, study), history))
      fail('history references outside selected cohort');
    return envelope;
  }
  function build(study, history) {
    return clone(
      validate({
        schema_version: 1,
        publication: study.publication,
        generated_at: study.generated_at,
        study,
        release_history: history,
        limitations: policy.customer_limitations,
      }),
    );
  }
  function* csvRows(envelope) {
    const study = envelope.study,
      history = envelope.release_history,
      stringify = (value) => json.stringify(value),
      common = {
        study_representation: study.representation,
        study_schema_version: study.schema_version,
        publication_id: envelope.publication?.id,
        publication_generated_at: envelope.generated_at,
        totals_basis: 'repeated_totals_nonadditive',
        scope_level: study.selection.scope_level,
        window: study.selection.requested_window,
        limitations: stringify(envelope.limitations),
      },
      row = (kind, values = {}) => ({ ...common, row_type: kind, ...values }),
      studyRows = new Map(study.rows.map((r) => [r.vendor, r]));
    for (const cells of switching.csvRows(study)) {
      const facets = Object.fromEntries(switching.csvFields.map((field, i) => [field, cells[i]]));
      yield row('study_summary', { ...facets, details: stringify(studyRows.get(facets.vendor)) });
    }
    for (const release of history.releases) {
      const fields = Object.fromEntries(
        [
          'vendor',
          'family',
          'release_id',
          'version',
          'reported_release_dates',
          'vendor_reported_fixed_cve_count',
          'affected_scope_cve_count',
          'vendor_reported_fixed_cve_ids',
          'affected_scope_cve_ids',
        ].map((k) => [k, Array.isArray(release[k]) ? stringify(release[k]) : release[k]]),
      );
      for (const ref of release.references.length ? release.references : [null])
        yield row('release_reference', {
          ...fields,
          reference_kind: ref?.kind ?? 'history_context',
          advisory_id: ref?.advisory_id,
          cve_id: ref?.cve_id,
          claim_id: ref?.claim_id,
          details: stringify({ reference: ref, history: release.history, issues: release.issues }),
        });
    }
    for (const bundle of history.bundles)
      yield row('bundle_context', { vendor: bundle.vendor, details: stringify(bundle) });
    for (const support of history.platform_support)
      yield row('platform_support', {
        vendor: support.vendor,
        source_id: support.source_id,
        details: stringify(support),
      });
    for (const selected of study.rows)
      for (const source of selected.coverage.sources)
        yield row('source_coverage', {
          vendor: selected.vendor,
          coverage_kind: 'study',
          details: stringify(source),
        });
    for (const source of study.sources ?? [])
      yield row('source_coverage', { coverage_kind: 'study_claim', details: stringify(source) });
    for (const source of history.sources)
      yield row('source_coverage', {
        source_id: source.source_id,
        coverage_kind: 'release_history',
        details: stringify(source),
      });
    yield row('source_coverage', {
      coverage_kind: 'release_history_summary',
      details: stringify({
        availability: history.availability,
        coverage: history.coverage,
        diagnostics: history.diagnostics,
        method: history.method,
      }),
    });
  }
  function csvExport(envelope, options = {}) {
    validate(envelope);
    return switching.csvTable(
      policy.customer_fields,
      (function* () {
        for (const row of csvRows(envelope)) yield policy.customer_fields.map((k) => row[k]);
      })(),
      options,
    );
  }
  const esc = (v) =>
      String(v ?? '').replace(
        /[&<>"']/g,
        (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
      ),
    text = (v) => esc(v ?? 'unknown'),
    view = window.InfrastructureSwitchingView;
  function source(s) {
    return view.source(s);
  }
  function overview(envelope) {
    const names = { cisco: 'Cisco IOS XE', aruba: 'Aruba AOS-CX', arista: 'Arista EOS' };
    return (
      '<section class="customer-overview"><div class="table-wrap" tabindex="0" role="region" aria-label="Selected vendor overview"><table><caption>Selected vendor overview · disclosure evidence, in study order</caption><thead><tr><th scope="col">Vendor</th><th scope="col">Affected CVEs</th><th scope="col">Remediation publications</th><th scope="col">KEV membership</th><th scope="col">Selected fix evidence</th><th scope="col">Source coverage</th><th scope="col">Scope / model limits</th></tr></thead><tbody>' +
      envelope.study.rows
        .map((row) => {
          const releases = envelope.release_history.releases.filter((n) => n.vendor === row.vendor),
            fixed = new Set(
              releases
                .filter((n) => n.vendor_reported_fixed_cve_count > 0)
                .map((n) => n.release_id),
            ).size,
            affected = new Set(
              releases.filter((n) => n.affected_scope_cve_count > 0).map((n) => n.release_id),
            ).size,
            evidence =
              fixed || affected
                ? `${fixed ? esc(fixed) + ' literal fixed versions' : 'Vendor-reported fixed versions not established'}<small>${affected ? esc(affected) + ' with affected-scope links' : 'Affected-scope release links not established'}</small>`
                : 'No linked release evidence<small>Fix workload not established</small>';
          return `<tr data-customer-vendor="${esc(row.vendor)}"><th scope="row">${esc(names[row.vendor] ?? row.vendor)}</th><td>${text(row.counts.affected_cves)}</td><td>${text(row.counts.remediation_events)}</td><td>${text(row.kev.listed_count)} listed; ${text(row.kev.unknown_count)} unknown<small>${text(row.kev.availability)}</small></td><td>${evidence}</td><td>${text(row.coverage.state)}</td><td>${text(row.scope_level)}<small>${text(row.counts.model_unresolved_claims)} model-unspecified claims</small></td></tr>`;
        })
        .join('') +
      '</tbody></table></div><p>CVE counts use the original advisory-publication cohort; remediation-publication counts use event dates. Publications are not customer upgrades. Literal fixed versions are source evidence, not an upgrade count or path. Model applicability and historical completeness remain unknown; zero observations do not establish no exposure. Provider-specific severity and supporting evidence follow below.</p></section>'
    );
  }
  function render(envelope, state = {}) {
    const title =
      '<h2>Customer switching comparison</h2><p class="notice">Counts measure disclosure, not vendor security quality. Actual customer upgrades: unknown.</p><p>The advisory cohort uses the study publication window; release dates and publication events describe separate evidence.</p>';
    if (!envelope) return title + view.render(null, { ...state, customer: true });
    validate(envelope);
    const history = envelope.release_history;
    return (
      title +
      overview(envelope) +
      view.render(envelope.study, { ...state, customer: true }) +
      '<section class="customer-history"><h3>Reported fixed releases and source history</h3><p>A release without linked CVEs is not evidence of a silent security fix or vendor concealment. Evidence gaps do not establish zero exposure or withholding. Model applicability and actual upgrades remain unknown.</p>' +
      `<p>History: ${esc(history.availability)}. Release coverage denominator: unknown. ${esc(history.method)}</p>` +
      (history.availability === 'unavailable'
        ? '<p>Release history unavailable for this publication; missing evidence is unknown.</p>'
        : '') +
      history.releases
        .map(
          (n) =>
            `<article class="switching-row"><h4>${n.references.length ? 'Reported fixed release' : 'Vendor release context (no selected CVE fix references)'}: ${esc(n.vendor)} · ${esc(n.version)}</h4><p>Reported release date: ${esc(n.reported_release_dates.join('; ') || 'unknown')}. Vendor-reported fixed CVEs: ${text(n.vendor_reported_fixed_cve_count)}. Affected-scope linked CVEs: ${text(n.affected_scope_cve_count)}.</p><details><summary>Release evidence and current claim references</summary>${n.history.map((h) => `<p>Reported release date: ${text(h.reported_release_date)} · posting reported: ${text(h.publisher_reports_posted)} · ${esc(h.product)} · ${esc(h.platforms.join('; '))}</p><p>${esc(h.statement)}</p>${source(h.source)}`).join('')}${n.references.map((r) => `<p>${r.kind === 'vendor_fixed' ? 'Vendor-reported fixed CVE' : 'Affected-scope link'}: ${esc(r.cve_id)} · ${esc(r.advisory_id)} · ${esc(r.scope_level)}. Advisory initial publication: ${text(r.initial_published_at)}. Remediation availability (advisory context): ${text(r.availability_date)}.</p><p>Current claim ${esc(r.claim_id)} · ${esc(r.link_basis)} · ${esc(r.expression)}</p>${source(r.source)}${source(r.claim_source)}`).join('')}<p>Issues: ${esc(n.issues.join('; ') || 'none recorded')}</p></details></article>`,
        )
        .join('') +
      '<h3>Separate bundle context</h3><p>Vendor context; bundle membership does not establish CVEs resolved per software version. Bundle notice publication and member publication are advisory dates; they do not date a software release or a customer upgrade.</p>' +
      (history.bundles
        .map(
          (b) =>
            `<details><summary>${esc(b.vendor)} · ${esc(b.publisher_id)} · ${text(b.title)}</summary><p>notice publication: ${text(b.initial_published_at)} · member publication: ${text(b.member_publication_date)}</p><p>Members: ${esc(b.member_advisory_ids.join('; '))}</p>${source(b.source)}</details>`,
        )
        .join('') || '<p>No retained bundle context; grouping unknown.</p>') +
      '<h3>Model / SKU limits</h3><p>Vendor support context, not attribution to selected CVEs. Literal minimum versions describe source support context; model applicability and deployed exposure are unknown. Versions are not ordered.</p>' +
      history.platform_support
        .map(
          (s) =>
            `<details><summary>${esc(s.model_literal)} · SKU ${esc(s.sku)}</summary><p>Reported minimum version: ${esc(s.minimum_version)}</p>${source(s.source)}</details>`,
        )
        .join('') +
      `<details><summary>Source coverage and diagnostics</summary><p>History availability: ${esc(history.availability)} · completeness: ${esc(history.coverage.completeness)} · expected releases: ${text(history.coverage.expected_releases)} · expected advisories: ${text(history.coverage.expected_advisories)}</p>${history.sources.map((s) => `<p>${esc(s.source_id)} · ${esc(s.availability)} · checked ${text(s.checked_at)} · latest outcome ${text(s.latest_attempt?.outcome)} / ${text(s.latest_attempt?.error_code)}</p>${view.link(s.source_url, 'History source')}<pre>${esc(json.stringify(s, null, 2))}</pre>`).join('')}<pre>${esc(json.stringify(history.diagnostics, null, 2))}</pre></details><details><summary>Customer comparison limitations</summary>${envelope.limitations.map((l) => `<p>${esc(l)}</p>`).join('')}</details></section>`
    );
  }
  window.InfrastructureCustomerComparison = {
    build,
    validate,
    validateHistory,
    selectHistory,
    csvExport,
    render,
  };
})();
