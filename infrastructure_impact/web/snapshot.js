/* Snapshot transport: no vendor requests, credentials, or writable backend. */
window.snapshotMode = true;
function snapshotCompare(records, cohort, vendors, template, retainedVendors, retainedDrafts) {
  const included = records.filter((r) => r.document_status !== 'draft');
  const rows = Object.entries(vendors).map(([vendor, name]) => {
    const claims = included
      .filter((r) => r.vendor === vendor)
      .flatMap((r) => r.assessments)
      .filter((a) => cohort.includes(a.cve_id));
    const by = cohort.map((c) => claims.filter((a) => a.cve_id === c));
    const count = (pred) => by.filter((aa) => aa.some(pred)).length;
    const assessed = count((a) => !['unknown', 'recommended'].includes(a.status));
    return {
      vendor,
      name,
      cohort_size: cohort.length,
      has_imported_advisories: retainedVendors
        ? retainedVendors.includes(vendor)
        : included.some((r) => r.vendor === vendor),
      assessed_cves: assessed,
      no_assessment_in_dataset: cohort.length - assessed,
      affected_cves: count((a) => ['affected', 'partially_mitigated'].includes(a.status)),
      unaffected_cves: count((a) => a.status === 'unaffected'),
      investigating_cves: count((a) => a.status === 'investigating'),
      fixed_cves: count((a) => a.status === 'fixed'),
      explicit_affected_cves: count((a) => a.status === 'affected' && a.scope === 'cve_specific'),
      shared_bulletin_affected_cves: count(
        (a) => a.status === 'affected' && a.scope === 'bulletin_shared',
      ),
      product_labels: new Set(claims.map((a) => a.product)).size,
      conflicting_cves: count((a) => a.status === 'conflicting'),
    };
  });
  return {
    ...template,
    cohort,
    vendors: rows,
    draft_advisories_excluded: retainedDrafts ?? records.length - included.length,
  };
}
function selectScorecards(document, cohort) {
  const states = [
    'affected',
    'partially_mitigated',
    'unaffected',
    'fixed',
    'investigating',
    'unknown',
    'recommended',
    'conflicting',
  ];
  return {
    ...document,
    cohort,
    vendors: (document.vendors || []).map((card) => {
      const by = new Map(card.cases.map((c) => [c.cve_id, c]));
      const cases = cohort.map(
        (cid) =>
          by.get(cid) || {
            cve_id: cid,
            statuses: [],
            product_labels: [],
            statement_count: 0,
            cve_specific_statements: 0,
            shared_bulletin_statements: 0,
            coverage_state: 'not_checked',
            source_urls: [],
          },
      );
      return {
        ...card,
        cases,
        cohort_size: cases.length,
        with_statement: cases.filter((c) => c.statement_count > 0).length,
        without_statement: cases.filter((c) => c.statement_count === 0).length,
        explicit_unknown: cases.filter((c) => c.statuses.includes('unknown')).length,
        status_counts: Object.fromEntries(
          states.map((s) => [s, cases.filter((c) => c.statuses.includes(s)).length]),
        ),
      };
    }),
  };
}

/* Conservative, versioned family rules. A match never establishes exposure. */
function classifyProduct(vendor, assessment, taxonomy) {
  const name = (assessment.product_family || assessment.product || '').trim();
  let matches = (taxonomy?.rules || []).filter(
    (r) =>
      r.vendor === vendor &&
      (!r.platform_prefixes ||
        (Array.isArray(assessment.platforms) &&
          assessment.platforms.length > 0 &&
          assessment.platforms.every(
            (p) =>
              typeof p === 'string' && r.platform_prefixes.some((prefix) => p.startsWith(prefix)),
          ))) &&
      (name === r.prefix ||
        (name.startsWith(r.prefix) &&
          [' ', '-', '('].includes(name.slice(r.prefix.length, r.prefix.length + 1)))),
  );
  if (!matches.length) return { state: 'unmapped', group: null, rule_ids: [] };
  const length = Math.max(...matches.map((r) => r.prefix.length));
  matches = matches.filter((r) => r.prefix.length === length);
  if (matches.some((r) => r.platform_prefixes))
    matches = matches.filter((r) => r.platform_prefixes);
  const groups = [...new Set(matches.map((r) => r.group))];
  return {
    state: groups.length === 1 ? 'mapped' : 'ambiguous',
    group: groups.length === 1 ? groups[0] : null,
    rule_ids: matches.map((r) => r.id).sort(),
  };
}

/* Pure comparison policy shared with the Python reader through parity tests. */
function productLabels(source, vendor, group = null) {
  if (source.product_label_index)
    return group
      ? source.product_label_index[vendor]?.groups[group] || []
      : source.product_label_index[vendor]?.all || [];
  return [
    ...new Set(
      source.records
        .filter((r) => r.vendor === vendor && r.document_status !== 'draft')
        .flatMap((r) =>
          r.assessments
            .filter(
              (a) => !group || classifyProduct(vendor, a, source.product_groups).group === group,
            )
            .map((a) => a.product),
        ),
    ),
  ].sort();
}
function comparisonEligibility(source, ids, options = {}) {
  const taxonomy = source.product_groups;
  const group = options.group ?? null;
  if (group !== null && !(taxonomy?.groups || []).some((g) => g.id === group))
    throw Error('Unknown reviewed product group');
  const inGroup = (vendor, a) =>
    group === null || classifyProduct(vendor, a, taxonomy).group === group;
  const datePattern = /^\d{4}-\d{2}-\d{2}$/;
  const stampPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
  const calendar = (v) => {
    if (typeof v !== 'string' || v.startsWith('0000-')) return null;
    if (datePattern.test(v)) {
      const d = new Date(v + 'T00:00:00Z');
      return Number.isFinite(d.getTime()) && d.toISOString().slice(0, 10) === v ? v : null;
    }
    const t = instant(v);
    return t === null ? null : new Date(t).toISOString().slice(0, 10);
  };
  const instant = (v) => {
    if (typeof v !== 'string' || v.startsWith('0000-') || !stampPattern.test(v)) return null;
    // Date.parse normalizes invalid month-days; Python rejects them.
    const day = v.slice(0, 10);
    const check = new Date(day + 'T00:00:00Z');
    if (!Number.isFinite(check.getTime()) || check.toISOString().slice(0, 10) !== day) return null;
    const [hours, minutes, seconds] = v.slice(11, 19).split(':').map(Number);
    if (
      hours > 23 ||
      minutes > 59 ||
      seconds > 59 ||
      (!v.endsWith('Z') && (Number(v.slice(-5, -3)) > 23 || Number(v.slice(-2)) > 59))
    )
      return null;
    const t = Date.parse(v);
    return Number.isFinite(t) &&
      new Date(t).getUTCFullYear() >= 1 &&
      new Date(t).getUTCFullYear() <= 9999
      ? t
      : null;
  };
  const asAt = instant(source.generated_at);
  if (asAt === null) throw Error('Comparison requires a timezone-qualified publication timestamp');
  const end = options.end ?? new Date(asAt).toISOString().slice(0, 10);
  if (!datePattern.test(end) || calendar(end) !== end) throw Error('Invalid comparison end');
  const start =
    options.start ??
    new Date(Date.parse(end + 'T00:00:00Z') - 364 * 86400000).toISOString().slice(0, 10);
  if (
    !datePattern.test(start) ||
    calendar(start) !== start ||
    start < '1900-01-01' ||
    start > end ||
    end > new Date(asAt).toISOString().slice(0, 10)
  )
    throw Error('Invalid comparison period');
  const rawProducts = options.products ?? {};
  if (
    typeof rawProducts !== 'object' ||
    Array.isArray(rawProducts) ||
    encodeURIComponent(JSON.stringify(rawProducts)).replace(/%[0-9A-F]{2}|./g, 'x').length > 4096
  )
    throw Error('Invalid product selection');
  const products = {};
  for (const vendor of Object.keys(rawProducts).sort()) {
    const labels = rawProducts[vendor];
    const available = new Set(productLabels(source, vendor));
    if (
      !Object.hasOwn(source.vendors, vendor) ||
      !Array.isArray(labels) ||
      labels.length > 20 ||
      labels.some((p) => typeof p !== 'string' || !available.has(p))
    )
      throw Error('Invalid exact product labels');
    products[vendor] = [...new Set(labels)].sort();
  }
  const cohort = [...new Set(ids ?? source.all_cves ?? [])].sort();
  const profiles = new Map((source.catalogue?.vendors || []).map((v) => [v.vendor, v]));
  const audits = new Map((source.source_audit?.vendors || []).map((v) => [v.vendor, v]));
  const statuses = [
    'affected',
    'partially_mitigated',
    'unaffected',
    'fixed',
    'investigating',
    'unknown',
    'recommended',
    'conflicting',
  ];
  const vendors = Object.entries(source.vendors).map(([vendor, name]) => {
    const profile = profiles.get(vendor) || {},
      audit = audits.get(vendor) || {};
    const available = productLabels(source, vendor, group);
    const labels = Object.hasOwn(products, vendor)
      ? products[vendor].filter((p) => available.includes(p))
      : available;
    const pool = new Map(cohort.map((cid) => [cid, []]));
    const included = new Map(cohort.map((cid) => [cid, []]));
    const excluded = {
      draft: 0,
      outside_period: 0,
      unusable_publication_date: 0,
      future_timestamp: 0,
    };
    const advisoryIds = new Set();
    for (const r of source.records.filter((r) => r.vendor === vendor)) {
      if (r.document_status === 'draft') {
        if (
          r.assessments.some(
            (a) =>
              cohort.includes(a.cve_id) &&
              inGroup(vendor, a) &&
              (!Object.hasOwn(products, vendor) || labels.includes(a.product)),
          )
        )
          excluded.draft++;
        continue;
      }
      const claims = r.assessments.filter(
        (a) => cohort.includes(a.cve_id) && labels.includes(a.product) && inGroup(vendor, a),
      );
      if (!claims.length) continue;
      claims.forEach((a) => pool.get(a.cve_id).push([r, a]));
      const published = calendar(r.published_at);
      if (!published) excluded.unusable_publication_date++;
      else if (published < start || published > end) excluded.outside_period++;
      else if (instant(r.published_at) !== null && instant(r.published_at) > asAt)
        excluded.future_timestamp++;
      else {
        advisoryIds.add(r.advisory_id);
        claims.forEach((a) => included.get(a.cve_id).push([r, a]));
      }
    }
    const cases = cohort.map((cid) => {
      const statements = included.get(cid),
        claims = statements.map(([, a]) => a),
        reasons = [];
      if (!statements.length) reasons.push('no_statement_in_period_and_scope');
      if (pool.get(cid).some(([r]) => !calendar(r.published_at)))
        reasons.push('undated_statement_excluded');
      if (claims.some((a) => a.status === 'conflicting')) reasons.push('conflicting_statement');
      const byDocument = new Map(
        statements
          .filter(([, a]) => a.scope === 'cve_specific')
          .map(([r]) => [JSON.stringify([r.advisory_id, r.source_url]), r]),
      );
      if (!byDocument.size) reasons.push('no_cve_specific_statement_in_period');
      const reference = source.upstream?.[cid] || {},
        upstreamTime = instant(reference.published_at);
      if (upstreamTime === null || upstreamTime > asAt) reasons.push('upstream_timestamp_unusable');
      const upstreamProvenance =
        typeof reference.source_url === 'string' &&
        reference.source_url.startsWith('https://') &&
        /^[a-f0-9]{64}$/.test(reference.sha256 || '');
      if (!upstreamProvenance) reasons.push('upstream_provenance_missing');
      const observations = [];
      for (const [, r] of [...byDocument].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
        const t = instant(r.published_at);
        if (t === null) {
          if (!reasons.includes('vendor_timestamp_not_precise'))
            reasons.push('vendor_timestamp_not_precise');
          continue;
        }
        const vendorProvenance =
          typeof r.source_url === 'string' &&
          r.source_url.startsWith('https://') &&
          /^[a-f0-9]{64}$/.test(r.sha256 || '');
        if (!vendorProvenance) reasons.push('vendor_provenance_missing');
        if (
          !upstreamProvenance ||
          !vendorProvenance ||
          upstreamTime === null ||
          upstreamTime > asAt ||
          reasons.includes('conflicting_statement')
        )
          continue;
        observations.push({
          advisory_id: r.advisory_id,
          advisory_source: r.source_url,
          advisory_sha256: r.sha256 ?? null,
          advisory_date: r.published_at,
          upstream_source: reference.source_url ?? null,
          upstream_sha256: reference.sha256 ?? null,
          upstream_date: reference.published_at,
          offset_seconds: Math.trunc(t / 1000) - Math.trunc(upstreamTime / 1000),
        });
      }
      return {
        cve_id: cid,
        statuses: [...new Set(claims.map((a) => a.status))].sort(),
        explicit_statuses: [
          ...new Set(claims.filter((a) => a.scope === 'cve_specific').map((a) => a.status)),
        ].sort(),
        shared_statuses: [
          ...new Set(claims.filter((a) => a.scope === 'bulletin_shared').map((a) => a.status)),
        ].sort(),
        product_labels: [...new Set(claims.map((a) => a.product))].sort(),
        statement_count: claims.length,
        publication_observations: observations,
        timing_reasons: [...new Set(reasons)].sort(),
        first_disclosure_days: null,
        verified_fix_delay_days: null,
      };
    });
    const sources = new Set((profile.sources || []).map((s) => s.url));
    const checks = new Map(
      (source.health || []).filter((h) => h.vendor === vendor).map((h) => [h.source_url, h]),
    );
    const stale = [...sources].filter(
      (url) =>
        instant(checks.get(url)?.checked_at) === null ||
        instant(checks.get(url)?.checked_at) > asAt ||
        asAt - instant(checks.get(url)?.checked_at) > (profile.stale_after_hours ?? 36) * 3600000,
    ).length;
    const errors = [...checks]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .filter(([, h]) => h.outcome === 'error')
      .map(([, h]) => ({
        source_url: h.source_url ?? null,
        checked_at: h.checked_at ?? null,
        error_code: h.error_code ?? null,
      }));
    const archives = (audit.archives || []).map((a) => ({
      source_url: a.source_url,
      kind: a.kind,
      pages: Object.fromEntries(
        ['pending', 'done', 'not_applicable', 'error'].map((s) => [s, a.pages?.[s] ?? 0]),
      ),
      documents: Object.fromEntries(
        ['pending', 'done', 'not_applicable', 'error'].map((s) => [s, a.documents?.[s] ?? 0]),
      ),
      known_queue_exhausted: Boolean(a.known_queue_exhausted),
      discovery_link_gaps: a.discovery_link_gaps ?? 0,
      observed_scopes: a.observed_scopes || [],
    }));
    const review = audit.archive_source_review
      ? Object.fromEntries(
          ['status', 'source_url', 'scope', 'configured'].map((k) => [
            k,
            audit.archive_source_review[k] ?? null,
          ]),
        )
      : null;
    const pending = archives.reduce(
      (n, a) => n + (a.pages?.pending || 0) + (a.documents?.pending || 0),
      0,
    );
    const failed = archives.reduce(
      (n, a) => n + (a.pages?.error || 0) + (a.documents?.error || 0),
      0,
    );
    const count = (predicate) => cases.filter(predicate).length;
    const counts = {
      cohort_size: cohort.length,
      advisories_in_period: advisoryIds.size,
      cves_with_statement: count((c) => c.statement_count > 0),
      no_statement: count((c) => !c.statement_count),
      explicit_affected: count((c) =>
        c.explicit_statuses.some((s) => ['affected', 'partially_mitigated'].includes(s)),
      ),
      shared_affected: count((c) =>
        c.shared_statuses.some((s) => ['affected', 'partially_mitigated'].includes(s)),
      ),
      explicit_unaffected: count((c) => c.explicit_statuses.includes('unaffected')),
      no_cve_specific_exposure_assessment: count(
        (c) =>
          !c.explicit_statuses.some((s) =>
            ['affected', 'partially_mitigated', 'unaffected'].includes(s),
          ),
      ),
      ...Object.fromEntries(statuses.map((s) => [s, count((c) => c.statuses.includes(s))])),
    };
    const blockers = [
      'portfolio_denominator_missing',
      'cross_vendor_product_equivalence_unverified',
      'cve_statement_date_unverified',
      'independent_fix_availability_and_linkage_unverified',
    ];
    if (pending) blockers.push('backfill_pending');
    if (failed) blockers.push('backfill_failed');
    if (!archives.length) blockers.push('no_configured_archive');
    if (archives.some((a) => !a.known_queue_exhausted)) blockers.push('archive_scope_incomplete');
    if (errors.length) blockers.push('source_errors_retained');
    if (stale || !sources.size) blockers.push('source_checks_stale_or_missing');
    if (excluded.unusable_publication_date) blockers.push('undated_statements_excluded');
    if (!labels.length) blockers.push('empty_product_scope');
    return {
      vendor,
      name,
      product_scope: {
        mode: Object.hasOwn(products, vendor) ? 'explicit_labels' : 'all_retained_labels',
        labels,
        declared_families: profile.product_families || [],
      },
      counts,
      excluded_advisories: excluded,
      eligibility: {
        descriptive_counts_usable: counts.cves_with_statement > 0,
        rate_comparison: 'suppressed',
        first_disclosure_comparison: 'suppressed',
        fix_timing_comparison: 'suppressed',
        reason_codes: blockers.sort(),
      },
      source_coverage: {
        configured_urls: sources.size,
        stale_or_unchecked_urls: stale,
        errors,
        history_scope: profile.history_scope || 'Not declared',
        known_gaps: profile.known_gaps || [],
        archive_review: review,
        archives,
        backfill_pending: pending,
        backfill_failed: failed,
        portfolio_completeness: 'not_established',
      },
      cases,
    };
  });
  return {
    schema_version: 1,
    cohort,
    period: { start, end, basis: 'initial_advisory_publication_calendar_date', inclusive: true },
    product_selection: products,
    product_group: group,
    taxonomy_version: taxonomy?.taxonomy_version ?? null,
    vendors,
    method:
      'Latest retained non-draft product statements grouped by initial advisory publication date. Timezone-qualified timestamps use UTC dates; date-only values keep their calendar date. Missing or timezone-unspecified timestamps are excluded. This is not an as-of reconstruction or a date of individual CVE disclosure.',
    metric_policy: {
      sample_counts: 'qualified_descriptive_evidence',
      vendor_rates: 'suppressed_without_comparable_portfolio_denominators',
      first_disclosure: 'suppressed_without_verified_cve_statement_dates_and_history',
      fix_delay: 'suppressed_without_independent_fix_availability_and_product_cve_linkage',
      publication_offsets: 'paired_document_metadata_only_not_disclosure_response_time',
    },
  };
}

function selectSnapshot(source, ids, options = {}) {
  const cohort = [...new Set(ids || source.all_cves)].sort();
  const coverage = cohort.flatMap((cid) =>
    Object.keys(source.vendors).map(
      (v) =>
        source.coverage.find((c) => c.cve_id === cid && c.vendor === v) || {
          vendor: v,
          cve_id: cid,
          state: 'not_checked',
          checks: [],
          advisory_sources: [],
        },
    ),
  );
  return {
    ...source,
    comparison: snapshotCompare(
      source.records,
      cohort,
      source.vendors,
      source.comparison,
      source.non_draft_record_vendors,
      source.draft_advisories_count,
    ),
    comparison_eligibility: source.generated_at
      ? comparisonEligibility(source, cohort, options)
      : {},
    coverage,
    scorecards: selectScorecards(source.scorecards || {}, cohort),
    casefiles: {
      ...(source.casefiles || {}),
      cases: (source.casefiles?.cases || [])
        .filter((c) => c.cve_ids.some((id) => cohort.includes(id)))
        .map((c) => {
          const selected = c.cve_ids.filter((id) => cohort.includes(id)).sort();
          const rows = c.exposure.by_cve.filter((r) => selected.includes(r.cve_id));
          const count = rows.reduce((n, r) => n + r.statement_count, 0);
          return {
            ...c,
            selected_cve_ids: selected,
            reported_documentation_offsets: (c.reported_documentation_offsets || []).filter((o) =>
              selected.includes(o.cve_id),
            ),
            earlier_dated_vendor_documents: (c.earlier_dated_vendor_documents || [])
              .filter((d) => d.cve_ids.some((id) => selected.includes(id)))
              .map((d) => ({
                ...d,
                cve_ids: d.cve_ids.filter((id) => selected.includes(id)).sort(),
              })),
            publisher_document_histories: (c.publisher_document_histories || []).map((d) => ({
              ...d,
              events: d.events.filter(
                (e) => !e.cve_ids.length || e.cve_ids.some((id) => selected.includes(id)),
              ),
            })),
            exposure: {
              ...c.exposure,
              by_cve: rows,
              statement_count: count,
              publisher_statement_retained: count > 0,
              observed_statuses: [...new Set(rows.flatMap((r) => r.observed_statuses))].sort(),
            },
            timeline_event_ids: c.timeline_event_ids.filter((e) =>
              selected.some((id) => e.endsWith('-' + id)),
            ),
          };
        }),
    },
    timeline: {
      ...(source.timeline || {}),
      events: (source.timeline?.events || []).filter((e) => cohort.includes(e.cve_id)),
    },
    delays: [],
  };
}
function exportSnapshot(source) {
  const cohort = source.comparison.cohort;
  return {
    ...source,
    records: source.records
      .filter((r) => r.cves.some((c) => cohort.includes(c)))
      .map((r) => ({ ...r, assessments: r.assessments.filter((a) => cohort.includes(a.cve_id)) })),
  };
}
function snapshotCSV(source) {
  const fields = [
    'cve_id',
    'vendor',
    'advisory_id',
    'product',
    'status',
    'scope',
    'versions',
    'remediations',
    'source_url',
    'observed_at',
    'sha256',
  ];
  const quote = (v) => {
    v = typeof v === 'object' ? JSON.stringify(v) : String(v ?? '');
    if (/^[=+\-@]/.test(v)) v = "'" + v;
    return '"' + v.replaceAll('"', '""') + '"';
  };
  return [
    fields.join(','),
    ...exportSnapshot(source).records.flatMap((r) =>
      r.assessments.map((a) => fields.map((f) => quote(a[f] ?? r[f])).join(',')),
    ),
  ].join('\r\n');
}
if (typeof document !== 'undefined') {
  const originalFetch = window.fetch.bind(window);
  const siteBase = new URL('.', document.baseURI).pathname;
  const delivery = createStaticDelivery(originalFetch, siteBase);
  let current,
    requestSequence = 0;
  window.fetch = async (input, options) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.origin);
    if (url.origin === location.origin && url.pathname === '/api/state') {
      const ids = url.searchParams.has('cves') ? url.searchParams.get('cves').split(',') : null;
      const options = {
        start: url.searchParams.get('start') ?? undefined,
        end: url.searchParams.get('end') ?? undefined,
        group: url.searchParams.get('group') ?? undefined,
        products: url.searchParams.has('products')
          ? JSON.parse(url.searchParams.get('products'))
          : undefined,
      };
      const sequence = ++requestSequence;
      const source = await (await delivery)(ids, url.searchParams.get('view') === 'changes');
      const chosen = selectSnapshot(source, ids ?? Object.keys(source.benchmark_cohort), options);
      if (sequence === requestSequence) current = chosen;
      return new Response(JSON.stringify(chosen), {
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input, options);
  };
  document.addEventListener('click', async (e) => {
    const a = e.target.closest('#json-export,#csv-export');
    if (!a) return;
    e.preventDefault();
    if (!current) return;
    const chosen = current;
    const csv = a.id === 'csv-export';
    try {
      const complete = csv
        ? chosen
        : {
            ...chosen,
            changes: (await (await delivery)(chosen.comparison.cohort, true)).changes,
          };
      const content = csv
        ? snapshotCSV(complete)
        : JSON.stringify(exportSnapshot(complete), null, 2);
      const url = URL.createObjectURL(
        new Blob([content], { type: csv ? 'text/csv' : 'application/json' }),
      );
      const out = document.createElement('a');
      out.href = url;
      out.download = csv ? 'impact.csv' : 'impact.json';
      out.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      document.querySelector('#feedback').textContent = 'Export failed: ' + error.message;
    }
  });
}
