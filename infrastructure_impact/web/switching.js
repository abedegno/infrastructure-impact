/* Pure selection from complete, immutable public study inputs. */
(() => {
  const legacyDefinition = {
    schema_version: 1,
    id: 'campus-branch-switching',
    version: 1,
    start_date: '2021-01-01',
    cutoff_date: '2026-04-07',
    targets: [
      {
        id: 'cisco-9200',
        vendor: 'cisco',
        family: 'cisco-iosxe',
        models: ['9200'],
        aliases: [
          {
            literal: 'Catalyst 9200',
            model: '9200',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html',
            source_locator: 'Product overview',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'cisco-9300',
        vendor: 'cisco',
        family: 'cisco-iosxe',
        models: ['9300', '9300L'],
        aliases: [
          {
            literal: 'Catalyst 9300',
            model: '9300',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html',
            source_locator: 'Product overview; Catalyst 9300 and 9300L models',
          },
          {
            literal: 'Catalyst 9300L',
            model: '9300L',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html',
            source_locator: 'Product overview; Catalyst 9300 and 9300L models',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'cisco-9400',
        vendor: 'cisco',
        family: 'cisco-iosxe',
        models: ['C9407R', 'C9410R'],
        aliases: [
          {
            literal: 'Cisco Catalyst C9407R',
            model: 'C9407R',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9400-series-switches/nb-06-cat9400-ser-data-sheet-cte-en.html',
            source_locator: 'Table 1: chassis features; Table 11: ordering information',
          },
          {
            literal: 'Cisco Catalyst C9410R',
            model: 'C9410R',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9400-series-switches/nb-06-cat9400-ser-data-sheet-cte-en.html',
            source_locator: 'Table 1: chassis features; Table 11: ordering information',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'cisco-9500',
        vendor: 'cisco',
        family: 'cisco-iosxe',
        models: ['9500'],
        aliases: [
          {
            literal: 'Catalyst 9500',
            model: '9500',
            source_url:
              'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/nb-06-cat9500-ser-data-sheet-cte-en.html',
            source_locator: 'Introduction',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'cisco-9600',
        vendor: 'cisco',
        family: 'cisco-iosxe',
        models: ['C9606R'],
        aliases: [
          {
            literal: 'Catalyst 9606R',
            model: 'C9606R',
            source_url:
              'https://www.cisco.com/site/us/en/products/collateral/networking/switches/catalyst-9600-series-switches/nb-06-cat9600-series-data-sheet-cte-en.html',
            source_locator: 'Cisco Catalyst 9606R chassis',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'aruba-6300',
        vendor: 'aruba',
        family: 'aruba-aoscx',
        models: ['6300M'],
        aliases: [
          {
            literal: 'HPE Aruba Networking CX 6300M',
            model: '6300M',
            source_url: 'https://www.hpe.com/int/en/collaterals/collateral.a00073540enw.html',
            source_locator: 'Models; CX 6300M',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'aruba-6400',
        vendor: 'aruba',
        family: 'aruba-aoscx',
        models: ['6410'],
        aliases: [
          {
            literal: 'HPE Aruba Networking 6410 Switch',
            model: '6410',
            source_url: 'https://www.hpe.com/psnow/doc/a00073541enw',
            source_locator: 'HPE Aruba Networking 6410 Switch (R0X27A)',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'arista-7050x3',
        vendor: 'arista',
        family: 'arista-eos',
        models: ['7050X3'],
        aliases: [
          {
            literal: 'Arista 7050X3 Series',
            model: '7050X3',
            source_url: 'https://www.arista.com/en/products/7050x3-series',
            source_locator: 'Overview heading',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'arista-720xp',
        vendor: 'arista',
        family: 'arista-eos',
        models: ['720XP'],
        aliases: [
          {
            literal: 'Arista 720XP Series',
            model: '720XP',
            source_url: 'https://www.arista.com/en/products/720xp-series',
            source_locator: 'Overview heading',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
      {
        id: 'arista-750',
        vendor: 'arista',
        family: 'arista-eos',
        models: ['750'],
        aliases: [
          {
            literal: 'Arista 750 Series',
            model: '750',
            source_url: 'https://www.arista.com/en/products/750-series',
            source_locator:
              'Arista 750 Series Cognitive Campus Modular POE Leaf Switches; technical specifications',
          },
        ],
        issues: [
          'lifecycle_unresolved',
          'release_train_coverage_unresolved',
          'role_equivalence_not_established',
        ],
      },
    ],
    references: [
      {
        id: 'cisco-9200-catalogue',
        vendor: 'cisco',
        source_url:
          'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9200-series-switches/nb-06-cat9200-ser-data-sheet-cte-en.html',
        source_locator: 'Product overview',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'cisco-9300-catalogue',
        vendor: 'cisco',
        source_url:
          'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html',
        source_locator: 'Product overview; Catalyst 9300 and 9300L models',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'cisco-9400-catalogue',
        vendor: 'cisco',
        source_url:
          'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9400-series-switches/nb-06-cat9400-ser-data-sheet-cte-en.html',
        source_locator: 'Table 1: chassis features; Table 11: ordering information',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'cisco-9500-catalogue',
        vendor: 'cisco',
        source_url:
          'https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9500-series-switches/nb-06-cat9500-ser-data-sheet-cte-en.html',
        source_locator: 'Introduction',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'cisco-9600-catalogue',
        vendor: 'cisco',
        source_url:
          'https://www.cisco.com/site/us/en/products/collateral/networking/switches/catalyst-9600-series-switches/nb-06-cat9600-series-data-sheet-cte-en.html',
        source_locator: 'Cisco Catalyst 9606R chassis',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'aruba-6300-catalogue',
        vendor: 'aruba',
        source_url: 'https://www.hpe.com/int/en/collaterals/collateral.a00073540enw.html',
        source_locator: 'Models; CX 6300M',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'aruba-6400-catalogue',
        vendor: 'aruba',
        source_url: 'https://www.hpe.com/psnow/doc/a00073541enw',
        source_locator: 'HPE Aruba Networking 6410 Switch (R0X27A)',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'arista-7050x3-catalogue',
        vendor: 'arista',
        source_url: 'https://www.arista.com/en/products/7050x3-series',
        source_locator: 'Overview heading',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'arista-720xp-catalogue',
        vendor: 'arista',
        source_url: 'https://www.arista.com/en/products/720xp-series',
        source_locator: 'Overview heading',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
      {
        id: 'arista-750-catalogue',
        vendor: 'arista',
        source_url: 'https://www.arista.com/en/products/750-series',
        source_locator:
          'Arista 750 Series Cognitive Campus Modular POE Leaf Switches; technical specifications',
        reviewed_at: '2026-11-04',
        issues: ['catalogue_not_historical_inventory'],
      },
    ],
  };
  const legacyHash = '5224471b014fccc278f985d08328926bac29ebc6bfb96d25f98972f91be6fd33';
  const method =
    'Distinct observed identities, not prevalence or a security ranking. OS-family and model-qualified contexts overlap; CVE sets across years and severity facets are nonadditive. Initial publisher dates determine disclosures; explicit bundles use their own initial dates. Conditional statements do not establish deployed configuration. General context notes do not establish prerequisites; absent conditionality is unclassified. Scores are provider-reported, not independently rescored. No timing, fix-delay, causal, equivalence or no-difference inference. Coverage describes source observation windows, not historical period completeness. The observation-end year is partial.';
  const vendors = ['cisco', 'aruba', 'arista'];
  const clone = (v) => JSON.parse(JSON.stringify(v));
  // Python orders Unicode scalar values; JS default UTF-16 ordering differs
  // for supplementary publisher identities. Never locale-normalize identities.
  const compareText = (a, b) => {
    const left = Array.from(a),
      right = Array.from(b);
    for (let i = 0; i < Math.min(left.length, right.length); i++) {
      const delta = left[i].codePointAt(0) - right[i].codePointAt(0);
      if (delta) return delta;
    }
    return left.length - right.length;
  };
  let allocationQuota = null,
    outputQuota = null,
    outputRows = 0;
  function boundedObject(entries, quota = null) {
    const json = window.InfrastructureJSON;
    if (quota) {
      quota.charge(2);
      let count = 0;
      for (const [key, value] of entries)
        quota.charge(
          json.stringBytes(key) +
            1 +
            (count++ ? 1 : 0) +
            json.measure(value, null, '', quota.remaining),
        );
    }
    return Object.fromEntries(entries);
  }
  function outputRow(entries) {
    if (outputQuota && outputRows++) outputQuota.charge(1);
    return boundedObject(entries, outputQuota);
  }

  const retain = (value, extra = 0) => {
    if (allocationQuota)
      allocationQuota.charge(
        window.InfrastructureJSON.measure(value, null, '', allocationQuota.remaining) + extra,
      );
    return value;
  };
  const append = (array, value) => {
    retain(value, array.length ? 1 : 2);
    array.push(value);
  };
  const sorted = (values) => {
    const unique = new Set();
    if (allocationQuota) allocationQuota.charge(2);
    for (const value of values)
      if (!unique.has(value)) {
        retain(value, unique.size ? 1 : 0);
        unique.add(value);
      }
    return [...unique].sort(compareText);
  };
  const canonical = (v, prepaid = false) => {
    if (allocationQuota)
      window.InfrastructureJSON.measure(
        v,
        null,
        '',
        prepaid ? 128000000 : allocationQuota.remaining,
      );
    return JSON.stringify(v, (_, x) =>
      x && typeof x === 'object' && !Array.isArray(x)
        ? Object.fromEntries(
            Object.keys(x)
              .sort()
              .map((k) => [k, x[k]]),
          )
        : x,
    );
  };
  const order = (a, b) => compareText(canonical(a), canonical(b));
  const day = (v) =>
    v === null ? null : /^\d{4}-\d{2}-\d{2}$/.test(v) ? v : new Date(v).toISOString().slice(0, 10);
  const ids = (rows, key) => sorted(rows.map((c) => c[key]).filter((v) => v !== null));
  const explicit = (c) =>
    c.status === 'affected' &&
    c.scope === 'cve_specific' &&
    c.cve_id !== null &&
    (c.publisher.status || '').toLowerCase() !== 'draft';
  function severityBand(version, value) {
    if (
      typeof value !== 'number' ||
      !Number.isFinite(value) ||
      value < 0 ||
      value > 10 ||
      !['2.0', '3.0', '3.1', '4.0'].includes(version)
    )
      return 'Unknown';
    if (version !== '2.0' && value === 0) return 'None';
    return value < 4
      ? 'Low'
      : value < 7
        ? 'Medium'
        : value < 9 || version === '2.0'
          ? 'High'
          : 'Critical';
  }
  function bounds(definition, end, window) {
    const start = definition.start_date,
      cutoff = definition.cutoff_date;
    if (window === 'undated') return [null, null];
    if (window === 'all') return [start, end];
    if (window === 'pre')
      return [
        start,
        [end, new Date(Date.parse(cutoff) - 86400000).toISOString().slice(0, 10)].sort()[0],
      ];
    if (window === 'post') return [cutoff, end];
    if (
      typeof window !== 'string' ||
      !/^\d{4}$/.test(window) ||
      +window < 2021 ||
      +window > +end.slice(0, 4)
    )
      throw Error('Invalid study window');
    return [[start, window + '-01-01'].sort()[1], [end, window + '-12-31'].sort()[0]];
  }
  const inWindow = (value, start, end, window) =>
    value === null
      ? ['all', 'undated'].includes(window)
      : window !== 'undated' && start <= value && value <= end;
  function events(claims) {
    const groups = [],
      buckets = new Map();
    for (const c of claims) {
      if (
        !explicit(c) ||
        !c.remediations.some(
          (r) =>
            r.category === 'vendor_fix' &&
            r.availability === 'vendor_reports_fixed' &&
            ((c.product_id && r.product_ids.includes(c.product_id)) || r.scope_binding != null),
        )
      )
        continue;
      const b = c.bundle,
        publisher = b ? b.publisher_id : c.advisory_id,
        prefix = c.vendor + ':' + (b ? 'bundle:' : 'unbundled:');
      if (!buckets.has(prefix)) buckets.set(prefix, new Map());
      const bucket = buckets.get(prefix);
      if (!bucket.has(publisher)) {
        // Reserve both event identity and publisher value before concatenation.
        if (allocationQuota)
          allocationQuota.charge(
            2 * window.InfrastructureJSON.measure(publisher, null, '', allocationQuota.remaining) +
              prefix.length +
              128,
          );
        const event = {
          event_id: prefix + publisher,
          kind: b ? 'bundle' : 'unbundled',
          publisher_id: publisher,
          dates: [],
          claim_ids: [],
          advisory_ids: [],
          cve_ids: [],
        };
        bucket.set(publisher, event);
        groups.push(event);
      }
      const e = bucket.get(publisher);
      append(e.dates, day(b ? b.published_at : c.initial_published_at));
      for (const [k, v] of [
        ['claim_ids', c.claim_id],
        ['advisory_ids', c.advisory_id],
        ['cve_ids', c.cve_id],
      ])
        append(e[k], v);
    }
    return groups
      .map((e) => {
        const dates = [...new Set(e.dates)];
        delete e.dates;
        return boundedObject(
          [
            ['event_id', e.event_id],
            ['kind', e.kind],
            ['publisher_id', e.publisher_id],
            ['claim_ids', sorted(e.claim_ids)],
            ['advisory_ids', sorted(e.advisory_ids)],
            ['cve_ids', sorted(e.cve_ids)],
            ['published_at', dates.length === 1 ? dates[0] : null],
            [
              'issues',
              dates.length > 1
                ? ['event_publication_date_conflicting']
                : dates[0] === null
                  ? ['event_publication_date_missing']
                  : [],
            ],
          ],
          allocationQuota ? window.InfrastructureJSON.budget(128000000) : null,
        );
      })
      .sort((a, b) => compareText(a.event_id, b.event_id));
  }
  function row(report, vendor, scope, window, requested, evaluated) {
    if (allocationQuota) allocationQuota.charge(2048);
    const [start, end] = bounds(report.definition, report.observation_end, window);
    const families = report.definition.targets
      .filter((t) => t.vendor === vendor)
      .map((t) => t.family);
    const candidates = report.inputs.evidence.claims.filter(
      (c) =>
        c.vendor === vendor &&
        families.includes(c.family) &&
        (scope === 'os_family' || c.scope_level === 'model_qualified') &&
        (requested === null || requested.includes(c.cve_id)) &&
        (day(c.initial_published_at) === null ||
          (report.definition.start_date <= day(c.initial_published_at) &&
            day(c.initial_published_at) <= report.observation_end)),
    );
    const claims = candidates.filter((c) =>
      inWindow(day(c.initial_published_at), start, end, window),
    );
    const active = claims.filter((c) => (c.publisher.status || '').toLowerCase() !== 'draft');
    const affected = active.filter(explicit);
    const selectedEvents = events(candidates).filter((e) =>
      inWindow(e.published_at, start, end, window),
    );
    const facets = new Map(),
      ratings = new Map(),
      statuses = new Map();
    for (const c of affected) {
      let scores = c.scores.filter((s) => s.scope === 'cve_specific' && s.cve_id === c.cve_id);
      if (!scores.length) scores = [{}];
      for (const s of scores) {
        const f = {
          version: s.version ?? null,
          provider: s.provider ?? null,
          origin: s.origin ?? null,
          preferred: s.preferred ?? null,
          band: severityBand(s.version, s.validation === 'incomplete' ? null : s.value),
        };
        const key = canonical(f);
        if (!facets.has(key)) {
          retain(key, 128);
          facets.set(key, { ...f, cve_ids: [] });
        }
        append(facets.get(key).cve_ids, c.cve_id);
      }
    }
    for (const c of active) {
      for (const r of c.vendor_severity || []) {
        const key = canonical([r.rating, r.scheme, r.namespace]);
        if (!ratings.has(key)) {
          retain(key, 128);
          ratings.set(key, {
            rating: r.rating,
            scheme: r.scheme,
            namespace: r.namespace,
            scope: 'advisory',
            advisory_ids: [],
          });
        }
        append(ratings.get(key).advisory_ids, c.advisory_id);
      }
      const key = canonical([c.status, c.scope]);
      if (!statuses.has(key)) statuses.set(key, []);
      retain(c.claim_id, 1);
      statuses.get(key).push(c);
    }
    const severity = [...facets.values()]
      .map((f) => ({ ...f, cve_ids: sorted(f.cve_ids), count: sorted(f.cve_ids).length }))
      .sort(order);
    const vendorSeverity = [...ratings.values()]
      .map((f) => ({
        ...f,
        advisory_ids: sorted(f.advisory_ids),
        count: sorted(f.advisory_ids).length,
      }))
      .sort(order);
    const buckets = [...statuses.entries()]
      .sort(([a], [b]) => compareText(a, b))
      .map(([, cs]) => ({
        status: cs[0].status,
        scope: cs[0].scope,
        claim_ids: ids(cs, 'claim_id'),
        cve_ids: ids(cs, 'cve_id'),
        count: ids(cs, 'cve_id').length,
      }));
    const sources = report.inputs.evidence.coverage.filter((c) => c.vendor === vendor).sort(order);
    const affectedIds = ids(affected, 'cve_id');
    const k = windowObject.InfrastructureKev.selectReport(report.inputs.kev, affectedIds, {
      evaluatedAt: evaluated,
    });
    const listed = affectedIds.filter((c) => k.selection.membership[c] === 'listed'),
      unknown = affectedIds.filter((c) => k.selection.membership[c] === 'unknown');
    const advisoryIds = ids(active, 'advisory_id'),
      affectedAdvisoryIds = ids(affected, 'advisory_id'),
      selectedCves = sorted([
        ...ids(claims, 'cve_id'),
        ...selectedEvents.flatMap((e) => e.cve_ids),
      ]),
      claimIds = ids(claims, 'claim_id'),
      conditional = ids(
        affected.filter((c) => c.conditional_affected === true),
        'cve_id',
      );
    const counts = {
      advisories: advisoryIds.length,
      affected_advisories: affectedAdvisoryIds.length,
      cves: selectedCves.length,
      claims: claimIds.length,
      affected_cves: affectedIds.length,
      conditional_cves: conditional.length,
      conditionality_unclassified_cves: ids(
        affected.filter((c) => c.conditional_affected == null),
        'cve_id',
      ).length,
      draft_advisories: ids(
        claims.filter((c) => (c.publisher.status || '').toLowerCase() === 'draft'),
        'advisory_id',
      ).length,
      remediation_events: selectedEvents.length,
      bundled_events: selectedEvents.filter((e) => e.kind === 'bundle').length,
      unbundled_publications: selectedEvents.filter((e) => e.kind === 'unbundled').length,
      fixed_only_claims: active.filter((c) => c.status === 'fixed').length,
      planned_fix_claims: active.filter((c) =>
        c.remediations.some((r) => r.availability === 'planned'),
      ).length,
      workaround_claims: active.filter((c) =>
        c.remediations.some((r) => r.category === 'workaround'),
      ).length,
      model_unresolved_claims: active.filter((c) => c.scope_level !== 'model_qualified').length,
    };
    return outputRow([
      ['row_id', `${vendor}:${scope}:${window}`],
      ['vendor', vendor],
      ['scope_level', scope],
      ['window', window],
      ['period_start', start],
      ['period_end', end],
      ['date_basis', 'initial_publisher_date_utc_day'],
      ['event_date_basis', 'explicit_bundle_initial_else_advisory_initial'],
      ['advisory_ids', advisoryIds],
      ['affected_advisory_ids', affectedAdvisoryIds],
      ['cve_ids', selectedCves],
      ['claim_ids', claimIds],
      ['affected_cve_ids', affectedIds],
      ['conditional_cve_ids', conditional],
      ['event_ids', selectedEvents.map((e) => e.event_id)],
      ['events', selectedEvents],
      ['counts', counts],
      ['status_buckets', buckets],
      ['severity', severity],
      ['vendor_severity', vendorSeverity],
      [
        'kev',
        {
          availability: k.source.availability,
          listed_cve_ids: listed,
          unknown_cve_ids: unknown,
          listed_count: listed.length,
          unknown_count: unknown.length,
          denominator: affectedIds.length,
        },
      ],
      [
        'coverage',
        {
          state: sources.length ? 'partial' : 'unknown',
          expected_advisories: null,
          observed_advisories: advisoryIds.length,
          basis: 'retained_source_windows_not_period_completeness',
          sources,
        },
      ],
      [
        'denominators',
        {
          affected_cves: affectedIds.length,
          observed_advisories: advisoryIds.length,
          expected_advisories: null,
        },
      ],
      [
        'issues',
        sorted([
          ...report.inputs.evidence.issues,
          'period_coverage_unknown',
          'sets_nonadditive',
          ...(counts.model_unresolved_claims ? ['model_binding_unresolved'] : []),
        ]),
      ],
    ]);
  }
  const windowObject = window;
  function selectUnchecked(report, options = {}) {
    const vendor = options.vendor ?? null,
      scope = options.scope_level ?? options.scope ?? 'os_family',
      window = options.window ?? 'all',
      requested = options.cve_ids ?? options.cveIds ?? null,
      evaluated = options.evaluated_at ?? options.evaluatedAt ?? new Date().toISOString();
    if (
      (vendor !== null && !vendors.includes(vendor)) ||
      !['os_family', 'model_qualified'].includes(scope) ||
      (requested !== null &&
        (!Array.isArray(requested) ||
          requested.some((c) => typeof c !== 'string' || !/^CVE-\d{4}-\d{4,19}$/.test(c))))
    )
      throw Error('Invalid study selection');
    if (!report || report.availability === 'unavailable' || report.schema_version !== 1) {
      const e = Error('Switching unavailable');
      e.code = 'switching_unavailable';
      throw e;
    }
    if (
      report.representation ||
      !report.inputs ||
      Object.keys(report.inputs).sort().join(',') !== 'evidence,kev'
    )
      throw Error('Complete study inputs required');
    for (const input of [report.inputs.evidence, report.inputs.kev])
      if (
        canonical(input.publication) !== canonical(report.publication) ||
        input.generated_at !== report.generated_at
      )
        throw Error('Mixed study generations');
    if (report.inputs.evidence.definition_sha256 !== report.selection.definition_sha256)
      throw Error('Mixed study definitions');
    const result = { ...report },
      selectedVendors = vendor ? [vendor] : vendors,
      selectedIds = requested === null ? null : sorted(requested);
    result.evaluated_at = evaluated;
    result.rows = selectedVendors.map((v) => row(result, v, scope, window, selectedIds, evaluated));
    const nextSelection = {
      requested_vendor: vendor,
      effective_vendors: [...selectedVendors],
      scope_level: scope,
      requested_window: window,
      effective_windows: result.rows.map((r) => r.row_id),
      requested_cve_ids: selectedIds,
      effective_cve_ids: sorted(result.rows.flatMap((r) => r.cve_ids)),
      definition_sha256: report.selection.definition_sha256,
    };
    if (outputQuota)
      outputQuota.charge(
        windowObject.InfrastructureJSON.stringBytes('selection') +
          2 +
          windowObject.InfrastructureJSON.measure(nextSelection, null, '', outputQuota.remaining),
      );
    result.selection = nextSelection;
    const used = new Set(
        result.rows.flatMap((r) => [...r.claim_ids, ...r.events.flatMap((e) => e.claim_ids)]),
      ),
      sources = new Map();
    function collect(v) {
      if (Array.isArray(v)) v.forEach(collect);
      else if (v && typeof v === 'object') {
        if (
          Object.keys(v).sort().join(',') === 'retrieved_at,source_locator,source_sha256,source_url'
        ) {
          retain(v, 2);
          retain(v, 2);
          sources.set(canonical(v, true), v);
        } else Object.values(v).forEach(collect);
      }
    }
    result.inputs.evidence.claims.filter((c) => used.has(c.claim_id)).forEach(collect);
    if (allocationQuota) allocationQuota.charge(2);
    if (outputQuota) {
      let count = 0;
      for (const value of sources.values())
        outputQuota.charge(
          windowObject.InfrastructureJSON.measure(value, null, '', outputQuota.remaining) +
            (count++ ? 1 : 0),
        );
    }
    result.sources = [...sources.values()].sort(order);
    return result;
  }
  // Trust only objects owned here. Caller-owned objects are copied, checked and
  // deeply frozen once; no public flag or mutable object identity bypasses gates.
  const acceptedReports = new WeakSet(),
    frozenNodes = new WeakSet();
  function freezeOwned(value) {
    if (value && typeof value === 'object' && !frozenNodes.has(value)) {
      Object.values(value).forEach(freezeOwned);
      Object.freeze(value);
      frozenNodes.add(value);
    }
    return value;
  }
  function accept(report) {
    freezeOwned(report);
    acceptedReports.add(report);
    return report;
  }
  function ownedJSON(value, ancestors = new Set()) {
    if (value === null || ['string', 'boolean'].includes(typeof value)) return value;
    if (typeof value === 'number' && Number.isFinite(value)) return value;
    if (!value || typeof value !== 'object' || ancestors.has(value))
      throw Error('Study inputs must be finite, acyclic JSON values');
    ancestors.add(value);
    const copy = Array.isArray(value)
      ? Array.from(value, (v) => ownedJSON(v, ancestors))
      : Object.fromEntries(Object.keys(value).map((k) => [k, ownedJSON(value[k], ancestors)]));
    ancestors.delete(value);
    return copy;
  }
  function prepareReport(input) {
    if (acceptedReports.has(input)) return input;
    const report = ownedJSON(input);
    window.InfrastructureSwitchingContracts.full(report);
    if (report.availability === 'available') {
      const original = selectUnchecked(report, {
        vendor: report.selection.requested_vendor,
        scope_level: report.selection.scope_level,
        window: report.selection.requested_window,
        cve_ids: report.selection.requested_cve_ids,
        evaluated_at: report.evaluated_at,
      });
      for (const key of ['rows', 'sources', 'selection'])
        if (canonical(report[key]) !== canonical(original[key]))
          throw Error('Study derived ' + key + ' disagree with inputs');
    }
    return accept(report);
  }
  function selectReport(report, options = {}) {
    if (
      report &&
      report.schema_version === 1 &&
      report.availability === 'available' &&
      !report.inputs
    )
      throw Error('Complete study inputs required');
    const recognized = report && report.schema_version === 1 && 'availability' in report;
    if (recognized) report = prepareReport(report);
    if (!recognized) {
      const evaluated = options.evaluated_at ?? options.evaluatedAt ?? new Date().toISOString();
      const generated = options.generated_at ?? report?.generated_at ?? evaluated;
      report = {
        schema_version: 1,
        publication: clone(options.publication ?? report?.publication ?? null),
        generated_at: generated,
        evaluated_at: evaluated,
        availability: 'unavailable',
        definition: clone(legacyDefinition),
        observation_end: day(generated),
        inputs: null,
        rows: [],
        sources: [],
        issues: ['comparison_unavailable'],
        method: method,
      };
    }
    if (report.availability === 'unavailable') {
      if (report.inputs !== null || report.rows.length || report.sources.length)
        throw Error('Invalid unavailable study');
      const vendor = options.vendor ?? null,
        scope = options.scope_level ?? options.scope ?? 'os_family',
        window = options.window ?? 'all',
        requested = options.cve_ids ?? options.cveIds ?? null;
      if (
        (vendor !== null && !vendors.includes(vendor)) ||
        !['os_family', 'model_qualified'].includes(scope) ||
        (requested !== null &&
          (!Array.isArray(requested) ||
            requested.some((c) => typeof c !== 'string' || !/^CVE-\d{4}-\d{4,19}$/.test(c))))
      )
        throw Error('Invalid study selection');
      bounds(report.definition, report.observation_end, window);
      const result = clone(report);
      result.evaluated_at = options.evaluated_at ?? options.evaluatedAt ?? new Date().toISOString();
      // Validate evaluation timestamps through the same KEV time contract.
      windowObject.InfrastructureKev.selectReport(null, [], { evaluatedAt: result.evaluated_at });
      result.selection = {
        requested_vendor: vendor,
        effective_vendors: vendor ? [vendor] : [...vendors],
        scope_level: scope,
        requested_window: window,
        effective_windows: [],
        requested_cve_ids: requested === null ? null : sorted(requested),
        effective_cve_ids: [],
        definition_sha256: legacyHash,
      };
      return result;
    }
    const keys = [
      'schema_version',
      'publication',
      'generated_at',
      'evaluated_at',
      'availability',
      'definition',
      'observation_end',
      'selection',
      'rows',
      'sources',
      'issues',
      'method',
      'inputs',
    ].sort();
    if (
      Object.keys(report).sort().join(',') !== keys.join(',') ||
      report.method !== method ||
      report.availability !== 'available'
    )
      throw Error('Invalid full study envelope');
    return accept(selectUnchecked(report, options));
  }
  // Full claims are validated once at the stream boundary, then discarded.
  // This private projection is never passed off as a v1 evidence document.
  async function selectClaims(metadata, evidence, kev, claims, options = {}, limits = {}) {
    const reduced = [],
      cap = Math.min(limits.max_bytes ?? 128000000, 128000000),
      validation = window.InfrastructureSwitchingContracts.evidenceStream(
        evidence,
        metadata.definition,
      );
    // Validate controls before reading the claim stream; retain all candidate
    // dates because explicit bundle dates can select a claim outside its window.
    const controlReport = {
      ...metadata,
      schema_version: 1,
      inputs: { evidence: { ...evidence, claims: [] }, kev },
    };
    delete controlReport.representation;
    delete controlReport.detail_ranges;
    selectUnchecked(controlReport, options);
    const requested = options.cve_ids ?? options.cveIds ?? null,
      vendor = options.vendor ?? null,
      scope = options.scope_level ?? options.scope ?? 'os_family';
    const json = window.InfrastructureJSON,
      workingCap = limits.working_bytes ?? 512000000;
    if (!Number.isSafeInteger(workingCap) || workingCap < 1 || workingCap > 512000000)
      throw Error('Invalid reducer working budget');
    const projectionQuota = {
      remaining: workingCap,
      charge(size) {
        if (!Number.isSafeInteger(size) || size < 0 || size > this.remaining)
          throw Error('Reducer working byte budget exceeded');
        this.remaining -= size;
      },
    };
    projectionQuota.charge(2);
    let validationBytes = 0;
    const chargeProperty = (key, value) =>
      projectionQuota.charge(
        json.stringBytes(key) +
          1 +
          json.measure(value, null, '', Math.min(128000000, projectionQuota.remaining)),
      );
    function pick(value, keys) {
      projectionQuota.charge(2);
      const result = {};
      let count = 0;
      for (const key of keys)
        if (Object.hasOwn(value, key)) {
          chargeProperty(key, value[key]);
          if (count++) projectionQuota.charge(1);
          result[key] = value[key];
        }
      return result;
    }
    function arrayProperty(target, key, values, keys) {
      projectionQuota.charge(json.stringBytes(key) + 4);
      const result = [];
      for (const value of values) {
        if (result.length) projectionQuota.charge(1);
        result.push(pick(value, keys));
      }
      target[key] = result;
    }
    for await (const sourceClaim of claims) {
      json.measure(sourceClaim, null, '', 128000000);
      const claim = ownedJSON(sourceClaim);
      validation.add(claim);
      projectionQuota.charge(validation.bytes - validationBytes);
      validationBytes = validation.bytes;
      if (
        (vendor !== null && claim.vendor !== vendor) ||
        (requested !== null && !requested.includes(claim.cve_id)) ||
        (scope === 'model_qualified' && claim.scope_level !== 'model_qualified')
      )
        continue;
      if (reduced.length) projectionQuota.charge(1);
      const projection = pick(claim, [
        'claim_id',
        'vendor',
        'advisory_id',
        'cve_id',
        'product_id',
        'family',
        'scope_level',
        'status',
        'scope',
        'initial_published_at',
        'conditional_affected',
      ]);
      projectionQuota.charge(json.stringBytes('publisher') + 2);
      projection.publisher = pick(claim.publisher, ['status']);
      projectionQuota.charge(json.stringBytes('bundle') + 2);
      if (claim.bundle === null) {
        projectionQuota.charge(4);
        projection.bundle = null;
      } else projection.bundle = pick(claim.bundle, ['publisher_id', 'published_at']);
      arrayProperty(projection, 'remediations', claim.remediations, [
        'category',
        'availability',
        'product_ids',
        'scope_binding',
      ]);
      arrayProperty(projection, 'scores', claim.scores, [
        'scope',
        'cve_id',
        'version',
        'value',
        'provider',
        'origin',
        'preferred',
        'validation',
      ]);
      arrayProperty(projection, 'vendor_severity', claim.vendor_severity || [], [
        'rating',
        'scheme',
        'namespace',
      ]);
      projectionQuota.charge(json.stringBytes('sources') + 4);
      projection.sources = [];
      function collect(v) {
        if (Array.isArray(v)) {
          for (const child of v) collect(child);
        } else if (v && typeof v === 'object') {
          const keys = Object.keys(v);
          if (
            keys.length === 4 &&
            keys.includes('retrieved_at') &&
            keys.includes('source_locator') &&
            keys.includes('source_sha256') &&
            keys.includes('source_url')
          ) {
            projectionQuota.charge(
              json.measure(v, null, '', Math.min(128000000, projectionQuota.remaining)) +
                (projection.sources.length ? 1 : 0),
            );
            projection.sources.push(v);
          } else for (const key of keys) collect(v[key]);
        }
      }
      collect(claim);
      reduced.push(projection);
    }
    validation.finish();
    const report = {
      ...metadata,
      schema_version: 1,
      inputs: { evidence: { ...evidence, claims: reduced }, kev },
    };
    delete report.representation;
    delete report.detail_ranges;
    let selected;
    const previousQuota = allocationQuota,
      previousOutput = outputQuota,
      previousRows = outputRows;
    allocationQuota = json.budget(cap);
    outputQuota = json.budget(cap);
    outputRows = 0;
    try {
      const { inputs, rows, sources, selection, ...header } = report;
      const base = {
        ...header,
        evaluated_at: options.evaluated_at ?? options.evaluatedAt ?? new Date().toISOString(),
        rows: [],
        sources: [],
        representation: 'summary',
      };
      const size = json.measure(base, null, '', cap);
      allocationQuota.charge(size);
      outputQuota.charge(size);
      selected = summary(selectUnchecked(report, options));
    } finally {
      allocationQuota = previousQuota;
      outputQuota = previousOutput;
      outputRows = previousRows;
    }
    window.InfrastructureSwitchingContracts.summary(selected, metadata);
    return selected;
  }
  function summary(report) {
    const { inputs, ...body } = report;
    body.representation = 'summary';
    if (window.InfrastructureJSON?.measure) window.InfrastructureJSON.measure(body);
    const r = clone(body);
    return r;
  }
  function queryOptions(params, end) {
    const allowed = ['vendor', 'scope', 'window', 'cves', 'format'];
    for (const key of params.keys())
      if (!allowed.includes(key) || params.getAll(key).length !== 1 || !params.get(key))
        throw Error('Invalid study query');
    const vendor = params.get('vendor'),
      scope = params.get('scope') ?? 'os_family',
      window = params.get('window') ?? 'all',
      cves = params.has('cves') ? params.get('cves').split(',') : null,
      format = params.get('format') ?? 'json';
    if (
      (vendor !== null && !vendors.includes(vendor)) ||
      !['os_family', 'model_qualified'].includes(scope) ||
      !['json', 'csv'].includes(format) ||
      (cves !== null &&
        (new Set(cves).size !== cves.length || cves.some((c) => !/^CVE-\d{4}-\d{4,19}$/.test(c))))
    )
      throw Error('Invalid study query');
    bounds({ start_date: '2021-01-01', cutoff_date: '2026-04-07' }, end, window);
    return { options: { vendor, scope_level: scope, window, cve_ids: cves }, format };
  }
  window.InfrastructureSwitching = {
    selectReport,
    prepareReport,
    severityBand,
    summary,
    selectClaims,
    queryOptions,
    render: (...args) => window.InfrastructureSwitchingView.render(...args),
  };
})();
(() => {
  const fields = [
    'publication_id',
    'publication_generated_at',
    'definition_id',
    'definition_version',
    'definition_sha256',
    'vendor',
    'scope_level',
    'window',
    'period_start',
    'period_end',
    'totals_basis',
    'observed_advisories',
    'affected_advisories',
    'observed_cves',
    'affected_cves',
    'remediation_events',
    'bundled_events',
    'unbundled_publications',
    'draft_advisories',
    'model_unresolved_claims',
    'conditional_cves',
    'conditionality_unclassified_cves',
    'severity_version',
    'severity_provider',
    'severity_origin',
    'severity_preferred',
    'severity_band',
    'severity_count',
    'kev_basis',
    'kev_availability',
    'kev_listed',
    'kev_unknown',
    'coverage_state',
    'coverage_observed_advisories',
    'coverage_expected_advisories',
    'coverage_issues',
    'source_window_states',
  ];
  function csvExport(report, options = {}) {
    const quota =
      options.max_bytes === undefined ? null : window.InfrastructureJSON.budget(options.max_bytes);
    function cellBytes(value) {
      let size = 2,
        first = true,
        formula = false;
      for (const c of value) {
        if (first && !/\s/u.test(c)) {
          formula = /[=+\-@]/.test(c);
          first = false;
        }
        const n = c.codePointAt(0);
        size += c === '"' ? 2 : n < 128 ? 1 : n < 2048 ? 2 : n < 65536 ? 3 : 4;
      }
      if (formula || /^[\t\r\n]/.test(value)) size++;
      return size;
    }
    const cell = (value) => {
      let v = value == null ? '' : String(value);
      quota?.charge(cellBytes(v));
      if (/^[=+\-@]/.test(v.trimStart()) || /^[\t\r\n]/.test(v)) v = "'" + v;
      return '"' + v.replaceAll('"', '""') + '"';
    };
    quota?.charge(fields.join(',').length);
    const lines = [fields.join(',')];
    for (const r of report.rows) {
      const c = r.counts,
        k = r.kev,
        coverage = r.coverage;
      const issues = [
        ...new Set(coverage.sources.flatMap((s) => [...s.issues, ...(s.enumeration?.gaps || [])])),
      ].sort();
      const common = [
        report.publication?.id,
        report.generated_at,
        report.definition.id,
        report.definition.version,
        report.selection.definition_sha256,
        r.vendor,
        r.scope_level,
        r.window,
        r.period_start,
        r.period_end,
        'repeated_totals_nonadditive',
        c.advisories,
        c.affected_advisories,
        c.cves,
        c.affected_cves,
        c.remediation_events,
        c.bundled_events,
        c.unbundled_publications,
        c.draft_advisories,
        c.model_unresolved_claims,
        c.conditional_cves,
        c.conditionality_unclassified_cves,
      ];
      for (const f of r.severity.length ? r.severity : [{ band: 'Unknown', count: 0 }]) {
        quota?.charge(fields.length - 1 + 2);
        lines.push(
          [
            ...common,
            ...['version', 'provider', 'origin', 'preferred', 'band', 'count'].map((key) => f[key]),
            'documented_affected_cves',
            k.availability,
            k.listed_count,
            k.unknown_count,
            coverage.state,
            coverage.observed_advisories,
            coverage.expected_advisories,
            issues.join(';'),
            [...new Set(coverage.sources.map((s) => s.enumeration?.coverage_state ?? s.state))]
              .sort()
              .join(';'),
          ]
            .map(cell)
            .join(','),
        );
      }
    }
    return lines.join('\r\n');
  }
  Object.assign(window.InfrastructureSwitching, { csvExport, csvFields: fields });
})();
