/* Portable selection of native-owned facts. No vendor parsing or inference. */
(() => {
  const C = window.InfrastructureSwitchingContracts,
    S = window.InfrastructureSwitching,
    J = window.InfrastructureJSON,
    D = C.policy.study_definition,
    families = { cisco: 'cisco-iosxe', aruba: 'aruba-aoscx', arista: 'arista-eos' },
    trains = {
      cisco: ['17.9', '17.12', '17.15'],
      aruba: ['10.13', '10.14', '10.16'],
      arista: ['4.32', '4.33', '4.34'],
    },
    scenarios = ['publisher_first_fixed', 'known_fixed_target', 'inferred_inclusive'],
    policies = ['all_affected', 'high_risk'],
    clone = (v) => J.clone(v),
    sorted = (v) => [...new Set(v)].sort(),
    hash = (v) => C.fingerprint(Array.isArray(v) ? { items: v } : v),
    eq = (a, b) => hash(a) === hash(b),
    omit = (v, keys) => Object.fromEntries(Object.entries(v).filter(([k]) => !keys.includes(k))),
    fail = (text) => {
      throw Error('Switching analysis: ' + text);
    },
    explicit = (c) =>
      c.status === 'affected' &&
      c.scope === 'cve_specific' &&
      (c.publisher.status || '').toLowerCase() !== 'draft',
    measure = (v) => J.measure(v, null, '', 128000000);
  function shape(v, name) {
    C.validate('switching-analysis-v1.json', v, '/$defs/' + name);
  }
  function claimFacets(report) {
    return Object.entries(report.claims).map(([id, value]) => {
      const source = report.requirements.facts[value.source_ref];
      if (
        value.claim_id !== id ||
        !source ||
        Array.isArray(source) ||
        !eq(Object.keys(source).sort(), [
          'retrieved_at',
          'source_locator',
          'source_sha256',
          'source_url',
        ])
      )
        fail('source reference ownership/type differs');
      return { ...omit(value, ['source_ref']), source };
    });
  }
  function validate(report, identity = report) {
    measure(report);
    C.identity(report, identity);
    shape(report, 'compiled');
    if (report.content_sha256 !== hash(omit(report, ['content_sha256'])))
      fail('content fingerprint differs');
    if (report.definition_sha256 !== C.policy.definition_sha256) fail('definition differs');
    const r = report.requirements;
    C.identity(r, report);
    if (
      r.content_sha256 !== hash(omit(r, ['content_sha256'])) ||
      r.membership_sha256 !== hash(r.members) ||
      r.membership_count !== Object.keys(r.members).length
    )
      fail('requirement fingerprint differs');
    for (const [id, f] of Object.entries(r.facts))
      if (id !== hash(f)) fail('fact fingerprint differs');
    const expandedClaims = claimFacets(report),
      claimsById = new Map(expandedClaims.map((c) => [c.claim_id, c]));
    for (const [id, m] of Object.entries(r.members)) {
      const c = claimsById.get(id);
      if (
        !c ||
        c.claim_sha256 !== m.claim_sha256 ||
        ['vendor', 'family', 'cve_id', 'advisory_id', 'scope_level'].some((k) => c[k] !== m[k]) ||
        S.day(c.initial_published_at) !== m.date
      )
        fail('member ownership differs');
      for (const k of ['source_ref', 'severity_facets_ref'])
        if (!Object.hasOwn(r.facts, m[k])) fail('missing fact');
      if (!eq(c.source, r.facts[m.source_ref])) fail('member source ownership differs');
    }
    for (const q of r.requirements)
      if (
        !r.members[q.claim_id] ||
        !Object.hasOwn(r.facts, q.proof_ref) ||
        !Object.hasOwn(r.facts, q.train_binding_ref)
      )
        fail('missing requirement ownership');
    for (const child of [
      report.disclosure,
      report.kev_reconciliation,
      report.release_history,
    ].filter(Boolean))
      C.identity(child, report);
    if (
      r.observation_end !== S.day(r.generated_at) ||
      r.kev_context.evaluated_at !== r.generated_at ||
      r.selection !== null
    )
      fail('requirement bounds differ');
    for (const child of [r, report.disclosure, report.kev_reconciliation])
      for (const key of ['definition_sha256', 'observation_end'])
        if (child[key] !== report[key]) fail('child bounds differ');
    const groups = new Map(r.inference_groups.map((g) => [g.group_id, g])),
      seen = new Set(),
      membership = new Map();
    if (groups.size !== r.inference_groups.length) fail('duplicate inference group');
    for (const [id, g] of groups)
      if (id !== hash(omit(g, ['group_id']))) fail('inference fingerprint differs');
    for (const q of r.requirements) {
      const m = r.members[q.claim_id],
        key = JSON.stringify([q.claim_id, q.train, q.scenario]),
        scope = JSON.stringify([q.claim_id, q.train]);
      shape(
        {
          ...omit(m, ['source_ref', 'severity_facets_ref']),
          ...omit(q, ['proof_ref', 'train_binding_ref']),
          source: r.facts[m.source_ref],
          severity_facets: r.facts[m.severity_facets_ref],
          proof: r.facts[q.proof_ref],
          train_binding: r.facts[q.train_binding_ref],
        },
        'upgrade_constraint',
      );
      let minimum = q.alternatives[0] ?? null;
      for (const value of q.alternatives) {
        const parts = /^([0-9]+)\.([0-9]+)\./.exec(value),
          order = compare(m.vendor, value, minimum);
        if (!parts || `${BigInt(parts[1])}.${BigInt(parts[2])}` !== q.train || order === null) {
          minimum = null;
          break;
        }
        if (order < 0) minimum = value;
      }
      if (q.target !== minimum) fail('compiled target differs');
      if (seen.has(key)) fail('duplicate requirement');
      seen.add(key);
      if (!membership.has(scope)) membership.set(scope, new Set());
      membership.get(scope).add(q.scenario);
      if (q.target !== null && !r.facts[q.proof_ref].length) fail('target lacks proof');
      if (m.date === null && !q.issues.includes('unknown_initial_publication'))
        fail('unknown date lost');
      if (q.target === null && !q.issues.length) fail('unknown target lost');
      if (q.inference) {
        const g = groups.get(q.inference.group_id);
        if (
          !g ||
          !g.affected_claim_ids.includes(q.claim_id) ||
          g.maximum_affected !== q.inference.maximum_affected
        )
          fail('inference membership differs');
      }
    }
    if (
      [...membership.values()].some(
        (v) => v.size !== scenarios.length || scenarios.some((s) => !v.has(s)),
      ) ||
      new Set(r.requirements.map((q) => q.claim_id)).size !== Object.keys(r.members).length
    )
      fail('scenario ownership differs');
    const full = context(report, {}),
      owned = new Map(),
      pairKey = (c) =>
        JSON.stringify([
          c.vendor,
          c.family,
          c.advisory_id,
          c.cve_id,
          c.source.source_url,
          c.source.source_sha256,
        ]);
    for (const child of [report.disclosure, report.kev_reconciliation])
      if (!eq(child.selection, full.selection)) fail('child selection differs');
    for (const c of selectedClaims(report, full.selection).filter(explicit)) {
      const key = pairKey(c);
      if (!owned.has(key)) owned.set(key, []);
      owned.get(key).push(c);
    }
    if (!eq(sorted(report.disclosure.pairs.map(pairKey)), [...owned.keys()].sort()))
      fail('disclosure membership differs');
    for (const p of report.disclosure.pairs) {
      const claims = owned.get(pairKey(p)),
        facets = new Map(
          claims.flatMap((c) => c.disclosure_severity).map((f) => [canonical(f), f]),
        );
      if (
        !eq(p.claim_ids, claims.map((c) => c.claim_id).sort()) ||
        !eq(p.source, claims[0].source) ||
        claims.some((c) => c.initial_published_at !== p.initial_published_at) ||
        !eq(p.product_ids, sorted(claims.map((c) => c.product_id).filter((v) => v !== null))) ||
        !eq(
          p.models,
          sorted(
            claims
              .flatMap((c) => c.platform_bindings.map((b) => b.model))
              .filter((v) => v !== null),
          ),
        ) ||
        !eq(
          p.severity,
          [...facets.keys()].sort().map((k) => facets.get(k)),
        )
      )
        fail('disclosure claim ownership differs');
    }
    for (const e of report.kev_reconciliation.entries) {
      const claims = expandedClaims.filter(
          (c) =>
            c.vendor === e.mapping.vendor && c.family === e.mapping.family && c.cve_id === e.cve_id,
        ),
        refs = claims.map((c) => ({
          claim_id: c.claim_id,
          advisory_id: c.advisory_id,
          status: c.status,
          publisher_status: c.publisher.status,
          scope: c.scope,
          scope_level: c.scope_level,
          initial_published_at: c.initial_published_at,
          models: sorted(c.platform_bindings.map((b) => b.model).filter((v) => v !== null)),
          conditional_affected: c.conditional_affected,
          source: c.source,
        }));
      if (!eq(e.current_claims, refs)) fail('KEV current claim ownership differs');
    }
    return report;
  }
  function selectedClaims(report, s) {
    const [start, end] = S.bounds(D, report.observation_end, s.requested_window);
    return claimFacets(report).filter((c) => {
      const d = S.day(c.initial_published_at);
      return (
        s.effective_vendors.includes(c.vendor) &&
        c.family === families[c.vendor] &&
        (s.scope_level === 'os_family' || c.scope_level === 'model_qualified') &&
        (s.requested_cve_ids === null || s.requested_cve_ids.includes(c.cve_id)) &&
        (d === null || (D.start_date <= d && d <= report.observation_end)) &&
        S.inWindow(d, start, end, s.requested_window)
      );
    });
  }
  function context(report, options = {}) {
    if (
      Object.keys(options).some((k) => !['vendor', 'scope_level', 'window', 'cve_ids'].includes(k))
    )
      fail('unknown selection option');
    const { vendor = null, scope_level = 'os_family', window = 'all', cve_ids = null } = options;
    if (
      (vendor !== null && !Object.hasOwn(families, vendor)) ||
      !['os_family', 'model_qualified'].includes(scope_level) ||
      (cve_ids !== null &&
        (!Array.isArray(cve_ids) ||
          new Set(cve_ids).size !== cve_ids.length ||
          cve_ids.some((v) => !/^CVE-[0-9]{4}-[0-9]{4,19}$/.test(v))))
    )
      fail('invalid selection');
    S.bounds(D, report.observation_end, window);
    const vendors = vendor ? [vendor] : Object.keys(families),
      s = {
        requested_vendor: vendor,
        effective_vendors: vendors,
        scope_level,
        requested_window: window,
        effective_windows: vendors.map((v) => `${v}:${scope_level}:${window}`),
        requested_cve_ids: cve_ids === null ? null : sorted(cve_ids),
        effective_cve_ids: [],
        definition_sha256: report.definition_sha256,
      };
    const selected = selectedClaims(report, s);
    s.effective_cve_ids = sorted(selected.map((c) => c.cve_id).filter((v) => v !== null));
    return {
      publication: clone(report.publication),
      generated_at: report.generated_at,
      observation_end: report.observation_end,
      selection: s,
      definition: clone(D),
      rows: vendors.map((v) => ({
        vendor: v,
        affected_cve_ids: sorted(
          selected.filter((c) => c.vendor === v && explicit(c)).map((c) => c.cve_id),
        ),
      })),
    };
  }
  // Ordering only applies to already-compiled target literals; it never derives a target.
  function compare(v, a, b) {
    function key(x) {
      if (typeof x !== 'string' || x.length > 128) return null;
      let m;
      if (v === 'cisco' && (m = /^([0-9]+)\.([0-9]+)\.([0-9]+)([abc]?)$/.exec(x)))
        return [...m.slice(1, 4).map(BigInt), BigInt(m[4] ? 'abc'.indexOf(m[4]) + 1 : 0)];
      if (v === 'aruba' && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(x)) return x.split('.').map(BigInt);
      if (v === 'arista' && (m = /^([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)([FM]?)$/.exec(x)))
        return [...m[1].split('.').map(BigInt), m[2]];
      return null;
    }
    let x = key(a),
      y = key(b);
    if (!x || !y || x[0] !== y[0] || x[1] !== y[1]) return null;
    if (v === 'arista') {
      if (
        x.length !== y.length ||
        (x.slice(0, -1).every((n, i) => n === y[i]) && x.at(-1) !== y.at(-1))
      )
        return null;
      x = x.slice(0, -1);
      y = y.slice(0, -1);
    }
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] > y[i] ? 1 : -1;
    return 0;
  }
  function walk(constraints, end, vendors, window) {
    const [start, stop] = S.bounds(D, end, window),
      last = Number(end.slice(0, 4)),
      rows = [];
    for (const vendor of vendors)
      for (const train of sorted([
        ...trains[vendor],
        ...constraints.filter((c) => c.vendor === vendor).map((c) => c.train),
      ]))
        for (const scenario of scenarios) {
          const source = constraints.filter(
            (c) => c.vendor === vendor && c.train === train && c.scenario === scenario,
          );
          for (const policy of policies) {
            let state = null,
              tainted = false;
            for (let year = Number(D.start_date.slice(0, 4)); year <= last; year++) {
              let startState = state;
              const relevant = source.filter(
                  (c) =>
                    (c.date === null || Number(c.date.slice(0, 4)) === year) &&
                    (policy === 'all_affected' || c.high_risk !== false) &&
                    (c.date === null ||
                      (window !== 'undated' && (stop === null || c.date <= stop))),
                ),
                days = new Map(),
                events = [];
              let unresolved = [];
              for (const c of relevant) {
                const issues = [...c.issues];
                if (policy === 'high_risk' && c.high_risk === null)
                  issues.push('unknown_high_risk_eligibility');
                if (issues.length) {
                  unresolved.push({ claim_id: c.claim_id, issues: sorted(issues) });
                  tainted = true;
                } else if (c.date <= end) {
                  if (!days.has(c.date)) days.set(c.date, []);
                  days.get(c.date).push(c);
                }
              }
              for (const date of [...days.keys()].sort()) {
                const group = days.get(date);
                let target = group[0].target,
                  comparable = true;
                for (const c of group.slice(1)) {
                  const order = compare(vendor, c.target, target);
                  if (order === null) {
                    comparable = false;
                    break;
                  }
                  if (order > 0) target = c.target;
                }
                const order = state === null ? 1 : compare(vendor, target, state);
                if (!comparable || order === null) {
                  unresolved.push(
                    ...group.map((c) => ({
                      claim_id: c.claim_id,
                      issues: ['incomparable_walk_state'],
                    })),
                  );
                  tainted = true;
                  continue;
                }
                if (order > 0) {
                  const previous = state;
                  state = target;
                  if (S.inWindow(date, start, stop, window))
                    events.push({
                      date,
                      previous,
                      target,
                      claim_ids: sorted(group.map((c) => c.claim_id)),
                    });
                }
                if (start !== null && date < start) startState = state;
              }
              const selected = relevant.filter((c) => S.inWindow(c.date, start, stop, window));
              if (
                window !== 'undated' &&
                start !== null &&
                (year < Number(start.slice(0, 4)) || year > Number(stop.slice(0, 4)))
              )
                continue;
              const ids = sorted(selected.map((c) => c.claim_id));
              unresolved = unresolved.filter((u) => ids.includes(u.claim_id));
              rows.push({
                vendor,
                family: families[vendor],
                train,
                year,
                scenario,
                policy,
                event_count:
                  selected.length && !unresolved.length && !tainted ? events.length : null,
                supported_event_count: events.length,
                events,
                unresolved,
                affected_claim_ids: ids,
                start_version: startState,
                end_version: state,
                coverage: tainted
                  ? 'partial'
                  : selected.length
                    ? 'observed_constraints_only'
                    : 'unknown',
                baseline: 'assumed_below_first_target_actual_unknown',
                partial_year: year === last,
              });
            }
          }
        }
    return rows;
  }
  function upgrades(report, study) {
    const s = study.selection,
      base = {
        schema_version: 1,
        publication: clone(study.publication),
        generated_at: study.generated_at,
        observation_end: study.observation_end,
        definition_sha256: s.definition_sha256,
        selection: clone(s),
      };
    if (report === null)
      return { ...base, availability: 'unavailable', requirements: null, rows: [] };
    const members = Object.fromEntries(
        Object.entries(report.members).filter(
          ([, m]) =>
            s.effective_vendors.includes(m.vendor) &&
            (s.scope_level === 'os_family' || m.scope_level === 'model_qualified') &&
            (s.requested_cve_ids === null || s.requested_cve_ids.includes(m.cve_id)) &&
            (m.date === null || (D.start_date <= m.date && m.date <= report.observation_end)),
        ),
      ),
      requirements = report.requirements.filter((r) => Object.hasOwn(members, r.claim_id)),
      facts = {};
    for (const m of Object.values(members))
      for (const k of ['source_ref', 'severity_facets_ref']) facts[m[k]] = report.facts[m[k]];
    for (const r of requirements)
      for (const k of ['proof_ref', 'train_binding_ref']) facts[r[k]] = report.facts[r[k]];
    const compact = {
      ...clone(
        omit(report, [
          'representation',
          'members',
          'facts',
          'requirements',
          'membership_sha256',
          'membership_count',
          'content_sha256',
        ]),
      ),
      representation: 'compact-requirements',
      members: clone(members),
      facts: clone(facts),
      requirements: clone(requirements),
    };
    compact.source_groups = compact.source_groups.filter((g) =>
      Object.values(members).some(
        (m) =>
          m.vendor === g.vendor && m.advisory_id === g.advisory_id && g.cve_ids.includes(m.cve_id),
      ),
    );
    compact.inference_groups = compact.inference_groups.filter((g) =>
      requirements.some((r) => r.inference?.group_id === g.group_id),
    );
    compact.membership_sha256 = hash(compact.members);
    compact.membership_count = Object.keys(members).length;
    compact.content_sha256 = hash(compact);
    const constraints = requirements.map((r) => ({
      ...omit(members[r.claim_id], ['source_ref', 'severity_facets_ref']),
      ...r,
    }));
    const result = {
      ...base,
      availability: 'available',
      requirements: compact,
      rows: walk(constraints, report.observation_end, s.effective_vendors, s.requested_window),
    };
    measure(result);
    return result;
  }
  const countBy = (values) =>
    Object.fromEntries(sorted(values).map((v) => [v, values.filter((x) => x === v).length]));
  const counts = (claims) => ({
    claims: new Set(claims.map((c) => c.claim_id)).size,
    advisories: new Set(claims.map((c) => JSON.stringify([c.vendor, c.advisory_id]))).size,
    cves: new Set(claims.map((c) => c.cve_id).filter((v) => v !== null)).size,
  });
  const byStatus = (claims) =>
    Object.fromEntries(
      sorted(claims.map((c) => c.status)).map((s) => [
        s,
        counts(claims.filter((c) => c.status === s)),
      ]),
    );
  const sourceKey = (s) => [s.source_url, s.source_sha256, s.retrieved_at, s.source_locator];
  const tupleCompare = (a, b) => {
    for (let i = 0; i < a.length; i++) {
      if (a[i] === b[i]) continue;
      return a[i] < b[i] ? -1 : 1;
    }
    return 0;
  };
  function sources(claims, model = null) {
    const map = new Map();
    for (const c of claims)
      for (const s of [
        c.source,
        ...c.platform_bindings
          .filter((b) => b.source !== null && (model === null || b.model === model))
          .map((b) => b.source),
      ])
        map.set(JSON.stringify(sourceKey(s)), s);
    return [...map.values()].sort((a, b) => tupleCompare(sourceKey(a), sourceKey(b))).map(clone);
  }
  function modelCoverage(selected, study) {
    const models = [];
    for (const target of D.targets.filter((t) =>
      study.selection.effective_vendors.includes(t.vendor),
    ))
      for (const model of target.models) {
        const claims = selected.filter(
            (c) =>
              c.vendor === target.vendor &&
              c.family === target.family &&
              c.platform_bindings.some((b) => b.model === model && b.basis !== 'unresolved'),
          ),
          groups = new Map();
        for (const c of claims)
          for (const b of c.platform_bindings.filter(
            (b) => b.model === model && b.basis !== 'unresolved' && b.source !== null,
          )) {
            const key = JSON.stringify(sourceKey(b.source));
            if (!groups.has(key)) groups.set(key, { source: b.source, claims: new Map() });
            groups.get(key).claims.set(c.claim_id, c);
          }
        const by_source = [...groups.values()]
          .sort((a, b) => tupleCompare(sourceKey(a.source), sourceKey(b.source)))
          .map((g) => ({
            source: clone(g.source),
            counts: counts([...g.claims.values()]),
            by_status: byStatus([...g.claims.values()]),
            claim_ids: [...g.claims.keys()].sort(),
          }));
        models.push({
          vendor: target.vendor,
          family: target.family,
          model,
          counts: counts(claims),
          by_status: byStatus(claims),
          by_source,
          claim_ids: claims.map((c) => c.claim_id).sort(),
          advisory_ids: sorted(claims.map((c) => c.advisory_id)),
          cve_ids: sorted(claims.map((c) => c.cve_id).filter((v) => v !== null)),
          sources: sources(claims, model),
        });
      }
    const unresolved = new Map();
    for (const c of selected) {
      if (c.platform_bindings.some((b) => b.model !== null && b.basis !== 'unresolved')) continue;
      let reasons = c.issues.filter((i) => i.startsWith('cisco_model_'));
      if (!reasons.length) reasons = ['model_binding_unresolved'];
      for (const reason of reasons) {
        if (!unresolved.has(reason)) unresolved.set(reason, []);
        unresolved.get(reason).push(c);
      }
    }
    const bound = new Set(models.flatMap((m) => m.claim_ids)),
      ids = new Set(selected.map((c) => c.claim_id));
    return {
      schema_version: 1,
      publication: clone(study.publication),
      generated_at: study.generated_at,
      definition_sha256: study.selection.definition_sha256,
      observation_end: study.observation_end,
      selection: clone(study.selection),
      nonadditive: true,
      interpretation: 'Missing model evidence does not establish unaffectedness or an upgrade.',
      totals: {
        ...counts(selected),
        bound_claims: bound.size,
        unresolved_claims: [...ids].filter((id) => !bound.has(id)).length,
      },
      models,
      unresolved: [...unresolved.keys()].sort().map((reason) => ({
        reason,
        counts: counts(unresolved.get(reason)),
        claim_ids: sorted(unresolved.get(reason).map((c) => c.claim_id)),
        sources: sources(unresolved.get(reason)),
      })),
    };
  }
  // Canonical keys here mirror Python's sorted-key compact JSON ordering for facets.
  const canonical = (v) =>
    JSON.stringify(v, (_, x) =>
      x && typeof x === 'object' && !Array.isArray(x)
        ? Object.fromEntries(
            Object.keys(x)
              .sort()
              .map((k) => [k, x[k]]),
          )
        : x,
    );
  function disclosureSummary(pairs) {
    const advisories = new Map(),
      facets = new Map();
    for (const p of pairs) {
      advisories.set(JSON.stringify([p.vendor, p.advisory_id]), {
        vendor: p.vendor,
        advisory_id: p.advisory_id,
      });
      for (const f of p.severity.length
        ? p.severity
        : [{ version: null, provider: null, origin: null, preferred: null, band: 'Unknown' }]) {
        const key = JSON.stringify([f.version, f.provider, f.origin, f.preferred, f.band]);
        if (!facets.has(key)) facets.set(key, { ...f, cve_ids: new Set() });
        facets.get(key).cve_ids.add(p.cve_id);
      }
    }
    const cves = sorted(pairs.map((p) => p.cve_id)),
      umbrella = sorted(pairs.filter((p) => p.umbrella !== null).map((p) => p.cve_id));
    return {
      counts: {
        advisories: advisories.size,
        cves: cves.length,
        owned_pairs: new Set(pairs.map((p) => JSON.stringify([p.vendor, p.advisory_id, p.cve_id])))
          .size,
        umbrella_cves: umbrella.length,
      },
      advisory_ids: [...advisories.entries()]
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([, v]) => v),
      cve_ids: cves,
      umbrella_cve_ids: umbrella,
      method_counts: countBy(pairs.map((p) => p.method.classification || 'unknown')),
      severity: [...facets.keys()].sort().map((k) => {
        const f = facets.get(k),
          ids = [...f.cve_ids].sort();
        return { ...f, cve_ids: ids, count: ids.length };
      }),
    };
  }
  function disclosure(report, s, selected) {
    const out = clone(report),
      ids = new Set(selected.map((c) => c.claim_id));
    out.selection = clone(s);
    out.pairs = out.pairs.filter((p) => p.claim_ids.some((id) => ids.has(id)));
    for (const p of out.pairs) {
      p.claim_ids = p.claim_ids.filter((id) => ids.has(id)).sort();
      const owned = selected.filter((c) => p.claim_ids.includes(c.claim_id));
      p.product_ids = sorted(owned.map((c) => c.product_id).filter((v) => v !== null));
      p.models = sorted(
        owned.flatMap((c) => c.platform_bindings.map((b) => b.model)).filter((v) => v !== null),
      );
      const facets = new Map(
        owned.flatMap((c) => c.disclosure_severity).map((f) => [canonical(f), f]),
      );
      p.severity = [...facets.keys()].sort().map((k) => clone(facets.get(k)));
      p.source = clone(owned[0].source);
    }
    const facts = new Set(out.pairs.map((p) => p.fact_id));
    out.advisory_facts = out.advisory_facts.filter((f) => facts.has(f.id));
    out.bundles = out.bundles.filter((b) => {
      if (
        b.kind === 'explicit_publisher_bundle' &&
        b.upstream === null &&
        !selected
          .filter(explicit)
          .some(
            (c) =>
              c.bundle !== null &&
              c.bundle.publisher_id === b.publisher_id &&
              eq(c.bundle.source, b.source),
          )
      )
        return false;
      const members = out.pairs.filter(
        (p) =>
          p.vendor === b.vendor &&
          p.family === b.family &&
          b.member_advisory_ids.includes(p.advisory_id),
      );
      if (!members.length) return false;
      b.selected_advisory_ids = sorted(members.map((p) => p.advisory_id));
      b.selected_cve_ids = sorted(members.map((p) => p.cve_id));
      return true;
    });
    for (const p of out.pairs) {
      const meta = out.advisory_facts.find((f) => f.id === p.fact_id)?.metadata,
        has =
          (meta != null && meta.bundle !== null) ||
          out.bundles.some(
            (b) =>
              p.vendor === b.vendor &&
              p.family === b.family &&
              b.selected_advisory_ids.includes(p.advisory_id) &&
              b.selected_cve_ids.includes(p.cve_id),
          );
      p.missing = p.missing.filter((m) => m !== 'explicit_bundle_unavailable');
      if (!has) p.missing.push('explicit_bundle_unavailable');
    }
    const periods = ['pre_july', 'from_july', 'unknown'],
      years = sorted(
        out.pairs.map((p) => S.day(p.initial_published_at)?.slice(0, 4)).filter(Boolean),
      );
    out.periods = Object.fromEntries(
      periods.map((p) => [p, disclosureSummary(out.pairs.filter((x) => x.date_period === p))]),
    );
    out.years = Object.fromEntries(
      years.map((y) => [
        y,
        disclosureSummary(
          out.pairs.filter((p) => S.day(p.initial_published_at)?.slice(0, 4) === y),
        ),
      ]),
    );
    out.year_periods = Object.fromEntries(
      years.map((y) => [
        y,
        Object.fromEntries(
          periods.map((period) => [
            period,
            disclosureSummary(
              out.pairs.filter(
                (p) => S.day(p.initial_published_at)?.slice(0, 4) === y && p.date_period === period,
              ),
            ),
          ]),
        ),
      ]),
    );
    out.coverage = {
      selected_affected_claims: new Set(out.pairs.flatMap((p) => p.claim_ids)).size,
      owned_source_pairs: out.pairs.length,
      metadata_advisories: out.advisory_facts.length,
      missing_counts: countBy(out.pairs.flatMap((p) => p.missing)),
      unsupported_advisory_types: sorted(
        out.advisory_facts
          .filter((f) => f.metadata?.advisory_type === 'unknown')
          .map((f) => f.metadata.advisory_type),
      ),
    };
    return out;
  }
  function kevState(claims, e, s, end) {
    if (!claims.length)
      return [
        e.current_records.length
          ? e.current_records.every((r) => (r.document_status || '').toLowerCase() === 'draft')
            ? 'draft_only'
            : 'observed_no_study_claim'
          : e.retained_records.length
            ? 'retained_only'
            : 'no_observed_vendor_record',
        [],
      ];
    const final = claims.filter((c) => (c.publisher.status || '').toLowerCase() !== 'draft');
    if (!final.length) return ['draft_only', []];
    const [start, stop] = S.bounds(D, end, s.requested_window),
      dated = final.filter((c) => S.day(c.initial_published_at) !== null),
      eligible = final.filter((c) => {
        const d = S.day(c.initial_published_at);
        return d === null
          ? s.requested_window === 'undated'
          : D.start_date <= d && d <= end && S.inWindow(d, start, stop, s.requested_window);
      });
    if (!eligible.length)
      return dated.length !== final.length
        ? ['unknown', ['publisher_initial_date_missing']]
        : ['outside_study_window', ['publisher_initial_date_outside_window']];
    if (!eligible.some((c) => c.initial_published_at !== null))
      return ['unknown', ['publisher_initial_date_missing']];
    const selected = eligible.filter(
      (c) => s.scope_level === 'os_family' || c.scope_level === 'model_qualified',
    );
    if (!selected.length)
      return [
        eligible.some(explicit) ? 'affected_scope_unresolved' : 'unknown',
        ['selected_model_binding_unresolved'],
      ];
    const scopes = new Map();
    for (const c of selected) {
      const key = JSON.stringify([c.product_id, c.product, [...c.named_platforms].sort()]);
      if (!scopes.has(key)) scopes.set(key, new Set());
      scopes.get(key).add(c.status);
    }
    if (
      selected.some((c) => c.status === 'conflicting') ||
      [...scopes.values()].some((v) => v.has('affected') && v.has('unaffected'))
    )
      return ['conflicting_representations', []];
    if (selected.some(explicit)) return ['documented_affected', []];
    if (selected.every((c) => c.status === 'unaffected' && c.scope === 'cve_specific'))
      return ['documented_unaffected_for_selected_scope', []];
    return ['unknown', ['vendor_claim_not_explicit_affected_or_unaffected']];
  }
  function kev(report, s) {
    const out = clone(report.kev_reconciliation);
    out.selection = clone(s);
    out.entries = out.entries.filter(
      (e) => e.mapping.vendor === null || s.effective_vendors.includes(e.mapping.vendor),
    );
    const allClaims = claimFacets(report);
    for (const e of out.entries) {
      const claims = allClaims.filter(
          (c) =>
            c.vendor === e.mapping.vendor && c.family === e.mapping.family && c.cve_id === e.cve_id,
        ),
        [state, reasons] = e.mapping.vendor
          ? kevState(claims, e, s, report.observation_end)
          : ['unknown', ['exact_pair_unmapped']];
      e.claim_state = state;
      e.in_requested_cve_filter =
        s.requested_cve_ids === null || s.requested_cve_ids.includes(e.cve_id);
      e.in_effective_study_cohort = s.effective_cve_ids.includes(e.cve_id);
      if (!e.in_requested_cve_filter) reasons.push('outside_explicit_cve_filter');
      if (!e.in_effective_study_cohort) reasons.push('outside_effective_study_cohort');
      e.reason_codes = sorted(reasons);
    }
    const mapped = out.entries.filter((e) => e.mapping.status === 'mapped');
    out.summary = {
      candidate_cves: new Set(mapped.map((e) => e.cve_id)).size,
      entry_count: out.entries.length,
      unmapped_entries: out.entries.filter((e) => e.mapping.status === 'unmapped').length,
      unknown_membership_entries: out.entries.filter((e) => e.membership === 'unknown').length,
      state_counts: countBy(mapped.map((e) => e.claim_state)),
      completeness: 'not_established',
    };
    return out;
  }
  function select(report, study) {
    if (report !== null) validate(report, study);
    let out = {
      schema_version: 1,
      publication: clone(study.publication),
      generated_at: study.generated_at,
      selection: clone(study.selection),
      availability: report === null ? 'unavailable' : 'available',
      upgrades: upgrades(report?.requirements ?? null, study),
      disclosure: null,
      model_coverage: null,
      kev_reconciliation: null,
      release_history: window.InfrastructureCustomerComparison.selectHistory(null, {
        ...study,
        rows: [],
      }),
    };
    if (report !== null) {
      const expected = context(report, {
        vendor: study.selection.requested_vendor,
        scope_level: study.selection.scope_level,
        window: study.selection.requested_window,
        cve_ids: study.selection.requested_cve_ids,
      });
      if (!eq(expected.selection, study.selection)) fail('accepted cohort differs');
      const selected = selectedClaims(report, study.selection);
      out = {
        ...out,
        disclosure: disclosure(report.disclosure, study.selection, selected),
        model_coverage: modelCoverage(selected, expected),
        kev_reconciliation: kev(report, study.selection),
        release_history: window.InfrastructureCustomerComparison.selectHistory(
          report.release_history,
          expected,
        ),
      };
    }
    measure(out);
    return out;
  }
  function csvJSON(value) {
    if (typeof value === 'number') return C.numberToken(value);
    if (Array.isArray(value)) return '[' + value.map(csvJSON).join(',') + ']';
    if (value && typeof value === 'object')
      return (
        '{' +
        Object.entries(value)
          .map(([k, v]) => JSON.stringify(k) + ':' + csvJSON(v))
          .join(',') +
        '}'
      );
    return JSON.stringify(value);
  }
  const upgradeFields = [
    'vendor',
    'family',
    'train',
    'year',
    'scenario',
    'policy',
    'event_count',
    'supported_event_count',
    'events',
    'unresolved',
    'affected_claim_ids',
    'start_version',
    'end_version',
    'coverage',
    'baseline',
    'partial_year',
  ];
  function csv(report, { upgradesOnly = false, max_bytes = 128000000 } = {}) {
    const fields = upgradesOnly
      ? upgradeFields
      : ['row_type', 'vendor', 'cve_id', 'year', 'event_count', 'payload'];
    const sections = [['upgrade', report.upgrades.rows]];
    if (!upgradesOnly && report.availability === 'available')
      sections.push(
        ['disclosure', report.disclosure.pairs],
        ['kev_reconciliation', report.kev_reconciliation.entries],
        ['model_coverage', report.model_coverage.models],
        ['release_history', report.release_history.releases],
      );
    const rows = sections.flatMap(([kind, values]) =>
      values.map((v) =>
        upgradesOnly
          ? fields.map((k) => (v[k] !== null && typeof v[k] === 'object' ? csvJSON(v[k]) : v[k]))
          : [kind, ...fields.slice(1, -1).map((k) => v[k]), csvJSON(v)],
      ),
    );
    return S.csvTable(fields, rows, { max_bytes });
  }
  window.InfrastructureSwitchingAnalysis = {
    validate,
    claimFacets,
    context,
    select,
    upgrades,
    walk,
    compare,
    csv,
  };
})();
(() => {
  const A = window.InfrastructureSwitchingAnalysis,
    esc = (v) =>
      String(v ?? 'unknown')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;'),
    option = (v, label = v) => `<option value="${esc(v)}">${esc(label)}</option>`,
    table = (headers, rows) =>
      `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((v) => `<td>${esc(v)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
  A.render = (report, { loading = false, error = '' } = {}) => {
    const lead = `<section id="switching-analysis"><h3>Upgrade estimates and disclosure context</h3><p>Optional source-owned analysis for the accepted study selection. Family, scope, CVE and time-window controls above select evidence before the walk.</p><button id="analysis-load" ${loading ? 'disabled' : ''}>${loading ? 'Loading analysis…' : report ? 'Refresh optional analysis' : 'Load optional analysis'}</button>${error ? `<p role="alert">${esc(error)}</p>` : ''}`;
    if (!report) return lead + '</section>';
    if (report.availability !== 'available')
      return lead + '<p>Optional analysis is unavailable for this publication.</p></section>';
    const rows = report.upgrades.rows,
      select = (key, values) =>
        `<label for="analysis-${key}">${esc(key)}<select id="analysis-${key}">${option('', 'All')}${values.map((v) => option(v)).join('')}</select></label>`;
    const controls = ['family', 'train', 'year', 'policy', 'scenario']
      .map((k) => select(k, [...new Set(rows.map((r) => r[k]))].sort()))
      .join('');
    const periods = Object.entries(report.disclosure.periods).map(([period, p]) => [
      period,
      p.counts.advisories,
      p.counts.cves,
      p.counts.umbrella_cves,
      JSON.stringify(p.method_counts),
    ]);
    const gaps = Object.entries(report.kev_reconciliation.summary.state_counts).map(
      ([state, n]) => [state, n],
    );
    return (
      lead +
      `<p>${esc(report.upgrades.requirements.method)}</p><p>Display filters below choose matrix rows; JSON and CSV export the entire accepted study selection, including every train, policy and scenario.</p><div class="controls">${controls}</div><div id="analysis-rows"></div><button id="analysis-json">Selected analysis JSON</button> <button id="analysis-csv">Selected analysis CSV</button> <button id="analysis-upgrades-csv">Selected upgrade CSV</button><h4>Disclosure eras</h4>${table(['Era', 'Advisories', 'CVEs', 'Umbrella CVEs', 'Source methods'], periods)}<p>Counts measure disclosure, not security quality. Higher scrutiny can increase counts. Nondisclosed bugs are unknown; no concealed-CVE intent is inferred.</p><h4>Per-model evidence coverage</h4>${table(
        ['Vendor', 'Model', 'Claims', 'Advisories', 'CVEs'],
        report.model_coverage.models.map((m) => [
          m.vendor,
          m.model,
          m.counts.claims,
          m.counts.advisories,
          m.counts.cves,
        ]),
      )}<p>${esc(report.model_coverage.interpretation)} Counts overlap across models.</p><h4>Retrospective KEV reconciliation</h4>${table(['State', 'Mapped candidates'], gaps)}<p>Unmapped entries: ${esc(report.kev_reconciliation.summary.unmapped_entries)}. Family candidates do not establish model affectedness or historical exposure.</p><details><summary>Coverage, diagnostics and source links</summary><p>Independent human review pending. Alternative fixed targets and inferred-inclusive results retain source proofs; missing targets, risk, dates and incomplete walks remain unknown. Supported partial steps are not reliable bounds. Operational batching or jumps can reduce actual upgrade operations.</p><pre>${esc(JSON.stringify({ coverage: report.disclosure.coverage, model_totals: report.model_coverage.totals, kev: report.kev_reconciliation.summary, chronology: report.release_history.diagnostics }, null, 2))}</pre>${Object.values(
        report.upgrades.requirements.facts,
      )
        .filter(
          (f) =>
            f && typeof f === 'object' && !Array.isArray(f) && typeof f.source_url === 'string',
        )
        .map((f) => {
          let safe = false;
          try {
            safe = ['https:', 'http:'].includes(new URL(f.source_url).protocol);
          } catch {}
          return safe
            ? `<p><a href="${esc(f.source_url)}" target="_blank" rel="noopener noreferrer">${esc(f.source_url)}</a> · ${esc(f.source_sha256)}</p>`
            : '';
        })
        .join('')}</details></section>`
    );
  };
  A.mount = (root, report) => {
    if (!report || report.availability !== 'available') return;
    const draw = () => {
      const keys = ['family', 'train', 'year', 'policy', 'scenario'],
        rows = report.upgrades.rows.filter((r) =>
          keys.every(
            (k) =>
              !root.querySelector('#analysis-' + k).value ||
              String(r[k]) === root.querySelector('#analysis-' + k).value,
          ),
        );
      root.querySelector('#analysis-rows').innerHTML = table(
        [
          'Family',
          'Train',
          'Year',
          'Scenario',
          'Policy',
          'Annual total',
          'Supported steps',
          'Coverage',
        ],
        rows.map((r) => [
          r.family,
          r.train,
          r.year,
          r.scenario,
          r.policy,
          r.event_count,
          r.supported_event_count,
          r.coverage,
        ]),
      );
    };
    for (const k of ['family', 'train', 'year', 'policy', 'scenario'])
      root.querySelector('#analysis-' + k).addEventListener('change', draw);
    draw();
  };
})();
