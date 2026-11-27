/* Optional, accepted-generation release evidence. No vendor fetch or persistence. */
(() => {
  const C = window.InfrastructureSwitchingContracts,
    J = window.InfrastructureJSON,
    clone = (v) => J.clone(v),
    equal = (a, b) => C.fingerprint(a) === C.fingerprint(b),
    esc = (v) =>
      String(v ?? 'unknown')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;'),
    fail = (message) => {
      throw Error('Release reliability: ' + message);
    };
  function versionKey(vendor, v) {
    const patterns = {
        cisco: /^(\d+)\.(\d+)\.(\d+)([a-z]?)$/,
        aruba: /^(\d+)\.(\d+)\.(\d{4})$/,
        arista: /^(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?([FM])$/,
      },
      m = patterns[vendor].exec(v);
    if (!m || m[0] !== v) fail('unsupported release identity');
    return [
      Number(m[1]),
      Number(m[2]),
      Number(m[3]),
      vendor === 'cisco'
        ? m[4]
          ? m[4].charCodeAt(0) - 96
          : 0
        : vendor === 'arista'
          ? Number(m[4] ?? 0)
          : 0,
    ];
  }
  const releaseObservations = (cat) => cat.releases.flatMap((r) => r.observations ?? [r]);
  function mergedRelease(observations) {
    const rows = observations.filter((r, i) => !observations.slice(0, i).some((p) => equal(p, r))),
      merged = clone(rows[0]);
    if (rows.some((r) => r.family !== merged.family)) fail('conflicting release family');
    merged.platforms_stated = [...new Set(rows.flatMap((r) => r.platforms_stated))].sort();
    merged.evidence = [];
    for (const e of rows.flatMap((r) => r.evidence))
      if (!merged.evidence.some((p) => equal(p, e))) merged.evidence.push(clone(e));
    for (const field of ['release_date', 'announcement_date']) {
      const values = [...new Set(rows.map((r) => r[field]))];
      merged[field] = values.length === 1 ? values[0] : null;
    }
    merged.date_status = merged.release_date ? 'stated' : 'unknown';
    if (new Set(rows.map((r) => r.observation_basis)).size > 1) delete merged.observation_basis;
    if (rows.length > 1) merged.observations = rows;
    return merged;
  }
  function derive(cat, config) {
    const sources = new Map(cat.sources.map((s) => [s.source_id, s])),
      pairs = [],
      annual = [],
      same = (f, t) =>
        f.vendor === t.vendor && f.train === t.train && (f.family ?? t.family) === t.family,
      scope = (f, t) => intersection(f.platforms_stated, t.platforms),
      eligible = (f, t) => original(f, sources) && scope(f, t).length > 0,
      dayGap = (a, b) => Math.round((Date.parse(b) - Date.parse(a)) / 86400000),
      compareVersion = (vendor, a, b) => {
        const x = versionKey(vendor, a),
          y = versionKey(vendor, b);
        for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
        return 0;
      };
    const regular = (vendor, version) => {
      const key = versionKey(vendor, version);
      return vendor === 'aruba' ? key[2] % 10 === 0 : key[3] === 0;
    };
    for (const t of config.trains) {
      const groups = new Map(),
        releases = releaseObservations(cat).filter((f) => same(f, t)),
        regex = new RegExp(t.base_pattern),
        replacement = t.base_replacement.replace(/\\([0-9]+)/g, '$$$1');
      for (const f of releases) {
        if ((!t.respin_rule && !f.release_date) || !regex.test(f.version)) continue;
        const base = f.version.replace(regex, replacement);
        for (const platform of scope(f, t).slice().sort()) {
          const key = JSON.stringify([base, platform]);
          if (!groups.has(key)) groups.set(key, { base, platform, versions: new Map() });
          const versions = groups.get(key).versions,
            old = versions.get(f.version);
          if (
            !old ||
            (t.respin_rule &&
              ((Boolean(f.release_date) && !old.release_date) ||
                (Boolean(f.release_date) === Boolean(old.release_date) &&
                  original(f, sources) &&
                  !original(old, sources)))) ||
            (!t.respin_rule && original(f, sources) && !original(old, sources))
          )
            versions.set(f.version, f);
        }
      }
      for (const { base, platform, versions } of groups.values()) {
        const ordered = [...versions.values()]
          .filter((f) => f.release_date)
          .sort(
            (a, b) =>
              a.release_date.localeCompare(b.release_date) ||
              compareVersion(t.vendor, a.version, b.version),
          );
        for (let i = 1; i < ordered.length; i++)
          if (
            t.respin_rule &&
            compareVersion(t.vendor, ordered[i].version, ordered[i - 1].version) <= 0
          )
            fail('nonmonotonic release chronology');
        let candidates = ordered.slice(1).map((f, i) => [ordered[i], f]);
        if (t.respin_rule) {
          const byVersion = [...versions.values()].sort((a, b) =>
            compareVersion(t.vendor, a.version, b.version),
          );
          candidates = byVersion
            .filter((f) => !regular(t.vendor, f.version))
            .map((curr) => [
              byVersion
                .filter(
                  (f) =>
                    regular(t.vendor, f.version) &&
                    compareVersion(t.vendor, f.version, curr.version) < 0,
                )
                .at(-1),
              curr,
            ]);
        }
        for (const [prev, curr] of candidates) {
          if (
            curr.release_date &&
            (curr.release_date < config.start ||
              curr.release_date > [config.end, cat.generated_at.slice(0, 10)].sort()[0])
          )
            continue;
          if (!t.respin_rule && compareVersion(t.vendor, curr.version, prev.version) <= 0)
            fail('nonmonotonic release chronology');
          const days =
            prev?.release_date && curr.release_date
              ? dayGap(prev.release_date, curr.release_date)
              : null;
          if (days !== null && (days < 0 || days > 90)) continue;
          const explicit = cat.statements.filter(
            (f) =>
              same(f, t) &&
              f.status === 'corrective_respin' &&
              f.version === (prev?.version ?? null) &&
              f.related_release === curr.version &&
              f.platforms_stated.includes(platform),
          );
          const pair = {
            vendor: t.vendor,
            train: t.train,
            base_version: base,
            previous_release: prev?.version ?? null,
            followup_release: curr.version,
            previous_release_date: prev?.release_date ?? null,
            followup_release_date: curr.release_date,
            days,
            within_30_days: days !== null ? days <= 30 : null,
            within_90_days: days !== null ? true : null,
            classification: explicit.length ? 'corrective_respin' : 'possible_respin',
            reason: explicit.length ? explicit[0].evidence[0].quote : null,
            platforms_stated: [platform],
            production_eligible:
              prev != null &&
              days !== null &&
              original(prev, sources) &&
              original(curr, sources) &&
              explicit.every((f) => original(f, sources)),
            evidence: [
              ...(prev?.evidence ?? []),
              ...curr.evidence,
              ...explicit.flatMap((f) => f.evidence),
            ],
          };
          if (t.respin_rule) {
            pair.respin_rule = t.respin_rule;
            if (t.vendor === 'aruba') {
              const build = versionKey(t.vendor, curr.version)[2];
              pair.expected_regular_build = `${t.train}.${String(build - (build % 10)).padStart(4, '0')}`;
              pair.expected_regular_build_absent = !versions.has(pair.expected_regular_build);
            }
          }
          pairs.push(pair);
        }
      }
    }
    const names = [
      'releases_shipped',
      'deferred_or_withdrawn',
      'possible_respin_30',
      'possible_respin_90',
      'corrective_respin_30',
      'corrective_respin_90',
      'software_defect_notices',
      'deferral_notices',
    ];
    for (const t of config.trains)
      for (
        let year = Number(config.start.slice(0, 4));
        year <= Number(config.end.slice(0, 4));
        year++
      ) {
        const start = [config.start, `${year}-01-01`].sort().at(-1),
          end = [config.end, `${year}-12-31`, cat.generated_at.slice(0, 10)].sort()[0],
          coverage = cat.coverage.find(
            (c) => c.vendor === t.vendor && c.train === t.train && c.year === year,
          ),
          status = coverage && start <= end ? coverage.status : 'unknown',
          reason = coverage?.reason ?? 'No reviewed enumeration and date coverage judgement',
          releases = releaseObservations(cat).filter((f) => same(f, t)),
          during = (day) => day != null && start <= end && start <= day && day <= end,
          dated = releases.filter((f) => during(f.release_date)),
          ids = (a) => new Set(a.map((f) => f.version));
        let denominator = null;
        if (status === 'complete') {
          if (
            !coverage.enumeration_complete ||
            !coverage.date_coverage_complete ||
            !t.platforms.every((p) => coverage.platforms.includes(p)) ||
            !coverage.source_ids.length ||
            !coverage.source_ids.every(
              (id) => sources.get(id)?.capture_kind === 'original_document',
            ) ||
            releases.some((f) => !f.release_date || (during(f.release_date) && !eligible(f, t)))
          )
            fail('unsupported complete release denominator');
          denominator = ids(dated.filter((f) => eligible(f, t))).size;
        }
        const actions = [
          ...cat.statements.filter(
            (f) =>
              same(f, t) &&
              ['deferred', 'withdrawn', 'removed_from_download', 'no_longer_available'].includes(
                f.status,
              ),
          ),
          ...cat.notices
            .filter(
              (f) =>
                same(f, t) && ['release_deferral', 'release_withdrawal'].includes(f.classification),
            )
            .flatMap((f) =>
              (f.affected_releases.length ? f.affected_releases : [null]).map((version) => ({
                ...f,
                version,
              })),
            ),
        ];
        const actionModelBlockers = new Set(),
          actionCohortBlockers = new Set();
        if (start <= end)
          for (const action of actions) {
            const models = scope(action, t);
            if (action.platforms_stated.length && !models.length) continue;
            const blockerId = action.version ?? 'notice:' + action.notice_id,
              matching = releases.filter((r) => r.version === action.version);
            if (!action.platforms_stated.length) {
              actionModelBlockers.add(blockerId);
              actionCohortBlockers.add(blockerId);
              continue;
            }
            for (const model of models) {
              const scoped = matching.filter((r) => r.platforms_stated.includes(model));
              if (!scoped.length || scoped.some((r) => r.release_date === null))
                actionCohortBlockers.add(blockerId);
              if (!scoped.length && matching.some((r) => !r.platforms_stated.length))
                actionModelBlockers.add(blockerId);
            }
          }
        const metrics = {};
        for (const name of names) {
          let facts, key;
          if (name === 'releases_shipped') {
            facts = dated;
            key = (f) => f.version;
          } else if (name === 'deferred_or_withdrawn') {
            facts = actions.flatMap((f) =>
              releases
                .filter(
                  (r) =>
                    r.version === f.version &&
                    during(r.release_date) &&
                    intersection(r.platforms_stated, f.platforms_stated).length,
                )
                .map((r) => ({
                  ...f,
                  evidence: [...f.evidence, ...r.evidence],
                  platforms_stated: sorted(intersection(f.platforms_stated, r.platforms_stated)),
                })),
            );
            key = (f) => f.version;
          } else if (name.includes('respin')) {
            facts = pairs.filter(
              (f) =>
                same(f, t) &&
                during(f.followup_release_date) &&
                f.days !== null &&
                f.days <= Number(name.split('_').at(-1)) &&
                (!name.startsWith('corrective') || f.classification === 'corrective_respin'),
            );
            key = (f) => f.followup_release;
          } else {
            facts = cat.notices.filter(
              (f) =>
                same(f, t) &&
                during(f.notice_date) &&
                (name === 'software_defect_notices'
                  ? ['software_defect']
                  : ['release_deferral', 'release_withdrawal']
                ).includes(f.classification),
            );
            key = (f) => f.notice_id;
          }
          const count = (a) => new Set(a.map(key)).size,
            observed = count(facts),
            production = count(facts.filter((f) => f.production_eligible ?? eligible(f, t))),
            research = count(
              facts.filter(
                (f) =>
                  !original(f, sources) &&
                  !facts.some(
                    (p) => key(p) === key(f) && (p.production_eligible ?? eligible(p, t)),
                  ),
              ),
            ),
            unresolvedIds = new Set(facts.filter((f) => !scope(f, t).length).map(key));
          if (name === 'deferred_or_withdrawn')
            for (const id of actionModelBlockers) unresolvedIds.add(id);
          const unresolved = unresolvedIds.size;
          let signalComplete =
            start <= end &&
            coverage?.signal_coverage?.[name] === 'complete' &&
            coverage.source_ids.length > 0 &&
            t.platforms.every((model) => coverage.platforms.includes(model)) &&
            coverage.source_ids.every((id) => sources.get(id).capture_kind === 'original_document');
          if (name.includes('respin'))
            signalComplete =
              signalComplete &&
              !pairs.some(
                (f) =>
                  same(f, t) &&
                  f.days === null &&
                  (f.followup_release_date === null || during(f.followup_release_date)),
              );
          if (['software_defect_notices', 'deferral_notices'].includes(name)) {
            const kinds =
              name === 'software_defect_notices'
                ? ['software_defect']
                : ['release_deferral', 'release_withdrawal'];
            const potentialNotices = cat.notices.filter(
              (f) =>
                same(f, t) &&
                kinds.includes(f.classification) &&
                (f.notice_date === null || during(f.notice_date)) &&
                (!f.platforms_stated.length || scope(f, t).length),
            );
            signalComplete =
              signalComplete &&
              potentialNotices.every((f) => f.notice_date !== null && eligible(f, t));
          } else
            signalComplete =
              signalComplete &&
              !research &&
              !unresolved &&
              (name !== 'deferred_or_withdrawn' || !actionCohortBlockers.size);
          let supported = denominator !== null && signalComplete;
          if (supported) {
            supported =
              coverage.source_ids.length > 0 &&
              coverage.source_ids.every(
                (id) => sources.get(id).capture_kind === 'original_document',
              ) &&
              !research &&
              !unresolved;
            if (name.includes('respin')) {
              const lookback = new Date(
                  Date.parse(start) - Number(name.split('_').at(-1)) * 86400000,
                )
                  .toISOString()
                  .slice(0, 10),
                history = coverage.prior_release_history_start;
              supported =
                supported &&
                history != null &&
                history <= lookback &&
                releases
                  .filter(
                    (f) => !f.release_date || (history <= f.release_date && f.release_date < start),
                  )
                  .every((f) => f.release_date && eligible(f, t));
            }
          }
          const countComplete =
              name === 'releases_shipped'
                ? denominator !== null
                : ['software_defect_notices', 'deferral_notices'].includes(name)
                  ? signalComplete
                  : supported,
            numerator = production || countComplete ? production : null,
            countOnly = [
              'releases_shipped',
              'software_defect_notices',
              'deferral_notices',
            ].includes(name),
            den = countOnly
              ? name === 'releases_shipped'
                ? denominator
                : null
              : supported
                ? denominator
                : null;
          metrics[name] = {
            observed_count: observed || countComplete ? observed : null,
            numerator,
            denominator: den,
            rate: !countOnly && den && numerator !== null ? numerator / den : null,
            coverage: countComplete ? 'complete' : observed ? 'partial' : 'unknown',
            evidence_class:
              research && production
                ? 'mixed'
                : research
                  ? 'research_only'
                  : production || supported
                    ? 'original_document'
                    : 'unknown',
            model_unresolved_count: unresolved,
            research_only_count: research || null,
            reason: supported
              ? 'Complete dated original release and signal coverage'
              : 'Rate unavailable: complete dated original release denominator and signal coverage not established. ' +
                reason,
          };
          if (
            name === 'deferred_or_withdrawn' &&
            (actionModelBlockers.size || actionCohortBlockers.size)
          )
            metrics[name].reason +=
              ` Unresolved action inputs: ${new Set([...actionModelBlockers, ...actionCohortBlockers]).size} (model scope: ${actionModelBlockers.size}; release cohort: ${actionCohortBlockers.size}).`;
        }
        annual.push({
          vendor: t.vendor,
          train: t.train,
          year,
          period_start: start,
          period_end: start <= end ? end : null,
          year_to_date: end < `${year}-12-31`,
          metrics,
        });
      }
    const review = [
      ['notices', 'notice'],
      ['statements', 'statement'],
    ].flatMap(([section, type]) =>
      cat[section].map((f, index) => ({
        type,
        index,
        vendor: f.vendor,
        train: f.train,
        classification: f.classification ?? f.status,
        notice_date: f.notice_date,
        action_date: f.action_date,
        platforms_stated: f.platforms_stated,
        evidence: f.evidence,
        review_status: 'independent_human_review_pending',
        fact: f,
      })),
    );
    for (const [index, f] of pairs.entries())
      if (f.respin_rule)
        review.push({
          type: 'respin',
          index,
          vendor: f.vendor,
          train: f.train,
          classification: f.classification,
          notice_date: null,
          action_date: null,
          platforms_stated: f.platforms_stated,
          evidence: f.evidence,
          review_status: 'independent_human_review_pending',
          fact: f,
        });
    return { annual, pairs, review };
  }

  function validate(report, identity = report) {
    C.identity(report, identity);
    C.validate('release-reliability-v1.json', report);
    if (report.published_staircase_version) {
      const s = report.upgrade_selection,
        study = s?.study;
      if (
        report.staircase_join_version !== 1 ||
        !study ||
        !equal(s, publishedSelection(report, study)) ||
        study.requested_vendor !== null ||
        study.requested_cve_ids !== null ||
        study.requested_window !== 'all' ||
        study.scope_level !== 'os_family' ||
        !equal(
          Object.keys(study).sort(),
          [
            'requested_vendor',
            'effective_vendors',
            'scope_level',
            'requested_window',
            'effective_windows',
            'requested_cve_ids',
            'effective_cve_ids',
            'definition_sha256',
          ].sort(),
        ) ||
        !equal(study.effective_vendors, ['cisco', 'aruba', 'arista']) ||
        !equal(study.effective_windows, [
          'cisco:os_family:all',
          'aruba:os_family:all',
          'arista:os_family:all',
        ])
      )
        fail('invalid published staircase selection');
    }
    const config = report.config,
      trainIds = new Set();
    if (
      config.start > config.end ||
      Number(config.end.slice(0, 4)) - Number(config.start.slice(0, 4)) > 20
    )
      fail('invalid configured period');
    for (const train of config.trains) {
      const key = JSON.stringify([train.vendor, train.train]);
      if (
        !['cisco', 'aruba', 'arista'].includes(train.vendor) ||
        trainIds.has(key) ||
        !train.platforms.length
      )
        fail('invalid or duplicate configured train');
      trainIds.add(key);
      if (
        train.respin_rule &&
        train.respin_rule !==
          {
            cisco: 'letter_suffix',
            aruba: 'non_decadal_build',
            arista: 'subrelease',
          }[train.vendor]
      )
        fail('invalid vendor respin rule');
      try {
        new RegExp(train.base_pattern);
      } catch {
        fail('invalid configured train regular expression');
      }
    }
    if (
      report.dataset_observed_at &&
      Date.parse(report.dataset_observed_at) > Date.parse(report.generated_at)
    )
      fail('future catalogue capture');
    if (report.availability === 'unavailable') {
      if (
        [
          'catalogue',
          'dataset_observed_at',
          'catalogue_sha256',
          'annual',
          'respins',
          'review_packet',
          'upgrade_annotations',
        ].some((k) => (Array.isArray(report[k]) ? report[k].length : report[k] !== null))
      )
        fail('unavailable report contains evidence');
    } else {
      if (
        !report.catalogue ||
        C.fingerprint(report.catalogue) !== report.catalogue_sha256 ||
        report.dataset_observed_at !== report.catalogue.generated_at
      )
        fail('catalogue identity differs');
      const cat = report.catalogue,
        sources = new Map(),
        dates = new Map();
      const releaseIds = new Set();
      for (const r of cat.releases) {
        const key = JSON.stringify([r.vendor, r.train, r.version]);
        if (cat.release_identity && releaseIds.has(key)) fail('duplicate release identity');
        releaseIds.add(key);
        if (
          r.observations &&
          (r.observations.some((o) => JSON.stringify([o.vendor, o.train, o.version]) !== key) ||
            !equal(mergedRelease(r.observations), r))
        )
          fail('release observation union differs');
      }
      const hosts = {
        cisco: ['www.cisco.com', 'cisco.com'],
        aruba: [
          'arubanetworking.hpe.com',
          'www.hpe.com',
          'hpe.com',
          'arubanetworks.com',
          'www.arubanetworks.com',
          'support.hpe.com',
          'csaf.arubanetworking.hpe.com',
        ],
        arista: ['www.arista.com', 'arista.com'],
      };
      for (const source of cat.sources) {
        const url = new URL(source.source_url);
        if (
          url.protocol !== 'https:' ||
          !hosts[source.vendor]?.includes(url.hostname) ||
          url.username ||
          url.password ||
          url.port ||
          url.hash ||
          /[\\\s\x00-\x1f]/.test(source.source_url) ||
          source.source_url.slice(8).split(/[/?#]/)[0] !== url.hostname ||
          sources.has(source.source_id)
        )
          fail('unsafe or duplicate source');
        if (
          source.retrieved_at.slice(0, 10) > cat.generated_at.slice(0, 10) ||
          (source.retrieved_at.length !== 10 &&
            Date.parse(source.retrieved_at) > Date.parse(cat.generated_at))
        )
          fail('future source receipt');
        if (
          (source.capture_kind === 'original_document') !== Boolean(source.original_sha256) ||
          (source.capture_kind !== 'original_document' && !source.excerpt_sha256)
        )
          fail('source capture fingerprint differs');
        sources.set(source.source_id, source);
      }
      for (const section of ['releases', 'notices', 'statements'])
        for (const f of section === 'releases' ? releaseObservations(cat) : cat[section]) {
          const receipts = f.evidence.map((e) => {
            const source = sources.get(e.source_id);
            if (!source || source.vendor !== f.vendor) fail('missing or cross-vendor source');
            return source.retrieved_at.slice(0, 10);
          });
          for (const key of [
            'release_date',
            'announcement_date',
            'notice_date',
            'action_date',
            'revision_date',
          ])
            if (f[key] && f[key] > receipts.sort()[0]) fail('fact later than receipt');
          const versions = Object.hasOwn(f, 'version') ? [f.version] : f.affected_releases;
          for (const v of versions) {
            const parts = versionKey(f.vendor, v);
            if (`${parts[0]}.${parts[1]}` !== f.train) fail('release train differs');
          }
          for (const fixed of f.fixed_releases ?? []) {
            const parts = versionKey(f.vendor, fixed.version);
            if (
              !fixed.platforms_stated.every((p) => f.platforms_stated.includes(p)) ||
              `${parts[0]}.${parts[1]}` !== f.train
            )
              fail('fixed release scope or train differs');
          }
          if (section === 'releases') {
            if ((f.date_status === 'stated') !== Boolean(f.release_date))
              fail('release date status differs');
            if (f.release_date)
              for (const model of f.platforms_stated.length ? f.platforms_stated : [null]) {
                const key = JSON.stringify([f.vendor, f.train, f.version, model]);
                if (dates.has(key) && dates.get(key) !== f.release_date)
                  fail('conflicting release dates');
                dates.set(key, f.release_date);
              }
          }
          if (
            section === 'statements' &&
            f.status === 'corrective_respin' &&
            (!f.related_release || f.related_release === f.version)
          )
            fail('corrective release identity differs');
        }
      const coverageIds = new Set();
      for (const c of cat.coverage) {
        const key = JSON.stringify([c.vendor, c.train, c.year]);
        if (
          coverageIds.has(key) ||
          !c.source_ids.every((id) => sources.get(id)?.vendor === c.vendor)
        )
          fail('coverage source or identity differs');
        coverageIds.add(key);
      }
      const derived = derive(report.catalogue, report.config);
      if (
        !equal(derived.annual, report.annual) ||
        !equal(derived.pairs, report.respins) ||
        !equal(derived.review, report.review_packet)
      )
        fail('derived release facts differ');
    }
    for (const row of report.annual)
      for (const metric of Object.values(row.metrics)) {
        if (
          metric.rate !== null &&
          (metric.denominator === null ||
            metric.denominator <= 0 ||
            metric.numerator === null ||
            metric.coverage !== 'complete')
        )
          fail('unsupported rate');
      }
    for (const annotation of report.upgrade_annotations)
      if (annotation.date > report.generated_at.slice(0, 10))
        fail('future upgrade annotation date');
    if (report.upgrade_annotations.length) {
      if (report.upgrade_selection === null) fail('annotations require selection');
      const rows = report.upgrade_annotations.flatMap((a) =>
        a.references.map((r) => ({
          vendor: a.vendor,
          train: a.train,
          ...r,
          events: [{ date: a.date, target: a.target, models: a.models }],
        })),
      );
      if (!equal(annotations(report, { rows }), report.upgrade_annotations))
        fail('annotation source facts differ');
    }
    return report;
  }
  const original = (fact, sources) =>
      fact.evidence.every((e) => sources.get(e.source_id)?.capture_kind === 'original_document'),
    intersection = (a, b) => a.filter((v) => b.includes(v)),
    sorted = (a) => [...new Set(a)].sort();
  function publishedSelection(report, study) {
    return {
      kind: 'configured_staircases',
      start: report.config.start,
      end: report.config.end,
      trains: report.config.trains.map((t) => ({ vendor: t.vendor, train: t.train })),
      study: clone(study),
    };
  }
  function validatePublished(report, identity = report) {
    validate(report, identity);
    if (
      (report.upgrade_selection !== null || report.upgrade_annotations.length) &&
      !report.published_staircase_version
    )
      fail('Published reliability report contains selected analysis');
    return report;
  }
  function catalogueMatch(report, g) {
    const candidates = report.catalogue.releases.filter(
        (r) => r.vendor === g.vendor && r.train === g.train,
      ),
      exact = candidates.filter((r) => r.version === g.target);
    let variants = [];
    if (!exact.length && g.vendor === 'cisco') {
      try {
        const key = versionKey('cisco', g.target).slice(0, 3);
        variants = candidates.filter((r) => equal(versionKey('cisco', r.version).slice(0, 3), key));
      } catch {}
    }
    const found = exact.length ? exact : variants,
      observations = found.flatMap((r) => r.observations ?? [r]),
      scope = new Set(observations.flatMap((r) => r.platforms_stated)),
      evidence = [];
    for (const e of observations.flatMap((r) => r.evidence))
      if (!evidence.some((p) => equal(p, e))) evidence.push(clone(e));
    return {
      present: Boolean(exact.length),
      match_type: exact.length ? 'exact' : variants.length ? 'suffix_variant' : 'not_found',
      versions: sorted(found.map((r) => r.version)),
      scope_status:
        exact.length && g.models.length && g.models.every((m) => scope.has(m))
          ? 'matched'
          : 'model_unresolved',
      evidence,
      release_observations: observations.map((o) => ({
        version: o.version,
        release_date: o.release_date,
        platforms_stated: clone(o.platforms_stated),
        evidence: clone(o.evidence),
      })),
    };
  }
  function annotations(report, selected) {
    const groups = new Map(),
      cat = report.catalogue,
      sources = new Map((cat?.sources ?? []).map((s) => [s.source_id, s]));
    for (const row of selected.rows)
      for (const event of row.events) {
        if (
          report.staircase_join_version === 1 &&
          (!report.config.trains.some((t) => t.vendor === row.vendor && t.train === row.train) ||
            event.date < report.config.start ||
            event.date > report.config.end)
        )
          continue;
        const key = JSON.stringify([row.vendor, row.train, event.date, event.target]);
        if (!groups.has(key))
          groups.set(key, {
            vendor: row.vendor,
            train: row.train,
            date: event.date,
            target: event.target,
            references: [],
            models: [],
            matches: [],
            caveats: [],
            modelSets: [],
          });
        const group = groups.get(key),
          ref = { scenario: row.scenario, policy: row.policy };
        if (!group.references.some((r) => equal(r, ref))) group.references.push(ref);
        group.modelSets.push(event.models ?? row.models ?? []);
      }
    const values = [...groups.values()].sort((a, b) => {
      for (const key of ['vendor', 'train', 'date', 'target']) {
        if (a[key] < b[key]) return -1;
        if (a[key] > b[key]) return 1;
      }
      return 0;
    });
    for (const g of values) {
      g.models = g.modelSets.every((a) => a.length) ? sorted(g.modelSets.flat()) : [];
      delete g.modelSets;
      g.references.sort((a, b) =>
        a.scenario < b.scenario
          ? -1
          : a.scenario > b.scenario
            ? 1
            : a.policy < b.policy
              ? -1
              : a.policy > b.policy
                ? 1
                : 0,
      );
      if (!g.models.length)
        g.caveats.push(
          'Upgrade rows do not establish exact models; matches are model-unresolved context.',
        );
      if (!cat) continue;
      if (report.staircase_join_version === 1) g.target_catalogue = catalogueMatch(report, g);
      for (const [kind, facts] of [
        ['notice', cat.notices],
        ['statement', cat.statements],
        ['respin', report.respins],
      ])
        for (const f of facts) {
          if (f.vendor !== g.vendor || f.train !== g.train) continue;
          const versions =
            kind === 'notice'
              ? f.affected_releases
              : [kind === 'statement' ? f.version : f.previous_release];
          if (
            !versions.includes(g.target) ||
            (g.models.length &&
              f.platforms_stated.length &&
              !intersection(g.models, f.platforms_stated).length)
          )
            continue;
          if (
            g.models.length &&
            f.platforms_stated.length &&
            !g.models.every((model) => f.platforms_stated.includes(model))
          ) {
            const caveat =
              'Source scope covers only some selected models; applicability remains model-unresolved.';
            if (!g.caveats.includes(caveat)) g.caveats.push(caveat);
          }
          const day = kind === 'respin' ? f.followup_release_date : f.action_date;
          g.matches.push({
            type: kind,
            classification: f.classification ?? f.status,
            notice_id: f.notice_id ?? null,
            notice_date: f.notice_date ?? null,
            action_date: f.action_date ?? null,
            release_date: f.followup_release_date ?? null,
            previous_release_date: f.previous_release_date ?? null,
            days: f.days ?? null,
            chronology: day == null ? 'unknown' : day > g.date ? 'after_step' : 'on_or_before_step',
            scope_status:
              g.models.length && g.models.every((model) => f.platforms_stated.includes(model))
                ? 'matched'
                : 'model_unresolved',
            platforms_stated: clone(f.platforms_stated),
            production_eligible: f.production_eligible ?? original(f, sources),
            evidence: clone(f.evidence),
          });
          if (report.staircase_join_version === 1)
            Object.assign(g.matches.at(-1), {
              related_release:
                kind === 'respin'
                  ? (f.followup_release ?? null)
                  : (f.replacement_release ?? f.related_release ?? null),
              days_after_step: day
                ? Math.round((Date.parse(day) - Date.parse(g.date)) / 86400000)
                : null,
            });
        }
    }
    return values;
  }
  function withUpgrades(report, selected) {
    validate(report);
    C.identity(selected, report);
    const out = clone(report);
    delete out.published_staircase_version;
    out.upgrade_selection = clone(selected.selection);
    if (out.availability === 'available') out.upgrade_annotations = annotations(report, selected);
    return validate(out);
  }
  const csvFields = [
    'row_type',
    'publication_id',
    'generated_at',
    'dataset_observed_at',
    'catalogue_sha256',
    'vendor',
    'train',
    'year',
    'period_start',
    'period_end',
    'year_to_date',
    'metric',
    'observed_count',
    'numerator',
    'denominator',
    'rate',
    'coverage',
    'evidence_class',
    'model_unresolved_count',
    'research_only_count',
    'reason',
    'date',
    'target',
    'references',
    'models',
    'matches',
    'upgrade_selection',
    'limitation',
    'payload',
  ];
  const canonicalJSON = (value) =>
    J.stringify(value, (_, v) =>
      v && typeof v === 'object' && !Array.isArray(v)
        ? Object.fromEntries(
            Object.keys(v)
              .sort()
              .map((k) => [k, v[k]]),
          )
        : v,
    );
  function csvExport(report, { max_bytes = 128000000 } = {}) {
    validate(report);
    const identity = {
        publication_id: report.publication?.id,
        generated_at: report.generated_at,
        dataset_observed_at: report.dataset_observed_at,
        catalogue_sha256: report.catalogue_sha256,
      },
      rows = [];
    for (const annual of report.annual)
      for (const [metric, data] of Object.entries(annual.metrics))
        rows.push({ ...identity, ...annual, ...data, row_type: 'annual', metric });
    for (const a of report.upgrade_annotations)
      rows.push({
        ...identity,
        ...a,
        row_type: 'upgrade_annotation',
        references: canonicalJSON(a.references),
        models: canonicalJSON(a.models),
        matches: canonicalJSON(a.matches),
        upgrade_selection: canonicalJSON(report.upgrade_selection),
        payload: report.staircase_join_version === 1 ? canonicalJSON(a) : undefined,
      });
    const catalogue = report.catalogue ?? {};
    for (const [kind, facts] of [
      ['catalogue_source', catalogue.sources ?? []],
      ['coverage', catalogue.coverage ?? []],
      ['release', catalogue.releases ?? []],
      ['notice', catalogue.notices ?? []],
      ['statement', catalogue.statements ?? []],
      ['respin', report.respins],
      ['review_item', report.review_packet],
      ['validation', [report.validation]],
      [
        'report_context',
        [
          Object.fromEntries(
            ['availability', 'config', 'method', 'upgrade_selection'].map((key) => [
              key,
              report[key],
            ]),
          ),
        ],
      ],
    ])
      for (const fact of facts)
        rows.push({
          ...identity,
          row_type: kind,
          vendor: fact.vendor,
          train: fact.train,
          year: fact.year,
          payload: canonicalJSON(fact),
        });
    for (const limitation of report.limitations)
      rows.push({ ...identity, row_type: 'limitation', limitation });
    return window.InfrastructureSwitching.csvTable(
      csvFields,
      rows.map((r) =>
        csvFields.map((k) =>
          r[k] == null ? null : k === 'rate' && Number.isInteger(r[k]) ? String(r[k]) + '.0' : r[k],
        ),
      ),
      { max_bytes },
    );
  }
  function sourceLinks(report, evidence, vendor) {
    return evidence
      .map((e) => {
        const source = report.catalogue?.sources?.find(
          (s) => s.id === e.source_id || s.source_id === e.source_id,
        );
        if (!source) return `<p>Source ${esc(e.source_id)} · ${esc(e.locator)}</p>`;
        const url = source.url ?? source.source_url;
        try {
          C.official(url, vendor);
          if (new URL(url).protocol !== 'https:') throw Error();
        } catch {
          return `<p>Source link unavailable · ${esc(e.locator)}</p>`;
        }
        return `<div class="reliability-source"><p><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">Publisher source</a> · ${esc(e.locator)}</p><p>Capture kind: ${esc(source.capture_kind)} · Source retrieved: ${esc(source.retrieved_at)}</p><p>Original SHA-256: <code style="overflow-wrap:anywhere">${esc(source.original_sha256)}</code><br>Excerpt SHA-256: <code style="overflow-wrap:anywhere">${esc(source.excerpt_sha256)}</code></p>${e.quote ? `<blockquote>${esc(e.quote)}</blockquote>` : ''}</div>`;
      })
      .join('');
  }
  function renderSteps(report, rows, selection) {
    if (!report || report.availability !== 'available')
      return '<p>Release context unavailable for this generation.</p>';
    validate(report);
    if (!equal(selection, report.upgrade_selection))
      return '<p>Release context unavailable for this selected analysis.</p>';
    const selected = report.upgrade_annotations.filter((a) =>
      rows.some(
        (r) =>
          r.vendor === a.vendor &&
          r.train === a.train &&
          r.events.some((e) => e.date === a.date && e.target === a.target) &&
          a.references.some((ref) => ref.policy === r.policy && ref.scenario === r.scenario),
      ),
    );
    return (
      '<section class="release-staircase"><h4>Distinct upgrade steps and release context</h4><p>One marker per date and target; scenario and policy references do not add upgrades. Model applicability is unknown unless exact step models match source scope. Hardware and configuration context establish no software withdrawal or additional upgrade.</p>' +
      selected
        .map(
          (a) =>
            `<article class="switching-row"><h5>${esc(a.vendor)} · ${esc(a.train)} · ${esc(a.date)} → ${esc(a.target)}</h5>${catalogueMarker(report, a)}<p>Scenario / policy: ${a.references.map((r) => esc(r.scenario) + ' / ' + esc(r.policy)).join('; ')}. Models: ${esc(a.models.join(', ') || 'unknown')}.</p>${!a.matches.length ? '<p>No matching notice, action or follow-up observed; status unknown.</p>' : ''}${a.matches.map((m) => `<details><summary>${esc(m.classification)} · ${esc(m.scope_status)}</summary><p>Notice date: ${esc(m.notice_date)}; action date: ${esc(m.action_date)}; software release date: ${esc(m.release_date)}. Related release: ${esc(m.related_release)}. Previous release date: ${esc(m.previous_release_date)}; software release gap days: ${esc(m.days)}; days after upgrade step: ${esc(m.days_after_step)}. Chronology: ${esc(m.chronology)}. Source model scope: ${esc(m.platforms_stated.join(', ') || 'unknown')}. Production eligible: ${esc(m.production_eligible)}.</p>${sourceLinks(report, m.evidence, a.vendor)}</details>`).join('')}<p>${a.caveats.map(esc).join('; ')}</p></article>`,
        )
        .join('') +
      '</section>'
    );
  }
  function catalogueMarker(report, a) {
    const c = a.target_catalogue;
    if (!c) return '';
    const label = c.present
      ? 'Exact target recorded'
      : c.match_type === 'suffix_variant'
        ? 'Suffix variant only; exact target unknown'
        : 'No target record observed';
    return `<details class="release-catalogue-marker" data-version-match="${esc(c.match_type)}"><summary>${esc(label)} · ${esc(c.scope_status)}</summary><p>Catalogue versions: ${esc(c.versions.join(', ') || 'unknown')}. Catalogue absence is not withdrawal evidence. A suffix variant does not transfer notices or fixes to the target.</p>${c.release_observations.map((o) => `<p>${esc(o.version)} · Software release date: ${esc(o.release_date)} · Stated models: ${esc(o.platforms_stated.join(', ') || 'unknown')}</p>`).join('')}${c.evidence.length ? sourceLinks(report, c.evidence, a.vendor) : ''}</details>`;
  }
  function deriveCoverage(report) {
    const result = Object.fromEntries(
      [
        'publication',
        'generated_at',
        'dataset_observed_at',
        'catalogue_sha256',
        'availability',
      ].map((key) => [key, clone(report[key])]),
    );
    Object.assign(result, {
      schema_version: 1,
      config: clone(report.config),
      method: clone(report.method),
      review_status: report.validation.review_status,
      sources: clone(report.catalogue?.sources ?? []),
      trains: [],
      limitations: [
        'Counts describe disclosure and collection, not vendor quality. Missing evidence is unknown, never zero. Independent human review pending.',
        'Inventory lists contain observed versions, not a complete release denominator.',
        'Undated versions cannot be allocated to a calendar year.',
        'Dates and original evidence resolve gaps only for the explicitly stated model.',
        'Independent human review pending.',
      ],
    });
    if (report.availability === 'unavailable') return result;
    const sources = new Map(result.sources.map((s) => [s.source_id, s])),
      values = (facts) => new Set(facts.map((r) => r.version)),
      sorted = (set) =>
        [...set].sort((a, b) => {
          const x = Array.from(a, (c) => c.codePointAt(0)),
            y = Array.from(b, (c) => c.codePointAt(0));
          for (let i = 0; i < Math.min(x.length, y.length); i++)
            if (x[i] !== y[i]) return x[i] - y[i];
          return x.length - y.length;
        }),
      without = (set, other) => sorted(new Set([...set].filter((v) => !other.has(v))));
    for (const train of report.config.trains) {
      const same = (f) =>
          f.vendor === train.vendor &&
          f.train === train.train &&
          (f.family ?? train.family) === train.family,
        releases = releaseObservations(report.catalogue).filter(same),
        notices = report.catalogue.notices.filter(same),
        models = train.platforms.map((model) => {
          const scoped = releases.filter((r) => r.platforms_stated.includes(model)),
            known = values(scoped),
            dated = values(scoped.filter((r) => r.release_date)),
            originals = values(scoped.filter((r) => r.release_date && original(r, sources))),
            announced = values(scoped.filter((r) => r.announcement_date));
          return {
            model,
            observed_versions: sorted(known),
            dated_original_versions: sorted(originals),
            dated_research_only_versions: without(dated, originals),
            undated_versions: without(known, dated),
            announcement_only_versions: without(announced, dated),
          };
        });
      result.trains.push({
        vendor: train.vendor,
        family: train.family,
        train: train.train,
        models,
        unbound_versions: sorted(values(releases.filter((r) => !r.platforms_stated.length))),
        outside_cohort_versions: sorted(
          values(
            releases.filter(
              (r) =>
                r.platforms_stated.length &&
                !r.platforms_stated.some((p) => train.platforms.includes(p)),
            ),
          ),
        ),
        notice_date_unknown_ids: sorted(
          new Set(notices.filter((n) => n.notice_date === null).map((n) => n.notice_id)),
        ),
        notice_model_unresolved_ids: sorted(
          new Set(notices.filter((n) => !n.platforms_stated.length).map((n) => n.notice_id)),
        ),
        release_evidence: clone(report.catalogue.releases.filter(same)),
        notice_evidence: clone(notices),
        statement_evidence: clone(report.catalogue.statements.filter(same)),
        coverage_judgements: clone(report.catalogue.coverage.filter(same)),
        respin_evidence: clone(report.respins.filter(same)),
        periods: clone(
          report.annual.filter((a) => a.vendor === train.vendor && a.train === train.train),
        ),
      });
    }
    return result;
  }
  function coverageReport(report) {
    validate(report);
    return deriveCoverage(report);
  }
  function coverageCSV(report, { max_bytes = 128000000 } = {}) {
    const payload = (v) => {
      if (typeof v === 'number') return C.numberToken(v);
      if (Array.isArray(v)) return '[' + v.map(payload).join(',') + ']';
      if (v && typeof v === 'object')
        return (
          '{' +
          Object.keys(v)
            .sort()
            .map((k) => JSON.stringify(k) + ':' + payload(v[k]))
            .join(',') +
          '}'
        );
      return J.stringify(v);
    };
    const value = coverageReport(report),
      fields = [
        'row_type',
        'publication_id',
        'generated_at',
        'catalogue_sha256',
        'vendor',
        'train',
        'model',
        'year',
        'metric',
        'payload',
      ],
      identity = {
        publication_id: value.publication?.id,
        generated_at: value.generated_at,
        catalogue_sha256: value.catalogue_sha256,
      },
      omit = (v, keys) => Object.fromEntries(Object.entries(v).filter(([k]) => !keys.includes(k))),
      rows = [
        {
          ...identity,
          row_type: 'context',
          payload: payload(omit(value, ['sources', 'trains', 'limitations'])),
        },
      ];
    for (const train of value.trains) {
      const row = { ...identity, vendor: train.vendor, train: train.train };
      for (const model of train.models)
        rows.push({
          ...row,
          row_type: 'model_inventory',
          model: model.model,
          payload: payload(model),
        });
      for (const period of train.periods)
        for (const [metric, fact] of Object.entries(period.metrics))
          rows.push({
            ...row,
            row_type: 'period_metric',
            year: period.year,
            metric,
            payload: payload({ ...omit(period, ['metrics']), metric, ...fact }),
          });
      rows.push({
        ...row,
        row_type: 'train_gaps',
        payload: payload(
          omit(train, [
            'models',
            'periods',
            'release_evidence',
            'notice_evidence',
            'statement_evidence',
            'coverage_judgements',
            'respin_evidence',
          ]),
        ),
      });
      for (const kind of [
        'release_evidence',
        'notice_evidence',
        'statement_evidence',
        'coverage_judgements',
        'respin_evidence',
      ])
        for (const fact of train[kind])
          rows.push({
            ...row,
            row_type: kind === 'coverage_judgements' ? 'coverage_judgement' : kind,
            payload: payload(fact),
          });
    }
    for (const source of value.sources)
      rows.push({
        ...identity,
        row_type: 'source',
        vendor: source.vendor,
        payload: payload(source),
      });
    for (const limitation of value.limitations)
      rows.push({ ...identity, row_type: 'limitation', payload: limitation });
    return window.InfrastructureSwitching.csvTable(
      fields,
      rows.map((r) => fields.map((f) => r[f])),
      { max_bytes },
    );
  }
  function renderCoverage(report) {
    const coverage = deriveCoverage(report),
      rows = coverage.trains.flatMap((t) =>
        t.models.map(
          (m) =>
            `<tr><td>${esc(t.vendor)} · ${esc(t.train)} · ${esc(m.model)}</td><td>${m.observed_versions.length || 'No model-bound observations'}</td><td>${m.observed_versions.length ? m.dated_original_versions.length : 'unknown'}</td><td>${m.observed_versions.length ? m.dated_research_only_versions.length : 'unknown'}</td><td>${m.observed_versions.length ? m.undated_versions.length : 'unknown'}</td></tr>`,
        ),
      ),
      details = coverage.trains
        .map(
          (t) =>
            `<details><summary>${esc(t.vendor)} ${esc(t.train)} · ${t.unbound_versions.length} version observations without model binding · coverage gaps</summary><p>Version observations without stated study-model scope: ${esc(t.unbound_versions.join(', ') || 'No such observations retained')}. Notices without model scope: ${esc(t.notice_model_unresolved_ids.join(', ') || 'No such observations retained')}.</p>${t.models.map((m) => `<p><strong>${esc(m.model)}</strong> · Missing release date: ${esc(m.undated_versions.join(', ') || 'No undated observations retained')}; dates supported only by research excerpts: ${esc(m.dated_research_only_versions.join(', ') || 'No such observations retained')}.</p>`).join('')}${t.periods.map((p) => `<p>${esc(p.year)} · ${esc(p.metrics.releases_shipped.reason)}</p>`).join('')}<p>To resolve a gap, obtain a publisher release-date statement and original capture for the named model/version, plus an explicit archive-completeness statement. Notice and respin rates additionally require complete signal coverage and prior-release history.</p></details>`,
        )
        .join('');
    return `<section class="reliability-coverage"><h4>Coverage gaps by model</h4><p>Inventory counts describe retained observations across the train, including undated versions. They are not annual release totals or completeness claims. Zero inventory means no qualifying observation, not zero releases. Unknown dates cannot be assigned to a year. Study-model scope is never borrowed from another platform.</p><div class="table-wrap"><table><thead><tr><th>Train / model</th><th>Observed version identities</th><th>Dated original evidence</th><th>Research-only dates</th><th>Missing release dates</th></tr></thead><tbody>${rows.join('')}</tbody></table></div>${details}<p><button id="reliability-coverage-json">Coverage JSON</button> <button id="reliability-coverage-csv">Coverage CSV</button></p></section>`;
  }

  function selectionDetails(report) {
    return J.stringify(
      {
        upgrade_selection: report.upgrade_selection,
        method: report.method,
        limitations: report.limitations,
        review_packet: report.review_packet,
        validation: report.validation,
      },
      null,
      2,
    );
  }
  function render(report, { loading = false, error = '' } = {}) {
    const period = report
      ? `${report.config.start.slice(0, 4)}–${report.config.end.slice(0, 4)}`
      : 'configured period';
    const lead = `<section id="release-reliability"><h3>Release reliability catalogue · ${esc(period)}</h3><p>Catalogue metrics are independent of advisory, CVE and study filters. Selected upgrade annotations retain their own accepted analysis selection. Counts describe publisher disclosure and collection, not vendor security quality. Independent human review pending.</p>`;
    if (!report)
      return (
        lead +
        `<p>${loading ? 'Loading release evidence…' : 'Release reliability unavailable for this publication.'}</p>${error ? `<p role="alert">${esc(error)}</p><button id="reliability-retry" type="button">Retry release evidence</button>` : ''}</section>`
      );
    validate(report);
    if (report.availability !== 'available')
      return (
        lead +
        `<p>Release reliability unavailable for this publication.</p><p>${report.limitations.map(esc).join('; ')}</p></section>`
      );
    const table = (headers, rows) =>
      `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th scope="col">${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
    const count = (m, prefix = '') => {
      const qualifiers = [];
      if (m.research_only_count !== null) qualifiers.push(`${m.research_only_count} research only`);
      if (m.model_unresolved_count)
        qualifiers.push(`${m.model_unresolved_count} unresolved scope inputs`);
      if (m.numerator !== m.observed_count) qualifiers.push(`eligible ${m.numerator ?? 'unknown'}`);
      return `${prefix ? esc(prefix) + ': ' : ''}<strong>${esc(m.observed_count)}</strong>${qualifiers.length ? `<small>${qualifiers.map(esc).join(' · ')}</small>` : ''}`;
    };
    const paired = (a, b, first, second) =>
      `<div>${count(a, first)}</div><div>${count(b, second)}</div>`;
    const summaryHeaders = [
      'Year',
      'Publisher-dated releases',
      'Explicit deferred / withdrawn',
      'Possible respins',
      'Corrective respins',
      'Notices',
      'Coverage / rates',
    ];
    const auditHeaders = [
      'Year / period',
      'Metric',
      'Observed',
      'Production eligible numerator',
      'Research only',
      'Denominator',
      'Rate',
      'Coverage / evidence',
      'Model unresolved / reason',
    ];
    const cards = report.config.trains
      .map((train) => {
        const years = report.annual.filter(
          (r) => r.vendor === train.vendor && r.train === train.train,
        );
        const summaryRows = years.map((r) => {
          const m = r.metrics,
            coverage = sorted(Object.values(m).map((v) => v.coverage)).join(' / '),
            rates = Object.entries(m).filter(([, v]) => v.rate !== null),
            rateText = rates.length
              ? rates.map(([key, v]) => `${key.replaceAll('_', ' ')}: ${v.rate}`).join('; ')
              : 'Rates: Unavailable';
          return `<tr><th scope="row">${esc(r.year)}${r.year_to_date ? '<small>Year to date</small>' : ''}</th><td>${count(m.releases_shipped)}</td><td>${count(m.deferred_or_withdrawn)}</td><td>${paired(m.possible_respin_30, m.possible_respin_90, '30d', '90d')}</td><td>${paired(m.corrective_respin_30, m.corrective_respin_90, '30d', '90d')}</td><td>${paired(m.software_defect_notices, m.deferral_notices, 'Software', 'Deferral')}</td><td>${esc(coverage)}<small>${esc(rateText)}</small></td></tr>`;
        });
        const auditRows = years.flatMap((r) =>
          Object.entries(r.metrics).map(
            ([key, m]) =>
              `<tr><td>${esc(r.year)}<small>${esc(r.period_start)} – ${esc(r.period_end)}</small></td><td>${esc(key.replaceAll('_', ' '))}</td><td>${esc(m.observed_count)}</td><td>${esc(m.numerator)}</td><td>${esc(m.research_only_count)}</td><td>${esc(m.denominator)}</td><td>${m.rate === null ? 'Unavailable' : esc(m.rate)}</td><td>${esc(m.coverage)} / ${esc(m.evidence_class)}</td><td>${esc(m.model_unresolved_count)} / ${esc(m.reason)}</td></tr>`,
          ),
        );
        return `<article class="reliability-train"><h4>${esc(train.vendor)} · ${esc(train.family)} ${esc(train.train)}</h4>${table(summaryHeaders, summaryRows)}<details class="reliability-metric-details"><summary>Full metrics, eligibility and evidence · ${auditRows.length} records</summary>${table(auditHeaders, auditRows)}</details></article>`;
      })
      .join('');
    return (
      lead +
      `<p>Dataset observed: ${esc(report.dataset_observed_at)}. Generated: ${esc(report.generated_at)}.</p><p>Numbers below are observed counts. Research-only observations and unresolved model scope are labelled beside each count; production eligibility, denominators and reasons are in each train’s full metrics. Unknown evidence remains unknown. Research excerpts are research-only. Rates require complete dated release denominators, signal coverage and prior-release history; no cross-vendor rate is inferred.</p>${renderCoverage(report)}${cards}<p><button id="reliability-json">Release reliability JSON</button> <button id="reliability-csv">Release reliability CSV</button> <button id="reliability-review">Pending review packet JSON</button></p><details><summary>Publisher sources and capture dates</summary>${report.catalogue.sources.map((s) => sourceLinks(report, [{ source_id: s.source_id, locator: s.source_id, quote: '' }], s.vendor)).join('')}</details><details><summary>Selection, methodology, coverage and pending review</summary><pre id="reliability-selection-details">${esc(selectionDetails(report))}</pre></details></section>`
    );
  }
  window.InfrastructureReleaseReliability = {
    selectionDetails,
    validate,
    validatePublished,
    withUpgrades,
    csvExport,
    coverageReport,
    coverageCSV,
    render,
    renderSteps,
  };
})();
