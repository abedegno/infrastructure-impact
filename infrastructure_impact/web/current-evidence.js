/* Consume publisher dispositions. No source-policy inference or record-key hashing. */
function validateCurrentEvidence(report, publication, generatedAt) {
  const json = window.InfrastructureJSON;
  window.InfrastructureSwitchingContracts.validate('current-evidence-v1.json', report);
  if (
    (report.publication?.id ?? null) !== (publication?.id ?? null) ||
    (report.publication?.advisory_schema_version ?? null) !==
      (publication?.advisory_schema_version ?? null) ||
    report.generated_at !== generatedAt
  )
    throw Error('Current-evidence publication generation mismatch');
  if (new TextEncoder().encode(json.stringify(report)).length + 1 > 2000000)
    throw Error('Current-evidence report exceeds budget');
  const policies = new Map();
  for (const p of report.policies) {
    const key = json.stringify([p.vendor, p.policy_id]);
    if (policies.has(key)) throw Error('Duplicate current-evidence policy');
    policies.set(key, p);
  }
  const compareText = (a, b) => {
    const left = Array.from(a),
      right = Array.from(b);
    for (let i = 0; i < Math.min(left.length, right.length); i++) {
      const delta = left[i].codePointAt(0) - right[i].codePointAt(0);
      if (delta) return delta;
    }
    return left.length - right.length;
  };
  const ids = new Set(),
    targets = new Set();
  for (const d of report.decisions) {
    const p = policies.get(json.stringify([d.vendor, d.policy_id]));
    if (
      !p ||
      p.version !== d.policy_version ||
      p.fingerprint !== d.policy_fingerprint ||
      p.reason_text !== d.reason_text ||
      d.target.vendor !== d.vendor ||
      ids.has(d.decision_id) ||
      targets.has(d.target_key)
    )
      throw Error('Current-evidence decision identity/policy mismatch');
    ids.add(d.decision_id);
    targets.add(d.target_key);
    const proofs = d.proofs.map((p) =>
      json.stringify(
        Object.fromEntries(
          Object.keys(p)
            .sort()
            .map((k) => [k, p[k]]),
        ),
      ),
    );
    if (
      new Set(proofs).size !== proofs.length ||
      proofs.some((p, i) => i && compareText(p, proofs[i - 1]) < 0)
    )
      throw Error('Invalid decision proofs');
  }
  const issues = new Set();
  for (const issue of report.issues) {
    const key = json.stringify([issue.vendor, issue.policy_id, issue.target_key, issue.code]);
    if (
      !policies.has(json.stringify([issue.vendor, issue.policy_id])) ||
      targets.has(issue.target_key) ||
      issues.has(key)
    )
      throw Error('Invalid current-evidence issue');
    issues.add(key);
  }
  const counts = report.counts;
  if (
    report.availability === 'available' &&
    (counts.excluded !== ids.size || counts.current + counts.excluded !== counts.retained_total)
  )
    throw Error('Current-evidence counts mismatch');
  return report;
}
(() => {
  const fields = ['vendor', 'advisory_id', 'revision_id', 'source_url', 'sha256'];
  function sameIdentity(record, target) {
    return fields.every(
      (key) =>
        Object.hasOwn(record, key) &&
        typeof record[key] === typeof target[key] &&
        record[key] === target[key],
    );
  }
  function unavailable(publication, generated_at) {
    return {
      schema_version: 1,
      availability: 'unavailable',
      publication: publication ?? null,
      generated_at,
      policies: [],
      decisions: [],
      issues: [],
      counts: { current: null, retained_total: null, excluded: null },
    };
  }
  function validatePartition(source, { completeRetained = true, completeCurrent = false } = {}) {
    const report = validateCurrentEvidence(
      source.current_evidence,
      source.publication,
      source.generated_at,
    );
    const decisions = new Map(report.decisions.map((d) => [d.decision_id, d])),
      seen = new Set();
    for (const w of source.retained_advisories ?? []) {
      const d = decisions.get(w.decision_id);
      if (
        !w ||
        Object.keys(w).sort().join(',') !== 'decision_id,record,record_scope,target_key' ||
        !d ||
        w.record_scope !== 'retained_latest_excluded' ||
        w.target_key !== d.target_key ||
        !sameIdentity(w.record, d.target) ||
        seen.has(w.decision_id)
      )
        throw Error('Retained target identity/reference mismatch');
      seen.add(w.decision_id);
    }
    if (completeRetained && seen.size !== decisions.size)
      throw Error('Missing retained decision records');
    if ((source.records ?? []).some((r) => report.decisions.some((d) => sameIdentity(r, d.target))))
      throw Error('Excluded identity in current evidence');
    if (
      completeCurrent &&
      report.availability === 'available' &&
      source.records.length !== report.counts.current
    )
      throw Error('Current evidence count mismatch');
    return source;
  }
  window.InfrastructureCurrentEvidence = {
    validateCurrentEvidence,
    validatePartition,
    unavailable,
    sameIdentity,
  };
})();
function selectRetainedSnapshot(source, cveIds, options = {}) {
  window.InfrastructureCurrentEvidence.validatePartition(source, { completeRetained: false });
  if (options.vendor && !Object.hasOwn(source.vendors, options.vendor))
    throw Error('Invalid retained vendor');
  const cohort = cveIds == null ? null : new Set(cveIds);
  return {
    ...source,
    retained_advisories: (source.retained_advisories ?? [])
      .filter(
        (w) =>
          (!options.vendor || w.record.vendor === options.vendor) &&
          (cohort === null || w.record.cves.some((id) => cohort.has(id))),
      )
      .map((w) => ({
        ...w,
        record: {
          ...w.record,
          assessments: w.record.assessments.filter((a) => cohort === null || cohort.has(a.cve_id)),
        },
      })),
  };
}
function exportRetainedSnapshot(source) {
  window.InfrastructureCurrentEvidence.validatePartition(source, { completeRetained: false });
  const decisions = new Map(source.current_evidence.decisions.map((d) => [d.decision_id, d]));
  return {
    schema_version: 1,
    publication: source.publication ?? null,
    generated_at: source.generated_at,
    current_evidence: source.current_evidence,
    record_scope: 'retained_latest_excluded',
    records: (source.retained_advisories ?? []).map((w) => {
      const d = decisions.get(w.decision_id),
        metadata = { record_scope: w.record_scope };
      for (const key of [
        'disposition',
        'reason',
        'reason_text',
        'decision_id',
        'target_key',
        'policy_id',
        'policy_version',
        'policy_fingerprint',
      ])
        metadata[key] = d[key];
      return {
        ...w.record,
        ...metadata,
        assessments: w.record.assessments.map((a) => ({ ...a, ...metadata })),
      };
    }),
  };
}
function retainedSnapshotCSV(source) {
  const exported = exportRetainedSnapshot(source);
  return snapshotCSV(
    {
      ...exported,
      kev: source.kev,
      comparison: { cohort: [...new Set(exported.records.flatMap((r) => r.cves))] },
    },
    [
      'record_scope',
      'disposition',
      'reason',
      'reason_text',
      'decision_id',
      'target_key',
      'policy_id',
      'policy_version',
      'policy_fingerprint',
    ],
  );
}
