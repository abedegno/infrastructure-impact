// Pure membership selection over retained, generation-bound public KEV reports.
(() => {
  const policy = {
    max_bytes: 8000000,
    max_entries: 20000,
    fresh_for_seconds: 129600,
    future_tolerance_seconds: 300,
  };
  const clone = (value) => JSON.parse(JSON.stringify(value));
  function timestamp(value) {
    if (typeof value !== 'string') throw Error('Invalid KEV timestamp');
    const parts =
      /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(
        value,
      );
    if (!parts) throw Error('Invalid KEV timestamp');
    const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number);
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (
      year < 1 ||
      month < 1 ||
      month > 12 ||
      day < 1 ||
      day > days[month - 1] ||
      hour > 23 ||
      minute > 59 ||
      second > 59
    )
      throw Error('Invalid KEV timestamp');
    const seconds = Date.parse(
      `${parts[1]}-${parts[2]}-${parts[3]}T${parts[4]}:${parts[5]}:${parts[6]}${parts[8].toUpperCase()}`,
    );
    if (!Number.isFinite(seconds)) throw Error('Invalid KEV timestamp');
    // Match Python datetime's microsecond precision, including fractional boundaries.
    return BigInt(seconds) * 1000n + BigInt((parts[7] || '').padEnd(6, '0').slice(0, 6));
  }
  function availability(report, evaluated) {
    const source = report.source;
    if (source.configured === null) return 'missing';
    if (!source.configured) return 'not_configured';
    if (!source.enabled) return 'disabled';
    if (!report.catalogue || !source.checked_at || !source.latest_attempt) return 'missing';
    let checked;
    try {
      checked = timestamp(source.checked_at);
      timestamp(source.latest_attempt.checked_at);
    } catch {
      return 'missing';
    }
    if (source.latest_attempt.outcome !== 'ok') return 'failed';
    const age = evaluated - checked;
    if (age < -BigInt(policy.future_tolerance_seconds) * 1000000n) return 'future';
    if (age > BigInt(policy.fresh_for_seconds) * 1000000n) return 'stale';
    return 'available';
  }
  function selectReport(report, requested, { kevOnly = false, evaluatedAt = null } = {}) {
    const evaluation = evaluatedAt === null ? new Date().toISOString() : evaluatedAt;
    const evaluated = timestamp(evaluation);
    const selected =
      report == null
        ? {
            schema_version: 1,
            publication: null,
            generated_at: evaluation,
            evaluated_at: evaluation,
            source: {
              id: 'cisa-kev',
              retrieval_url:
                'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json',
              catalogue_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
              configured: null,
              enabled: null,
              availability: 'missing',
              latest_attempt: null,
              checked_at: null,
            },
            catalogue: null,
            policy: { ...policy },
            listed_cve_ids: [],
            entries: {},
            selection: {},
          }
        : clone(report);
    const state = availability(selected, evaluated);
    if (kevOnly && state !== 'available') {
      const error = Error('KEV membership is unavailable for a filtered selection');
      error.code = 'kev_unavailable';
      throw error;
    }
    const ids = [
      ...new Set(
        requested.filter((id) => typeof id === 'string' && /^CVE-[0-9]{4}-[0-9]{4,19}$/.test(id)),
      ),
    ].sort();
    const listed = new Set(selected.listed_cve_ids);
    const membership = Object.fromEntries(
      ids.map((id) => [
        id,
        state === 'available' ? (listed.has(id) ? 'listed' : 'not_listed') : 'unknown',
      ]),
    );
    selected.evaluated_at = evaluation;
    selected.source.availability = state;
    selected.selection = {
      requested_cve_ids: ids,
      effective_cve_ids: kevOnly ? ids.filter((id) => membership[id] === 'listed') : [...ids],
      kev_only: kevOnly,
      membership,
    };
    return selected;
  }
  if (typeof window !== 'undefined') window.InfrastructureKev = { selectReport };
  if (typeof module !== 'undefined' && module.exports) module.exports = { selectReport };
})();
