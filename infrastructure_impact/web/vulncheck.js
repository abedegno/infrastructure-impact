// Optional in-memory research overlay. No network, persistence, or publication writes.
(() => {
  const MAX_FILE_BYTES = 8000000;
  const API = 'https://api.vulncheck.com/v3/backup/vulncheck-kev';
  const CVE = /^CVE-[0-9]{4}-[0-9]{4,19}$/;
  const esc = (v) =>
    String(v ?? 'Not supplied').replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
    );
  function fail() {
    throw Error('Invalid private KEV report');
  }
  function time(value) {
    if (
      typeof value !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
    )
      fail();
    const n = Date.parse(value);
    if (!Number.isFinite(n)) fail();
    // Date.parse normalizes invalid calendar dates; compare the literal UTC date.
    const day = value.slice(0, 10),
      d = new Date(day + 'T00:00:00Z');
    if (d.toISOString().slice(0, 10) !== day) fail();
    return n;
  }
  function availability(source, now) {
    if (!source) return 'missing';
    if (['missing', 'failed'].includes(source.availability)) return source.availability;
    const age = time(now) - time(source.checked_at);
    return age < -300000 ? 'future' : age > 129600000 ? 'stale' : 'available';
  }
  function parseReport(text) {
    if (
      typeof text !== 'string' ||
      text.length > MAX_FILE_BYTES ||
      new TextEncoder().encode(text).length > MAX_FILE_BYTES
    )
      fail();
    const json = typeof window !== 'undefined' ? window.InfrastructureJSON : null;
    if (!json?.parseStrict) throw Error('Strict JSON reader unavailable');
    const report = json.parseStrict(text);
    if (
      report.schema_version !== 1 ||
      report.distribution !== 'private_research_only' ||
      report.attribution?.name !== 'VulnCheck Known Exploited Vulnerabilities' ||
      report.attribution?.url !== 'https://www.vulncheck.com/kev' ||
      report.source?.id !== 'vulncheck-kev' ||
      report.source.url !== API ||
      report.source.parser_version !== 1 ||
      !['available', 'stale', 'future', 'missing', 'failed'].includes(report.source.availability) ||
      !Array.isArray(report.cves) ||
      report.cves.length > 100000
    )
      fail();
    time(report.evaluated_at);
    if (report.source.checked_at !== null) time(report.source.checked_at);
    if (report.source.sha256 !== null && !/^[a-f0-9]{64}$/.test(report.source.sha256)) fail();
    if (['available', 'stale', 'future'].includes(report.source.availability)) {
      if (
        !report.source.sha256 ||
        !Number.isSafeInteger(report.source.revision_id) ||
        report.source.revision_id < 1
      )
        fail();
      time(report.source.retrieved_at);
      time(report.source.publisher_backup_at);
      if (availability(report.source, report.evaluated_at) !== report.source.availability) fail();
    }
    const entries = new Map();
    for (const row of report.cves) {
      if (
        !CVE.test(row.cve_id) ||
        entries.has(row.cve_id) ||
        !['unknown', 'listed', 'not_listed'].includes(row.cisa_membership) ||
        typeof row.vulncheck?.retained_listed !== 'boolean' ||
        !['unknown', 'listed', 'not_listed'].includes(row.vulncheck.membership)
      )
        fail();
      const e = row.vulncheck.evidence;
      if (row.vulncheck.retained_listed !== Boolean(e)) fail();
      const expected =
        report.source.availability === 'available' ? (e ? 'listed' : 'not_listed') : 'unknown';
      if (row.vulncheck.membership !== expected) fail();
      if (e) {
        time(e.listed_at);
        if (
          ![e.vendor_label, e.product_label].every((v) => v === null || typeof v === 'string') ||
          !(e.canary_reported === null || typeof e.canary_reported === 'boolean') ||
          !Array.isArray(e.reported_exploitation)
        )
          fail();
        for (const ref of e.reported_exploitation) {
          if (typeof ref.url !== 'string') fail();
          time(ref.date_added);
        }
      }
      entries.set(row.cve_id, row);
    }
    return { report, entries };
  }
  function membership(parsed, id, now = new Date().toISOString()) {
    if (
      !parsed ||
      availability(parsed.report.source, now) !== 'available' ||
      !parsed.entries.has(id)
    )
      return 'unknown';
    return parsed.entries.get(id).vulncheck.retained_listed ? 'listed' : 'not_listed';
  }
  function summarize(
    parsed,
    {
      cves = [],
      cisa = null,
      study = null,
      kev = null,
      now = new Date().toISOString(),
      filter = 'all',
    } = {},
  ) {
    if (!['all', 'cisa', 'vulncheck', 'both', 'unknown'].includes(filter)) fail();
    const groups = new Map();
    for (const row of study?.rows ?? []) {
      const ids = groups.get(row.vendor) ?? new Set();
      row.affected_cve_ids.forEach((id) => ids.add(id));
      groups.set(row.vendor, ids);
    }
    const ids = [...new Set(study ? [...groups.values()].flatMap((s) => [...s]) : cves)].sort();
    let cisaStates = {},
      cisaCheckedAt = null,
      publicAvailable = false;
    if (kev && cisa) {
      const selected = kev.selectReport(cisa, ids, { evaluatedAt: now });
      publicAvailable = selected.source.availability === 'available';
      cisaStates = selected.selection.membership;
      cisaCheckedAt = selected.source.checked_at;
    }
    // CLI reports may contain an independently verified CISA source too.
    if (!publicAvailable && parsed?.report.cisa_source?.availability === 'available') {
      const source = parsed.report.cisa_source;
      const checked = source.checked_at ?? source.retrieved_at;
      if (checked && availability({ ...source, checked_at: checked }, now) === 'available') {
        cisaStates = Object.fromEntries(
          [...parsed.entries].map(([id, r]) => [id, r.cisa_membership]),
        );
        cisaCheckedAt = checked;
      }
    }
    const rows = ids.map((id) => ({
      cve_id: id,
      cisa: cisaStates[id] ?? 'unknown',
      vulncheck: membership(parsed, id, now),
    }));
    const count = (selected, key) =>
      selected.some((r) => r[key] === 'unknown')
        ? null
        : selected.filter((r) => r[key] === 'listed').length;
    return {
      now,
      source: parsed?.report.source ?? null,
      availability: parsed ? availability(parsed.report.source, now) : 'missing',
      study: study
        ? {
            publication: study.publication,
            generated_at: study.generated_at,
            selection: study.selection,
          }
        : null,
      cisa_checked_at: cisaCheckedAt,
      vendors: [...groups].map(([vendor, set]) => {
        const selected = rows.filter((r) => set.has(r.cve_id));
        return {
          vendor,
          cves: set.size,
          cisa_listed: count(selected, 'cisa'),
          vulncheck_listed: count(selected, 'vulncheck'),
          cisa_unknown: selected.filter((r) => r.cisa === 'unknown').length,
          vulncheck_unknown: selected.filter((r) => r.vulncheck === 'unknown').length,
        };
      }),
      total: rows.length,
      rows: rows.filter(
        (r) =>
          filter === 'all' ||
          (filter === 'both'
            ? r.cisa === 'listed' && r.vulncheck === 'listed'
            : filter === 'unknown'
              ? r.cisa === 'unknown' || r.vulncheck === 'unknown'
              : r[filter] === 'listed'),
      ),
    };
  }
  function badge(source, state) {
    return `<span class="badge kev-${state}">${source} ${state.replaceAll('_', ' ')}</span>`;
  }
  function render(model, limit = 150) {
    const value = (n) => (n === null ? 'Unknown' : n);
    return `<p><a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">VulnCheck Known Exploited Vulnerabilities ↗</a> · ${esc(model.availability)} · verified ${esc(model.source?.checked_at)} · evaluated ${esc(model.now)}. CISA verified ${esc(model.cisa_checked_at)}.</p>${model.source ? `<details><summary>Local source provenance</summary><p>Backup ${esc(model.source.publisher_backup_at)} · retrieved ${esc(model.source.retrieved_at)} · revision ${esc(model.source.revision_id)}</p><code>${esc(model.source.sha256)}</code><p>${esc(API)}</p></details>` : ''}
      ${model.study ? `<p>Selected switching-study CVE sets · publication ${esc(model.study.publication?.id)} · ${esc(model.study.generated_at)}. Scope ${esc(model.study.selection?.scope_level)} / ${esc(model.study.selection?.requested_window)}. Current catalogue membership is separate from historical disclosure dates.</p><div class="table-wrap"><table><thead><tr><th>Vendor</th><th>Study CVEs</th><th>CISA KEV listed</th><th>VulnCheck KEV listed</th><th>Unknown CISA / VulnCheck</th></tr></thead><tbody>${model.vendors.map((v) => `<tr><td>${esc(v.vendor)}</td><td>${v.cves}</td><td>${value(v.cisa_listed)}</td><td>${value(v.vulncheck_listed)}</td><td>${v.cisa_unknown} / ${v.vulncheck_unknown}</td></tr>`).join('')}</tbody></table></div>` : '<p>Counts below use the selected site CVE cohort. Open the switching comparison for vendor counts based on documented study membership.</p>'}
      <p>${Math.min(limit, model.rows.length)} shown of ${model.rows.length} filter matches / ${model.total} selected CVEs. Filters affect this research panel only; published study totals and exports remain unchanged.</p><div class="table-wrap"><table><thead><tr><th>CVE</th><th>CISA</th><th>VulnCheck</th></tr></thead><tbody>${
        model.rows
          .slice(0, limit)
          .map(
            (r) =>
              `<tr><td>${esc(r.cve_id)}</td><td>${badge('CISA KEV', r.cisa)}</td><td>${badge('VulnCheck KEV', r.vulncheck)}</td></tr>`,
          )
          .join('') ||
        '<tr><td colspan="3">No CVEs match this filter. Unknown membership is not a negative.</td></tr>'
      }</tbody></table></div>`;
  }
  function renderContext(parsed, id, now = new Date().toISOString()) {
    if (!parsed) return '';
    const state = membership(parsed, id, now),
      e = parsed.entries.get(id)?.vulncheck.evidence;
    const reference = (ref) => {
      let safe = false;
      try {
        const u = new URL(ref.url);
        safe =
          ['http:', 'https:'].includes(u.protocol) &&
          !u.username &&
          !u.password &&
          !/[\x00-\x20]/.test(ref.url) &&
          ref.url_status !== 'publisher_url_unresolved';
      } catch {
        /* literal only */
      }
      return `<li>${safe ? `<a href="${esc(ref.url)}" target="_blank" rel="noopener noreferrer">Reported-exploitation reference ↗</a>` : `Unresolved publisher URL: ${esc(ref.url)}`} · reference added ${esc(ref.date_added)}</li>`;
    };
    return `<aside class="kev-context">${badge('VulnCheck KEV', state)}<small><a href="https://www.vulncheck.com/kev" target="_blank" rel="noopener noreferrer">VulnCheck Known Exploited Vulnerabilities ↗</a> · private local report · verified ${esc(parsed.report.source.checked_at)} · evaluated ${esc(now)}</small>${state === 'unknown' ? '<p>Current membership unknown. Any retained positive evidence is historical.</p>' : ''}${e ? `<details><summary>VulnCheck evidence and dates</summary><p>Listed ${esc(e.listed_at)} · publisher labels: ${esc(e.vendor_label)} / ${esc(e.product_label)} · canary reported: ${esc(e.canary_reported)}</p><ul>${e.reported_exploitation.slice(0, 20).map(reference).join('')}</ul><p>Showing up to 20 of ${e.reported_exploitation.length} citations. Listing and reference dates are not exploitation start dates; vendor affectedness requires separate evidence.</p></details>` : ''}</aside>`;
  }
  function mount(document, { onChange = () => {}, kev = null } = {}) {
    const input = document.querySelector('#vulncheck-file');
    if (!input) return null;
    let parsed = null,
      context = {},
      filter = 'all',
      limit = 150,
      sequence = 0;
    const node = (id) => document.querySelector('#' + id);
    const paint = () => {
      node('vulncheck-results').innerHTML = render(
        summarize(parsed, { ...context, kev, filter }),
        limit,
      );
    };
    const changed = () => {
      paint();
      onChange();
    };
    input.addEventListener('change', async () => {
      const current = ++sequence,
        file = input.files?.[0];
      if (!file) return;
      try {
        if (file.size > MAX_FILE_BYTES) fail();
        const text = await file.text();
        if (current !== sequence) return;
        const accepted = parseReport(text);
        // Validate optional CISA timestamps before replacing accepted evidence.
        summarize(accepted, { ...context, kev, filter });
        parsed = accepted;
        limit = 150;
        node('vulncheck-message').textContent =
          'Private report loaded in memory. Nothing uploaded or added to exports.';
        changed();
      } catch {
        if (current !== sequence) return;
        node('vulncheck-message').textContent =
          'Report rejected. Check the CLI report format and 8 MB limit. The last accepted report remains in use.';
      }
    });
    node('vulncheck-clear').addEventListener('click', () => {
      ++sequence;
      parsed = null;
      input.value = '';
      node('vulncheck-message').textContent = 'Local evidence cleared.';
      changed();
    });
    node('vulncheck-filter').addEventListener('change', (e) => {
      filter = e.target.value;
      limit = 150;
      paint();
    });
    node('vulncheck-refresh').addEventListener('click', changed);
    node('vulncheck-more').addEventListener('click', () => {
      limit += 150;
      paint();
    });
    paint();
    return {
      update(value) {
        context = value;
        paint();
      },
      renderContext(id) {
        return renderContext(parsed, id);
      },
    };
  }
  const api = { MAX_FILE_BYTES, parseReport, membership, summarize, render, renderContext, mount };
  if (typeof window !== 'undefined') window.InfrastructureVulncheck = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})();
