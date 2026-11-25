(() => {
  'use strict';

  const MAX_BYTES = 4 * 1024 * 1024;
  const MAX_ROWS = 20000;
  const hosts = {
    cisco: ['cisco.com', 'www.cisco.com'],
    aruba: [
      'arubanetworking.hpe.com',
      'hpe.com',
      'www.hpe.com',
      'arubanetworks.com',
      'www.arubanetworks.com',
    ],
    arista: ['arista.com', 'www.arista.com'],
  };
  const vendorNames = { cisco: 'Cisco', aruba: 'Aruba', arista: 'Arista' };
  const kinds = {
    release: 'Release announcement',
    withdrawn: 'Explicit withdrawal',
    deferred: 'Explicit deferment',
    corrective_respin: 'Confirmed corrective respin',
    field_notice: 'Field notice',
    recommended: 'Recommendation',
    bug_list: 'Published bug list',
    candidate_follow_up: 'Candidate follow-up',
  };
  const coverageLabels = {
    partial: 'Partial',
    blocked: 'Blocked',
    not_collected: 'Not collected',
  };
  const chronologyLabels = {
    later: 'Later',
    not_later: 'Same date or earlier',
    unknown: 'Unknown',
  };
  const metricLabels = {
    observed_releases: 'Release announcements',
    explicit_withdrawals: 'Explicit withdrawals',
    explicit_deferred: 'Explicit deferments',
    confirmed_corrective_respins: 'Confirmed corrective respins',
    field_notices: 'Field notices',
    recommendations: 'Recommendations',
    published_bug_ids: 'Published bug IDs',
    undated_events: 'Undated events',
  };

  const check = (condition, path) => {
    if (!condition) throw Error('Invalid release signals report at ' + path + '.');
  };
  const oneOf =
    (...choices) =>
    (value) =>
      choices.includes(value);
  const text = (limit) => (value) =>
    typeof value === 'string' && value.length <= limit && /\S/u.test(value);
  const short = text(256);
  const long = text(2000);
  const locator = text(512);
  const train = (value) => text(24)(value) && /^[0-9]+\.[0-9]+$/.test(value);
  const identity = (limit) => (value) =>
    text(limit)(value) && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
  const release = identity(128);
  const bugId = identity(80);
  const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
  const count = (max) => (value) => Number.isSafeInteger(value) && value >= 0 && value <= max;
  const bool = (value) => typeof value === 'boolean';
  const year = (value) => Number.isSafeInteger(value) && value >= 1 && value <= 9999;
  const nullable = (valid) => (value) => value === null || valid(value);

  function date(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const parsed = new Date(value);
    return (
      value.slice(0, 4) !== '0000' &&
      Number.isFinite(parsed.getTime()) &&
      parsed.toISOString().slice(0, 10) === value
    );
  }

  function timestamp(value) {
    return (
      typeof value === 'string' &&
      /^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(
        value,
      ) &&
      date(value.slice(0, 10))
    );
  }

  function sourceUrl(value, vendor) {
    if (
      typeof value !== 'string' ||
      value.length > 2048 ||
      value.includes('#') ||
      /[\s\\\x00-\x1f\x7f]/u.test(value)
    )
      return false;
    // Check the literal authority before URL normalization can erase an explicit port.
    const authority = /^https:\/\/([a-z0-9.]+)(?:[/?#]|$)/i.exec(value);
    return Boolean(authority && hosts[vendor].includes(authority[1].toLowerCase()));
  }

  function array(valid, max = MAX_ROWS, min = 0) {
    return (value) =>
      Array.isArray(value) && value.length >= min && value.length <= max && value.every(valid);
  }

  function uniqueList(valid, max = MAX_ROWS) {
    const validArray = array(valid, max);
    return (value) => validArray(value) && new Set(value).size === value.length;
  }

  function fields(value, path, required) {
    check(value && typeof value === 'object' && !Array.isArray(value), path);
    for (const name of Object.keys(value)) check(Object.hasOwn(required, name), path);
    for (const [name, valid] of Object.entries(required))
      check(Object.hasOwn(value, name) && valid(value[name]), path + '.' + name);
  }

  const vendorTrain = { vendor: oneOf(...Object.keys(hosts)), train };
  const eventKind = oneOf(...Object.keys(kinds).filter((kind) => kind !== 'candidate_follow_up'));
  const period = { start: date, end: date };

  const countFields = {
    release: 'observed_releases',
    withdrawn: 'explicit_withdrawals',
    deferred: 'explicit_deferred',
    corrective_respin: 'confirmed_corrective_respins',
    field_notice: 'field_notices',
    recommended: 'recommendations',
  };
  const annualIdentities = new Set(['release', 'withdrawn', 'deferred', 'corrective_respin']);
  const rollingSource = 'https://www.arista.com/en/support/release-notes';
  const key = (...parts) => JSON.stringify(parts);
  const eventPlatforms = (event) => [...event.platforms].sort();
  const yearOf = (day) => Number(day.slice(0, 4));

  function factKey(event) {
    const base = [event.vendor, event.train, event.release, event.kind];
    if (event.kind !== 'release') base.push(event.related_release, eventPlatforms(event));
    if (event.kind === 'field_notice') {
      // Match Python's Unicode whitespace handling for publisher statements.
      const space =
        /[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+/g;
      base.push(event.statement.split(space).filter(Boolean).join(' '));
    }
    return key(...base);
  }

  function metricGroups(report, factDates) {
    const firstYear = yearOf(report.window.start);
    const lastYear = yearOf(report.window.end);
    const groups = new Map();
    function groupFor(row, year) {
      const identity = key(row.vendor, row.train, year);
      if (!groups.has(identity)) groups.set(identity, new Map());
      return groups.get(identity);
    }
    for (const row of report.coverage) {
      const lower = Math.max(firstYear, yearOf(row.start));
      const upper = Math.min(lastYear, yearOf(row.end));
      for (let year = lower; year <= upper; year++) groupFor(row, year);
    }
    const crossYear = new Set();
    for (const [identity, dates] of factDates) {
      if (new Set([...dates].map(yearOf)).size > 1) crossYear.add(identity);
    }
    for (const event of report.events) {
      if (!event.date) continue;
      const identity = factKey(event);
      const annualIdentity = annualIdentities.has(event.kind);
      if (annualIdentity && crossYear.has(identity)) continue;
      const counts = groupFor(event, yearOf(event.date));
      const field = countFields[event.kind];
      if (field) {
        if (!counts.has(field)) counts.set(field, new Set());
        counts.get(field).add(annualIdentity ? identity : key(identity, event.date));
      }
      if (event.bug_ids.length) {
        if (!counts.has('published_bug_ids')) counts.set('published_bug_ids', new Set());
        for (const bug of event.bug_ids) counts.get('published_bug_ids').add(bug);
      }
    }
    return groups;
  }

  function validate(report) {
    fields(report, 'report', {
      schema_version: oneOf(1),
      generated_at: timestamp,
      window: (v) => Boolean(v),
      dataset_sha256: hash,
      upgrades_sha256: nullable(hash),
      events: array(() => true),
      date_conflict_evidence: array(() => true),
      metrics: array(() => true),
      candidate_pairs: array(() => true),
      upgrade_links: array(() => true),
      coverage: array(() => true, 1024),
      caveats: array(long, 32, 1),
      review_status: oneOf('independent_human_review_pending'),
    });
    fields(report.window, 'window', period);
    check(
      report.window.start <= report.window.end &&
        yearOf(report.window.end) - yearOf(report.window.start) < 100,
      'window',
    );
    check(report.events.length + report.date_conflict_evidence.length <= MAX_ROWS, 'events');
    const asOf = report.generated_at.slice(0, 10);

    const events = new Map();
    const eventIds = new Set();
    const factDates = new Map();
    const receipts = new Map();
    const sourceRevisions = new Map();
    const candidates = new Set();
    const sameTrain = (first, second) =>
      first.vendor === second.vendor && first.train === second.train;
    check(report.upgrade_links.length === 0 || report.upgrades_sha256 !== null, 'upgrades_sha256');
    const each = (key, consume) =>
      report[key].forEach((row, i) => consume(row, key + '[' + i + ']'));
    function readEvent(event, path, conflict) {
      fields(event, path, {
        ...vendorTrain,
        event_id: hash,
        kind: eventKind,
        release: nullable(release),
        related_release: nullable(release),
        date: nullable(date),
        platforms: uniqueList(text(128), 64),
        statement: long,
        bug_ids: uniqueList(bugId, 4096),
        source_locator: locator,
        source: (v) => Boolean(v),
      });
      check(!eventIds.has(event.event_id), path + '.event_id');
      eventIds.add(event.event_id);
      if (!conflict) events.set(event.event_id, event);
      fields(event.source, path + '.source', {
        source_url: (value) => sourceUrl(value, event.vendor),
        source_sha256: hash,
        retrieved_at: timestamp,
        capture_method: oneOf('http_response', 'rendered_capture'),
        source_locator: locator,
        revision_id: hash,
        previous_revision_id: nullable(hash),
      });
      const receipt = event.source;
      const content = key(
        receipt.source_url,
        receipt.source_sha256,
        receipt.retrieved_at,
        receipt.capture_method,
        receipt.previous_revision_id,
      );
      check(
        (receipts.get(receipt.revision_id) ?? content) === content,
        path + '.source.revision_id',
      );
      receipts.set(receipt.revision_id, content);
      const identity = factKey(event);
      const revisionKey =
        receipt.source_url === rollingSource && event.kind === 'release'
          ? key(receipt.source_url, identity, eventPlatforms(event))
          : receipt.source_url;
      check(
        (sourceRevisions.get(revisionKey) ?? receipt.revision_id) === receipt.revision_id,
        path + '.source.revision_id',
      );
      sourceRevisions.set(revisionKey, receipt.revision_id);
      const dateInside =
        event.date !== null && report.window.start <= event.date && event.date <= report.window.end;
      const knownDates = factDates.get(identity);
      check(
        conflict
          ? event.date !== null && !dateInside && knownDates?.size
          : event.date === null || dateInside,
        path + '.date',
      );
      if (event.date !== null) {
        check(event.date <= receipt.retrieved_at.slice(0, 10), path + '.date');
        const dates = knownDates ?? new Set();
        dates.add(event.date);
        factDates.set(identity, dates);
      }
      check(event.source.source_locator === event.source_locator, path + '.source_locator');
      check(event.kind === 'field_notice' || event.release !== null, path + '.release');
      check(
        event.kind !== 'corrective_respin' ||
          (event.related_release !== null && event.related_release !== event.release),
        path + '.related_release',
      );
      check(event.kind !== 'bug_list' || event.bug_ids.length > 0, path + '.bug_ids');
    }
    each('events', (event, path) => readEvent(event, path, false));
    each('date_conflict_evidence', (event, path) => readEvent(event, path, true));
    each('coverage', (coverage, path) => {
      fields(coverage, path, {
        ...vendorTrain,
        ...period,
        status: oneOf(...Object.keys(coverageLabels)),
        expected_releases: nullable(count(100000)),
        reason: long,
      });
      check(
        coverage.start <= coverage.end &&
          coverage.start <= report.window.end &&
          coverage.end >= report.window.start,
        path,
      );
    });
    const expectedMetrics = metricGroups(report, factDates);

    each('metrics', (metric, path) => {
      fields(metric, path, {
        ...vendorTrain,
        year,
        partial_year: bool,
        ...Object.fromEntries(Object.keys(metricLabels).map((key) => [key, count(100000000)])),
        withdrawal_rate: oneOf(null),
        coverage: oneOf('not_established'),
      });
      const identity = key(metric.vendor, metric.train, metric.year);
      const counts = expectedMetrics.get(identity);
      const yearLabel = String(metric.year).padStart(4, '0');
      check(
        counts &&
          Object.keys(metricLabels).every(
            (field) => metric[field] === (counts.get(field)?.size ?? 0),
          ) &&
          metric.partial_year ===
            (report.window.start > yearLabel + '-01-01' ||
              report.window.end < yearLabel + '-12-31' ||
              asOf < yearLabel + '-12-31'),
        path,
      );
      expectedMetrics.delete(identity);
    });
    check(expectedMetrics.size === 0, 'metrics');
    each('candidate_pairs', (pair, path) => {
      fields(pair, path, {
        ...vendorTrain,
        earlier_release: release,
        later_release: release,
        earlier_date: date,
        later_date: date,
        calendar_days: count(30),
        within_14_days: bool,
        within_30_days: oneOf(true),
        corrective_respin_confirmed: oneOf(false),
        event_ids: array(hash, 2, 2),
      });
      const days = (Date.parse(pair.later_date) - Date.parse(pair.earlier_date)) / 86400000;
      check(
        days > 0 &&
          days === pair.calendar_days &&
          pair.within_14_days === days <= 14 &&
          pair.within_30_days === days <= 30,
        path,
      );
      const [earlier, later] = pair.event_ids.map((id) => events.get(id));
      check(
        earlier?.kind === 'release' &&
          later?.kind === 'release' &&
          sameTrain(earlier, pair) &&
          sameTrain(later, pair) &&
          earlier.release === pair.earlier_release &&
          later.release === pair.later_release &&
          earlier.release !== later.release &&
          earlier.date === pair.earlier_date &&
          later.date === pair.later_date &&
          factDates.get(factKey(earlier))?.size === 1 &&
          factDates.get(factKey(later))?.size === 1 &&
          earlier.platforms.length === later.platforms.length &&
          earlier.platforms.every((platform) => later.platforms.includes(platform)),
        path + '.event_ids',
      );
      const identity = key(pair.event_ids[1], pair.earlier_release);
      check(!candidates.has(identity), path);
      candidates.add(identity);
    });
    each('upgrade_links', (link, path) => {
      fields(link, path, {
        ...vendorTrain,
        year,
        scenario: text(128),
        policy: text(128),
        target: release,
        date: nullable(date),
        claim_ids: uniqueList(short, 4096),
        event_id: nullable(hash),
        signal: oneOf(...Object.keys(kinds), 'unknown'),
        relation: oneOf('model_unresolved'),
        chronology: oneOf(...Object.keys(chronologyLabels)),
        model_applicability: oneOf('unresolved'),
        reason: long,
      });
      if (link.signal === 'unknown') {
        check(
          link.event_id === null &&
            link.chronology === 'unknown' &&
            link.reason === 'no_retained_release_signal',
          path,
        );
        return;
      }
      const event = events.get(link.event_id);
      check(event && sameTrain(event, link), path + '.event_id');
      if (link.signal === 'candidate_follow_up') {
        check(candidates.has(key(link.event_id, link.target)), path + '.target');
      } else {
        check(
          link.signal === event.kind &&
            (link.target === event.release ||
              (event.kind === 'corrective_respin' && link.target === event.related_release)),
          path + '.target',
        );
      }
      const knownDates = factDates.get(factKey(event));
      const chronology =
        !link.date || !event.date || knownDates.size > 1
          ? 'unknown'
          : event.date > link.date
            ? 'later'
            : 'not_later';
      check(link.chronology === 'unknown' || link.chronology === chronology, path + '.chronology');
    });
    return report;
  }

  function parseReport(input, parseStrict) {
    check(
      typeof input === 'string' &&
        input.length <= MAX_BYTES &&
        new TextEncoder().encode(input).length <= MAX_BYTES,
      'file size',
    );
    let report;
    try {
      report = parseStrict(input, { transport: true });
    } catch {
      throw Error(
        'Invalid release signals report. Expected strict JSON with unique keys and integer counts.',
      );
    }
    return validate(report);
  }

  const safe = (value) =>
    String(value).replace(
      /[&<>"']/g,
      (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch],
    );
  const show = (value) => safe(value === null ? 'Unknown' : value);
  const group = (row) => vendorNames[row.vendor] + ' ' + row.train;
  const yesNo = (value) => (value ? 'Yes' : 'No');

  function table(title, headers, rows, empty) {
    const body = rows.length
      ? '<div class="table-wrap" tabindex="0" role="region" aria-label="' +
        safe(title) +
        '"><table><thead><tr>' +
        headers.map((header) => '<th scope="col">' + safe(header) + '</th>').join('') +
        '</tr></thead><tbody>' +
        rows
          .map(
            (row) => '<tr>' + row.map((cell) => '<td>' + show(cell) + '</td>').join('') + '</tr>',
          )
          .join('') +
        '</tbody></table></div>'
      : '<p>' + safe(empty) + '</p>';
    return '<section><h2>' + safe(title) + '</h2>' + body + '</section>';
  }

  function render(report) {
    validate(report);
    const summary = `<h2>Report details</h2>
      <p>Window ${safe(report.window.start)} to ${safe(report.window.end)}. Generated ${safe(report.generated_at)}.</p>
      <p>Dataset SHA-256 <code>${safe(report.dataset_sha256)}</code></p>
      ${report.upgrades_sha256 ? `<p>Staircase SHA-256 <code>${safe(report.upgrades_sha256)}</code></p>` : ''}
      <p><strong>Independent human review pending.</strong> Counts reflect disclosures retained for the
        sample. Historical coverage and withdrawal rates are unknown.</p>`;
    const metrics = table(
      'Observed sample counts',
      ['Train', 'Year', ...Object.values(metricLabels), 'Withdrawal rate', 'Historical coverage'],
      report.metrics.map((row) => [
        group(row),
        row.partial_year ? row.year + ' (partial year)' : row.year,
        ...Object.keys(metricLabels).map((name) => row[name]),
        row.withdrawal_rate,
        'Not established',
      ]),
      'No annual observations in this report.',
    );
    const coverage = table(
      'Coverage gaps',
      ['Train', 'Start', 'End', 'Status', 'Expected releases', 'Reason'],
      report.coverage.map((row) => [
        group(row),
        row.start,
        row.end,
        coverageLabels[row.status],
        row.expected_releases,
        row.reason,
      ]),
      'The report has no coverage entries. Historical completeness remains unknown.',
    );
    const candidates = table(
      'Candidate follow-up pairs',
      ['Train', 'Earlier', 'Later', 'Interval', 'Evidence IDs'],
      report.candidate_pairs.map((row) => [
        group(row),
        row.earlier_release + ' (' + row.earlier_date + ')',
        row.later_release + ' (' + row.later_date + ')',
        row.calendar_days +
          ' calendar days. Within 14 days: ' +
          yesNo(row.within_14_days) +
          '. Within 30 days: ' +
          yesNo(row.within_30_days) +
          '. Corrective respin unconfirmed.',
        row.event_ids.join(' · '),
      ]),
      'No candidate pairs in this report.',
    );
    const upgrades = table(
      'Upgrade target annotations',
      [
        'Train',
        'Year',
        'Target',
        'Date',
        'Scenario',
        'Policy',
        'Signal',
        'Chronology',
        'Model applicability',
        'Reason',
        'Evidence ID',
        'Claim IDs',
      ],
      report.upgrade_links.map((row) => [
        group(row),
        row.year,
        row.target,
        row.date,
        row.scenario,
        row.policy,
        kinds[row.signal] ?? 'Unknown',
        chronologyLabels[row.chronology],
        'Model scope unresolved',
        row.reason === 'no_retained_release_signal' ? 'No retained release signal' : row.reason,
        row.event_id,
        row.claim_ids.join(' · ') || 'None supplied',
      ]),
      'No upgrade annotations in this report.',
    );
    const receipts = (events) =>
      events
        .map((event) => {
          const receipt = event.source;
          const releaseLabel =
            event.kind === 'corrective_respin'
              ? safe(event.related_release + ' → ' + event.release)
              : show(event.release);
          return `<details><summary>${safe(group(event))} · ${safe(kinds[event.kind])} · ${releaseLabel}
        · ${show(event.date)}</summary>
        <p>${safe(event.statement)}</p>
        <dl>
          <dt>Event ID</dt><dd><code>${safe(event.event_id)}</code></dd>
          <dt>Platform scope</dt><dd>${safe(event.platforms.join(', ') || 'Model scope unresolved')}</dd>
          <dt>Related release</dt><dd>${show(event.related_release)}</dd>
          <dt>Published bug IDs</dt><dd>${safe(event.bug_ids.join(', ') || 'None supplied')}</dd>
          <dt>Source</dt><dd><a href="${safe(receipt.source_url)}" referrerpolicy="no-referrer">${safe(receipt.source_url)}</a></dd>
          <dt>Source locator</dt><dd>${safe(receipt.source_locator)}</dd>
          <dt>Source SHA-256</dt><dd><code>${safe(receipt.source_sha256)}</code></dd>
          <dt>Retrieved</dt><dd>${safe(receipt.retrieved_at)}</dd>
          <dt>Capture method</dt><dd>${receipt.capture_method === 'http_response' ? 'HTTP response' : 'Rendered capture'}</dd>
          ${receipt.revision_id ? `<dt>Revision ID</dt><dd><code>${safe(receipt.revision_id)}</code></dd>` : ''}
          ${receipt.previous_revision_id ? `<dt>Previous revision ID</dt><dd><code>${safe(receipt.previous_revision_id)}</code></dd>` : ''}
        </dl>
      </details>`;
        })
        .join('');
    const caveats = report.caveats.length
      ? '<section><h2>Report caveats</h2><ul>' +
        report.caveats.map((caveat) => '<li>' + safe(caveat) + '</li>').join('') +
        '</ul></section>'
      : '';
    const undated = report.events.filter((event) => event.date === null).length;
    return (
      summary +
      coverage +
      metrics +
      candidates +
      upgrades +
      '<section><h2>Events and source receipts</h2>' +
      (undated ? '<p>Events without an established date: ' + undated + '</p>' : '') +
      (receipts(report.events) || '<p>No events in this report.</p>') +
      '</section>' +
      (report.date_conflict_evidence.length
        ? '<section><h2>Conflicting dates outside the report window</h2>' +
          receipts(report.date_conflict_evidence) +
          '</section>'
        : '') +
      caveats
    );
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { parseReport, render, MAX_BYTES };
    return;
  }

  const input = document.getElementById('report-file');
  const status = document.getElementById('report-status');
  const output = document.getElementById('report-output');
  let loadSequence = 0;
  input.addEventListener('change', async () => {
    const file = input.files[0];
    if (!file) return;
    input.value = '';
    const sequence = ++loadSequence;
    status.textContent = 'Reading report…';
    output.replaceChildren();
    try {
      if (file.size > MAX_BYTES) throw Error('Choose a JSON report up to 4 MiB.');
      const body = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
      if (sequence !== loadSequence) return;
      const report = parseReport(body, window.InfrastructureJSON.parseStrict);
      output.innerHTML = render(report);
      status.textContent = 'Loaded ' + file.name + '.';
    } catch (error) {
      if (sequence === loadSequence) status.textContent = 'Could not load report. ' + error.message;
    }
  });
})();
