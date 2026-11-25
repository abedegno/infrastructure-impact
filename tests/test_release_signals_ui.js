const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const test = require('node:test');

const context = { window: {} };
vm.runInNewContext(fs.readFileSync('web/lossless-json.js', 'utf8'), context);
const { parseStrict } = context.window.InfrastructureJSON;
const { parseReport, render, MAX_BYTES } = require('../web/release-signals.js');

const date = '2026-11-25';
const timestamp = date + 'T12:30:00Z';
const digest = 'a'.repeat(64);
const source = {
  source_url: 'https://www.arista.com/en/support/release-notes?a=1&b=2',
  source_sha256: digest,
  retrieved_at: timestamp,
  capture_method: 'http_response',
  source_locator: 'item <img src=x onerror=alert(1)>',
  revision_id: 'd'.repeat(64),
  previous_revision_id: null,
};
const announcement = (release, date, event_id) => ({
  kind: 'release',
  vendor: 'arista',
  train: '4.33',
  release,
  related_release: null,
  date,
  platforms: [],
  statement: '<script>alert(1)</script>',
  bug_ids: [],
  source_locator: source.source_locator,
  source,
  event_id,
});
const report = () => ({
  schema_version: 1,
  generated_at: timestamp,
  window: { start: '2024-01-01', end: date },
  dataset_sha256: digest,
  upgrades_sha256: digest,
  events: [
    announcement('4.33.11M', '2026-10-15', 'b'.repeat(64)),
    announcement('4.33.11.2M', '2026-11-03', 'c'.repeat(64)),
  ],
  date_conflict_evidence: [],
  metrics: [
    {
      vendor: 'arista',
      train: '4.33',
      year: 2026,
      partial_year: true,
      observed_releases: 2,
      explicit_withdrawals: 0,
      explicit_deferred: 0,
      confirmed_corrective_respins: 0,
      field_notices: 0,
      recommendations: 0,
      published_bug_ids: 0,
      undated_events: 0,
      withdrawal_rate: null,
      coverage: 'not_established',
    },
  ],
  candidate_pairs: [
    {
      vendor: 'arista',
      train: '4.33',
      earlier_release: '4.33.11M',
      later_release: '4.33.11.2M',
      earlier_date: '2026-10-15',
      later_date: '2026-11-03',
      calendar_days: 19,
      within_14_days: false,
      within_30_days: true,
      corrective_respin_confirmed: false,
      event_ids: ['b'.repeat(64), 'c'.repeat(64)],
    },
  ],
  upgrade_links: [
    {
      vendor: 'arista',
      train: '4.33',
      year: 2026,
      scenario: 'supported_partial',
      policy: 'retrospective',
      date: '2026-10-15',
      target: '4.33.11M',
      claim_ids: [digest],
      event_id: 'c'.repeat(64),
      signal: 'candidate_follow_up',
      relation: 'model_unresolved',
      chronology: 'later',
      model_applicability: 'unresolved',
      reason: 'Model scope unavailable',
    },
  ],
  coverage: [
    {
      vendor: 'arista',
      train: '4.33',
      start: '2026-01-01',
      end: date,
      status: 'partial',
      expected_releases: null,
      reason: 'Limited feed window',
    },
  ],
  caveats: ['Counts reflect disclosure.'],
  review_status: 'independent_human_review_pending',
});
const parse = (value) => parseReport(JSON.stringify(value), parseStrict);

test('shows unknown rates, unresolved scope and incomplete observations', () => {
  const html = render(parse(report()));
  for (const label of [
    'Withdrawal rate',
    'Unknown',
    'Model scope unresolved',
    'partial year',
    'Later',
    'Coverage gaps',
    'Independent human review pending',
    'Limited feed window',
  ])
    assert(html.includes(label), label);
});

test('separates candidate follow-ups from confirmed corrective respins', () => {
  const input = report();
  const confirmed = announcement('4.33.12M', '2026-11-20', 'd'.repeat(64));
  confirmed.kind = 'corrective_respin';
  confirmed.related_release = '4.33.11.2M';
  input.events.push(confirmed);
  input.metrics[0].confirmed_corrective_respins = 1;
  input.upgrade_links.push({
    ...input.upgrade_links[0],
    target: '4.33.11.2M',
    event_id: confirmed.event_id,
    signal: 'corrective_respin',
  });
  const html = render(parse(input));
  assert.match(html, /Candidate follow-up pairs/);
  assert.match(html, /19 calendar days/);
  assert.match(html, /Within 14 days: No/);
  assert.match(html, /Within 30 days: Yes/);
  assert.match(html, /Confirmed corrective respin/);
  assert.match(html, /4\.33\.11\.2M → 4\.33\.12M/);
  input.candidate_pairs[0].corrective_respin_confirmed = true;
  assert.throws(() => parse(input), /candidate_pairs/);
});

test('renders literal publisher text and escapes link attributes', () => {
  const html = render(parse(report()));
  assert(!html.includes('<script>'));
  assert(!html.includes('<img'));
  assert(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
  assert(html.includes('href="https://www.arista.com/en/support/release-notes?a=1&amp;b=2"'));
});

test('rejects unsafe or misleading official source routes', () => {
  for (const url of [
    'javascript:alert(1)',
    'data:text/html,hello',
    'http://www.arista.com/',
    'https://www.arista.com.evil.test/',
    'https://arista.com@evil.test/',
    'https://user@www.arista.com/',
    'https://www.arista.com:444/',
    'https://www.arista.com:443/',
    'https://www.arista.com\\@evil.test/',
    'https://www.arista.com%2e/',
    'https://www.cisco.com/',
  ]) {
    const input = report();
    input.events[0] = { ...input.events[0], source: { ...source, source_url: url } };
    assert.throws(() => parse(input), /source_url/, url);
  }
});

test('rejects missing, malformed and oversized nested report fields', () => {
  for (const mutate of [
    (r) => delete r.window.end,
    (r) => delete r.upgrades_sha256,
    (r) => {
      r.upgrades_sha256 = null;
    },
    (r) => {
      r.metrics.push(r.metrics[0]);
    },
    (r) => {
      r.candidate_pairs.push(r.candidate_pairs[0]);
    },
    (r) => {
      r.candidate_pairs[0].earlier_release = '4.33.4M';
    },
    (r) => {
      r.upgrade_links[0].target = '4.33.4M';
    },
    (r) => {
      r.upgrade_links[0].date = '2026-11-03';
    },
    (r) => {
      r.upgrade_links[0].model_applicability = 'resolved';
    },
    (r) => {
      r.upgrade_links[0].chronology = 'maybe';
    },
    (r) => {
      r.window.end = '2026-02-30';
    },
    (r) => {
      r.metrics[0].withdrawal_rate = 0;
    },
    (r) => {
      r.events[0].bug_ids = [['CSC00000']];
    },
    (r) => {
      r.events[0].platforms = Array.from({ length: 65 }, (_, i) => '750-' + i);
    },
    (r) => {
      r.events[0].source = [];
    },
    (r) => {
      r.events[0].source = { ...source, revision_id: ['x'] };
    },
    (r) => {
      r.upgrade_links[0].claim_ids = [[digest]];
    },
    (r) => {
      r.events.push(r.events[0]);
    },
    (r) => {
      r.coverage[0].status = 'complete';
    },
    (r) => {
      r.caveats[0] = { message: 'unexpected' };
    },
  ]) {
    const input = report();
    mutate(input);
    assert.throws(() => parse(input), /Invalid release signals report/);
  }
});

test('rejects duplicate keys, nonfinite literals and excess input before rendering', () => {
  const json = JSON.stringify(report());
  for (const text of [
    json.replace('"schema_version":1', '"schema_version":2,"schema_version":1'),
    json.replace('"observed_releases":2', '"observed_releases":1e999'),
    json.replace('"observed_releases":2', '"observed_releases":2.0'),
    ' '.repeat(MAX_BYTES + 1),
  ])
    assert.throws(() => parseReport(text, parseStrict), /Invalid release signals report/);
});

test('retains upgrade steps whose release signal history is unknown', () => {
  const input = report();
  input.upgrade_links[0] = {
    ...input.upgrade_links[0],
    event_id: null,
    signal: 'unknown',
    chronology: 'unknown',
    reason: 'no_retained_release_signal',
  };
  const html = render(parse(input));
  assert.match(html, /No retained release signal/);
  assert.match(html, /Model scope unresolved/);
  assert.match(html, /4\.33\.11M/);
});

test('rejects forged annual metrics', () => {
  const input = report();
  input.metrics[0].observed_releases = 999;
  assert.throws(() => parse(input), /metrics/);
});

test('corrective respin can annotate its replacement target', () => {
  const input = report();
  const confirmed = announcement('4.33.12M', '2026-11-20', 'd'.repeat(64));
  confirmed.kind = 'corrective_respin';
  confirmed.related_release = '4.33.11.2M';
  input.events.push(confirmed);
  input.metrics[0].confirmed_corrective_respins = 1;
  input.upgrade_links.push({
    ...input.upgrade_links[0],
    target: confirmed.release,
    event_id: confirmed.event_id,
    signal: confirmed.kind,
  });
  assert.doesNotThrow(() => parse(input));
});

test('conflicting withdrawal dates cannot establish later chronology', () => {
  const input = report();
  const withdrawn = {
    ...announcement('4.33.11M', '2026-11-03', 'd'.repeat(64)),
    kind: 'withdrawn',
  };
  input.events.push(withdrawn, {
    ...withdrawn,
    event_id: 'e'.repeat(64),
    date: '2026-10-14',
    source: { ...source, source_url: source.source_url + '&archive=1', revision_id: digest },
  });
  input.metrics[0].explicit_withdrawals = 1;
  input.upgrade_links.push({
    ...input.upgrade_links[0],
    event_id: withdrawn.event_id,
    signal: withdrawn.kind,
    chronology: 'unknown',
  });
  assert.doesNotThrow(() => parse(input));
  input.upgrade_links.at(-1).chronology = 'later';
  assert.throws(() => parse(input), /chronology/);
});
