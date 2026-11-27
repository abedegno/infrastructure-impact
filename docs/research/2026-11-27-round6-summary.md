# Unique respins and source-backed build reasons — 27 November 2026

Counts describe disclosure and collection, not vendor quality. Missing evidence
is unknown, never zero. Independent human evidence review remains pending.
The [candidate preview](2026-11-27-round6-preview.json) has no publication identity;
live deployment acceptance is recorded separately.

## Respin pairs after deduplication

| Vendor/train | Predecessor | Follow-up | Interval | Build reason |
| --- | --- | --- | --- | --- |
| Cisco 17.12 | 17.12.7 | 17.12.7a | Unknown | unknown |
| Aruba 10.13 | 10.13.1000 | 10.13.1003 | 34 days | unknown |
| Aruba 10.13 | 10.13.1000 | 10.13.1005 | 51 days | unknown |
| Aruba 10.13 | Unknown; expected 10.13.1100 absent | 10.13.1101 | Unknown | unknown |

All four remain `possible_respin`, not source-confirmed corrective respins. The
1005 pair merges 6200/6300 evidence. The 7a pair retains a null-predecessor 9200
observation beneath the resolved 9300 identity; the latter never establishes a
9200 predecessor. Differing scoped dates/eligibility remain in `observations`;
annual metrics use those observations. No duplicate platform row adds an event.

The catalogue retains **43 unique versions**. Aruba **10.13.1031** and
**10.13.1161** have `build_reason: security_fix`, supported by original anonymous
CSAF captures for **HPESBNW04669** and **HPESBNW05027** respectively. They remain
OS-family-only fixed-version references with unknown software dates, outside the
model-scoped respin timing list. Both reasons have their own pending review items
and source-linked staircase labels. Timing alone supplies no build reason.

The [build-source packet](2026-11-27-round6-build-sources.json) retains every
requested build, including unknowns. No qualifying 9200/9300 or family-only
advisory evidence confirmed 17.12.5a/5b; router/SD-WAN references were not
transferred to this switch catalogue. They were not fabricated as release rows.
The 7a caveat names a resolved operational defect, but its predecessor and
security status are not established; it does not meet the requested `defect_fix`
criterion. Its admitted reason remains unknown.

## Dates and rates

The [date/control packet](2026-11-27-round6-dates-control.json) records attempted
release-note histories, What's New, image tables, release-information and index
sources. **No new qualifying model-bound binary release dates** were established
for Cisco 17.12 or EOS 4.33. Stated document revisions are explicitly
`date_kind: document_revision`; article, certification, announcement and train
dates never become literal software release dates. Indexed excerpts remain
research-only; access controls were respected and known blocked origins were not retried.

Aruba's 2024 observed research 90-day count remains **two distinct versions**,
1003 and 1005. No complete original dated denominator or signal coverage was
established, so **no new rate is supportable**. All rates remain null.

## Outside-cohort 17.9.6 control

**Result: `not_established`.** A CSCwm57734 fix is stated for 17.9.6a, but the
retained Cisco material does not explicitly establish withdrawal, deferral or a
supersession relationship with 17.9.6. Release, notice and action dates remain
separately null. This control existed in the round-four research packet; the new
dedicated record improves discoverability and adds fresh indexed corroboration.
It is not an incident, rate input or member of the switching cohort.

## Review and publication

The [pending review packet](2026-11-27-round6-review.json) contains four unique
respin candidates, two source-backed security-build reasons and the five retained
notice/statement items. No item is marked human-reviewed. New optional schema
fields preserve historical roots. Native/browser validation checks uniqueness,
reason provenance, exact literals, dates, scope and derived metrics; exports keep
the complete evidence payload. Existing schedules, profiles, workflow permissions
and secrets are unchanged.
