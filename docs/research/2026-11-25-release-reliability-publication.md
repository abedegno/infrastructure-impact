# Release reliability: second delivery

The second delivery publishes the frozen, extracted first-delivery catalogue as
generation-bound release-reliability JSON, CSV and pending-review roots. It adds
per-train annual tables and distinct date/target upgrade annotations. Counts
describe publisher disclosure and collection, not vendor security quality.
Independent human review remains pending.

## Observed results

| Train | 2024 dated versions | 2025 dated versions | 2026 dated versions | Denominator coverage |
| --- | ---: | ---: | ---: | --- |
| IOS XE 17.12, Catalyst 9200/9300 | unknown | unknown | unknown | unknown |
| AOS-CX 10.13, 6200/6300 | 11 | 8 | 5 | partial research observations; unknown production denominator |
| EOS 4.33, 720XP/720DP | unknown | unknown | unknown | unknown |

Aruba's observed possible follow-ups within 90 days number 9, 7 and 4 in those
years; two 2024 follow-ups are within 30 days. These are research observations,
not publisher-confirmed corrective respins. The catalogue retains 21 candidate
pairs covering 20 distinct follow-up versions: 10.13.1005 has different preceding
versions in the stated 6200 and 6300 histories. Annual counts deduplicate the
follow-up version rather than adding those model-specific pairs. No supported corrective-respin count
or complete signal history is available. Every current rate remains unavailable.

Arista FN0103 supplies one observed 2025 deferral notice. Its action date and
target-model applicability remain unknown; it does not become an annual withdrawn
release count. Unresolved action inputs block completeness across possible cohort
years and must not be summed as incidents. Cisco notices retain hardware and
configuration classifications and conditional replacement statements.

The catalogue contains 27 source receipts and five pending review items. Each
review item retains its source fact and evidence. Original-document and excerpt
fingerprints stay distinct. The targeted follow-up's other-platform Cisco release
dates and Arista train-start date are documented separately and do not fill the
requested binary-release denominators.

## Verification

- Final combined feature, catalogue, compiled-contract, delivery and validation
  checks: 201 passed, one intentional v2-only skip.
- Candidate browser: three train cards, no runtime exceptions, accepted generation
  identity, working JSON/CSV/review downloads and table jump control.
- Public source export: synthetic-fixture integrity and private-artifact checks
  passed.
- Fresh review cleared scope-completeness, CSV coverage provenance and browser
  version-validation findings. Full release CI is required before merge.

The browser candidate uses synthetic advisory records and the real extracted
public release catalogue. It is a transport/render check and is never deployed as
production advisory data. Production publication uses the ordinary hosted job.

## Remaining limitations

Public anonymous sources have not established complete dated release enumeration
for the requested models, complete notice histories, or Cisco 17.9.6 withdrawal.
Those gaps remain visible. The view cannot support a cross-vendor reliability
ranking. Existing compact upgrade rows lack exact device models, so source-linked
markers remain target-version context with unresolved model applicability.

See [method and review instructions](../RELEASE_RELIABILITY.md) and the
[targeted coverage finding](2026-11-25-round4-coverage-pass.md). No schedules,
permissions, secrets, authenticated access or vendor collectors change.
