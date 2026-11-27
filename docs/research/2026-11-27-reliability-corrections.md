# Reliability corrections, phase one — 27 November 2026

Items 1–3 only. This is an unpublished candidate, not a replacement for live
generation `58fe89dbb1e847e09d20e3e27b08492b`. Independent human review is pending.
Counts describe disclosure and collection, not vendor quality. Missing evidence
is unknown, never zero. No analysis targets, schedules, permissions, secrets or
publication settings changed. Items 4–5, including the separate 17.9.6 control,
remain deferred at the requested stop point.

## Respin correction

The configured rules now distinguish regular releases from rebuild candidates.
AOS-CX builds divisible by ten are regular maintenance. A non-decadal candidate
uses the nearest preceding regular build in the same configured maintenance line
and stated model scope. Both 1003 and 1005 therefore anchor to 1000. The expected
regular build is computed by rounding its build down to the preceding multiple
of ten and explicitly labelled; it is not an observed release if absent.

Cisco letter suffixes anchor to the same numeric release; EOS sub-releases anchor
to the same regular F/M base. The rule is optional in the schema for historical
report compatibility, explicit in every new packaged train configuration.

The [recomputed preview](2026-11-27-reliability-corrections-preview.json) retains:

| Candidate | Regular anchor | Stated scope | Days | Result |
| --- | --- | --- | --- | --- |
| AOS-CX 10.13.1003 | 10.13.1000 | 6200 | 34 | Possible within 90 days; research excerpt evidence |
| AOS-CX 10.13.1005 | 10.13.1000 | 6200, 6300 | 51 | Possible within 90 days; separate model receipts retained |
| AOS-CX 10.13.1101 | Unknown; expected 10.13.1100 absent | 6300 | Unknown | `expected_regular_build_absent: true`; not a withdrawal finding |
| IOS XE 17.12.7a | Unknown in the retained catalogue | Catalyst 9200, 9300 | Unknown | Undated rebuild reference; not included in timed counts |

There are six scoped candidate rows for these four literal follow-up versions:
1005 and 7a each retain two model-specific rows. This is not six software
releases or incidents. The retained EOS sub-release references do not establish
the configured 720XP/720DP scope and binary-release dates needed for timed pairs.

For Aruba 2024, the 90-day observed research count is now **2 distinct versions**
(1003 and 1005), replacing the broad maintenance-cadence result. Neither meets
30 days from its regular anchor. The published 30-day count stays unknown rather
than claiming a complete zero. Later periods retain the missing-base candidate
but no established interval. All rate numerators/denominators remain unsupported;
all rates remain null. No candidate has an established corrective reason.

The [updated review packet](2026-11-27-reliability-corrections-review.json) has
11 pending items: the original four notices and one statement, plus six scoped
candidate rows, including unresolved anchors. Review generation never approves
their classifications.

## Deduplicated release records

| Vendor/train | Previous model/source rows | Unique version records |
| --- | --- | --- |
| Cisco IOS XE 17.12 | 16 | 8 |
| Aruba AOS-CX 10.13 | 27 | 24 |
| Arista EOS 4.33 | 8 | 8 |
| Total | 51 | 40 |

No original release observation was dropped. Each union retains all source
references and models; differing dates or evidence classes remain in optional
original `observations`. An aggregate date becomes unknown when observations
differ. The reducers use the original model-scoped observations, so a date or
original-byte receipt for one model cannot establish either for another.
Uniqueness and observation-union validation run in native and browser readers.

Aruba's dated research-version counts remain 11 / 8 / 5 for 2024 / 2025 / 2026.
Cisco and EOS binary-release dates remain unknown in this phase. Deduplication
does not manufacture dates, complete denominators or improve provenance classes.
The pinned 25 November research dataset remains unchanged as a historical record.

## Version-gap findings

The [source packet](2026-11-27-reliability-version-gaps.json) records quotes,
locators, receipts, original/excerpt fingerprints, access outcomes and date kinds.
Full vendor documents remain outside Git.

**Cisco 17.12.7 versus 17.12.7a.** The official Catalyst 9300
[software-image table](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/upgrading_the_switch_software.html)
explicitly lists 17.12.7 with `cat9k_iosxe.17.12.07.SPA.bin`. The Catalyst 9200
[feature chapter](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/17-12/release_notes/ol-17-12-9200/whats_new_in_cisco_ios_dublin_1712x.html)
has a 17.12.7a section. This establishes model-specific documentary references;
it does not establish a binary publication date, current download availability,
withdrawal, deferral or an explicit supersession relationship. Those statuses
remain unknown. A bounded Cisco-only search found no qualifying action statement.
Wireless-controller recommendations were not applied to these switches.

The new Cisco evidence is a labelled indexed tool excerpt: a direct robots check
returned 403, so no original-document request followed it. The quote-record
fingerprint is explicitly not an original-document fingerprint. Existing original
boot-loader observations remain intact. There is no basis here to silently
replace every IOS XE 17.12.7 analysis target with 17.12.7a.

**Aruba 10.13.1031 and 10.13.1161.** These are literal vendor fix references,
not apparent extraction errors. Official
[HPESBNW04669](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json)
names 10.13.1031 in remediation text and `product_status.fixed` for CVE-2024-6387.
[HPESBNW05027](https://csaf.arubanetworking.hpe.com/2026/hpe_aruba_networking_-_hpesbnw05027.json)
does the same for 10.13.1161. Both original anonymous fetches returned 200 and
their SHA-256 values match the retained advisory revisions used by the analysis.

The adjacent 1030/1160 entries do not contradict these patch-build references.
Their omission from a rendered release history does not prove withdrawal or
nonexistence. The advisory statements do not supply the missing model-qualified
binary-release dates. No analysis extraction-defect finding is opened because
the source text supports both extracted literals. Source-led validation and
independent review remain distinct. The new findings are retained separately,
not silently added to release denominators or upgrade targets.

## Verification and remaining work

Regression cases cover regular Aruba cadence, both rebuilds against 1000, missing
1100, Cisco letter and EOS sub-release examples, scope-separated observations,
duplicate rejection and native/browser parity. Additional controls cover dated
original evidence following an undated same-model observation, receipt order,
legacy out-of-window chronology, and tampered union scope. The refresh workflow
also emits unique version records while preserving its source revision cache.

Verification completed with 6,463 passing tests, four intentional skips and 12
passing subtests in the broad regression run. That run began before the two
final review corrections; the final affected-subsystem run then passed 158 tests
with one intentional skip. Native/browser parity, preview replay, the live
generation's unchanged legacy report, CI-scoped Ruff and web formatting checks
pass. A fresh code review closed both ordering/compatibility findings; it does
not constitute independent human review of vendor evidence. A wider optional
whole-checkout Ruff invocation also reported 57 pre-existing findings in 17
unchanged compatibility/legacy-test files outside the configured CI scope;
those files were verified unchanged and were not reformatted by this work.

The preview has `publication: null`, empty `upgrade_annotations` and null
`upgrade_selection` by design at this stop point. The next approved phase is the
existing staircase join/markers, dated-release investigation and new publication;
none is claimed complete here.
