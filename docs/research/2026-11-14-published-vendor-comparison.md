# Campus and branch switching: what the published evidence tells us

Cisco has more distinct affected CVEs in this retained OS-family sample over
**1 January 2021–14 November 2026**: **199**, compared with **106 for Aruba** and
**71 for Arista**. In **partial 2026**, Cisco has fewer: **24**, compared with
**43 for Aruba** and **37 for Arista**. These are descriptive disclosure counts.
They do not establish which vendor is safer or requires more customer upgrades.
A fair comparison of equivalent named switching models remains unresolved.

This report describes publication `3591f3596d5e41fe8d50ac633b8357e1`, generated
**14 November 2026 at 22:02:30 UTC**, from source commit
`a0e1f4212fb1f11bfdcc79564aa45f0bb237cead`. It succeeds the earlier
[interim brief](2026-11-14-vendor-comparison-brief.md), whose pinned observations
remain unchanged. The [technical run report](2026-11-14-published-switching-run.md)
and [machine-readable evidence](2026-11-14-published-switching-evidence.json)
provide provenance, definitions and verification details.

## Does Cisco have more CVEs?

Yes, across this sample's whole period; no, in its partial 2026 slice. Both
answers depend on scope and collection coverage. The counts below use
`affected_advisories` and `affected_cves`: they exclude identifiers merely
observed without an affected relationship to the selected OS family.

| Vendor | Whole-period affected advisories / distinct CVEs | Partial 2026 affected advisories / distinct CVEs |
| ------ | -----------------------------------------------: | -----------------------------------------------: |
| Cisco  |                                        170 / 199 |                                          18 / 24 |
| Aruba  |                                         17 / 106 |                                           3 / 43 |
| Arista |                                          56 / 71 |                                          28 / 37 |

In the shared **7 April–14 November 2026** publication window, the affected
CVE counts are **12 Cisco, 38 Aruba and 36 Arista**. Sharing calendar dates
does not equalize products, coverage or disclosure practices, and the cutoff
does not attribute findings to a research programme.

| Initial publisher year    | Cisco affected advisories / CVEs | Aruba affected advisories / CVEs | Arista affected advisories / CVEs |
| ------------------------- | -------------------------------: | -------------------------------: | --------------------------------: |
| 2021                      |                          50 / 55 |                            1 / 2 |                             1 / 1 |
| 2022                      |                          24 / 24 |                           4 / 34 |                             6 / 7 |
| 2023                      |                          19 / 20 |                            3 / 6 |                             3 / 4 |
| 2024                      |                          26 / 27 |                            3 / 4 |                             5 / 7 |
| 2025                      |                          33 / 49 |                           3 / 17 |                           13 / 15 |
| 2026, through 14 November |                          18 / 24 |                           3 / 43 |                           28 / 37 |

Year means the advisory's initial publisher date, not the year in a CVE
identifier. CVEs can appear in multiple advisories and years, so annual unions
need not sum to the whole-period union. Later changes to retained advisories
can also alter historical affected evidence: these are latest retained
representations grouped by historical initial dates, not reconstructed annual
snapshots of what customers knew then.

The OS families cover different product roles and breadth. Explicit affected
model evidence is sparse: Cisco has evidence for selected 9200, 9300, 9300L and
9500 models; the selected Aruba and Arista models have no explicit affected
model bindings. Missing bindings mean **unknown**, not unaffected. Expected
advisory and release inventories remain unknown, so collection completeness
cannot be quantified.

The wider retained Arista set contains 21 records marked `draft` by the source;
that status is preserved. Source-validation case coverage also remains
incomplete. The technical report separates exact, scoped and unresolved sample
matches from passing code checks; these counts are vendor statements, not an
independent certification of every affected relationship.

## Why do the counts differ?

The evidence does not isolate a causal explanation. Product breadth, shared
components, researcher attention, disclosure practices, advisory grouping and
source coverage can all change published counts. A larger count can reflect
more discovery and disclosure as well as more defects. This study cannot
separate those effects.

There is documented context for AI-assisted research and grouped disclosure.
Cisco [announced Glasswing participation on 7 April 2026](https://blogs.cisco.com/news/rising-to-the-era-of-ai-powered-cyber-defense).
Its [scheduled-hardening announcement](https://blogs.cisco.com/security/strengthening-the-foundation-a-predictable-customer-focused-response-to-ai-accelerated-vulnerability-discovery)
describes batching intended to reduce separate maintenance events. Its
[disclosure policy](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure)
describes the July umbrella approach: grouping bugs of the same weakness class
under a CVE and scoring the group using its highest-severity member. One CVE
can therefore represent multiple underlying bugs.

Arista's [2 September statement on machine-speed threats](https://blogs.arista.com/blog/racing-against-machine-speed-threats)
also discusses AI and Glasswing. These primary-source statements were checked
on 14 November 2026. Programme participation does not establish that particular
CVEs came from that programme or explain the measured vendor difference.
Likewise, a missing advisory or ambiguous fix link does not establish an intent
to hide vulnerabilities; that would require corroborating product, version and
security-change evidence.

## Why CVE totals do not measure quality or workload

A CVE count omits deployed configuration, reachability, exploitation, time
exposed and operational consequences. Severity also needs its provider and
scoring version; source-specific severity facets cannot simply be added into
a common vendor score. A quality comparison needs equivalent products,
comparable coverage and exposure evidence that this release does not supply.

Workload depends on the installed baseline, supported release path, features,
maintenance policy and which fixes arrive together. Several CVEs can be
addressed by one upgrade; one vulnerability can require different paths across
a fleet. Published advisories and remediation publications are not observed
customer changes or minimum upgrade counts.

Usable fixed-target evidence exists for all three vendors:

| Evidence scenario: usable advisories / CVEs |     Cisco |  Aruba | Arista |
| ------------------------------------------- | --------: | -----: | -----: |
| Publisher first fixed                       |   76 / 91 |  0 / 0 |  0 / 0 |
| Known fixed target                          |   77 / 92 | 6 / 64 |  6 / 8 |
| Including inferred targets                  | 116 / 134 | 6 / 64 |  6 / 8 |

These are overlapping alternatives, not additive totals. A known fixed target
need not be the first fixed release or prove availability on disclosure day.
Cisco API first-fixed evidence contains **38 distinct literal release
alternatives**, covering **241 version/CVE pairs**, **84 CVEs** and **75
advisories**. That is fix context, not 38 required upgrades or a complete release
inventory.

All **324 requested annual train/scenario/policy totals remain unknown**. Across
the broader 3,240 rows, only 24 totals are non-null; those overlap across
alternatives and cannot be added as customer upgrades. Supported steps in an
incomplete walk do not establish a reliable minimum. The inference calibration
is also too small for a safe operational recommendation: one retained Cisco
table supplied six units, five eligible, with four predictions issued, two
matches, two mismatches and one abstention—**50% agreement among issued
predictions**.

## Exploitation and remaining evidence

The pinned CISA KEV reconciliation identifies four Cisco and one Arista CVE
with documented affected evidence; Aruba has none in the observed affected
cohort. These are retrospective catalogue matches, not proof of exposure or
absence of exploitation. Arista's previously unresolved draft-selection case
now has affected evidence in this publication.

The final unmatched set exactly matches 24 Cisco candidates researched
separately against official CVE and vendor records. That enrichment, recorded
at **22:11:57 UTC**, found 17 referenced advisories with initial dates in
**2016–2018**, before this study's window. It explains their exclusion by date;
it does not show that deployed equipment is unexposed or that vendor coverage
is complete. The enrichment is separate from the 22:02 publication snapshot.

The [successful recovery and Pages run](https://github.com/abedegno/infrastructure-impact/actions/runs/43645634729)
passed publication health checks. Native-reader and actual browser-code JSON/CSV
parity passed; visual browser review was not performed. Independent human
extraction review remains pending.

This release answers what the retained evidence records as disclosed and
affected, and which fixed-target scenarios have support. Equivalent model
coverage, historical revisions, complete release inventories, patch availability
dates and actual customer upgrade burden remain necessary for a defensible
procurement or operational comparison.
