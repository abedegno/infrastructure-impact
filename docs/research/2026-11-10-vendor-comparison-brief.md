# Cisco, Aruba and Arista: what the disclosed CVEs tell us

Evidence date: **10 November 2026**. Publication
`6d1e2458972f428ebe023e5deaa4a993`, generated at
`2026-11-10T02:41:08.074204+00:00`. Period: 1 January 2021 through 10 November
2026. This is an OS-family disclosure comparison, including product roles outside
campus switching. It is not a comparison of verified customer installations.

## Is Cisco publishing more CVEs?

**Cisco has more distinct affected CVE IDs in our retained full-period OS-family
collection. We cannot yet generalize that result to comparable deployed switches,
the vendors' complete portfolios, or required upgrades.**

| Observed family-level evidence | Cisco IOS XE | Aruba AOS-CX | Arista EOS |
| --- | ---: | ---: | ---: |
| Advisories containing affected claims | 170 | 16 | 53 |
| Distinct affected CVEs | 199 | 104 | 68 |
| CVEs with a sourced CVSS rating | 198 | 93 | 55 |
| CVEs without a sourced CVSS rating | 1 | 11 | 13 |
| KEV-listed affected CVEs at publication evaluation | 4 | 0 | 0 |
| Counted remediation publications | 159 | 2 | 4 |
| Historical disclosure completeness | Unknown | Unknown | Unknown |

These figures come from the same hash-verified publication. CVSS coverage is the
union of CVE IDs with a non-Unknown severity facet across sources and versions;
facets can overlap and must not be added together. KEV membership is pinned to
the publication's evaluation time. Absence from KEV does not establish absence of
exploitation. Detailed severity, provider, vector/version and source evidence are
available in the [customer comparison](https://abedegno.github.io/infrastructure-impact/#customer-comparison).

The remediation figures are particularly unsuitable as a vendor ranking: they
require explicit affected-to-fix links, and those links and bundle histories remain
incomplete. One Cisco bundle groups twelve retained advisory members into a single
event. One vendor publication can resolve multiple CVEs; multiple publications can
be addressed by one upgrade. None of these counts measures customer maintenance
windows. IOS XE also includes wireless-controller and other non-Catalyst scope.

Calendar boundaries matter. The [yearly coverage inventory](2026-11-10-comparison-evidence/coverage-by-year.csv)
counts observed affected advisories by their original publication year. Expected
totals remain unknown in every cell. Later CVE additions can inherit that original
advisory date; this is not a first-disclosure timeline or an AI-effect measurement.
Earlier dated CVE/window observations remain in the
[9 November results](2026-11-09-switching-activation-results.md), rather than being
silently relabelled as the current publication.

## Why might the volumes differ?

**Several explanations can coexist; the current data does not measure their
relative contributions.** Broader product/features, shared dependencies, more
defects, more internal/external scrutiny and different disclosure practices can
all change the count. Finding and fixing previously undisclosed bugs can increase
the visible count while reducing remaining exposure.

Cisco was named in the 7 April Glasswing launch. That establishes participation,
not causation for the CVEs in this collection. [Anthropic's launch statement](https://www.anthropic.com/glasswing)
describes the defensive programme and additional participating organizations.
Arista also reports using AI-assisted discovery and expected elevated advisory
volumes and batched releases; this is not a Cisco-only explanation.
[Arista's 2 September statement](https://blogs.arista.com/blog/racing-against-machine-speed-threats)
is vendor-reported context, not independent proof of individual findings.

Cisco changed its disclosure model in July 2026: it describes grouping common
weaknesses into umbrella CVE IDs, scheduled hardening disclosures, and less detail
for lower-risk findings. A CVE ID therefore need not represent one defect, and
counting rules can change within the observation period.
[Cisco's disclosure policy](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure)
is an explicit methodological break, separate from the April programme launch.

We have no evidence here establishing that any vendor deliberately conceals CVEs.
A release containing a component update without a CVE reference is a lead. To
establish an undisclosed security correction, we need the exact product/build,
component or fix evidence, applicability and versioned disclosure history.
Backports, disabled features and non-security updates are alternative explanations.
Even a corroborated correction does not by itself establish intent.

## Why is CVE volume a poor security metric?

- **Visibility differs:** a transparent, heavily researched vendor can publish more
  findings than one with less scrutiny. Unknown disclosure is not zero exposure.
- **Scope differs:** OS families, enabled features, product roles and upstream
  dependencies are not equal populations of comparable switches.
- **Counting differs:** umbrella CVEs, shared dependencies, revisions and bundles
  separate defect counts, CVE IDs, publications, software releases and upgrades.
- **Impact differs:** a conditionally reachable issue and an exploited management
  compromise each count as one. CVSS is severity evidence, not deployment risk.
- **Time and collection differ:** partial archives, later revisions and changing
  policies can produce apparent trends without a change in underlying quality.

The customer should monitor **applicable serious/exploited exposure and necessary
upgrade decisions**, with disclosure volume as supporting context. A useful
operational comparison would track urgent versus planned actions per comparable
supported platform/train, fixes available, time exposed and maintenance effort.
Those measures require inventory/configuration and change-history evidence that
this public dataset does not supply. We cannot conclude the vendors are equally
secure, either: lack of a fair comparison does not demonstrate equivalence.

## What is ready, and what still blocks a fair comparison?

The [evidence audit](2026-11-10-switching-evidence-audit.md) separates source access,
validation inventory and extraction outcomes. The 13 latest-run failures are not
13 new switching gaps. The study sample has seven exact-byte matches, six reviewed
section matches and three controls referencing an unselected Cisco alternate;
there are no observed extraction disagreements in this sample. Independent human
review remains pending, and this purposive sample is not an accuracy estimate.

Remaining blockers are complete historical inventories, exact model/configuration
applicability, fuller fix and release histories, and human adjudication. The
previously blocked Cisco 17.12.1 release page was freshly retrieved in this audit;
its actual layout is a local parser-repair candidate, not an enabled hosted source
or a complete Cisco release history.

[Machine-readable evidence and provenance](2026-11-10-comparison-evidence/evidence.json)
and the [blind review packet](2026-11-10-comparison-evidence/README.md) accompany this
brief. Counts measure disclosure, not vendor security quality; higher disclosure
can reflect more scrutiny.
