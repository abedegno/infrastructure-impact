# Retained switching model evidence — 6 November 2026

An automated source-led audit examined the separate 225-record public research
stage and its 419 retained evidence blobs. It is not a copy of the hosted vault,
a complete archive, an installed-device inventory or an independent human review.
The external 13-case matrix retains full URLs, hashes, literal sections and hook
results; its SHA-256 is
`123d88d4cb54fbfa5ab93621b9e3c93f00b813431a172d45bf8e56474f447916`.

## One supported local repair

The official [Cisco fast-reload CSAF](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5/csaf/cisco-sa-fast-Zqr6DD5.json)
names Catalyst 9300 and 9300L independently in the Details sections for
CVE-2021-1375 and CVE-2021-1376. It explicitly warns that their affected software
releases can differ. The existing structural-product hook retained the IOS XE
version branches but omitted the models stated in those sections.

A Cisco-only bridge now recognizes that exact URL and reviewed full-source hash,
`e38453288e918dcba73661b7c7fa507c4521b695bd8cfdfd9099cd08af4bbe69`.
A fresh anonymous capture at 2026-11-06T19:10:07.396013+00:00 matches that hash.
Positive assignment additionally requires the advisory identity, exactly the two
CVE branches, local Details headings, both explicit platform names under each
CVE and the differing-release qualification. Binding sources retain the local
CVE section locator. Conditions retain those literal sections and the release
qualification. Changed bytes or scope leave family evidence unqualified with a
visible issue; no general prose-to-model matcher is introduced.

Replay qualifies 89 existing claims: 51 remain owned by CVE-2021-1376 and 38 by
CVE-2021-1375. These are software product/version branches, **not 89 CVEs**.
CVE identities, product IDs, statuses, versions, remediations, dates and scores
are unchanged. Software exclusions are not promoted by affected-platform context.
The existing `publisher_explicit` binding contract supports these models; no
alias, schema or frozen-study change is needed.

This repair is local and unreleased. It does not import this source into the
hosted collection, establish a patch availability date, infer a bundle, or make
the three vendors comparable. Its bounded acceptance report uses this one Cisco
source only; unavailable KEV/coverage context in that isolated report stays unknown.

## Evidence gaps that remain

| Source/context | What the source supplies | Remaining boundary |
| --- | --- | --- |
| Cisco `ios-xe-cat-verify-D4NEQA6q`, `/document/notes/1` | Catalyst 9200 Series and vulnerable IOS XE condition | Separate reviewed local-scope bridge needed; no generic transfer of global notes to every software branch. |
| Cisco `cat9k-PtmD7bgy`, `/document/notes/1` | 9200/9300/9500, trunk/TrustSec/MACsec conditions, broader 9400/9600 references | Preserve configurations and distinguish broad series from the requested chassis. |
| Cisco `ios-xe-cat-verify-BQ5hrXgH`, `/document/notes/2` | Platform exclusions alongside affected C9500 SKUs | Exclusions cannot erase separate software affectedness or imply all neighbouring SKUs share status. |
| Cisco `c9300-spi-ace-yejYgnNQ`, `/document/notes/1` | 9300 with ROMMON/bootloader conditions | Whether this belongs in an IOS XE operating-system workload cohort needs a scope decision; no automatic family alias. |
| Arista SA-0140, Affected Platforms | Mixed affected/excluded 720XP and 7050X3-related SKUs, plus a 750 supervisor component | Preserve exact SKU/component statuses and Secure Boot conditions; study-model mappings need their own evidence review. |
| Aruba 2021-013, Affected Products | 6300 and 6400 series | Does not name 6300M or 6410; parser relaxation cannot supply missing model applicability. |

No literal C9407R, C9410R, C9606R or 6300M appeared in this bounded stage, and no
Aruba 6410 model statement was found. This is a search result for these captures,
not a statement of unaffectedness or absence across vendor archives. Arista slash
labels such as 7050X3/X4 and 720XP/722XPM remain unresolved; 750X does not establish
750. ESS9300, IE9300 and Firepower 9300 are not Catalyst 9300.

Next evidence work should preserve source-specific CVE/configuration ownership
for each bridge and seek exact primary model statements for Aruba and the named
chassis. Authorized private artifacts are still unavailable. Partial evidence,
different scrutiny and incomplete disclosure prevent security rankings,
equivalence findings or concealment claims.
