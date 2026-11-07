# Cisco/Aruba publication-gap proposal — 2026-11-07

This is an offline evidence proposal, **not an apply-compatible maintenance
preview or a validated publication candidate**. No hosted collection, source
configuration, pin, schedule, permissions, recovery state or website content
changed. Independent human impact review remains pending.

## Selected evidence and projected membership

The proposal selects exactly the **174 successful targets** from the earlier
[public-source backfill](2026-11-06-public-reconciliation-followup.md): 173 Cisco
article URLs and one Aruba bulletin. The public-only checkpoint was copied while
stable, with no nonempty WAL or rollback journal. The original was not opened
with SQLite; its SHA-256 remained unchanged. Current v0.12.1 normalizers validated
all selected retained captures against advisory schema v2, preserving stable
advisory identities and exact CVE sets. No new advisory HTTP request was made.

Each requested-to-resolved URL association comes from its retained successful
collection receipt. Capture hashes are checked before parsing; advisory aliases
are not inferred from URL filenames. Capture time, collection-check time and
vendor publication date remain separate. Offline parsing does not establish
current source availability or freshen an old collection success.

The public baseline is generation `5f02de1195954639a6abb4731af8db96`, generated
`2026-11-07T08:35:49.718634+00:00`, downloaded and checked against its manifest.
The candidate denominator is the pinned registry-publication window ending
6 November, described in the [comparison brief](2026-11-07-vendor-comparison-brief.md).

| OS family | Registry-window candidates | Current vendor presence | Projected vendor presence | Current family presence | Projected family presence |
| --------- | -------------------------: | ----------------------: | ------------------------: | ----------------------: | ------------------------: |
| IOS XE    |                        201 |                       0 |                       201 |                       0 |                       200 |
| AOS-CX    |                         70 |                      67 |                        70 |                      67 |                        70 |
| EOS       |                         86 |                      86 |                        86 |                      84 |                        84 |

All 174 selected normalized advisory identities are absent from the baseline's
current identity inventory. A union of independently scoped evidence identities
would contain **1,140 current identities**, up from 966. This arithmetic does not
prove a build fits hosted capacity or validate a complete candidate. Local
revision/evidence IDs must never be transplanted into the hosted database.
No existing published record or excluded historical representation is replaced.

Membership includes drafts and all literal assessment statuses. It is not a count
of affected devices, patches or confirmed affected CVEs. The Cisco documents
include other IOS XE platforms, including routers and wireless controllers;
173 documents do not establish 173 Catalyst switching advisories. Model,
configuration, version and shared-bulletin boundaries still require review.

CVE-2024-20508 remains an ambiguous IOS XE family lead, rather than receiving an
invented association. EOS family leads CVE-2021-28501 and CVE-2023-24512 remain
unchanged. The Aruba addition supplies CVE-2021-29143, CVE-2021-29148 and
CVE-2021-29149. Unsupported official CVE formats, upstream-component discovery,
unknown archive denominators and independent human review remain unresolved.
The result supports neither vendor ranking nor equivalence or concealment.

## Operational route still required

The installed hosted registry supports only
`arista-reviewed-2024-0099-0103-v1`. Its policy, expected CVE sets and cleanup
proofs are specific to Arista. It cannot be used for this batch, and this
proposal supplies **no accepted apply fingerprint**.

The recommended next implementation is a bounded, one-off exact-target import
route. Permanent scheduled pins would repeatedly fetch historical documents;
manual database/normalized-row transplantation would undermine provenance and
hosted revision identity. Neither is proposed.

Before activation, the reviewed route needs:

1. An explicit versioned vendor/URL/advisory/CVE manifest with request, redirect,
   response-size and total-work bounds. Live identity or scope changes must fail
   visibly rather than silently widening the accepted batch.
2. A genuine non-publishing preview bound to a fresh authenticated hosted
   inventory and installed normalizer identities. A public snapshot alone is
   insufficient to produce the existing apply contract's inventory fingerprint.
3. A separately approved apply under the single writer, with source selections,
   immutable captures, retained conflicts/exclusions and revision history intact.
   Success must not clear unrelated old source errors or mark human review done.
4. Audit and complete candidate construction, measured capacity and monitor
   budgets, native/static and switching exports, authenticated recovery
   backup/readback and public verification before any publication is claimed.

Preparing this proposal authorizes none of those hosted effects. Implementation
and its execution route require review; scheduling, permissions and publication
remain separately gated. Frozen studies and eligibility caveats stay unchanged.

## Verification and evidence packet

The outside-Git public-only packet contains the exact target CSV, JSON facts,
retained source hashes and timestamps, baseline public inputs, source-copy proof,
read-only calculation and verification receipt. It follows the repository's
[contribution rules](../../CONTRIBUTING.md); full captures and databases are not
committed. The original upstream scan and collection are not rerun by this
calculation.

- `proposal.json` SHA-256:
  `45a3b4bb2494d7620d6f469eb9d9691296b0db3ecff43dd542d61763eb0f0566`.
- `targets.csv` SHA-256:
  `557b46d85dd13d27bc0077241bdb7cd1b5d665cc64062001337c23562c19a9b5`.
- Original public stage SHA-256, unchanged:
  `a400c2268285ec69122ddcbf34494af321cd6135df68b0f5cb24a423a6cf3dca`.

Automated checks confirm 174 distinct new advisory identities, matching JSON/CSV
facts, exact retained capture hashes, schema-valid current normalization and
unchanged original source bytes. These checks do not establish complete vendor
coverage, source freshness, model exposure or successful hosted ingestion.
