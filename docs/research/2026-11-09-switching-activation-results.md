# Published switching evidence — 9 November 2026

The reviewed repairs are live on [Infrastructure Impact](https://abedegno.github.io/infrastructure-impact/). The initial Pages deployment timed out; the approved deployment-only recovery published the exact accepted artifact without repeating collection or the full build. This updates the [customer brief](2026-11-07-vendor-comparison-brief.md) and preserves the earlier [investigation](2026-11-09-live-switching-readiness.md) as a dated baseline.

Published generation `278bbaf40f714727a4eddcbaab450d85`, generated `2026-11-09T13:53:25.281891+00:00`. The comparison starts 2021-01-01; 2026 is partial. Counts below describe retained explicit affected statements at OS-family scope, including product roles outside campus switching. They are not deployment exposure or vendor security scores.

## What changed

| OS family | Affected CVEs before → after | Counted remediation events before → after | Explicit bundled events after |
| --- | ---: | ---: | ---: |
| Cisco IOS XE | 199 → 199 | 170 → 159 | 1 |
| Aruba AOS-CX | 104 → 104 | 1 → 1 | 0 |
| Arista EOS | 65 → 67 | 1 → 1 | 0 |

The Cisco ERP-75056 source is retained as bundle evidence, without creating an advisory. Its explicit membership groups publications; it does not remove CVEs or prove how many upgrades a deployed estate needed. Aruba ARUBA-PSA-2021-019 adds five shared AOS-CX unaffected statements and must not increase affectedness. The two Arista retained records SA-0128 and SA-0201 now contribute their literal EOS research claims. SA-0201 also separates CloudVision Portal versions from TerminAttr. Original source hashes and capture times are preserved.

## Calendar and cutoff views

Each cell is **distinct affected CVEs / counted remediation events**. These are latest retained claims grouped by advisory publication date, not dates when each CVE first appeared in a vendor revision. Totals are not additive across selections. The cutoff is 7 April 2026; it is descriptive and cannot establish a Glasswing effect.

| Advisory publication window | Cisco IOS XE | Aruba AOS-CX | Arista EOS |
| --- | ---: | ---: | ---: |
| pre | 187 / 153 | 66 / 1 | 34 / 1 |
| post | 12 / 6 | 38 / 0 | 33 / 0 |
| undated | 0 / 0 | 0 / 0 | 0 / 0 |
| 2021 | 55 / 50 | 0 / 0 | 1 / 0 |
| 2022 | 24 / 24 | 34 / 1 | 6 / 0 |
| 2023 | 20 / 19 | 6 / 0 | 4 / 0 |
| 2024 | 27 / 15 | 4 / 0 | 7 / 1 |
| 2025 | 49 / 33 | 17 / 0 | 15 / 0 |
| 2026 | 24 / 18 | 43 / 0 | 34 / 0 |

JSON and CSV selections were exported through the stock native publication reader, decoding the same verified claim set once for all twenty OS-family/model-qualified and time-window views. The website provides selection/export controls; GitHub Pages does not host a REST server. See the [comparison method and export contract](../switching-comparison.md). Generated publications and evidence captures are not committed to this repository.

## Validation and remaining boundaries

| Vendor | Cases | Exact-byte matches | Reviewed-section matches | Other outcomes |
| --- | ---: | ---: | ---: | --- |
| cisco | 5 | 2 | 0 | source_missing: 3 |
| aruba | 5 | 5 | 0 | None |
| arista | 6 | 0 | 6 | None |

The study-specific validation, matching section fingerprints and blind review packet are published and exposed by the browser client. Automated exact/section matches remain different outcomes. Independent human review is pending, missing sample categories remain explicit, and these samples are not a population accuracy estimate.

Historical expected advisory totals remain unknown for all three vendors. Exact model applicability, complete bundle histories, release availability dates and configuration exposure are still incomplete. Some disclosed fixes lack the strict affected-to-fix link required by the reducer, so small peer event counts cannot establish low patching workload. Higher disclosure can reflect more scrutiny, broader scope or more transparent publication. No result establishes vendor security quality, equal security, deliberate concealment or an AI programme's causal effect.

The ordering changes with the window: the retained **2026 advisory-date cohort** has 24 affected CVEs for Cisco, 43 for Aruba and 34 for Arista. This does not establish lower Cisco disclosure or risk; 2026 is partial, historical coverage is unresolved, and later CVE additions still inherit an advisory's original date. It does show why the longer-window ordering should not be presented as a universal trend.

The customer-facing answer remains: **Cisco has more observed affected CVE IDs in this family-level collection; the present evidence cannot establish greater patching work on comparable switches.** Use applicable serious/exploited exposure and necessary upgrade decisions alongside disclosure completeness, not raw CVE volume alone.

## Operation and verification

- [Merged repair PR #45](https://github.com/abedegno/infrastructure-impact/pull/45).
- [Successful hosted preview](https://github.com/abedegno/infrastructure-impact/actions/runs/42629072051).
- [Accepted candidate and initial timed-out deployment](https://github.com/abedegno/infrastructure-impact/actions/runs/42629259767).
- [Approved deployment-only recovery](https://github.com/abedegno/infrastructure-impact/actions/runs/42647218928).
- Full stock candidate audit, capacity, native/static parity and default/archive monitoring remained mandatory before encrypted backup/readback and publication.
- The accepted artifact passed its original full candidate gates. All 10,911 manifest-listed file hashes and stock native-reader exports were independently verified locally. The live manifest, index and catalogue match the accepted bytes exactly. The actual published browser data client loaded the matching validation, review packet and scope digests and confirmed the comparison counts; this was data-client execution, not visual browser testing.
- The recovery workflow passed both public default and compressed-archive health checks, requiring the pinned generation.
- Private recovery and keys stayed runner-only. Schedules, workflow permissions and existing limits were unchanged; ordinary runtime was restored to the merged repair commit.
