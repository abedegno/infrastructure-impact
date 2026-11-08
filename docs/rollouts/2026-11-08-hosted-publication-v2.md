# Hosted publication v2 rollout — 8 November 2026

Status: source and v2 selection activated; the first hosted apply was cancelled
by the outer job deadline. No hosted candidate was accepted or published.

## Source and controls

The maintainer approved merging PRs [37](https://github.com/abedegno/infrastructure-impact/pull/37),
[38](https://github.com/abedegno/infrastructure-impact/pull/38),
[39](https://github.com/abedegno/infrastructure-impact/pull/39) and
[40](https://github.com/abedegno/infrastructure-impact/pull/40), activating the
reviewed v2 source, and running the exact-profile hosted preview/apply sequence.
All four tested heads were merged in dependency order with merge commits.

The resulting `main` commit is `6af1c551cc3e14b83a956375cf81764a478596a2`.
Its tree matches the approved source `d473d60ec46783750fcaa1795035603ca43a9100`
exactly: `01d8db42c7740772befe134e7f01ce85858cd005`.

| Control | Before | After |
| --- | --- | --- |
| `IMPACT_SOURCE_COMMIT` | `cedc552479ff2d7467388d434ae5ea961abc82b2` | `d473d60ec46783750fcaa1795035603ca43a9100` |
| `IMPACT_PUBLICATION_FORMAT` | Unset; v1 default | `v2` |
| Recovery storage | `github-draft` | Unchanged |
| Vault profile | `large` | Unchanged |
| Replay limit | `0` | Unchanged |
| Collection schedule | 12:43 UTC daily | Unchanged |

No collector job was active during activation. Workflow permissions and recovery
key custody were unchanged. The hosted job restored its own encrypted checkpoint;
no local research vault was uploaded. Local inspection used public metadata and
the bounded preview receipt.

## Hosted preview

[Preview run 42461926389](https://github.com/abedegno/infrastructure-impact/actions/runs/42461926389)
completed successfully. Its bounded receipt matched the installed
`campus-switching-public-gap-2026-11-07-v1` profile: 174 target documents,
173 Cisco and one Aruba, with none already represented as hosted advisories.
All target identity, hash and CVE pins, source configuration and normalizer
fingerprints matched the reviewed profile. Recovery-retention and Pages steps
were skipped.

- Hosted binding: `d7166f62b7cd6adb2ae305d86363f4313424f69591858bb602d9fbd7bfe0ed8e`
- Baseline: `6c3548a19fd29b235ac40ef2ad5de003a40c9a9501786e2e9adacb0c2e335872`
- Preview SHA-256: `63353e951f74f73335669fd03f663a97df91ddcc808fcb53ac2d849d73cf8d53`

The local replay fingerprint was not substituted for the hosted binding.

## Hosted apply

[Apply run 42462098050](https://github.com/abedegno/infrastructure-impact/actions/runs/42462098050)
used the exact hosted preview binding, replay limit zero and no vendor override.
It ran from `2026-11-08T08:14:56Z` to `2026-11-08T08:55:11Z`. GitHub's check
annotation reports that the job exceeded its 40-minute execution limit.
No final candidate acceptance receipt was returned. Recovery-retention, Pages
upload, deployment and public verification steps were skipped.

The accepted recovery pointer and public v1 generation were independently
rechecked and remained unchanged. No validation failure or hosted acceptance
can be inferred from the cancellation.

## Orchestration budget repair

The outer job previously had the same 40-minute budget as the isolated candidate
verifier, leaving no allowance for setup, authenticated restore, acquisition,
normalization, backup/readback or deployment. The mirrored workflow now gives
the outer job 60 minutes. The verifier's 2,400-second deadline, byte limits,
source pin, profile, schedule, permissions and every acceptance gate are unchanged.

A fresh hosted preview is required before retrying the same exact profile.
The retry result and public verification will be recorded separately.

The previous public generation is `749b1131e0074a59826403c63110a47f`, generated
at `2026-11-07T17:55:17.617166+00:00` in v1 format. The pre-rollout recovery
manifest reports 704,847,872 database bytes and a verified remote readback at
`2026-11-07T17:59:55.571003+00:00`.

The [local acceptance proof](../research/2026-11-08-retained-import-acceptance.json)
certifies only the retained local sample. Vendor coverage remains incomplete,
independent human evidence review remains pending, and this manual rollout does
not establish scheduled reliability or vendor security quality.
