# v0.9.1 replacement activation proposal — 5 November 2026

Status: **local replacement candidate; renewed exact-commit approval required**.
This proposal authorizes no hosted change or collector retry by itself.

The [failed v0.9.0 activation receipt](2026-11-05-switching-activation-failed.md)
records the published immutable source, cancelled controlled run and restored
pin. The starting runtime pin remains
`5f15a88a956d783190a70aa1b99a3138aca24f76`; the public generation remains
`5090cf350ad24619b468bdca7ad0eafc`.

The replacement bounds explicit claim-local product scope while preserving all
claims, original source provenance, full valid ordinary advisory metrics,
preference decisions and strict independent writer validation. It adds phase
timings to distinguish any future collection, report, projection, writer or
backup failure. It does not increase the 40-minute timeout or any byte limit.

Before requesting renewed approval, the controller must independently review the
complete base-to-head change, resolve significant findings, run exact-head Python
3.11/3.13 and container CI, and verify the wheel/external-plugin and clean source
export. Record the full candidate commit and exact wheel/source/checksum assets
in the candidate manifest. Approval of the old source does not approve this new
candidate. The v0.9.0 tag and assets must not move.

Acceptance evidence must identify the single-source public replay separately
from hosted validation: retained capture metadata, all 1,529 claims, complete
valid ordinary metrics, bounded output and the ordinary query/publication/index
and stdlib-monitor path. Verify the actual stage's 60 vendor/scope/window rows
after deterministic claim-ID remapping. Scope projection can reduce broader
publisher PID unions in claim JSON; it must not be described as lossless
reconstruction of all source-wide memberships. Real captures stay outside Git.

Only after renewed exact-candidate approval may the controller publish v0.9.1,
change the source pin to that full release SHA and dispatch one controlled
ordinary incremental run with `reparse_limit=0`. Keep source defaults, schedules,
permissions, observation anchors, secrets and recovery configuration unchanged.
Do not provision Cisco credentials, run history/backfill or seed the hosted
vault from local replay/staging data. Require the existing recovery readback,
storage and deployment checks before accepting a new public generation, then
verify public monitor and reader/export parity. Record actual results in a new
dated receipt. A failure does not authorize repeated dispatches.

The [earlier proposal](2026-11-04-switching-activation-proposal.md) retains its
operational stop/rollback conditions and evidence limitations. Local replay
does not establish hosted runtime, recovery availability, complete vendor
coverage, scheduled reliability or completed human extraction review.
