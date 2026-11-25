# Retry the accepted switching publication

Run 42629259767 accepted a complete switching candidate, passed encrypted backup
and readback, retained recovery, and uploaded its sanitized public artifact. Only
its Pages deployment timed out. Repeating acquisition and a full candidate build
would produce a different artifact and spend the same work again.

The `pages-redeploy.yaml` workflow retries the exact accepted public
artifact. It is manual only, without input URLs or credentials. Its reviewed
[receipt](pages-redeploy-2026-11-09.json) pins the producer run/head, artifact and tar
digests, publication generation and accepted recovery manifest. Any changed or
expired input fails closed. It checks all manifest files and safe archive paths
before the existing pinned Pages upload/deploy actions, then runs the existing
public default/archive health checks.

It reads no private vault, encryption key or vendor source. It performs no
collection, normalization, candidate replacement or recovery promotion. The
original complete-candidate gates are preserved by byte-identical artifact reuse.
The normal collection workflow, schedule, source pin and capacity limits are
unchanged. Existing `service-publication` concurrency and the `github-pages`
environment protect deployment.

This is a concrete one-off recovery operation, not a generic artifact publisher.
The receipt ceases to apply when accepted recovery advances or the artifact
expires. A different artifact requires a new reviewed receipt.

**Approved and executed:** [PR #46](https://github.com/abedegno/infrastructure-impact/pull/46) was approved before merge and dispatch. [Recovery run 42647218928](https://github.com/abedegno/infrastructure-impact/actions/runs/42647218928) published the accepted generation. The workflow uses `actions: read`
for the earlier public artifact, alongside `contents: read`, `pages: write` and
`id-token: write`. A different recovery input or hosted permission/publication change still requires
explicit approval.

## Separate accepted upload and deployment

The normal and exact-artifact recovery workflows now put configure/deploy/health
in a dependent protected job. The producer must succeed and expose a successful
Pages upload with a nonempty artifact ID. Normal health checks use its captured
source commit; recovery health uses the verifier's exact generation. Workflow-wide
concurrency remains held through deployment, so accepted state cannot advance
between jobs. Source and generation outputs are required, not fallback defaults.

This follows the separate-job mitigation for the matching immediate-upload
visibility issue documented in [deploy-pages issue451](https://github.com/actions/deploy-pages/issues/451).
It retains the pinned official actions, upload acceptance conditions, manual
receipt checks, permissions, schedule and recovery bounds. A new artifact still
needs its own reviewed receipt. Live observation is required before calling a
particular workflow run successfully deployed.
