# Retry the accepted switching publication

Run 42629259767 accepted a complete switching candidate, passed encrypted backup
and readback, retained recovery, and uploaded its sanitized public artifact. Only
its Pages deployment timed out. Repeating acquisition and a full candidate build
would produce a different artifact and spend the same work again.

The proposed `pages-redeploy.yaml` workflow retries the exact accepted public
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

**Activation requires maintainer approval.** The workflow adds `actions: read`
for the earlier public artifact, alongside `contents: read`, `pages: write` and
`id-token: write`. It must not be merged or dispatched until that hosted
publication/permission change has been approved.
