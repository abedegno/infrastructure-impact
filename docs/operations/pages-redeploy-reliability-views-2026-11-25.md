# Release reliability views: deploy-only recovery

[Producer run 45691271417](https://github.com/abedegno/infrastructure-impact/actions/runs/45691271417)
passed collection, audit, encrypted recovery readback, helper-effects checks,
recovery retention and public artifact upload. The Pages action reported one
artifact and then failed to locate `github-pages`. The Actions API exposed the
uploaded artifact afterward. The underlying artifact-discovery cause remains
unverified; this is not evidence of a collection failure.

The [exact receipt](pages-redeploy-reliability-views-2026-11-25.json) pins that
accepted artifact and source commit. The existing verifier checks producer gates,
repository identity, the unchanged recovery pointer, ZIP/tar fingerprints and
every public manifest file before deploying those bytes. Collection and private
recovery are not repeated. Earlier receipts remain unchanged.

This changes only the retry target and its regression pins. Workflow permissions,
schedules, verifier bounds and ordinary collection remain unchanged. The runtime
source pin stays on the fully tested PR85 merge. A prepared retry is not a
successful deployment; Pages and pinned public-health verification must pass.
