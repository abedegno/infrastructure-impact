# Deploy the already accepted switching publication

The switching candidate passed full stock validation, encrypted backup/readback
and recovery retention in run 42629259767. Only the Pages deployment timed out.
Do not reimport or rebuild an already accepted publication just to retry hosting.

Prepare a manual-only deployment recovery workflow that reuses that run's exact
public `github-pages` artifact, bound to a reviewed receipt: repository, producing
run/head/workflow, artifact identity/digest, tar bytes/digest, publication generation
and accepted encrypted recovery manifest digest. No private vault, key or raw
worker log is downloaded or decrypted. No collection, normalization, new candidate,
recovery promotion, scheduled behavior, frozen definition or capacity changes.

Verify source metadata, archive identity and size before extraction. Fail closed
on extra ZIP members, links, duplicate/escaping tar paths, nonregular files, size
excess, wrong generation, manifest inventory/hash mismatches or changed accepted
recovery. Use existing pinned Pages upload/deploy actions and public health checks.
The original candidate's gates remain satisfied by byte-identical artifact reuse;
this operation does not substitute a new unchecked candidate.

The new workflow needs `actions: read` to retrieve the earlier artifact, plus the
existing Pages/OIDC permissions. It must remain a reviewed proposal until the
maintainer approves the hosted publication/permission change. No cron is added.
Keep service-publication concurrency and github-pages environment protection.
