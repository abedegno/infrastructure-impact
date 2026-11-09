# Deploy the accepted switching comparison artifact

The implementation is merged and certified at `d04c078`. Collection runs 42712803964 and 42714054236 completed audit, encrypted backup/readback and public artifact upload, but GitHub Pages respectively timed out and cancelled deployment. Public annotations and step metadata establish the failing boundary; private worker logs are not used.

Reuse the existing reviewed `pages-redeploy.yaml` and `checks/pages_redeploy.py` mechanism. This is an exact receipt/pin refresh, not a new retry facility.

1. Download only the latest sanitized `github-pages` artifact (13719707587 from run 42714054236 attempt 1), public API metadata and accepted `publication-state/state/current.json`. Bound archives, verify ZIP/TAR hashes and every public manifest member with the existing verifier. Keep raw artifacts outside Git.
2. Refresh only the workflow's exact run/artifact/receipt pins and add the measured receipt. Preserve the old receipt, every verifier gate, permissions, concurrency, timeout, source pin, schedules and behavior. Run focused receipt/workflow tests and privacy checks; fresh independent review.
3. Push a small PR, run required CI, merge after review, dispatch the existing deployment-only workflow once. It must verify accepted-manifest identity before publishing; no collection, rebuild or private recovery access. Confirm default/archive public health, the customer route, filters and generation-bound exports. A failed deployment requires its public annotation/status to be inspected, not a blind rebuild.

The current source code and runtime source pin remain unchanged. Unsupported vendor release dates, links and model applicability remain unknown.
