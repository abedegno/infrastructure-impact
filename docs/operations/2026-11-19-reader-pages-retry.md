# Reader deployment retry — 19 November 2026

[Collection run 44616329992](https://github.com/abedegno/infrastructure-impact/actions/runs/44616329992)
passed collection, validation, recovery retention, helper-effects checks and public
artifact upload. The Pages deployment action then reported zero matching artifacts.
The Actions API subsequently returned the uploaded `github-pages` artifact. This
establishes an artifact-visibility failure at deployment, not its underlying cause.

The [pinned receipt](pages-redeploy-reader-2026-11-19.json) identifies that existing
artifact, producing run, source commit and accepted recovery-pointer hash. Local
verification checked all 12,347 public file hashes and confirmed the new reader is
included. The deploy-only workflow verifies the same receipt again on the runner.
It does not collect, rebuild, decrypt or promote state.

Only the retry target changed. Workflow permissions, schedules, verifier bounds and
the normal collector remain unchanged. Prior retry receipts are preserved. The
runtime source pin remains `cc84ad64fa7704020228f47ea7e433dde0acb0ee`.

Preparation is not a deployment claim. Accept the retry only after its Pages and
live-health steps succeed and the deployed HTML references the expected reader
asset. An intervening recovery-pointer change blocks this exact receipt.
