# Release evidence deployment retry — 25 November 2026

[Collection run 45637918907](https://github.com/abedegno/infrastructure-impact/actions/runs/45637918907)
passed collection, audit, encrypted recovery readback, helper-effects checks and
public artifact upload. The Pages action reported one artifact, then failed to
find the named artifact. The Actions API subsequently returned the uploaded
`github-pages` artifact. This establishes a deployment artifact-visibility failure;
its underlying cause remains unknown.

The [pinned receipt](pages-redeploy-release-evidence-2026-11-25.json) identifies the
existing artifact, producer, source commit and accepted recovery-pointer hash.
The deploy-only verifier checks ZIP and tar hashes, all public manifest file
hashes, producer acceptance gates and the unchanged recovery pointer. It does not
collect, rebuild, decrypt or promote state. The artifact includes the release
reliability evidence section in the customer comparison reader.

Only the pinned retry target changes. Workflow permissions, schedules, verifier
bounds and normal collection remain unchanged. Previous receipts are preserved.
The runtime source pin remains `05e36fb3a711fbb937ae188ba71843320a513be3`.
An intervening recovery-pointer change invalidates this receipt.

A prepared retry is not a deployment claim. Acceptance requires successful Pages
and public-health checks and verification of the live reader asset.
