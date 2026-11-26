# Vendor delivery plan

1. Add failing native projection/parity/domain tests, then bounded implementation.
2. Add failing browser preparation/transport tests, then frozen preparation and lazy manifest-bound selection.
3. Add explicit preview-only writer API and native regenerated-root verification.
4. Run focused Python/Node checks; document limits and commit exact owned files for parent review. Default publication remains inactive; parent owns activation and full-suite review.


## Recorded evidence and remaining gates

Implementation commit: `4ad17da`. Focused native tests: 77 passed; richer browser tests compare selected JSON and both CSV exports across vendors, scopes, windows and CVE filters with nonempty source/inference groups, history and mapped/unmapped KEV. Lazy transport, absent-manifest compatibility, budgets and advertised missing-root failure were checked. Ruff and Prettier checks passed.

The accepted public generation passed native source-regenerated closure and exact selected JSON/both-CSV comparison for Cisco 2025, Aruba all and Arista all. Logical envelopes measure 122,781,333 / 3,839,930 / 3,390,303 bytes against the complete report's 126,633,200 logical bytes. See `docs/research/2026-11-26-analysis-vendor-delivery-proof.json` for hashes/counts. Cisco is only about 3.04% smaller; All vendors still uses the complete root. Native proof elapsed times are correctness-work durations, not browser latency or CPU-time measurements.

Remaining gates: independent review/full suite, full retained-generation preview artifact and aggregate hosted/site-budget validation, browser network/latency measurement, and a separate user decision about hosted-format activation. No further benchmark or activation was performed for this documentation update.
