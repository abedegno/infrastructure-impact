# Arista targeted coverage follow-up

Research date: 25 November 2026. EOS 4.33, 720XP/720DP, calendar years
2024–2026. Independent human review remains **pending**. This bounded pass
adds one train-level date, but does not resolve annual release denominators or
model-specific support. No rate is supported.

The public [EOS Life Cycle Policy](https://www.arista.com/en/support/product-documentation/eos-life-cycle-policy),
rendered lines 50–52, links an [EOS release support matrix](https://www.arista.com/assets/images/article/EOS-Life-Cycle-Policy.jpg).
Its **Arista EOS 4.33.x** row gives **10 October 2024** under **Initial Release
Date**. The image footer says it was last updated 23 October 2026. This is an
explicit train-level date. The row does not name 4.33.0F, enumerate individual
releases, or name 720XP/720DP as supported platforms. Do not assign this date
to a specific binary or infer support from the absence of model exceptions.

The original JPEG was obtained anonymously in one bounded request and visually
checked. It is 1220×610 pixels; the 4.33.x row is the fourth data row. Its SHA-256
is `2f073645658b4caa092351ab8fee8a6141e9ec6acf6243a860fee57621e86f27`.
The [JSON packet](2026-11-25-round4-coverage-arista.json) records the original
capture, exact locator, retrieval time, separate web excerpt fingerprint and
portable cache references.

Six search batches comprising 24 targeted official-domain queries explored
release dates, availability announcements, product bulletins, lifecycle policy,
and explicit 720XP/720DP support for EOS 4.33. Search receipts retain the actual
returned excerpts outside Git. They mostly surfaced TOI articles, security
affected/fixed-version lists, hardware documentation and certification material.
These do not establish a complete shipped-release catalogue or a supported-model
statement. For example, the [4.33.0F TOI listing](https://www.arista.com/en/support/toi/eos-4-33-0f)
has posted/updated dates on individual feature articles. Those article dates
were excluded from software release dates. Security version/model lists were
likewise excluded from general train-support evidence.

The existing cache was checked first. It still supplies the two explicit
[software RSS](https://www.arista.com/en/support/release-notes) availability
announcements: 4.33.11M on 15 October 2026 at 00:27:28 UTC and 4.33.11.2M on
3 November 2026 at 02:28:26 UTC. Their binary release dates remain null. The
20-item feed window cannot backfill 2024–2026. The public
[documentation library](https://www.arista.com/en/support/product-documentation)
directs other EOS release documentation to Software Download. Prior cached
bulletin and FN0103 detail attempts redirected to sign-in; neither was retried.

The resulting access decision is precise: **a public historical per-release
catalogue and explicit EOS 4.33 support statements for these study models were
not established by this bounded search**. This does not prove they exist nowhere
publicly. The newly found train date does not close those gaps. Annual release
denominators, model-specific incident totals and rates remain unknown.

Further progress requires a publisher-authorized historical release export or
an anonymously readable release-note support table that explicitly names the
train/release and model. No authentication, challenge bypass, blocked-route
retry, mirror or bulk crawler was used. Existing robots/terms restrictions and
unresolved production collection permission continue to apply. Full vendor
content stays outside Git; `$RELEASE_RELIABILITY_CACHE/arista/…` references
resolve under the existing round-4 cache root. No old research packet or code
was changed.
