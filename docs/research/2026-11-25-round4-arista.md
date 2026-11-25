# Arista EOS 4.33: round 4 public-source research

Research date: 25 November 2026. Scope: EOS 4.33, 720XP/720DP, 2024–2026.
Independent human review is **pending**. This is an incomplete evidence catalogue,
not a complete release history, incident total, or production collector dataset.

The [research packet](2026-11-25-round4-arista.json) records eight observed
release identities, two dated announcements, one explicit deferral statement,
one candidate follow-up pair, access receipts and coverage limits. Annual release
denominators and model-specific historical incident totals remain **unknown**.

| Release                   | Public evidence                                                                                                                                 | Date meaning                                      |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| 4.33.0F, 4.33.1F, 4.33.2F | [Product Documentation Library](https://www.arista.com/en/support/product-documentation), Product Bulletins :: EOS, lines 173–175               | Identity only; exact release dates unknown        |
| 4.33.3F                   | [FN0103 summary](https://www.arista.com/en/support/advisories-notices/fieldnotice?start=40), lines 102–110                                      | Notice dated 1 July 2025; action date unknown     |
| 4.33.4M, 4.33.5M          | [SA0127](https://www.arista.com/en/support/advisories-notices/security-advisory/22869-security-advisory-0127), Affected Software and Resolution | Identity/fix context; exact release dates unknown |
| 4.33.11M                  | [Software RSS](https://www.arista.com/en/support/release-notes), item 12                                                                        | Announcement: 15 October 2026, 00:27:28 UTC       |
| 4.33.11.2M                | [Software RSS](https://www.arista.com/en/support/release-notes), item 5                                                                         | Announcement: 3 November 2026, 02:28:26 UTC       |

These eight identities are observed references, not eight enumerated shipped releases.
In particular, the two SA0127 identities (4.33.4M and 4.33.5M) are affected/fixed
version research leads, not independent release-catalogue evidence. The three
product-bulletin links identify versions but their documents remain unread.
The RSS explicitly announces each sampled version as available for download;
the exact full titles are quoted in the JSON and checked against cached origin
XML. RSS publication does not prove an exact binary-availability date. The last two
announcement calendar dates are 19 days apart; no publisher statement obtained
links the pair to a defective predecessor, withdrawal or corrective respin.

FN0103 explicitly states: “EOS release 4.33.3F has been deferred for all supported
platforms due to software defect Bug ID 1165537.” Its posted, updated and displayed
notice dates are all 1 July 2025. The summary gives neither an exact action date
nor a replacement release. The [detail route](https://www.arista.com/en/support/advisories-notices/field-notice/21651-field-notice-0103)
redirects to sign-in. Neither study model is named in the public summary, so
model applicability remains unknown. Do not propagate this deferral to 4.33.4M
or 4.33.5M. SA0127 is a scope control: its affected-platform discussion explicitly
excludes 720D and 720XP/722XPM series for that advisory, despite its 4.33 fix
references. It does not establish general release/model support or withdrawal.

The [current index](https://www.arista.com/en/support/advisories-notices/fieldnotice?start=0)
and [offset 40](https://www.arista.com/en/support/advisories-notices/fieldnotice?start=40)
expose ten summaries each and pagination navigation. Twenty unique summaries
were inspected: FN0139–FN0148 and FN0099–FN0108. Other offsets were not traversed;
this is explicitly not systematic complete archive coverage. FN0144 is timezone
context, not a withdrawal: its RSS announcement is 2 November 2026, its displayed
summary date is 3 November, and its summary mentions EOS 4.36.2F or earlier.
These dates and generic software scope must not become a model-specific incident.

The origin software RSS has 20 items across products, spanning announcements
from 28 August to 20 November 2026, with only two EOS 4.33 items. The origin
[field-notice RSS](https://www.arista.com/en/support/advisories-notices/field-notice-rss)
has ten items, FN0139–FN0148, spanning 8 October to 23 November 2026. These feeds
are retained windows; they cannot establish 2024–2026 completeness or historical
absence. TOI article dates and security advisory dates were not used as software
release dates.

Three bounded anonymous origin reads were spaced at least seven seconds apart.
The two RSS responses were usable XML. The direct robots response was an HTTP
200 client challenge, whose fingerprint is only an access receipt. The web
research service separately rendered [robots.txt](https://www.arista.com/robots.txt),
lines 0–1 and 28, with a seven-second crawl delay and a disallowed download path.
The sampled 4.33.0F bulletin link redirected to login; no further download path,
login or challenge-bypass attempt followed. Initial sandbox HTTP attempts failed
at DNS; permitted network access supplied the bounded origin reads.

[Arista terms](https://www.arista.com/en/terms-of-use), §2 and §7, restrict copying,
redistribution and access-control circumvention. Forum Rule 6 additionally mentions
crawling, bots and scripts. Public readability and robots allowance do not establish
permission for a bulk unattended catalogue. That permission remains unresolved;
no pagination crawler or production source was enabled.

Original RSS bytes, challenge receipt and retained web-tool excerpts are cached
outside Git under `/Users/jonw/cve/data/release-reliability-round4/arista`.
The JSON distinguishes `original_sha256` from `excerpt_sha256`; web-tool facts
retain a null original-document fingerprint. Web observations have day-precision
retrieval dates; origin responses have exact UTC timestamps. Full vendor text is
not included in Git. Unknown counts must never be presented as zero, and no
cross-vendor rate or reliability ranking follows from this sample.
