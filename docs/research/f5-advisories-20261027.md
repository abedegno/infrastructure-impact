# F5 advisory source review — 27 October 2026

This assistant review adds two bounded official-source scopes. Independent human
adjudication remains pending. F5 is outside the original frozen eight-vendor
extraction packet; neither that packet nor its private worksheet is replaced.

## Acquisition

[F5 support](https://www.f5.com/support) advertises a security-advisory route to
[New and Updated Articles](https://my.f5.com/manage/s/new-updated-articles).
The ordinary public browser rendered the listing without sign-in. Selecting
Security Advisory produced an RSS link, but that exact generated link returned
HTTP 400 to both an ordinary anonymous collector-style GET and the browser.
The browser response requested a valid request specification; no cause beyond
that response is established. Its query is not added to public configuration.
No alternate API parameters, browser credentials or challenges were used.

Each selected article advertises **Download Article**. Both exact PDF routes
returned HTTP 200 / `application/pdf` anonymously, within a 3 MB cap:

| Article | Subject | Captured UTC | Bytes | SHA-256 |
| --- | --- | --- | ---: | --- |
| [K000163821](https://my.f5.com/manage/s/article/K000163821) / [PDF](https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000163821) | PHP CVE-2026-109618 / CVE-2026-109619 | 12:46:12 | 50,833 | `33e2520a4f28f49b54a2415cf4a24ab0e5e59563da92d54aa98d7ea8a471a78b` |
| [K000140222](https://my.f5.com/manage/s/article/K000140222) / [PDF](https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000140222) | OpenSSH CVE-2024-6387 | 12:50:41 | 32,016 | `88e6a21b9b21485bdd4eb53fb7724c50e39a7017464177cb4cc95e3913eeb311` |

The [Ubuntu runner probe](https://github.com/abedegno/infrastructure-impact/actions/runs/40508630305)
at 13:03 UTC independently retrieved both PDFs and passed the same normalization
checks: 38 PHP statements and 13 OpenSSH statements with parser fingerprint
`baf0ef19ceb9be67`. It retained only access metadata and normalization counts,
without a vault, key, source-body artifact or publication. The other source
probes retain their own successes and access gaps.

These local capture hashes and runner hashes identify different retrieved bytes.
A second local PHP download at 13:05:28 UTC had a different SHA-256 but identical
complete extracted text and normalized claims. Its PDF CreationDate and ModDate
changed from 12:46:12 to 13:05:28 UTC. Those generated-document metadata are not
the advisory's publisher dates. The regression check retains both byte captures
and revisions while generating no semantic-change or CVE-addition signal for
identical normalized claims. A changed PDF hash alone is not a disclosure event.

These are source-access observations, separate from independent human review.
The collector must retrieve its own responses; local captures are not seeded
into hosted recovery. Full PDFs and rendered browser content remain private.
Public normalization contains scoped product/version facts, source locators and
method limits, without reproducing the article bodies or mitigation commands.

## Interpretation boundaries

The PHP article shares one table across two CVEs. Its APM data-plane and
management control-plane rows have different authentication requirements.
Reported fix versions and engineering hotfix names remain literal candidates;
superscript footnote numbers are excluded from version strings. A table row can
contain several ranges and candidates, without automatic cross-branch matching.
The article's Final label does not convert affected ranges into fixed states.

The OpenSSH article distinguishes BIG-IP Next from BIG-IP. It has both explicit
no-fix plans and empty fix columns; those states remain separate. Its background
CVE-2006-5051 mention does not create a second vulnerability assessment. Container
and base-OS scope remain attached to the applicable Next products.

Evaluated products do not constitute an affected-products list. Product-table
All labels retain the publisher's supported-lifecycle qualification; they do not
certify every historical release. Service rows acquire no invented firmware
version. No exact-image inventory or exploitable deployment is inferred.

## Review and update policy

The adapter accepts only these two identities. It binds the evaluated list and
complete description/impact/status/footnote block to reviewed text fingerprints.
Unknown layouts and changed semantic text fail for review, preserving prior
normalized evidence. Dates are checked separately and retain day precision.

At inspection, the OpenSSH browser article showed an updated-date claim of
6 October 2026 while its downloaded PDF showed 5 October. The PDF parser records
its own source claim. This representation difference establishes neither a
publisher change sequence nor hidden exposure, fix availability or intent.

There is no enabled F5 RSS discovery or historical enumeration. Coverage is two
curated documents across three CVEs, with 38 PHP and 13 OpenSSH product/CVE/branch
statements. These are statement counts, not independent products, installations,
a portfolio denominator or a comparative security rate.
