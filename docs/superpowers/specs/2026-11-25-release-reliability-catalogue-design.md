# Release reliability catalogue: first delivery

Implement round 4 steps 1–4 only. The purpose is to establish release denominators
and explicit publisher actions for IOS XE 17.12 (Catalyst 9200/9300), AOS-CX 10.13
(6200/6300), and EOS 4.33 (720XP/720DP), 2024–2026. More trains use configuration.
2026 is year-to-date at capture, never a completed calendar year.

## Approach

Extend the existing release-signal project with an independent catalogue contract,
not the firmware artifact evidence contract. The existing generic event `date`
cannot safely represent release, notice and action dates. A new opt-in catalogue
keeps those explicit and leaves the current published dataset and reader intact.
A manual research appendix alone would not provide reusable parsing/validation;
a hosted crawler would exceed this delivery and the public-source permissions.
This choice is the implementer's under the user's existing autonomous-work ruling.

## Contract

Configuration selects vendor, family, train, platforms and period. A catalogue has
source receipts, releases, notices, status statements, access/coverage outcomes and
unreviewed derived respin pairs. Facts reference receipts plus short quotations and
locators. Source receipts distinguish origin-document and research-excerpt hashes;
a denied response fingerprint never becomes an origin-document fingerprint.
Only origin-document captures are eligible for production facts. Excerpt-only
observations remain visibly research-only and cannot establish a denominator.
Every extraction remains independent-human-review pending.

Release dates are stated or unknown. Announcement dates, document revision dates,
notice dates and action dates never substitute for release dates. Platform scope
comes from the document, not a matching version, link index or OS train. Multiple
model-scoped references to a version are retained; aggregate unique identities do
not sum repeated catalogue rows. Coverage is complete, partial or unknown with an
explicit judgement and enumerated source scope; future periods stay unknown.

Same-base follow-ups within 30/90 days are possible respins, never inferred fixes.
Cisco rebuild suffixes share the numeric base; Aruba build increments share the
10.13.xx maintenance line; EOS sub-releases share the x and F/M suffix. Cross-line
and F/M transitions are excluded. A corrective relationship requires an explicit
publisher reason, quote and scope. Missing dates do not produce a day interval.

## Boundary and safeguards

Public anonymous primary sources only. Respect robots and terms; do not deploy a
scraper where automation permission is unresolved. Cache raw captures outside Git,
reuse captures, bound reads, reject access/challenge pages and record failures.
No credentials, customer information, private vault or retained full vendor docs.
No hosted workflow, schedule, permission, publication, metrics, rates, staircase or
UI changes. Stop after tested catalogue tooling and a factual first-delivery
summary; steps 5–8 require the user's subsequent approval.
