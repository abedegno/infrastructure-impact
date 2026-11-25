# Switching release signals: Phase 1 feasibility

Research date: 25 November 2026. Automated research; independent human review
pending. Scope: IOS XE 17.12, AOS-CX 10.13 and EOS 4.33, calendar years
2024–2026; 2026 is incomplete. This is a feasibility sample, not an archive
backfill, production dataset or vendor reliability ranking. Phase 2 is not
implemented or activated.

## Decision

Proceed conditionally with **explicit withdrawals/deferments** and **dated
follow-up releases** as separate signals. Public evidence is sufficient for a
small evidence viewer, but does **not** currently support comparable historical
rates for all three vendors. Do not convert unavailable evidence into zero.
Withdrawal is a publisher action; an unusually close release pair is an
observation, not proof of a regression or withdrawal. A confirmed corrective
respin additionally needs a publisher statement linking the releases.

Keep field notices and recommendations as context. Keep published bug counts
separate. All counts measure what vendors disclose and what we can collect;
greater disclosure can reflect greater openness or scrutiny.

## Access matrix

“Public” means substantive evidence was readable anonymously, not that unattended
collection is approved. “Partial” means some public evidence exists but train,
history, detail or machine access is unresolved. “Login-only” applies to the
sampled route, not a claim that no alternative public source exists.

| Signal                     | Cisco IOS XE 17.12                                                                                                      | Aruba AOS-CX 10.13                                                                                                                                               | Arista EOS 4.33                                                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Withdrawn / deferred       | **Partial**: no explicit 17.12 withdrawal established in this sample; download-status/history not captured              | **Partial**: release-history remarks public; no explicit withdrawal established or complete status archive located                                               | **Partial**: public announcements exist; withdrawal history not established and download detail gated                                   |
| Field notices              | **Public**: product notice index; train/model applicability must come from each notice, not its appearance in the index | **Partial**: public release caveats available, but a complete comparable non-security field-notice archive for this train was not established                    | **Partial**: public index and RSS; sampled full notices redirect to login                                                               |
| Respins / rapid follow-ups | **Partial**: rebuild headings and bug tables public; exact dates and corrective relationships need additional evidence  | **Partial**: dated version history public; ordinary increments do not establish corrective respins                                                               | **Partial**: dated 4.33 announcements public; reason and full release notes unavailable in the sample                                   |
| Bugs listed per release    | **Public**: model-specific resolved-caveat tables; bug-detail tool requires sign-in                                     | **Public**: resolved and known issues with IDs in release notes; completeness not guaranteed                                                                     | **Login-only**: sampled full release-note/download routes gated or challenged; public feature bulletins do not substitute for bug lists |
| Recommended releases       | **Public**: current recommendation plus some explicit dated revision entries                                            | **Partial**: public Central compatibility minimum; personalized firmware recommendation is a different signal; historical general recommendation not established | **Login-only**: recommended-release route redirects to sign-in                                                                          |

Source links and access receipts are recorded in the
[manual research appendix](2026-11-25-release-signals-sample.json). These are
provisional access classifications, not completeness certifications.

## Hand-collected sample

### Cisco

The [Catalyst 9300 17.12 caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/caveats.html)
identify CSCwi70932 under 17.12.4 with C9300 scope: a PoE startup-test issue
following power loss. The same chapter has 17.12.7a rebuild entries. These
demonstrate public bug-to-release evidence, not a complete bug inventory or a
dated corrective-respin relationship.

The [Catalyst recommendation document](https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9300-series-switches/214814-recommended-releases-for-catalyst-9200-9.html)
has explicit revision entries recommending 17.12.4 on 26 February 2025,
17.12.5 on 6 May 2025, and 17.12.6 alongside 17.15.4 on 26 November 2025.
The September 2026 current table instead lists 17.15.6 and 17.18.4.
Revision dates describe recommendation changes, not software release dates.
Generic 2024 “updated recommendations” entries cannot reconstruct exact versions.

The [Catalyst 9300 notice index](https://www.cisco.com/c/en/us/support/switches/catalyst-9300-series-switches/products-troubleshooting-guides-list.html)
lists FN74221 for Catalyst 9200/9300 certificate-related DNS problems and FN74383
about access-point flash exhaustion. The latter appears in a switch index but
must not automatically become a switching-train incident. Notice publication,
revision, software scope and affected hardware need individual evidence.

### Aruba

The [6300/6400 10.13.1040 release notes](https://arubanetworking.hpe.com/techdocs/AOS-CX/10.13/RN/rn_6300-6400_10-13-1040.pdf),
PDF page 8, report releases 10.13.1000 (31 January 2024), 10.13.1010
(9 April), 10.13.1020 (20 May), 10.13.1030 (27 June), and 10.13.1040
(1 August). The table reports these as supported and posted at the document's
publication; it does not establish their status today or an absence of later
withdrawals. Pages 9–10 list resolved bug IDs, including 318883 concerning
EAP-TEAP authentication. This is a branch/model-scoped sample, not full
2025–2026 coverage. No withdrawal or corrective respin is confirmed here.

[Central's supported-platform table](https://arubanetworking.hpe.com/techdocs/CNX-CNXOP-NewHelp/HPE%20Aruba%20Networking%20Central/GUID-B4CE0CB3-EFB5-4BB2-8D0B-DF373C10D129.html)
gives 10.13.1110 as a minimum for full Central functionality for 6300/6400
families. This is a management-compatibility recommendation, not equivalent to
Cisco's general deployment recommendation or a historical recommendation timeline.

### Arista

The [public software RSS](https://www.arista.com/en/support/release-notes)
announces 4.33.11M at 2026-10-15 00:27:28 UTC and 4.33.11.2M at
2026-11-03 02:28:26 UTC. The calendar dates are 19 days apart. This is a
candidate follow-up pair only: the feed does not establish a defective predecessor,
withdrawal, reason, model applicability or exact binary-availability time. Its
retained window contains only two 4.33 announcements, so it cannot backfill
2024–2026 alone. F/M transitions must not automatically count as respins.

The [field-notice index](https://www.arista.com/en/support/advisories-notices/fieldnotice)
and [notice RSS](https://www.arista.com/en/support/advisories-notices/field-notice-rss)
are public. FN0144 has a public summary about EOS timezone rules, but its
[detail route](https://www.arista.com/en/support/advisories-notices/field-notice/25022-field-notice-0144)
redirects to login. The announcement date and later summary date differ; neither
is silently substituted for the other. The
[recommendation route](https://www.arista.com/en/support/software-download/recommended-releases)
also redirects to login. No authenticated material was accessed.

## Cisco 17.9.6 control case

The [official 17.9 caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/release_notes/ol-17-9-9300/caveats.html)
explicitly list CSCwm57734 as resolved in 17.9.6a: DHCP assignment fails in an
802.1X authentication-failure VLAN. This verifies a publisher-listed fix and
rebuild identity. It does **not** establish the first affected version, withdrawal
decision, withdrawal date or the original and replacement release dates.

The bug-detail tool redirects to Cisco authentication. No accessible Cisco-authored
withdrawal/deferment record was obtained. Community reports were not admitted as
publisher evidence; hosting on cisco.com does not establish Cisco authorship.
Therefore **17.9.6 withdrawal remains unverified**, rather than disproved. This
control case is outside the 17.12 cohort and must not enter its annual counts.

## Evidence and access limitations

Twelve bounded anonymous HTTP requests were made with four workers. Cisco/HPE
sample routes returned 403; several Arista HTML routes returned a client-challenge
page with status 200. A successful status alone is not a successful document.
The two Arista RSS responses were usable origin bytes. No repeated challenge
attempts, user-agent impersonation, login, cookie export or access bypass was used.
Browser access was unavailable in this session. The web research service could
render public Cisco/HPE content and resolve Arista sign-in redirects.

The appendix distinguishes SHA-256 of an origin response from SHA-256 of a retained
web-tool excerpt. A 403/challenge fingerprint is **not** the fingerprint of the
vendor document. For rendered-only facts, original document SHA-256 stays null;
these are research observations and are not eligible for production evidence
promotion until a supported capture supplies that provenance. The oversized support
guide capture was truncated and is excluded from evidence. Full responses and
excerpts remain outside Git; only facts, references and capture metadata are here.

Public readability does not establish permission for automated extraction or
redistribution. Review source-specific usage before enabling a collector:
[Cisco terms](https://www.cisco.com/c/en/us/about/legal/terms-conditions.html),
[HPE terms](https://www.hpe.com/us/en/about/legal/terms-of-use.html),
[HPE acceptable use](https://www.hpe.com/us/en/legal/acceptable-use-policy.html),
and [Arista terms](https://www.arista.com/en/terms-of-use).
In particular, Arista restricts copying/distribution and HPE addresses high-volume
automation. This feasibility check grants no new permission; request an authorized
feed/export or clarification where needed. Do not enable a blocked page scraper.

## Proposed Phase 2 boundary, subject to approval

1. Store explicit publisher withdrawal/deferment events separately from observed
   release pairs and confirmed corrective respins. Preserve vendor terminology;
   retirement/end-of-support is a different event. Missing dates remain null.
2. Add a narrowly scoped evidence contract alongside the existing
   `software-release-evidence-v1` contract. Existing release assets require firmware
   artifact evidence and should not be populated with document fingerprints instead.
   Use source URL, locator, capture method, retrieval time, document fingerprint,
   revision chain, platform scope, event date and method label.
3. Link exact release targets from the existing switching first-fixed/staircase
   analysis to these events. Keep stated and inferred targets distinct. “Later”
   requires a dated event after the target date; uncertain chronology stays unknown.
   Family-only scope must not bind to every model. Preserve 750 versus 7500.
4. Report per-train/year observed releases, explicit withdrawals, confirmed respins,
   candidate follow-ups, access gaps and coverage intervals separately. Publish
   rates only where both numerator and release denominator are supported. Show
   2026 as partial and never treat null staircase totals as zero upgrades.
5. Validate exact chronology, rebuild suffix ordering, duplicate announcements,
   ambiguous dates, unrelated hardware notices, inaccessible documents and
   cumulative versus per-release bug lists. Keep independent human review pending.

The most useful first output is an evidence-backed annotation of a particular
upgrade target. A fair three-vendor annual reliability comparison needs more
history and access than this sample establishes. No schedules, publication
behavior, permissions, secrets, collectors or site pages changed in Phase 1.
