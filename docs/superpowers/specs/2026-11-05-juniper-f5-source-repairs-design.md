# Juniper canonical reference and F5 PDF revision repairs

Status: approved with “Proceed”; preparation and execution of the implementation
plan are authorized. The existing subagent-driven execution choice is preserved.

## Intent and selected approach

The maintainer selected the two bounded repairs after the post-v0.10.0 failure
triage: restore the exact Juniper component-reference redirect, then review F5's
current PDF before changing its fingerprint-bound interpretation. These repairs
retain the existing plugin/schema architecture. They do not broaden comparison
eligibility or establish vendor security quality.

Use exact-source exceptions and versioned reviewed profiles. Broad HPE-domain
trust, generic PDF extraction and disabling fingerprint checks would weaken the
existing boundaries. Simply replacing F5's old hashes would also strand older
retained PDFs. The builder's call is to preserve both old and current profiles.

## Juniper behavior

The existing configured Juniper 24.2R1 authentication/access-control page redirects
to the same path at `https://networkingdocs.hpe.com`. That exact target returned
200, and the existing `parse_component_inventory` hook accepts its bytes at the
original source binding, returning the scoped OpenSSH 9.4 upgrade reference.

Permit only the exact observed HPE-hosted canonical URL through Juniper's source
policy. Preserve HTTPS, credentials, port and exact host/path checks. Reject
queries/fragments, lookalike hosts, subdomains, adjacent documents, other releases
and redirects to unreviewed destinations. Do not trust HPE documentation broadly
for Juniper. Keep configured sources and the original component binding unchanged;
the reference remains component-version context, not a CVE assessment.

## F5 behavior and source facts

Retain the original K000163821 profile and K000140222 OpenSSH behavior. Add an
explicit second K000163821 profile selected only by its complete evaluated,
critical-scope and guidance fingerprints, with the same identity/date checks.
Mixed old/new fingerprint combinations and any unreviewed revision fail visibly.

The current PHP PDF's complete evaluated-product fingerprint is unchanged. Its
critical-scope fingerprint is
`a672d9082bf84be5b3a8f49349d0c09238cd71f32bad4a3727efc1f190e2b7c3`;
guidance fingerprint is
`e33dda8738adc8c10013ea90706e003ed78cc301f76b957fc59bbfe7ec1242a4`.
Raw vendor PDFs remain outside Git; public fixtures are authored synthetic text.

Review the whole current table and its footnotes against the existing profile.
Preserve the two title CVEs, affected/unaffected products, branch/version scopes,
authentication and lifecycle qualifications. Retain the explicit 17.5.1.10 plus
engineering-hotfix and 17.1.3.6 plus engineering-hotfix combinations as literal
paired remediation expressions in the current profile; never apply one branch's
candidate to another. Old-profile facts remain unchanged.

The current fifth table footnote says F5 backported both title-CVE fixes while PHP
still reports 5.4.45 and discusses non-monotonic package revisions. Preserve that
as source-bound publisher context on the affected claims. It is not verified
firmware inventory, a measured release date or proof of a silent fix. Do not turn
the example PHP build timestamp into software release availability. The related
CVE-2026-115560 article link remains outside assessment scope.

If the table review reveals another semantic difference, document it before
implementing that difference; do not refresh hashes mechanically.

## Verification and delivery

Use regression-first tests for the exact redirect and hostile URL variants, a
blocked second hop, component-hook semantics and retained source provenance.
Exercise actual transport redirect handling with synthetic responses, rather
than only testing the standalone allowlist predicate.

Test old/current F5 profiles, mixed or unknown fingerprints, title/date/route
negatives, unchanged OpenSSH handling, paired hotfix expressions, backport context
and exclusion of background/related CVEs. Verify retained old-to-new processing
and strict public projection without changing advisory identities or dates.
Update normalizer dependencies where needed and explain any fingerprint change.

Replay the authorized public captures in a new isolated explicit-path stage;
never use a native/customer vault or hosted recovery material. Verify source
hashes, scoped component output, advisory claims and public projection. Report
fresh retrieval separately from retained replay. Run focused tests per repair,
then supported full suites, lint/format and clean source/package/plugin checks
appropriate to the final diff. Obtain independent whole-branch review and
exact-head CI before proposing integration.

No schema, dependency/package version, frozen study/review resource, default
source, schedule, workflow permission, runtime pin, secret, recovery setting or
delivery/storage budget changes. No tag, release, hosted dispatch or activation
is part of these local repairs. Human evidence review remains pending. Official
CVE reconciliation and release/hotfix inventory remain subsequent work.
