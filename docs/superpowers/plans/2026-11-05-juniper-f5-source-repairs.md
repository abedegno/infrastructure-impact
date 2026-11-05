# Juniper and F5 Source Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the exact Juniper component-reference redirect and accept the reviewed current F5 PHP PDF without losing older supported evidence.

**Architecture:** Keep the existing vendor plugins, source policy and advisory-v2 contracts. Add one exact canonical transport route in Juniper and a second complete fingerprint-bound PHP profile in F5; select whole profiles, never independent section combinations. Execute the two small repairs sequentially with separate task reviews, then controller-owned combined acceptance and a whole-branch review.

**Tech Stack:** Existing Python 3.11/3.13, urllib, pytest, JSON schemas, Poppler and native/static publication tooling; pinned dependencies unchanged.

**Spec:** `docs/superpowers/specs/2026-11-05-juniper-f5-source-repairs-design.md`

The maintainer approved the written design and prepare-and-execute handoff with “Proceed.” No second planning approval is required. The existing isolated worktree and subagent-driven preference are preserved.

## Global Constraints

- No schema, dependency/package version, frozen study/review resource, default source, schedule, workflow permission, runtime pin, secret, recovery setting or delivery/storage budget changes.
- No tag, release, hosted dispatch or activation is part of these local repairs. Human evidence review remains pending. Official CVE reconciliation and release/hotfix inventory remain subsequent work.
- Keep configured sources and the original Juniper component binding unchanged; the reference remains component-version context, not a CVE assessment.
- Raw vendor PDFs remain outside Git; public fixtures are authored synthetic text. Never use a native/customer vault or hosted recovery material.
- Preserve both old and current F5 profiles; mixed old/new fingerprint combinations and any unreviewed revision fail visibly. Do not derive software release availability from the example PHP build timestamp or assess the related CVE-2026-115560.
- Preserve existing source/document limits, including the F5 3,000,000-byte PDF and 1,500,000-character reviewed-text limits, 20 pages/200 archive documents, 512,000-byte target/8,000,000-byte maximum parts, 2,000,000-byte index and 20,000,000-byte default monitor budget.

## Review Focus

1. An accepted canonical URL must not admit adjacent HPE paths, encoded/query/fragment variants, lookalike authorities or an unallowlisted second redirect hop; Task 1 exercises the real transport handler.
2. Redirected component bytes retain the original configured source binding and parser scope, not an advisory/CVE claim; Task 1 covers storage and component output.
3. A mixed evaluated/scope/guidance tuple must not select a partially matching F5 revision; Task 2 covers all revision-selection boundaries and older replay.
4. Current hotfix/base pairs and backport wording must stay scoped publisher statements, without cross-branch matching, related-CVE expansion or inferred release dates; Task 2 pins exact remediation/context facts.
5. A helper/constant change must affect the installed normalizer fingerprint and survive wheel installation while frozen inputs remain unchanged; task self-review and final controller acceptance cover fingerprints, installed resources and strict projection.

### Task 1: Restore the exact Juniper canonical transport route

**Files:**
- Modify `infrastructure_impact/plugins/juniper.py` for the exact canonical route and its URL predicate.
- Extend `tests/test_component_statements.py`, `tests/test_references.py` or `tests/test_source_access.py` as appropriate for the existing transport/component seams; do not create a generic redirect framework.
- Create `docs/research/2026-11-05-juniper-canonical-reference.md`; add a short Unreleased entry to `CHANGELOG.md`.

**Interfaces:**
- Consume `infrastructure_impact.adapters.component_statements.JUNIPER_URL`, the existing `source_policy.allowed(url, vendor)`, `collection.transport.fetch(db, url, vendor)` and registry `normalize_component_inventory(raw, url, vendor)`.
- Produce exactly one additional allowed transport target: `JUNIPER_URL` with origin `https://www.juniper.net` replaced by `https://networkingdocs.hpe.com`. Keep the original exact component parser URL; direct canonical component binding need not be added.
- Normalized component result remains scoped `components={"openssh":["9.4"]}`, with the existing Junos OS Evolved 24.2R1/platform context and no automatic CVE assessment.

- [ ] **Step 1: Add failing source-policy and transport regressions.** Assert the canonical target is allowed only for Juniper; original routes remain valid. Reject HTTP, userinfo, wrong ports, query/fragment suffixes, adjacent documents/releases, lookalike hosts/subdomains and encoded-path variants. Malformed authorities may be rejected by the existing ValueError behavior. Add a synthetic HTTPS handler/response chain that exercises the actual transport redirect handler, accepts original→canonical, and prevents a second hop to an unallowlisted URL before fetching it.
- [ ] **Step 2: Record RED.** Run the new tests against existing policy and confirm canonical routing fails for the expected reason; keep unrelated cases green.
- [ ] **Step 3: Implement the exact policy exception.** Change Juniper's domain metadata and URL predicate only as needed; the new HPE-hosted route must use full exact identity, not a host-wide suffix allowance. Existing Juniper/CVE-service routes retain their behavior. Do not change transport's general policy, source configuration or component matcher.
- [ ] **Step 4: Verify component semantics and provenance.** With synthetic publisher text, exercise transport/evidence retention followed by the configured component hook. Assert original source URL, exact raw SHA-256, OpenSSH 9.4 and release/platform qualifiers; no prior version is promoted as current, no CVE affectedness is created, and unsafe redirects do not retain a substitute successful document. Test input mutations still fail the existing component validator.
- [ ] **Step 5: Focused GREEN and self-review.** Run `.venv/bin/python -m pytest -q tests/test_component_statements.py tests/test_references.py tests/test_source_access.py tests/test_normalizer_fingerprints.py`; run focused Ruff check/format and `git diff --check`. Verify fingerprint dependencies capture the new route metadata/helper. No broad suite yet.
- [ ] **Step 6: Document and commit.** Record the observed 301/200 chain, exact trust boundary, original binding and component-versus-affectedness limitation. Public prose has no local paths/raw capture content. Commit the independently testable repair and write the brief-specific report with exact RED/GREEN evidence and concerns.

### Task 2: Add the complete current F5 PHP profile and preserve older revisions

**Files:**
- Modify `infrastructure_impact/adapters/f5_pdf.py`; touch `infrastructure_impact/plugins/f5.py` only if fingerprint dependency wiring needs it.
- Extend `tests/test_f5_pdf.py` and existing normalizer/publication tests only where needed. If a new test file is genuinely needed, add it to existing CI lint/format paths without other workflow changes.
- Create `docs/research/2026-11-05-f5-php-profile-revision.md`; append its Unreleased changelog entry.

**Interfaces:**
- Consume `reviewed_scope(text)`, `advisory(raw, url, vendor)`, existing profile facts and registry normalization; preserve public signatures, source format, advisory identity, schema and date precision.
- Produce two supported complete profiles for `K000163821`; keep the original `K000140222` OpenSSH interpretation unchanged. Profile selection is internal builder discretion and must not alter old-profile facts or retain partially matched profiles.
- Current PHP fingerprint tuple: evaluated `7cb03fe23b90bd7a28da49d7608a60e4a180a3a97cd97b7cbe2d52d37a35c7f9`; critical `a672d9082bf84be5b3a8f49349d0c09238cd71f32bad4a3727efc1f190e2b7c3`; guidance `e33dda8738adc8c10013ea90706e003ed78cc301f76b957fc59bbfe7ec1242a4`.
- Both title CVEs remain `CVE-2026-109618` and `CVE-2026-109619`. The current table retains 38 assessments (8 affected, 30 unaffected) and the existing product/branch/version/authentication/lifecycle scope, subject to source review before implementation.
- The current 17.x fix-column expressions, in publisher order, are `17.5.1.11`, `17.1.3.7`, `17.5.1.10 + Hotfix-BIGIP-17.5.1.10.0.37.35-ENG`, `17.1.3.6 + Hotfix-BIGIP-17.1.3.6.0.9.20-ENG`. Superscript footnote 4 is not part of a version string. Retain these literal combinations without automatic minor-branch matching or independent availability claims.
- Current affected claims gain concise source-bound publisher context at `Security Advisory Status / table footnote 5`: fixes were backported while PHP still reports 5.4.45; package revisions need not increase monotonically. Preserve this as exposure/context under the existing schema, not an installed inventory or release-date field.

- [ ] **Step 1: Review and record source facts before changing profiles.** Read the entire retained current critical/guidance text and compare the table, footnotes, products, versions and conditions with the old profile. Record that the old raw text is unavailable for a complete historical prose diff; compare facts to the existing implemented profile without inventing that diff. Document any additional semantic discrepancy before implementing it.
- [ ] **Step 2: Write version-selection and fact regressions using synthetic text.** Cover original PHP output, current PHP output, unchanged OpenSSH, unsupported tuples and mixed old/new sections. Assert only the two title CVEs, 38/8/30 counts, exact paired current remediation expressions, unchanged old facts, source-bound new backport/versioning context on affected claims only and no PHP-build-derived dates. Retain the existing route/title/date/size/layout negatives and related/background-CVE exclusions.
- [ ] **Step 3: Record RED.** Run the targeted new tests against the old parser; fail on missing current-profile behavior, not a malformed test fixture.
- [ ] **Step 4: Implement complete profile selection and current facts.** Preserve old profiles, select one unambiguous full fingerprint tuple, retain existing identity/date/boundary guards, and use the selected profile's complete facts. Add no generic PDF/CVSS/version matching and no automatic fingerprint refresh. Ensure helpers/constants are in normalizer dependency coverage.
- [ ] **Step 5: Exercise retained old→current transitions and projection.** In a synthetic fresh DB, normalize/ingest old and current evidence with one stable advisory identity, preserve original raw hashes/revisions, and check strict public projection. A later unsupported revision must retain the last good parsed record and remain a visible failure. Do not rewrite frozen study bindings or human-review resources.
- [ ] **Step 6: Focused GREEN and self-review.** Run `.venv/bin/python -m pytest -q tests/test_f5_pdf.py tests/test_component_statements.py tests/test_references.py tests/test_source_access.py tests/test_normalizer_fingerprints.py`; run focused Ruff check/format and diff checks. No broad suite yet.
- [ ] **Step 7: Document and commit.** Describe the source-verified current profile, paired hotfix prerequisites, disclosed backport caveat, old-profile compatibility and remaining unknowns without reproducing vendor source prose or private receipts. Commit and report exact tests, source facts and limitations.

## Controller-owned combined acceptance and final delivery

- [ ] In a new public-only stage, explicitly set `IMPACT_HOME`, `IMPACT_DATABASE`, `IMPACT_SOURCES`, `IMPACT_PUBLICATIONS` and `IMPACT_SNAPSHOT`. Remove ambient Cisco credential variables from the stage subprocess environment without inspecting values. Retain exact authorized Juniper/F5 captures and original metadata outside Git; label replay separately from fresh network retrieval.
- [ ] Exercise the ordinary configured component-reference and pinned-advisory collection paths with a retained/synthetic redirect seam as appropriate. Verify Juniper's original binding/OpenSSH 9.4 and F5's 38 source-bound claims, title CVEs, paired fixes and publisher context; generate strict publication/query output. Do not claim a successful real hosted refresh.
- [ ] On final code run the full Python 3.13 suite; clean source/privacy/synthetic-fixture export; Python 3.11 suite from the clean export with the existing Git-only skip; exact CI Ruff check/format; five existing Node suites and frontend format; actionlint only if CI paths changed; frozen dependency exports with pinned uv 0.11.21; unreleased wheel and installed external-plugin probe. Preserve lock revision 5 and existing published assets. Repeat broad checks only for changed code, a failure or a concrete unresolved concern.
- [ ] Complete final whole-branch review and any single combined fix wave/scoped re-review. Collect rulings for the final handoff. Then push the feature branch, create a PR and verify exact-head Python 3.11/3.13/container CI under the existing push-and-PR preference. No merge, source release or hosted activation is implied.

## Plan self-review

The two repairs have independent test/review boundaries and share only existing contracts and final acceptance. Exact route, real redirect handling, component semantics, full profile selection, old facts, literal fix pairs, source-bound backport context, date/CVE negatives, fingerprints and packaging each have an owning test/verification step. No new API/schema/storage or generic extraction layer is introduced. Public-source research and local replay cannot complete human review, Cisco history, release-history inventory or hosted acceptance.
