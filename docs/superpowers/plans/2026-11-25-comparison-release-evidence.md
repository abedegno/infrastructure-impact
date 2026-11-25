# Comparison release-evidence implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development task by task.

**Goal:** Show verified publisher announcements and literal upgrade-target matches in the existing customer comparison without creating vendor reliability rates.

**Architecture:** Add a small pinned research section to the existing `customer-comparison.js` renderer. Its factual basis is the reviewed research packet merged in commit `15292f21f1e6d487757ed131426f2e70827cab4d`; it is explicitly independent of the selected live cohort and its exports. Existing reader assets already deliver this module, so no new publication path, data fetch or source activation is needed.

**Tech stack:** Existing plain JavaScript renderer and Node/Python integration tests.

**Spec:** User-approved recommendation to add “Release reliability evidence”; facts and limitations in `docs/research/2026-11-25-publisher-event-sample.{md,json}`.

## Global constraints

- No customer names or customer data.
- Keep independent human review pending and disclosure-versus-quality caveats.
- Vendor withdrawal/respin rates remain unavailable for all three vendors.
- Announcement dates are not action dates. Model applicability remains unresolved.
- Pinned 14 November 2026 scenario evidence, researched 25 November, does not follow current cohort, vendor, scope or time-window filters.
- No change to study counts, current-query JSON/CSV exports, schemas or selection contracts.
- No source activation, source pin advance, schedules, permissions, secrets or hosted deployment.

## Review focus

- A notice date cannot become a withdrawal action date.
- Nine scenario/policy rows are two date/target pairs, not nine upgrades/devices.
- No match in an incomplete pinned sample cannot become a vendor zero-incident assertion.
- Sources and research links must identify their pinned evidence and remain safe HTTPS links.
- Null/loading comparison state must not make the pinned research appear to be selected live results.

## Task 1: research section, tests and operator note

Files: modify `infrastructure_impact/web/customer-comparison.js`, `tests/test_customer_comparison.js`, `docs/RELEASE_SIGNALS.md`. `web` is the existing package symlink, not a second asset tree.

Interface: existing `InfrastructureCustomerComparison.render(envelope, state)` remains unchanged. Add a private renderer for pinned research examples, reachable both during loading/unavailable state and with a selected envelope. No new backend API or exported data contract.

- [x] Add failing tests that rendered HTML includes “Release reliability evidence”, unavailable vendor rates, pinned sample/filter distinction and human-review status. Run the existing Node suite and observe the missing-section failure.
- [x] Implement the section with primary source links and an immutable commit-pinned research packet/report link. Arista FN0103: public notice dated 1 July 2025 explicitly announces EOS 4.33.3F deferral; action date, replacement and exact model applicability unresolved; no exact frozen target match (targets 4.33.4M/4.33.5M). Cisco FN74221: conditional certificate/configuration remediation, nine annotation rows across two pairs (17.12.3 on 27 March 2024, 17.12.4 on 25 September 2024), not a software-upgrade/withdrawal count. Aruba: historical status unknown, not zero incidents. Keep bugs separate; do not imply 17.9.6 withdrawal verified.
- [x] Test selected-vendor/window cases keep this clearly pinned and independent, and existing JSON/CSV values/selection remain unchanged. Derive consistency assertions from the reviewed packet rather than invent new incident values.
- [x] Add an operator note explaining where the section appears, what the pin means and why current exports do not include the independent research examples.
- [x] Run Node customer-comparison and adjacent reader tests, Python comparison/bootstrap/publication tests, formatting and public-source export checks. Record actual results.
- [x] Fresh whole-branch review; resolve substantive findings, rerun affected checks, commit and open a reviewable PR. Hosted activation remains a later approved operation.

## Execution choices

Reuse the existing isolated worktree and existing reader asset rather than adding another data-delivery system. The tradeoff is that the research example is explicitly pinned and needs a reviewed code update to change. This implements the user's request to make evidence visible; it does not authorize advancing the hosted source pin or changing collection.

## Verification record

The customer-comparison Node regression failed before implementation and passed
afterward. Final integration checks passed: 171 Python tests with three expected
skips for v2-only checks on v1 fixtures, and 13 selected Node results. Formatting and whitespace checks
passed. Fresh review found no P1/P2 issues. Study envelopes and CSV values remain
unchanged after rendering. Hosted source activation was not performed.
