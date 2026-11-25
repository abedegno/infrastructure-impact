# Release Reliability Catalogue Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development for independent vendor investigations and a fresh final review; implement the shared interfaces together.

**Goal:** Deliver round 4 steps 1–4 with reusable catalogue tooling and honest coverage.
**Architecture:** Independent optional catalogue alongside release signals; source receipts distinguish original evidence from research excerpts. Three vendor research packets feed an explicit offline build; no hosted activation.
**Tech Stack:** Existing Python, JSON Schema, pytest; existing HTML and version utilities.
**Spec:** `docs/superpowers/specs/2026-11-25-release-reliability-catalogue-design.md` and the user's round 4 request.

## Global Constraints

- Public anonymous primary sources only; no access/challenge bypass or mirrors.
- Cache raw captures outside Git. Store extracted facts, links and fingerprints.
- Release, notice and action dates are separate; missing evidence is unknown.
- Scope comes from document statements; no customer data or names.
- Human review pending; counts describe disclosure and collection, not vendor quality.
- Stop after steps 1–4. No hosted changes or rates/staircase/site publication.

## Review Focus

- Excerpt and denied-response hashes must never impersonate original documents.
- Announcements/revisions must not turn into release or publisher-action dates.
- Model scopes and repeated versions must not inflate release denominators.
- Suffix/F-M transitions and missing dates must not create spurious respin pairs.
- Partial source enumeration and future intervals must never be marked complete.

## Tasks

- [x] Vendor research: independently inspect Cisco, Aruba and Arista primary sources and policies; cache outside Git; write dated JSON/Markdown packets containing quoted facts, locators, original/excerpt hashes and access/coverage outcomes. Record 17.9.6 and Aruba-source findings explicitly.
- [x] Shared catalogue: failing tests first for provenance, date separation, config/train binding, completeness, duplicate/conflicting dates, unknown dates and respin bases. Add strict optional schema, train configuration, source readers and offline CLI following existing patterns. Run focused tests and commit.
- [x] Build: validate research facts, retain research-only exclusions, generate first-delivery catalogue and summary with per-train/year observed counts and coverage, respins, notices and status statements. Never include research-only rows in production counts. Test real packets and commit facts/docs.
- [x] Review: fresh whole-diff review; resolve substantive findings, run release-signal adjacent checks, lint/format and absence-of-raw-data checks. Record findings and stop for user approval before steps 5–8.

## Rulings

Existing autonomous execution opt-out applies: no repeated design-approval loop.
Existing isolated worktree is reused on `feature/release-reliability-catalogue`.
Anonymous collection that is blocked or lacks automation permission remains
unavailable, rather than invoking a browser/login or treating missing results as zero.

## Completion record

First delivery complete with partial coverage and unknown denominators. Thirty new focused tests and 106 including adjacent release-signal tests passed; 47 external cached public captures/excerpts independently rehashed. Core and whole-packet reviews approved after regression fixes. No hosted activation, metrics/rates, staircase/UI or publication changes. See `docs/research/2026-11-25-round4-first-delivery.md`.

## Approved targeted coverage follow-up

The user approved a bounded additional source pass before steps 5–8. It found
eight official Cisco ISSU release-date references scoped outside Catalyst
9200/9300 and one Arista train-level initial date. No target-model dated rows
were promoted; Aruba navigation gaps remain. Three portable, fingerprinted
research supplements and a consolidated report were added. The 107 relevant
tests and public export checks (901 files) passed; 33 new/reused cached public
captures and excerpts were independently rehashed. Rates, site, collection and
publication remain unchanged. See `docs/research/2026-11-25-round4-coverage-pass.md`.
