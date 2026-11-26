# Release Reliability Coverage Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans for product code and a fresh whole-branch review. Independent bounded source research may run in parallel.

**Goal:** Expose actionable, evidence-backed coverage gaps without implying missing releases or incidents are zero.
**Architecture:** Derive a small report from the existing validated reliability root. Native and browser exporters share golden parity tests; no persisted schema or publication root changes.
**Tech Stack:** Existing Python, browser JavaScript and CSV helpers; no dependencies.
**Spec:** docs/superpowers/specs/2026-11-26-reliability-coverage-design.md

## Global Constraints

Public official sources only; preserve date semantics, explicit model scope and
source fingerprints/locators/retrieval times. No full documents in Git or customer
strings. Human review pending; no workflow/scheduling/permissions/secrets/default
source activation changes. User's standing request to proceed without approval
loops applies; publication-format activation remains separately gated.

## Review Focus

Per-model date gaps cannot be resolved by another model; duplicate observations
cannot inflate inventory; original evidence can supersede research for the same
model/version; unavailable reports stay unavailable; hostile CSV values remain
spreadsheet-safe and UI text escaped.

### Task 1: Bounded source follow-up

- [x] Read retained Cisco/Aruba/Arista packets before network research.
- [x] Record new eligible facts or explicit access/scope gaps in dated follow-ups;
  verify receipt hashes and keep every proposed classification review-pending.
- [x] Stop at bounded leads; never turn failed discovery into a zero count.

### Task 2: Derived coverage report and exports

Files: new application/reliability_coverage.py and reliability_coverage_cli.py;
web/release-reliability.js, web/app.js; tests/test_reliability_coverage.py and
existing UI parity harness; README and coverage guide.
Interface: build_coverage(report) -> dict; csv_export(coverage) -> str. Browser
coverageReport(report) / coverageCSV(report) return identical data/CSV.

- [x] Add failing tests for per-model unknown dates, original/research precedence,
  unbound/out-of-cohort facts, duplicate inventory, unavailable roots and CSV safety.
- [x] Implement source-referenced per-model gap lists and per-period existing
  metric reasons; preserve report identity. No inferred dates or new rates.
- [x] Add offline export and safe input/output separation. Render a concise
  coverage table/details and JSON/CSV buttons from the accepted generation.
- [x] Prove Python/browser JSON and CSV parity, including pending review and
  escaped unsafe values; run catalogue/reliability/delivery/UI suites and linters.
- [x] Commit the tested deliverable with documentation and a dated run summary.

### Task 3: Smaller analysis delivery

- [ ] Read selection/cohort dependencies and specify an opt-in slice design with
  exact legacy output parity. Implement/test separately once feasibility is clear.
- [ ] Keep hosted activation off; prepare a concrete preview for approval if a
  new publication root is required. Do not change reader capacity limits.
