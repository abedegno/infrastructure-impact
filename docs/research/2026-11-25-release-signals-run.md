# Release signals: initial implementation run

Run date: 25 November 2026. Independent human review pending. This is a
bounded public-evidence sample, not a completed three-vendor historical study.

## Results

The standalone CLI imported the retained public Arista software RSS response
retrieved at `2026-11-25T11:33:58.700291+00:00`. Original-response SHA-256:
`a88666706254a2b922e9e76026ea1602109dd5ada5ee624e6e47ed7adc6de7ef`.
No additional network download was needed for this run. Original vendor bytes,
the working dataset and generated JSON/CSV remain outside Git.

| Train        | Dated release observations | Candidate follow-up pairs within 14 / 30 days | Historical completeness                        |
| ------------ | -------------------------- | --------------------------------------------- | ---------------------------------------------- |
| IOS XE 17.12 | 0 imported                 | 0 / 0 observed                                | Not established; sampled origin routes blocked |
| AOS-CX 10.13 | 0 imported                 | 0 / 0 observed                                | Not established; sampled origin route blocked  |
| EOS 4.33     | 2 in 2026                  | 0 / 1 observed                                | Partial rolling RSS window                     |

EOS 4.33.11M was announced on 15 October 2026 and 4.33.11.2M on
3 November: 19 calendar days apart. The reason, model applicability and any
corrective relationship remain unknown. No explicit withdrawal, deferment or
confirmed corrective-respin event was imported. Zero imported observations are
not evidence that a vendor had no such events. No comparable vendor rates are
available; exported withdrawal rates are null.

## Existing staircase linkage

The run used a bounded projection of the previously retained public 14 November
switching analysis: publication `3591f3596d5e41fe8d50ac633b8357e1`.
The input contains rows and their original step target/date/claim IDs, with
publication context and the compressed parent export's fingerprint. It does not
recompute vulnerability affectedness or upgrade totals.

Within the three selected trains and 2024–25 November 2026, the output contains
55 annotation rows across scenarios and policies: 35 for IOS XE 17.12, 16 for
AOS-CX 10.13, and 4 for EOS 4.33. These are **not 55 distinct customer upgrades**.
Neither sampled EOS release matches an existing step target, so all 55 annotations
say that retained signal evidence is missing. They do not say the targets were
safe, never withdrawn or never respun. Device-model applicability also remains
unresolved. The input projection receives its own report fingerprint for replay.

## What is implemented and what remains

Implemented: a separate versioned evidence dataset with revision receipts;
source-specific offline readers for Cisco caveat HTML, an Aruba rendered history
table and Arista release RSS; an explicitly invoked public Arista RSS collector
with an outside-Git raw cache; train/year observed metrics, JSON/CSV, exact-target
annotations, and a standalone local-import research reader.

Formal publisher-action fields are supported by the evidence contract and
analysis, but verified source-specific imports for withdrawals, deferments,
confirmed corrective respins, field notices and recommendations remain deferred.
No suitable accessible primary layout was verified for those imports; arbitrary
statements must not be promoted into publisher actions. Cisco's 17.9.6 withdrawal
is still unverified from an accessible Cisco-authored record. The 17.9.6a fix is
separately verified in the Phase 1 report and remains outside this train cohort.

The Aruba reader supports an explicitly labelled operator-rendered HTML capture
of the reviewed version-history table; it is not a PDF downloader/parser or a
supported unattended portal collector. The Phase 1 web-service excerpts were not
promoted into origin documents. Cisco/HPE automated retrieval barriers and
Arista's login-only detail routes remain limitations. Usage permission must be
settled before source activation where needed.

The new page can be served explicitly by an operator as documented in
[the guide](../RELEASE_SIGNALS.md); it is not added to hosted publication assets.
No schedules, permissions, secrets, source activation or hosted publication
behavior changed. Those remain separately gated.

## Verification

The new Python tests and adjacent release/history/upgrade/source suites passed
341 tests; the reader's ten tests and existing Node suites passed. The actual
CLI-generated sample report was accepted by the reader validator. Original
capture fingerprints and the 19-day interval were checked.

A broad Python run was interrupted after 2,315 passes and 56 failures under the
sandbox. Fifty-four tracebacks showed loopback socket permission errors; two
reported candidate validation failures. Rerunning all three failing integration
files with loopback access allowed passed all 129 tests, including the candidate
validation cases. This is not a claim that the entire Python suite completed.

Independent code review identified revision-cutoff, action deduplication,
coverage-history, hidden-heading ownership and Python/browser validation issues.
The fixes include rolling RSS history retention and regression tests. A scoped
independent re-review found no remaining P1/P2 issue. The same actual CLI sample
was regenerated and accepted by the reader after the fixes.
