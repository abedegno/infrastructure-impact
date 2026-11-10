# Retained switching publication preview

The maintainer authorized merging PR54, previewing actual retained bytes, and publishing validated fixes. Routine design questions were waived. PR54 merged as1233ff93e0da27b8b2af8e36913b25caf3739a53.

## Finding and approach

switching_evidence.inputs reconstructs research claims from retained raw evidence during publication.build, which opens the database read-only. Core advisory reparse is unnecessary for these fixes. Avoid creating a replay framework or rewriting unrelated normalizer revisions. The existing target-import certification unnecessarily normalizes174 targets and can fetch missing captures; its current preview is inventory only. Add a default-off retained-publication mode to the existing non-publishing certification workflow, using the same permissions and private restore boundary.

## Contract

Add ops/switching_fix_preview.py. After authenticated restore, inspect only the eight sources in the packaged reviewed-remediation registry, selecting their actual latest retained capture and matching normalized source representation using existing chronology helpers. Compute old/new typed extraction on the same bytes by disabling only new fix helpers for the feature baseline. Compare every affected field except approved remediations and derived IDs. Preserve conditions/platforms/issues/hash/retrieval lineage. Detect absent sources, identity/scope drift, source extraction errors, contradictory/planned evidence and0140 truncation rather than inventing fixes. Emit bounded source identifiers/hashes/times/counts and comparison booleans; never raw text, normalized payloads, paths, exception text or private proof bodies.

Build a full v2 publication once from the unchanged restored database. Freeze the common evaluation time using the existing candidate-worker pattern. Reuse existing audit, physical inventory validation, native parity and default/archive monitor gates, byte budgets and base path. Derive compact full-cohort counts from the validated reader. Hash the database before/after and require equality. This is an offline publication preview: no ingestion, generic reparse, source HTTP, key access in the preview step, recovery promotion, runtime variable change or Pages upload/deployment.

The workflow retains its existing default target-import path. Add optional boolean retained_only default false. In true mode forbid prior-capture input; skip import preview/stage and capture checkpoint/upload. Run the helper after restore with only packaged source config and private temp paths. Sanitizer validates a closed <=65536-byte metadata receipt before embedding it in existing candidate-certification-result. Failure receipts use closed local codes; existing raw logs stay private. Keep template/installed workflow byte-identical. Permissions, schedule and existing default behavior stay unchanged.

After preview code is tested/reviewed and merged, dispatch retained_only against its exact source commit. Read only candidate-certification-result locally. Once passing source proofs/counts/full-candidate gates are reviewed and no collector is active, activate that tested pin and dispatch ordinary collection with reparse_limit0. Verify the resulting public generation, affected counts, source errors, fix history and exports. No additional semantic feature or model applicability work is part of this rollout.
