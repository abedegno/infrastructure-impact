# Critical architecture review — 8 November 2026

The project has useful evidence foundations, but acquisition, acceptance and publication are coupled too tightly. Repeated evidence representations and an elaborate delivery format then make validation expensive. Increasing runner capacity is not yet an evidence-backed remedy.

This review covers the current ingestion, publication, browser and CI code, the saved retained-scale publication, and the two hosted rollout failures. Three independent read-only reviews covered ingestion, publication and operations. Findings below distinguish reproduced behavior from hypotheses. Implementation and deployment attempts were paused for this review. Existing uncommitted diagnostic and root-verification experiments remain unmerged.

## Findings, in priority order

### 1. Successful acquisition is discarded when later validation fails — high

`ops/target_import_job.py:35–83` creates a temporary stage, requires a completed candidate, and only then saves a verified private backup. `application/target_import_stage.py` imports into a copied database. The transport's cache and raw evidence writes therefore live in that disposable stage.

Hosted retry [42465490495](https://github.com/abedegno/infrastructure-impact/actions/runs/42465490495) fetched and normalized all 174 pinned targets: 174 HTTP attempts and 32,176,699 received bytes. Candidate validation failed, and the newly acquired evidence was not promoted or checkpointed. The next attempt cannot reuse these successful acquisitions from that failed run.

**Remedy:** retain an encrypted, explicitly unaccepted acquisition checkpoint independently of the accepted database and public generation. Preserve source URL, capture time, content hash, HTTP validators and retrieval results. Candidate failure must prevent publication without erasing successful acquisition. Corrupt or mismatched captures must remain quarantined.

**Acceptance:** terminate a candidate after acquisition; a resumed exact-target run makes zero body downloads for matching retained captures, while the accepted public pointer remains unchanged until certification succeeds.

### 2. Cache behavior does not mean “download once” — high

`collection/transport.py:63–102` looks up cached validators but still opens an HTTP request. A retained body is reused after a 304 response; this is conditional refresh, not an offline cache-first replay. Exact-target staging fetches and normalizes each target. Unchanged ingestion is detected after parsing.

**Remedy:** separate refresh from replay. A pinned import should first use a retained capture matching the required hash. Refresh should use conditional HTTP and retain its own observation time. Cache normalized output by content hash, normalizer fingerprint and relevant schema/configuration identity. Never describe an old capture as freshly fetched. Existing offline retained-evidence facilities should be reused where their contracts fit.

### 3. The actual browser startup path fails on the saved v2 dataset — high

`web/app.js:174–209` initially requests state without selected CVEs; it learns the benchmark selection only from the response. `web/snapshot.js:867–874` expands an unspecified selection to all imported CVEs. `web/delivery.js:246–262` then materializes the complete snapshot with a 128,000,000-byte limit.

The saved v2 snapshot has 460 CVEs and 129,567,696 logical bytes. Replaying that whole-cohort loader rejected it with `Publication v2: selected byte budget` after five requests. This is a loader reproduction plus inspection of the application call chain, not a live browser deployment test. V2 has not been successfully published.

The earlier paging performance harness exercised the loader directly; it did not exercise this complete application startup sequence. Its good paging results did not establish that users could open the application.

**Remedy:** bootstrap small catalogue/benchmark metadata, then request the selected view. Keep complete exports explicit. Preserve the native API's documented full-scope default; fix the client bootstrap rather than silently changing that API contract.

**Acceptance:** a real browser opens the representative retained dataset, renders the default view and navigates details without first materializing the complete archive. Record transferred bytes, time and errors.

### 4. Publication repeatedly represents the same evidence — high

`application/publication.py:628` builds source contexts and its following CVE/product loop repeats contextual facts. `application/publication_v2.py:483–510` exposes overlapping snapshot, evidence and comparison roots; the runtime root adds another records representation at approximately line 568. Comparison construction also copies and walks evidence structures.

For the saved 223-identity sample, the writer produced 249 logical roots totaling approximately 1.00 GB of expanded JSON, while physical output was approximately 465 MB across 2,214 files. These are different measures: aliases contribute to logical expansion, so this is not a claim of a 1 GB network download. The evidence root expands to approximately 365 MB and the comparison root to approximately 387 MB. There are 91,393 claims, 91,441 diagnostics and 35,357 source entries. Some distinct locators are legitimate evidence; counts alone do not prove every entry is redundant.

**Remedy:** store source documents, locators, remediation facts and publication identities once, with references from assessments and comparison membership. Produce small materialized summaries and paged details. Measure repeated bytes and CPU before and after. Do not delete legitimate provenance to reduce size.

### 5. Full-state copying and verification are repeated too broadly — medium/high

Preview and staging use full database checkpoint copies (`application/target_import.py:129`, `storage/checkpoint_copy.py:45–60`, `application/target_import_stage.py:351–357`). Staging repeatedly hashes the baseline file and scans retained rows/raw bodies through `_file_state`, `_retained_rows` and preservation checks. Publication also clones full JSON structures and reconstructs overlapping projections for verification.

These checks defend real properties, but the transaction boundary makes a small import pay repeatedly for unchanged history. We have not measured the individual hosted costs, so their exact ranking remains unknown.

**Remedy:** take one immutable authenticated baseline, record the import delta, and reuse established unchanged-baseline proofs where equivalent. Retain full audits for unfamiliar snapshots, representation changes and periodic certification. Preserve race detection and independent semantic parity; do not merely remove checks until jobs pass.

### 6. Failure reporting is inadequate for expensive work — high

The deployed candidate worker reports `worker_failed` for multiple termination modes and keeps details in a temporary private log. The approximately 44-minute retry therefore does not establish whether the worker timed out, exited nonzero, exhausted memory or failed elsewhere. There is no basis yet to blame GitHub runner CPU or RAM, or to describe the complete duration as download time.

The earlier run [42462098050](https://github.com/abedegno/infrastructure-impact/actions/runs/42462098050) did have a proven orchestration defect: the outer job allowed 40 minutes while the child alone could consume 40 minutes, excluding setup and acquisition. The outer allowance was subsequently increased to 60 minutes. That fixed one defect, not the later validation failure.

**Remedy:** bounded, sanitized phase events; explicit timeout/nonzero/launch outcomes; per-phase elapsed and CPU time, peak memory, cache hits, document counts and byte counts. Retain private diagnostic outcomes independently of candidate promotion. The unmerged diagnostic experiment begins this work but is not deployed proof.

### 7. Delivery complexity and optimization priorities need reconsideration — medium

V2 introduces a custom codec, Python and browser readers, logical roots, aliases, ranges and streaming integrity machinery. This is substantial code to maintain alongside the domain logic. Its complexity should be justified against a simpler baseline: immutable ordinary JSON shards, compact indexes/precomputed views, and a standard compressed bulk export.

The [decision record](2026-11-07-publication-v2-decisions.md) explicitly acknowledges that the former 20 MB download target was our operational target, not a GitHub requirement. Work around that target distracted from coverage and import correctness. Hard hosting limits, security bounds and desired product performance must be documented separately.

The latest root-hashing experiment reduced CPU from 232.33 to 224.29 seconds, approximately 3.46%, in one isolated verification phase. Wall time changed from 607.18 to 537.46 seconds but is sensitive to competing work. This is a minor improvement, not evidence that it solves the hosted failure. Optimizing it before identifying the failing phase was poor prioritization.

**Remedy:** first remove data duplication and unnecessary full-archive work. Benchmark a simple delivery alternative before extending or replacing the codec. Preserve integrity and bounded reads in either design.

### 8. Validation effort is not sufficiently aligned with product risk — medium

`.github/workflows/ci.yaml` runs on both push and pull request. Both Python matrix jobs also run version-independent frontend checks and packaging work. This can duplicate work for the same PR head. Meanwhile, loader-level performance tests missed the actual startup path, and a successful 1,453-second local candidate used a 223-identity sample rather than the complete hosted database.

Passing unit tests, a sampled replay and full hosted acceptance establish different things. Earlier progress reporting did not keep those distinctions prominent enough. More passing checks did not compensate for missing representative operational evidence.

**Remedy:** run Python compatibility tests in the Python matrix; run frontend and shared packaging checks once. Use change-aware CI while preserving required checks. Add real application startup and representative full-hosted certification. Retain extraction quality and pending human review as visible limitations. Changes to hosted schedules, publication behavior or permissions remain subject to the user's existing approval constraint.

## Simpler target architecture

1. **Durable captures:** content-addressed official-source bytes and retrieval observations, encrypted where required; resumable independently of acceptance.
2. **Versioned normalized facts:** incremental SQLite processing keyed by capture and parser identity; provenance and revision history retained.
3. **Compact views:** shared evidence references, precomputed comparison summaries, paged details and an explicit compressed full export.
4. **Certification and promotion:** validate a reproducible artifact against an immutable baseline, retain rejection diagnostics, then atomically publish that same certified artifact.

Python, SQLite and the existing static hosting can support this structure. This review does not justify new microservices, a queue platform or a larger runner.

## Recommended implementation order

1. Fix actual browser bootstrap and add the representative startup test. Finish bounded failure diagnostics.
2. Make acquisition durable and exact-target replay cache-first; prove restart behavior without publication.
3. Measure a nonpublishing full-hosted certification from retained captures, with phase and resource metrics.
4. Normalize repeated evidence contexts and simplify projections; compare ordinary JSON shards with the current codec using the same semantics and dataset.
5. Reduce redundant baseline work and CI duplication using those measurements. Publish only the artifact that passed full certification.

Keep the advisory schema, pluggable vendor adapters, primary-source provenance, explicit unknown affectedness, normalizer fingerprints, revision history, verified private recovery and atomic accepted-generation pointer. The publication gates correctly protected the live site during both failures. The main correction is to make rejected work diagnosable and reusable, and make the data model cheaper to deliver—not to weaken those guarantees.

No further deployment was attempted during this review. The precise later worker failure, hosted peak memory and achievable simplification savings remain unproven.
