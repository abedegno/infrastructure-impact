# Bounded Table Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce v2 table transfer below the existing monitor budget without changing logical data or skipping checks.
**Architecture:** Optional content-addressed gzip table sidecars; preserve raw descriptors/assets and archive scope. Bound and verify both representations.
**Tech Stack:** Existing Python stdlib gzip/hashlib, schemas, browser DecompressionStream; no new dependencies.
**Spec:** ../specs/2026-11-08-table-transport-design.md

## Global Constraints

- Preserve 32 MB v2 / 20 MB v1 monitor transfer, 8 MB parts, all existing validation and archive gates.
- No scheduling, hosted permissions, live source activation or public promotion.
- Public/synthetic inputs only locally; no actual vault, key, ciphertext or private logs downloaded.
- Optional catalog map; old catalogs/raw assets remain supported; archive logical scope unchanged.
- Bounds, hash checks and cancellation apply before exposing decoded bytes.

## Review Focus

- Compression bombs, truncated streams and wrong length/hash must reject.
- Unknown/non-table mapping keys and unbound compressed files must reject.
- Failed declared transport must not silently fall back to unchecked bytes.
- Unsupported browser decompression must retain verified raw compatibility.
- Transfer accounting must count encoded bytes and keep decoded/cache limits.

## Tasks

- [x] 1. Core producer/contract: tests first; optional schema map and codec helpers; deterministic writer sidecars; physical inspection; regenerate browser contracts. Own publication_codec.py, application/publication_v2.py, publication-v2.json, generated switching-contracts.js, new tests/test_table_transport.py. Review and commit.
- [x] 2. Standalone monitor: tests first for compressed actual read accounting and all rejected integrity/overflow variants; wire codec helpers into checks/switching_health.py; retain old catalog behavior. Own that module and new tests/test_table_transport_monitor.py. Review and commit.
- [x] 3. Browser: tests first for bounded hashed decompression, legacy fallback and failures/cancellation; optional map in publication-v2.js raw table fetches. Own that module and new tests/test_table_transport.js. Review and commit.
- [ ] 4. Integration: all suites, built wheel/installed v2 checks, frozen public sample replay, fresh independent whole-branch review, then cached full hosted certification. Record exact results and retain draft until passing. No activation.
