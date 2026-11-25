# Remote recovery archive budget fix

> Use subagent-driven-development for implementation and a fresh scoped review.

**Goal:** Unblock the approved reader deployment after the ordinary hosted writer fails when Fernet ciphertext exceeds the legacy 50 MiB archive cap.

**Evidence:** Scheduled run 45503731891 fails at ops/hosted_job.py:238 with “Encrypted backup exceeds repository storage budget”; the failure predates the reader release. Active recovery storage is github-draft, expanded-vault profile extended (2 GiB). Git-embedded archives still need the existing 50 MiB bound; draft assets are a different transport.

**Architecture:** Keep ARCHIVE_LIMIT=50 MiB for Git/default callers. Add a shared REMOTE_ARCHIVE_LIMIT=512 MiB for managed encrypted draft assets. Pass the remote bound explicitly through backup, restore, ciphertext validation and remote readback paths. Remote transport pointer/upload/download and read-only storage accounting use the same remote constant. Manifests do not enlarge caller-selected limits. XZ memory (64 MiB), expanded SQLite profiles (up to 2 GiB), encrypted-only state, integrity checks, atomic restore, draft visibility, repository-origin/token redirect checks and legacy Git history are unchanged.

**Files:** recovery_policy.py; storage/remote_recovery.py; ops/hosted_job.py; checks/backup_storage.py; capacity/backup/remote recovery tests; current operator capacity/recovery docs. No workflow/schedule/permission/secret changes.

- [x] Write regression tests: remote encrypted archive larger than legacy bound accepted under explicit remote budget, Git/default rejects; remote pointer budget and storage monitor agree; oversized remote rejects before unsafe reads; authenticated roundtrip and corruption checks remain enforced. Use small monkeypatched/scaled synthetic budgets or sparse/stat fixtures rather than large real payloads. Observe failure before implementation.
- [x] Implement explicit backend-specific shared budgets, including every remote staging/readback/restore/verification call. Preserve existing signatures with optional private keyword parameters if needed. Existing low-budget monkeypatch tests must remain meaningful.
- [x] Update current capacity/recovery/operator docs and rollback guidance: after a >50 MiB remote checkpoint, old 50 MiB helpers cannot restore it; retain a remote-budget-capable helper when rolling back reader changes. Do not rewrite historical measurements.
- [ ] Run focused capacity, hosted backup, remote recovery, maintenance and private VulnCheck job tests, plus lint and public-source export checks. Fresh review, resolve substantive findings and PR.
- [ ] After CI, merge the necessary deployment fix, advance the hosted source pin to the tested merged commit, run normal collection/publication, and verify recovery/readback, Pages health and the exact live customer-comparison asset/content. Previous source pin stays recorded. No repinning to an incompatible old helper after accepting a large checkpoint.

## Authorization

User explicitly requested “Merge and deploy” and previously asked to increase self-imposed limits. This reversible recovery fix is necessary for that deployment; no new access or relaxed encryption checks are authorized. Do not expose private source bodies, tokens, keys or encrypted asset contents in model/tool output.

## Verification before CI

Fresh focused/integration run: 286 tests passed with loopback enabled. This
includes capacity, backup, remote recovery, maintenance, hosted protocol, private
VulnCheck job and target-import checks. Fresh scoped review found no P1/P2 issue.
The change preserves Git50MiB, remote512MiB, XZ64MiB and selected expanded-vault
limits. Peak memory at the full remote ceiling was not benchmarked; the observed
checkpoint was approximately49.5MiB encrypted before the next run exceeded50MiB.
