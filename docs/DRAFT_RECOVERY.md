# Encrypted draft-asset recovery

The hosted collector can store new encrypted recovery files outside Git history,
using unpublished draft releases in the same repository. This avoids one new
large encrypted Git blob per collection. Existing Git archives and history remain
untouched; no asset is overwritten, published or automatically deleted.

GitHub documents [draft release visibility and API permissions](https://docs.github.com/en/rest/releases/releases)
and [release asset limits](https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases).
A daily managed draft holds up to 1,000 assets. The application retains its stricter
50 MiB encrypted-archive, 512 MiB expanded-vault and 64 MiB XZ-decoder limits.
Drafts are not software releases and must remain unpublished. The recovery key is
still required even for an operator who can access a draft asset.

## Activation

1. Run source CI, including legacy and remote recovery tests.
2. Pin `IMPACT_SOURCE_COMMIT` to the verified full commit containing draft-storage support.
3. Set repository variable `IMPACT_RECOVERY_STORAGE` to `github-draft`.
4. Dispatch collection and inspect its recovery receipt, state manifest and public monitor.

The order matters: older pinned helpers do not recognize the new CLI flags or
remote pointer format. Leaving the variable unset selects compatible `git` mode.
The workflow uses its existing repository-scoped token with `contents: write` and
the existing `IMPACT_STATE_KEY` secret. No personal token, new account or permission
increase is needed. Pull requests do not run the collector.

This applies only to the hosted writer's independently collected public-source
vault. Never seed it by uploading an existing private research vault, captures,
notes, review worksheet or local recovery key. Pages still receives only the
sanitized publication directory.

## Write and recovery protocol

The writer restores either the prior Git archive or the asset named by the
current pointer. Remote pointers contain repository, release/asset IDs, a managed
tag, filename, SHA-256 and size; they cannot supply arbitrary network URLs.
API origins are fixed to GitHub. Download redirects are restricted to approved
GitHub asset hosts and receive no Authorization header. Metadata and downloads
have separate byte budgets. Errors do not print tokens, signed URLs or server
response bodies.

A new backup is compressed and encrypted in private temporary storage outside
the tracked state directory. The writer authenticates it and restores SQLite
locally before upload. It creates or reuses a managed daily draft, uploads a new
uniquely named ciphertext asset without replacement, and checks asset identity,
size and any advertised digest. It then downloads that exact asset, checks its
size and SHA-256, authenticates/decrypts it, bounds decompression and checks SQLite
integrity. Only after successful readback does it atomically update `current.json`
with `storage_backend: github-draft-release-v1` and a verification timestamp.

Upload/readback failures leave the previous pointer and all legacy bytes intact.
An interrupted upload can leave an unreferenced encrypted asset; it is retained
rather than silently deleted. Before committing metadata, the workflow downloads
and authenticates the pointed asset again and authenticates every remaining
legacy Git archive. No new ciphertext or plaintext is staged in the tracked tree.

## Monitoring and rollback

In an approved private recovery environment, set the key and repository token
through the protected environment and restore without collecting or publishing:

```sh
python ops/hosted_job.py --state-dir state --encrypted-state \
  --recovery-repository OWNER/REPO --restore-only /private/recovery/vault.sqlite3
```

The destination must be new and outside the tracked state tree. The helper refuses
to overwrite a file. Point `IMPACT_DATABASE` at the result and run `impact audit`
before using it. Neither the key nor token belongs in command arguments.

The public monitor reads only repository/branch/manifest metadata. It reports
legacy Git storage, the latest archive and raw-vault sizes, and the writer's
remote-readback timestamp. It does not download ciphertext or a key and cannot
independently attest draft access or decryptability. Successful writer readback is
a checkpoint recovery test, not a continuous availability or off-provider
disaster-recovery guarantee. GitHub is still a shared failure domain.

To return to Git storage, keep a draft-capable source pin and set
`IMPACT_RECOVERY_STORAGE=git`. The current helper can restore the remote checkpoint
and create an authenticated local encrypted archive using the existing Git-mode
retention behavior. Verify that checkpoint before rolling back to older code.
For pre-XZ helpers, also select `--backup-compression gzip` in an approved recovery
environment. Retain a protected copy of the key and required archives separately.
Do not publish a managed draft, delete recovery assets or rewrite Git history as
routine cleanup.

The old encrypted Git history is not reclaimed by this change. Its storage warning
can remain visible after new Git blob growth stops. Raw vault and per-archive
limits still require monitoring and an explicit future capacity decision.
