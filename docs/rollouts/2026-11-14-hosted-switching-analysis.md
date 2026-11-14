# Explicit hosted switching analysis

Hosted analysis is off by default. The only supported selector is
`campus-switching-openvuln-2026-11-14-v1`; it requires publication format `v2`.
The installed public resource has SHA-256
`e8cc5e131c3c2bd835185795357044f427ec9c796f708a98eb652f9831289356`
and 59 API frames. No file, URL, credential or arbitrary JSON input is accepted
by the hosted selector.

Both manual workflows accept `switching_analysis_profile`, default empty. Blank
uses repository variable `IMPACT_SWITCHING_ANALYSIS_PROFILE`, also default empty.
Collection checks the pinned helper's capability before invoking a selected run.
Certification validates the installed stage capability before recovery. Recovery-only
and retained-only requests reject selection. A maintenance preview validates the
profile configuration but does not build or simulate analysis.

`impact target-import stage --switching-analysis-profile <selector>
--publication-format v2` carries only the profile ID, digest and frame count into
the private context and fresh worker request. The isolated build reloads the
installed input. Independent native parity separately reloads it into freshly
queried native research before projecting the expected roots. All existing native
root, monitor, preservation, capacity and recovery gates remain required. Ordinary
collection and maintenance publication carry the selected input too. Empty
selection retains the previous build arguments, receipt versions and outputs.

Selected successful full certification validates the completed stage receipt and
its public generation/manifest digest before exposing either public artifact:

- `candidate-certification-public`: only the fixed `private-stage/public` tree.
- `candidate-certification-analysis-proof`: only `public-analysis-proof`, containing
  `selected-analysis.json`, `proof.json` and `attestation.json`.

The proof contains the full typed public-reader selection, its UTF-8 byte count and
SHA-256, and exact UTF-8 counts/hashes for both analysis and upgrades CSV exports.
JSON is written incrementally under the existing selected-output bound. The
attestation binds source commit, profile identity, generation, manifest digest and
validated stage checks. A proof requires a selected Cisco IOS XE publisher-first-fixed
target with its referenced owned `openvuln_api` proof matching the pinned profile’s receipt, locator, advisory/CVE and fixed target; unresolved metadata alone
cannot satisfy acceptance. No private context, database, recovery key or worker log
is uploaded. Default certification continues to emit its existing artifacts only.

For an already accepted public candidate, reproduce the reference with:

```sh
python -m checks.switching_analysis_acceptance \
  --publication PUBLIC_CANDIDATE \
  --profile campus-switching-openvuln-2026-11-14-v1 \
  --output NEW_PROOF_DIRECTORY
```

Run full trusted certification at the reviewed source before activating the runtime
pin and persistent profile variable. Verify browser selection, the complete selected
JSON and both CSV hashes against these public artifacts, including default lazy
loading. Use the existing accepted preview/apply path and encrypted recovery
readback before Pages readiness. Do not rebuild after candidate proof.

The complete hosted database remains authoritative. This bridge does not establish
Arista chronology or SA137 readiness, change ownership rules, infer no-fix from an
empty API result, or replace the baseline with a partial local dataset. Coverage,
full-state headroom and actual owned API matches require the trusted hosted run.
Human review remains pending.
