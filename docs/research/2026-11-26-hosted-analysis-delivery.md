# Hosted analysis delivery wiring and activation proposal

The installed `campus-switching-common-views-v1` profile prepares eight selected
views: All, Cisco, Aruba and Arista, each for all years and the fixed year 2025.
This is delivery configuration; it neither changes the scientific input nor
silently enables switching analysis. See the [operator guide](../HOSTED_SERVICE.md)
for invocation and compatibility handling.

## Verification boundary

The profile resource is SHA-256 pinned to
`79de64408c9df10cebeee363422784940e5288073d14dc0f7925e9b1d5e10dfc`.
Its normalized options match the independent eight-view receipt from the
[previous public-data verification](2026-11-26-analysis-worker-verification.md).
That run proved complete native regeneration, exact browser JSON and both CSV
downloads, and a 940,258,473-byte site. Keeping every accepted older artifact path
would total 941,172,658 bytes, under the existing 1,000,000,000-byte budget.
These are measurements of that pinned input, not a guarantee for future data.

This change adds operator routing and installed-profile verification. It does not
change the scientific reducer, transport format or browser worker. Repeating the
large publication and browser benchmark would not test the new boundaries more
closely than a small actual operator rehearsal. The new rehearsal uses authored
synthetic advisories in a local database, the real snapshot CLI, and fresh native
queries. The fixture clock is fixed, as in the existing isolated worker, and
selected versus compiled reports are compared within one publication identity.
The [rehearsal receipt](2026-11-26-hosted-analysis-delivery.json) records successful
selected/default CLI builds (1.388/1.240 seconds on the synthetic fixture), fresh
native verification (0.873 seconds), eight exact same-generation reducer matches,
and rejection of missing/unexpected roots and invalid configuration before any
state directory is created. These times are fixture timings, not production
performance claims. No vendor requests, private evidence or live collection were used.

A separate real CLI run then cleared the selector while reusing the selected
output directory. It removed 171 obsolete files, left 266 current files, and
passed exact physical inventory, capacity and fresh native verification. Managed
contents are staged and refreshed without replacing the destination directory,
preserving held working directories and mounted outputs. Modified or unmanaged
destinations are rejected safely rather than overlaid. The covering
snapshot/hosted/architecture regression run passed 139 tests and 12 subtests
after the directory-identity fix. The earlier 14-module
profile/operator regression run passed 536 tests.

The profile never establishes release-denominator completeness or vendor quality.
Existing unknowns and independent human review pending remain unchanged. The
previous cold-time regression and low-memory/browser limitations still apply.

Existing nonempty exports must match a retained local generation. Use a fresh
output directory if that prior generation is unavailable or the export was
modified. Refresh needs temporary space on the output filesystem; forced
termination can leave scratch data for recovery. Readers of the export directory
may observe a transition between manifests. The separately served generation
and its atomic `current` pointer retain their existing behavior. Mounted-output
coverage uses a simulated mount plus real held-directory and `--output .` checks;
no privileged mount or live deployment was performed.

## Proposed activation, not applied

Read-only settings captured on 26 November 2026:

| Setting | Current | Proposed after approval |
| --- | --- | --- |
| `IMPACT_SOURCE_COMMIT` | `26ccaef234bfe07d3cf5efd47d0cfe2b94616385` | Exact reviewed merge commit containing this wiring |
| `IMPACT_PUBLICATION_FORMAT` | `v2` | `v2` |
| `IMPACT_SWITCHING_ANALYSIS_PROFILE` | `campus-switching-openvuln-2026-11-14-v1` | Unchanged |
| `IMPACT_ANALYSIS_DELIVERY_PROFILE` | Absent | `campus-switching-common-views-v1` |

The proposed source pin must be resolved to the exact merged commit and verified
against the tested tree before application. The older pin lacks this selector;
do not set the delivery variable alone. The workflow checks helper capability
before the private collector and rejects incompatible selections.

After separate approval, apply the reviewed source pin and delivery variable,
then run one ordinary collection/publication. Accept only a successful isolated
verification, exactly eight advertised choices, intact existing roots and exports,
and a site within the unchanged capacity limits. Check the deployed immutable
worker and selected downloads against that newly published generation. A failed
candidate must not replace the accepted publication.

Rollback disables the delivery variable (remove it or set it blank), returning
future publications to the ordinary path. Restoring the captured source pin is a
separate runtime rollback if needed. Existing accepted immutable generations are
retained; disabling a selector does not rewrite them. No repository variables,
source pin, schedules, secrets, workflow permissions or dispatches were changed
while preparing this proposal.
