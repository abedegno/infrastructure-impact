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
refresh applies when the build selects precomputed delivery or when the output
contains evidence of a prior precomputed export. It preserves the destination
directory for held working directories and mounted outputs, authenticates a
nonempty prior export, and rejects modified or unmanaged contents. With blank
delivery and an ordinary output, snapshot overwrites matching paths and leaves
other files in place. The covering
snapshot/hosted/architecture regression run passed 139 tests and 12 subtests
after the directory-identity fix. The earlier 14-module
profile/operator regression run passed 536 tests.

The profile never establishes release-denominator completeness or vendor quality.
Existing unknowns and independent human review pending remain unchanged. The
previous cold-time regression and low-memory/browser limitations still apply.

For managed refresh, a nonempty export must match a retained local generation.
Use a fresh directory if that generation is unavailable or the export was
modified. A named export and a transition from precomputed to blank require
hard links on the output filesystem. Ordinary blank exports can use filesystems
without hard links. Each link exposes a
complete staged file at its final name and fails atomically if that name is
occupied. Refresh tests this capability before retiring prior contents. Use a
hard-link-capable output volume if the check fails. Refresh also needs temporary
space on that filesystem. Forced termination can leave scratch data for recovery.
Readers of the export directory may observe a transition between manifests.
A concurrent edit fails the managed refresh, restores prior entries where safe,
and preserves changed bytes at a reported recovery path. That directory needs operator attention before reuse. The
subsequent install/rollback regression run passed 118 tests and 12 subtests;
these overlapping runs are not additive test totals. The separately served generation
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

The isolated target-import worker has separate fixture evidence. On a staged
synthetic database it checked the caller's selector against the request and
context, rebuilt the publication and verified the selected views against fresh
native queries. The earlier pinned public-data run supplies the browser and
capacity measurements above. Each proof identifies its own input and generation.

After separate approval, apply the reviewed source pin and delivery variable
and run one ordinary collection/publication. Before upload, the helper requires
an `ok` or `partial` collection outcome, completion of the v2 writer's schema
and byte-budget checks (including the 1 GB site limit), a successful audit and
verified encrypted recovery. The workflow requires successful preflight and
the ordinary helper's recovery and publication readiness signals. A successful
artifact upload for the current attempt and the recorded source commit allow
the deploy job to proceed automatically.

After deployment, check the workflow's public availability and freshness result.
Record the served generation ID and catalog hash. For that generation, confirm
the eight advertised choices, existing roots and exports. Verify the immutable
worker against the artifact manifest. Compare the browser JSON and both CSV
downloads with the native exports from that publication's selected reports.
Record the generated site size from the matching artifact against the existing
limit. These observations can identify a problem after Pages has switched.
A failed observation calls for the separately approved rollback below.

Rollback disables the delivery variable (remove it or set it blank), returning
future publications to the ordinary path. Restoring the captured source pin is a
separate runtime rollback if needed. Existing accepted immutable generations are
retained; disabling a selector does not rewrite them. No repository variables,
source pin, schedules, secrets, workflow permissions or dispatches were changed
while preparing this proposal.
