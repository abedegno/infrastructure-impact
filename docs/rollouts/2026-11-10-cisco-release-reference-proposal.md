# Proposed activation: Cisco 17.12.1 release reference

Status: **prepared, not activated**. This is separate from the reporting/parser PR.
No hosted configuration, schedule, workflow permission or runtime pin has changed.

## Exact change

After merging and accepting the reviewed parser revision, change only the existing
reference-source entry in the hosted public source configuration:

```json
{
  "source_id": "cisco-iosxe-17-12-1-release",
  "url": "https://www.cisco.com/c/en/us/support/ios-nx-os-software/ios-xe-dublin-17-12-1/model.html",
  "enabled": true
}
```

The current entry has `enabled: false`. Use the existing runtime-pin/candidate
procedure if accepting new parser code requires it; do not point the hosted
collector at an unreviewed branch. Preserve every unrelated source and setting.
This proposal does not itself approve the pin update or source activation.

## Evidence and expected result

The 10 November anonymous response is HTTP 200, 120,943 bytes, SHA-256
`2f6c9f50a4dededb423e5ba80a4873e194310499d7911b7b34f22d8aded79ba6`.
The actual owned software metadata reports Release Date `28-JUL-2023` for
IOS XE Dublin 17.12.1. The repaired adapter retains it as `2023-07-28` with
the explicit software metadata locator. It rejects lifecycle, hardware and
unowned documentation dates. See the
[source-layout evidence](../research/cisco-release-evidence.md).

Acceptance should show the existing source as enabled and retained and the literal
17.12.1 date in release context. A different current source revision must pass the
same parser and evidence checks; the cached hash is evidence, not permission to
accept arbitrary changed content. An access failure remains visible. No retries,
rate limits, archive capacity or scheduling changes are proposed.

The source supplies one reported release date. It does not establish the complete
Cisco release history, affected switch models, patch availability for a specific
CVE, fix delay, or the number of customer upgrades. Affected-CVE and remediation
publication totals must remain unchanged by this contextual input.

## Verification and rollback

Use the existing retained-reference writer and candidate/export checks. Check
generation-bound customer JSON/CSV, selected-source URL/hash/retrieval provenance,
unchanged study counts and preserved missing-data caveats. Publish only through
the existing approved pipeline and check its ordinary health result. If the source
is unavailable or fails validation, leave the failure visible and disable this
entry again; retain capture/revision history rather than delete it. This rollback
does not require a schedule or permissions change.
