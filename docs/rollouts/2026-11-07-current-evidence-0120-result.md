# v0.12.0 hosted result — 7 November 2026

Status: **exact-target apply and Pages deployment completed; workflow acceptance
failed at the post-deployment KEV monitor gate**. This is not an all-green rollout.
No second apply, automatic rollback or weakened validation was performed.

## Authorized operation

The maintainer separately approved source publication, runtime-pin activation,
hosted read-only preview and one fingerprint-bound apply. Released source:
`d4d9b044ab2c8053f059fe75a304ced6be72b6e2` (v0.12.0).

[Preview run 42355416001](https://github.com/abedegno/infrastructure-impact/actions/runs/42355416001)
succeeded with no Pages or recovery writes. It found the exact legacy target,
one existing SA-0099 record and no SA-0103 HTML record. Its one issue was
`missing_primary_record` for SA-0103 HTML. The approved hosted fingerprint was:

```text
d2703a8ba24a6c106f8626e658ea861bc87c47b36d0b5d4eaaaaf1812b0b91cd
```

[Apply run 42356040768](https://github.com/abedegno/infrastructure-impact/actions/runs/42356040768)
used that fingerprint and the exact three-URL profile, with replay disabled.
The schema-validated core receipt reports `completed`, two imports, zero unchanged,
two successful primary results and the expected CSAF scope conflict. It reports
one exclusion decision, no unresolved policy issues, and no benchmark acquisition.
The hosted outcome is deliberately `partial` for the expected alternate conflict.
Audit, authenticated recovery backup/readback, retention and Pages deployment passed.

## Published evidence

Generation: `5f02de1195954639a6abb4731af8db96`.

| Measure | Before | After |
| --- | ---: | ---: |
| Current advisory identities | 966 | 966 |
| Labelled excluded latest identities | Not available on the old generation | 1 |
| Total latest identities | 966 | 967 |
| Retained source captures | 4,762 | 4,764 |

The old CSAF record remains literal CVE-2023-5501, revision 4650, source hash
`3491af5ed3486c8e74fd04cd432a5072bf0938733cd059d9d24e7f3f2355ef74`,
with historical CVSS 3.1=6.5. It is excluded from current claims and available in
labelled retained views. SA-0099 now names CVE-2024-27890/27892 separately;
SA-0103 HTML names CVE-2024-6858. These capture/normalization observations do not
establish publisher disclosure or fix dates, unaffectedness or CVE aliases.

The public compressed snapshot was downloaded and its compressed and expanded
hashes matched the deployed manifest within existing archive limits. This did
not download the private recovery vault or key. Original private database rows
were not independently exported for a row-by-row audit; append-only implementation,
automated preservation tests, completed audit and retained public identity provide
the stated evidence. Human extraction review remains pending.

## Failed gate and correction

The final health check failed with `KEV selection differs from publication scope`.
The published KEV scope includes CVE-2023-5501 for its retained record; the monitor
compared against current plus benchmark CVEs, omitting exactly that historical-only
CVE. The corrected local monitor accepts the same actual generation, with all
original strict checks and archive verification intact. This is a monitor scope
mismatch, not a reason to discard the retained KEV context or repeat acquisition.

The [v0.12.1 candidate](../releases/0.12.1.md) adds regression coverage and derives
scope from validated retained wrappers. Its source publication and runtime pin
need separate approval. The original failed run stays failed; no diagnostic has
been relabelled as successful. Until activation, the pinned old monitor can report
this same failure. A source pin change does not undo the deployed generation.
