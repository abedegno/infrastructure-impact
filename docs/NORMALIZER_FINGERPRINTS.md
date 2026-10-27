# Normalizer code identities

An advisory's `adapter_version` identifies the normalizer that produced it.
The archive parser-replay mechanism uses the same fingerprint. Code changes can
reinterpret retained bytes; they do not establish that a publisher changed a
document or disclosed a CVE later.

## Scoped built-in plugins

Built-in vendors use `scoped-code-v1`. The fingerprint covers:

- The plugin ID and declared version.
- Python source modules containing all callable plugin hooks.
- Modules containing explicitly declared helper callables, deduplicated by file.
- Shared normalization/finalization code, validation/schema, source policy, and
  the public cohort code/resource used by scoped PDF extraction.

Each source contributes its SHA-256 and a stable module/resource label. Absolute
installation paths are excluded. Dependency ordering and duplicate references do
not affect the result; changing source bytes does. The scheme returns the existing
16-character hexadecimal code identity, so the advisory schema is unchanged.

A Juniper-only Apstra parser edit changes Juniper's identity without changing
Arista's. A shared component-reference module changes Juniper and HPE. Shared
schema, standards or common parsing changes conservatively affect all built-ins.
The code is tracked at module granularity, not individual function semantics.

CLI plugin listings and publication plugin metadata expose
`normalizer_fingerprint_scheme` and `current_normalizer_fingerprint`. The latter
describes the installed plugin. Older retained records keep their original
`adapter_version`; publishing a new plugin does not silently reprocess all history.

## External plugin compatibility

`VendorPlugin.normalizer_dependencies` defaults to `None`. Those plugins keep the
exact prior `legacy-package-v1` calculation, including the package-wide adapter
version. Existing installed extensions need no change.

A trusted installed plugin can opt in with a tuple:

```python
VendorPlugin(
    "example", "Example", ("example.invalid",), parse_document,
    normalizer_dependencies=(parse_product_rows, parse_version_ranges),
)
```

An empty tuple opts into automatic hook/shared-source tracking without additional
helpers. Dependencies must be inspectable Python callables whose modules are
available in the installation. Invalid or unavailable declarations fail during
registration. Feeds and source configuration cannot nominate import paths or
load code through this field.

Declare indirect helper modules too. Source files alone do not attest runtime
libraries, dynamically loaded data or deployment configuration. Bump the plugin
version when such changes affect normalization. Deploy immutable source and
restart the writer after changing code; this is not a live-code reload mechanism.

## Transition and verification

Switching a built-in from the prior scheme changes its identity once. Retained
evidence, original capture times and earlier revisions remain intact. A metadata-
only identity change creates a new normalization revision, not a publisher-change
event. Real assessment changes from the new parser remain parser reinterpretations.

Unsupported captures may be replayed once under the new identity, within the
existing archive budget. HTTP failures remain ineligible for parser replay.
Subsequent unrelated vendor edits no longer spend that vendor's replay budget.

[Explicit normalization maintenance](NORMALIZATION_MAINTENANCE.md) can preview and
refresh latest retained advisories in bounded batches. It is separate from the
archive queue's retry mechanism and preserves unsupported records and capture times.

Tests cover vendor/shared-module changes, unchanged scoped identities when the
legacy package hash changes, duplicate/order handling, module relocation, schema
and cohort-resource changes, rejected declarations and legacy extension behavior.
An import-coverage check ensures the built-in adapter/shared-helper imports are
declared; maintainers must still review dynamic and external dependencies.
The installed-wheel check compares all built-in fingerprints with the source
checkout while exercising a separately installed legacy ninth vendor. Source
path overrides are removed from that probe's environment.
