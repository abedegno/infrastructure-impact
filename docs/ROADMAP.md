# Roadmap

Infrastructure Impact is an early-stage, single-host application. This is a list of
priorities, not delivery commitments or claims of complete vendor coverage.

## Implemented foundation

- Eight bundled vendor plugins and external Python entry-point discovery.
- Schema v2 with semantic validation, provenance and source revision history.
- Coverage-aware cohort comparisons and disclosure research review workflows.
- Immutable publication, read-only API, dashboard, Docker/Compose and backup tooling.
- Offline synthetic regression tests and installed-wheel extension checks.
- Resumable historical document queues, advertised pagination and explicit coverage progress; Aruba CSAF index enabled first.

## Coverage and deployment expansion

The source now includes a coverage catalogue, a 24-CVE benchmark, declared primary-source mapping evaluations, release-note revision history and stricter availability review gates. A scheduled collector publishes the public static dashboard, with authenticated encrypted recovery copies and freshness monitoring. See the corresponding guides for current limits.

## Next priorities

- Continue expanding vendor/product families and historical collection; publish source-specific
  coverage and freshness expectations rather than a blanket supported-vendor claim.
- Add vendor parser regression cases from reviewed layouts, with redistributable
  synthetic fixtures and explicit unresolved states.
- Validate independent release availability and product/CVE linkage for timing leads.
- Run a maintained public service with monitoring, retention and recovery practice.
- Establish a reviewed dataset redistribution policy and versioned releases.

## Capabilities requiring separate design

Full CSAF conformance/signature validation, firmware/SBOM dependency mapping,
vendor-specific version evaluators, indexed large-corpus search, notifications,
and distributed collection/storage are not implemented promises. Component presence
alone would still not prove exploitable product exposure.
