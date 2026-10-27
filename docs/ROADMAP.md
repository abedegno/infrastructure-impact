# Roadmap

Infrastructure Impact is an early-stage, single-host application. This is a list of
priorities, not delivery commitments or claims of complete vendor coverage.

## Implemented foundation

- Eight bundled vendor plugins and external Python entry-point discovery.
- Advisory schema v2 and component-reference schema v1, with semantic and finite-JSON validation, provenance and source revision history.
- Coverage-aware cohort comparisons and disclosure research review workflows.
- Immutable publication, read-only API, dashboard, Docker/Compose and backup tooling.
- Offline synthetic regression tests and installed-wheel extension checks.
- Resumable historical queues for Aruba, Arista, Palo Alto and Fortinet, with advertised pagination, explicit coverage progress and bounded offline parser recovery.
- Offline normalization previews and partial-failure reports that preserve capture times and distinguish parser reinterpretation from publisher changes.
- Encrypted draft-asset recovery with authenticated readback and preserved legacy copies, plus separately monitored public publication.

## Coverage and deployment expansion

The source now includes a coverage catalogue, a 24-CVE benchmark, declared primary-source mapping evaluations, release-note revision history and stricter availability review gates. A scheduled collector publishes the public static dashboard, with authenticated encrypted recovery copies and freshness monitoring. See the corresponding guides for current limits.

## Evidence-quality expansion — 26 October 2026

Versioned product-role filtering, source-led spot checks across all eight
vendors, blind review packets and publisher documentation histories are implemented.
Three disclosure investigations include earlier-advisory counter-evidence and
explicit unresolved availability/access gaps. Independent human adjudication,
portfolio denominators and verified fix timing remain outstanding.

The frozen OpenSSH service study now enrolls 21 reference CVEs across six selected
firewall families, producing 126 cells with explicit unknowns and source scope.
Its rates and rankings remain suppressed. Reviewed component references and
appliance-specific release statements retain patch, platform and role limits.
Multi-row Check Point SK advisories preserve each explicit CVE/product association;
the common feed writer rejects duplicate advisory identities before its first write.

Product/build planning and the investigation queue are documented in
[Product cohorts](PRODUCT_COHORTS.md), [Source access](SOURCE_ACCESS.md) and
[Disclosure research](DISCLOSURE_RESEARCH.md). Unknown inventories and independent
review remain blockers to vendor rates.

## Exact-build evidence preparation — 27 October 2026

The two-vendor firmware pilot now shows a side-by-side evidence table, separate
source-check status and blank vendor-neutral proposal downloads. Offline proposal
audits validate scope structure and local byte identity while leaving all semantic,
independence and comparison gates unverified. Official EOS source and AOS-CX
source-request leads are documented; no exact-image inventory has been certified.

The offline [SBOM reader](SBOM_OBSERVATIONS.md) now normalizes selected
CycloneDX/SPDX JSON fields into private component observations with literal
versions, source hashes and exact locators. It does not establish image binding,
patch state or CVE applicability. Proposal audits and SBOM inspection share a
bounded, duplicate-key and finite-number input boundary.

Recovery has explicit 512 MiB and 1 GiB profiles with unchanged archive and decoder
bounds, plus read-only payload accounting. Scheduled-run observations are tracked
separately from fresh manual publications. The elapsed service observation and
independent human review remain incomplete.

## Next priorities

- Continue expanding vendor/product families and historical collection; publish source-specific
  coverage and freshness expectations rather than a blanket supported-vendor claim.
- Add vendor parser regression cases from reviewed layouts, with redistributable
  synthetic fixtures and explicit unresolved states.
- Validate independent release availability and product/CVE linkage for timing leads.
- Complete the scheduled-service observation window, independently exercise operator recovery and review capacity as the retained vault grows.
- Continue per-source data-redistribution review before broadening published datasets; source releases and evidence publications have separate identities.

## Capabilities requiring separate design

Full CSAF conformance/signature validation, firmware/SBOM dependency mapping,
vendor-specific version evaluators, indexed large-corpus search, notifications,
and distributed collection/storage are not implemented promises. Component presence
alone would still not prove exploitable product exposure.
