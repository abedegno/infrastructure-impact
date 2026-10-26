# Coverage catalogue

The machine-readable profile is `infrastructure_impact/resources/coverage-catalogue.json`.
The dashboard's **Vendor catalogue** combines it with the configured source URLs,
actual latest source checks, error counts and collected advisory counts. Download
`catalogue.json` from a public publication, or use `/api/v1/catalogue` on the Python
reader. These are operational coverage boundaries, not certifications of support.

| Vendor | Product scope in the current adapters | Historical depth / main gap |
| --- | --- | --- |
| Cisco | Advisory-listed IOS/IOS XE, NX-OS and infrastructure products | Bounded current RSS, upstream references and curated history; not an exhaustive archive |
| HPE Aruba Networking | ClearPass and products encoded in official CSAF | Current index scanned within cap 200; actual inspected count and failures retained |
| Arista | EOS, 7130/MOS, CloudVision, selected fabric/cloud statements | Reviewed HTML/CSAF layouts and selected historical documents; hardware qualifiers stay source-defined |
| Palo Alto Networks | PAN-OS, Panorama, Prisma, GlobalProtect and explicit product rows | Current RSS plus curated CVE JSON/OSS tables; shared and per-CVE scope differ |
| Juniper | Session Smart Router, Apstra, RSS discovery | Two narrow PDF adapters; application shells and unresolved RSS discovery remain gaps |
| Check Point | Quantum Spark, Gaia OS, Scalable Platforms, active-index products | Active index plus two reviewed SK articles; not a complete historical archive |
| Fortinet | FortiOS, FortiProxy, FortiNAC-F and encoded PSIRT products | Some structured exports lack product statements; release fixes do not establish older affected ranges |
| HPE other | Selected Cray EX and NonStop products | Two pinned historical bulletins; no general HPE-wide discovery feed |

Collection targets a 24-hour cadence. A vendor profile becomes stale after 36 hours
without a successful check. “Fresh” means a successful check was observed, not that
all products were examined or every source succeeded. Errors remain separately
visible. The public GitHub-hosted service schedules 08:37 UTC; GitHub can delay runs.
New external plugins receive an explicit undeclared-profile state until their
coverage metadata is reviewed.
