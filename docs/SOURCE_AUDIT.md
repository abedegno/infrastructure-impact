# Vendor source-scope audit

`impact source-audit` inspects configured sources and retained HTTP cache evidence
without making network requests. Its metadata is published in Vendor catalogue,
`source-audit.json`, and the read-only `/api/v1/source-audit` endpoint.

The audit records response hashes and first-retained times, latest check outcome,
response entry counts, unique document links, exact-URL raw document retention,
and current product-advisory records matching those links. Bytes retained are not
successful extraction. Canonical redirects or alternate CSAF URLs can make
exact-URL counts lower than total collection activity. Record APIs are distinguished
from linked-document feeds; per-document URL metrics do not apply to those arrays.

Configured normal-feed limits and the bundled benchmark index cap are separate.
Bundled Juniper and Check Point feed plugins also retain matching cohort records
beyond the normal sample, so that limit is not a total record ceiling.
Retained `coverage_checks` search-scope strings identify the actual benchmark pass.
Advertised official next-page links are reported, but **not followed**. No archive
traversal is implemented. These limits remain explicit even when the entire
currently listed index has been inspected.

Declared product families come from the reviewed coverage catalogue. Observed
product-label counts are not a verified inventory of families, platforms or devices.
Errors for configured, discovered and historical URLs remain visible with their
retained check times and diagnostic categories; an old error is not proof of a
current outage. Malformed, non-feed and access-challenge responses are audit gaps,
not empty archives or evidence of no vendor disclosure.

## Reviewed configuration on 2026-10-26

| Vendor | Discovery scope | Historical/product boundary |
| --- | --- | --- |
| Cisco | Current security RSS, normal sample 4 | Pinned advisories, upstream references; no exhaustive IOS/IOS XE/NX-OS archive traversal; some release-note requests denied |
| HPE Aruba Networking | CSAF text index; normal sample 4; benchmark cap 200 | Retained index listed 110 documents in the local audit; raw retention does not establish complete product/configuration qualification |
| Arista | Current security RSS, normal sample 4 | Curated EOS/CloudVision/other supported layouts; no exhaustive archive traversal; lifecycle browser capture is separate |
| Palo Alto Networks | Current RSS, normal sample 4 | Pinned CVE JSON and OSS bulletin cases; shared product tables remain scoped; no portfolio denominator |
| Juniper | Current RSS metadata, normal sample 4 | Scoped SSR/Apstra documents; article shells and metadata do not establish product applicability |
| Check Point | Single active-index API response | Retained local response had 157 rows; server-side completeness and historical archive coverage are not established; gated SK/listing bodies remain gaps |
| Fortinet | Current PSIRT RSS, normal sample 4 | Structured exports and selected release notes; empty product-status envelopes and fixed-only statements remain qualified |
| HPE other products | Two pinned bulletins; no general feed | Selected Cray/NonStop coverage, not an HPE-wide product search |

The retained RSS windows contained 25–50 entries in this pass. These observations
are tied to source fingerprints in the machine-readable audit and can change.
The table is a code/configuration and primary-response audit by an automated
assistant, not independent human certification or a statement that vendors lack
other feeds or APIs. Contributions can add supported pagination/archive sources
with explicit scope, bounded retrieval, fixtures and evidence provenance.
