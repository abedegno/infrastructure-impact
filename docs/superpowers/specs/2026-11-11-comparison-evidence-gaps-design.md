# Comparison evidence gaps — design

The customer wants to know whether Cisco discloses more vulnerabilities and creates more patching work than Aruba and Arista. The current observed counts cannot establish security quality, complete disclosure rates or customer upgrade burden. This milestone closes two evidenced gaps and publishes a current audit; it does not invent missing histories.

## Approach and scope

Use existing source-owned evidence and narrow adapter extensions. Rewriting collectors would duplicate working backfill mechanisms; broadening generic version or HTML parsing would admit unsupported facts. Fresh public metadata shows a new Arista SA-0226 error and 13 pending archive documents, so the previous audit cannot simply be relabelled current.

1. Admit the existing reviewed Cisco OpenSSH row into release history: product `IOS XE Software with NETCONF enabled`, CVE-2024-6387, literal `17.15.1`, same-source-row remediation. Recognize only bare three-component numeric Cisco literals in this bounded extension. Do not admit arbitrary numeric CSAF affected leaves. Python projection and browser validation must agree. Preserve original claim/remediation sources, conditionality and scope; add no software date, vendor-fixed claim, model qualification or study count.
2. Normalize exact official Arista SA-0226 (`25048-security-advisory-0226`) as a reviewed hardware notice with an explicit EOS-unaffected statement. Bind its CVE identities to the two owned CVA tables and the literal EOS exclusion/platform block. Emit only shared-bulletin unaffected EOS assessments/claims; do not reconstruct server affected/fixed matrices or join DMF/AGNI hardware scope. Preserve slash-labelled platforms unresolved, and the DCA350E/DCA350 discrepancy as a limitation. Changes to the reviewed title, revision, table or exclusion ownership must fail visibly. Register the parser in the normalizer fingerprint and existing research bridge.
3. Publish the current coverage audit and a short customer assessment, distinguishing observed advisories/CVEs, queue totals, latest-run failures, retained error identities, release context and missing denominators. Preserve the older yearly audit as dated evidence unless fresh year grouping can be derived without a full claim scan. Explain the separate global mapping benchmark and switching extraction samples; human review remains pending.

## Constraints and acceptance

- Existing advisory schema v2 and report schemas remain unchanged; no dependency or generated schema payload change is expected.
- Primary vendor/public project evidence only. No private configuration, vaults, keys, firmware, customer data or worker logs. Raw vendor captures stay outside Git; fixtures are authored reductions.
- No credential, schedule, permissions, collection-budget, runtime-pin or hosted publication changes in this implementation milestone. Existing incremental queues are not declared historically complete.
- No automatic version comparison, patch date, installed model applicability, silent-fix allegation or ranking. Missing remains unknown. Bulletin-shared unaffected context cannot increase affected CVEs or remediation events.
- Tests must demonstrate the original omissions, exact positive ownership, foreign product/CVE/source boundaries, malformed/range rejection, unknown dates and Python/browser/publication parity where changed. Actual public-source replay is separate from synthetic tests and from hosted acceptance.

Implementation choices and normal review/PR preparation are delegated by the maintainer's existing instruction to continue without routine approval questions. This design records the bounded work; it does not authorize changing hosted configuration.
