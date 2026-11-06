# Source gaps after v0.11.0 — 6 November 2026

This dated audit reconciles the 15 failures in pipeline run 65 and public
generation `d7ae2a3d59564ca6a8d235413e27d124`. It separates that run's errors from
54 older latest-source errors. [JSON](2026-11-06-post011-failure-triage.json) and
[CSV](2026-11-06-post011-failure-triage.csv) enumerate the exact URLs, error codes
and check timestamps. Counts are not vendor completeness or security rates.

| Vendor | Run errors | Diagnosis and disposition |
| --- | ---: | --- |
| Arista | 8 | Unsupported legacy layouts, initially published in 2015–2016. Historical parser work remains; those initial dates precede the 2021 study window. |
| Palo Alto | 2 | Exact informational HTML layouts need separate handling. Local repairs below are validated against fresh official captures, but are not deployed. |
| Check Point | 4 | Two SK pages and two downloads require access verification. No authenticated content or challenge bypass was used. |
| Fortinet | 1 | Retrieved CSAF has no vulnerability entries. The existing publisher-scope error remains correct; no CVE/product claim can be manufactured. |

The three remaining benchmark cases are **source_missing**, all at Check Point
SK182459 and SK181833. They cover affected Quantum Spark, unaffected Gaia OS,
and a CVE-specific Scalable-platform fixed statement. They are not three observed
extraction disagreements. The frozen 47-case benchmark remains 44/47; expectations,
original review resources and independent human review status are unchanged.

## Palo Alto repairs, local and unreleased

[PAN-SA-2021-0002](https://security.paloaltonetworks.com/PAN-SA-2021-0002)
is a NAT slipstreaming notice without a CVE. The reviewed parser retains notice
context and mitigation qualifications, without inventing CVEs, product exposure,
firmware fixes or patch events from signature/browser versions.

[PAN-SA-2023-0003](https://security.paloaltonetworks.com/PAN-SA-2023-0003)
explicitly reports non-impact for three MOVEit CVEs across 26 literal product
labels. The reviewed parser emits 78 CVE/product **unaffected** statements, with
no version ranges or remediations. These are vendor claims, not independent
rescores, deployment conclusions or new vulnerability counts.

The adapters require the exact URL/title, one article and summary, ordered local
sections, unambiguous publisher dates, explicit status columns and positive scope
statements. Product roster, CVE set and status changes fail visibly. Navigation,
footer and metadata decoys cannot satisfy the article scope.

Both live anonymous captures on 6 November match the retained 5 November bytes:

| Source | SHA-256 | Fresh retrieved UTC |
| --- | --- | --- |
| PAN-SA-2021-0002 | `2a95d5e09a094e8098b8a1657131ddc8dce71cee18103236bfc22b784be7e4b3` | 2026-11-06T19:03:15.892744+00:00 |
| PAN-SA-2023-0003 | `5601bc1e0756d6d8b0d7f1b72ce7a429bb38319ff7de4d46162a6373a58745d9` | 2026-11-06T19:03:16.475481+00:00 |

Structured payloads cannot override these two policies or the existing reviewed
2025 configuration notice, including known direct export routes and a known
CSAF identity under another URL. This guard closes a reproduced code path tested
with synthetic populated CSAF; no claim is made about the actual export bodies,
which were not fetched for this audit. Unrelated structured PAN advisories retain
their existing behavior. Article updates that change scope need review.

## Remaining work and controls

- Preserve the access-challenged Check Point cases as missing. A separately
  authorized primary-source capture can unblock source-specific review; another
  source cannot silently replace the frozen SK identity or human adjudication.
- Keep the empty Fortinet envelope visibly unresolved. A later populated vendor
  publication must supply its own CVEs and product scope.
- Retain the eight legacy Arista gaps and their initial dates. Supporting them
  would broaden historical extraction, not prove 2021+ campus-platform exposure.
- Use the [two-advisory refresh preview](../rollouts/2026-11-06-arista-targeted-refresh-proposal.md)
  and [model-gap audit](2026-11-06-switching-model-evidence-gaps.md) for the
  comparison-relevant work; neither claims complete histories or vendor parity.

No hosted source pin, collection dispatch, default configuration, schedule,
permission, frozen study, secret or storage limit changes in this local work.
Raw captures, databases and operator receipts remain outside Git. Human review
remains pending. A lower error count must never be presented as more affected
products or evidence of concealment.
