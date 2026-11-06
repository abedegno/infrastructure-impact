# Switching staging observations — 2026-11-04

Observation end: **2026-11-04**, generated at **2026-11-04T16:14:18.680235+00:00** (UTC). Local sanitized generation `78e96c4f70ef44e6b3fe7bc9fbc7755d`. This generation was not deployed. History starts 2021-01-01; 2026-04-07 belongs to post and 2026 remains partial.

**Counts measure disclosure, not vendor security quality; higher disclosure can reflect more scrutiny.** No equivalence, ranking, causality or no-difference conclusion follows from these observations.

**Every model-qualified selection is zero because sufficient explicit target-model bindings were not retained. This is not evidence of no exposure.** OS-family context and the unequal named-model subset remain separate.

## Collection boundary

Two resumed invocations used the same fresh staging vault/configuration, 20 listing pages and 200 documents per vendor per invocation. Listing failures, cooldowns and parser failures were preserved. Public source bytes and operational receipts remain private and ignored; public tests use synthetic inputs only. No native review packet/vault, default configuration, schedule, permission, runtime pin or deployment was changed.

| Source | Enumeration state | Discovered identities | Retrieved documents | Parsed documents | Parse failures | Publisher expected total |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| cisco | blocked | 0 | 0 | 0 | 0 | unknown |
| aruba | enumerated | 112 | 112 | 112 | 0 | unknown |
| arista | enumerated | 203 | 203 | 150 | 53 | unknown |

Cisco authenticated enumeration returned `auth_not_configured`; no credential values were requested or recorded. Separately, eight existing repository-default public Cisco seeds were retrieved and normalized, and official KEV was retained. Those eight source observations are not a Cisco archive backfill. Their known initial years are one each in 2021, 2022, 2023, 2024 and 2026, with three undated. Only one advisory qualifies for this study.

[Aruba’s official index](https://csaf.arubanetworking.hpe.com/index.txt) supplied 112 parsed representations, which resolve to 111 retained advisory identities. Its official index begins in 2022; `pre_2022_history_not_enumerated` remains. The earlier failed official 2021 TXT lead does not establish a complete 2021 archive. The [Arista official listing](https://www.arista.com/en/support/advisories-notices) yielded 203 retrieved documents, which include 53 parse failures: 28 yielded no product assessments and 25 yielded no scoped software statements. Their dates/applicability remain unknown. No errors were reset, and no guessed archive URL crawl was used.

### Source identities by observed initial year

These are discovered source identities grouped only after a retained primary source supplied an initial date. They are not expected historical totals or family/model denominators. All identities in these two listings were retrieved; unparsed Arista documents remain in the unknown-year row. Cisco API enumeration has zero observed identities in every year and unknown completeness.

| Vendor | Initial year | Enumerated identities | Retrieved | Parsed |
| --- | --- | ---: | ---: | ---: |
| aruba | before 2021 | 0 | 0 | 0 |
| aruba | 2021 | 0 | 0 | 0 |
| aruba | 2022 | 21 | 21 | 21 |
| aruba | 2023 | 17 | 17 | 17 |
| aruba | 2024 | 20 | 20 | 20 |
| aruba | 2025 | 20 | 20 | 20 |
| aruba | 2026 | 34 | 34 | 34 |
| aruba | unknown | 0 | 0 | 0 |
| arista | before 2021 | 11 | 11 | 11 |
| arista | 2021 | 11 | 11 | 11 |
| arista | 2022 | 11 | 11 | 11 |
| arista | 2023 | 9 | 9 | 9 |
| arista | 2024 | 14 | 14 | 14 |
| arista | 2025 | 24 | 24 | 24 |
| arista | 2026 | 70 | 70 | 70 |
| arista | unknown | 53 | 53 | 0 |

## Qualified descriptive observations

Observed advisory totals use non-draft claims and can include non-affected statements. Distinct CVE totals retain all selected scoped claims, including drafts; scoped drafts are reported separately. Affected totals require explicit CVE-specific affectedness and exclude draft claims. Latest retained claims are grouped by initial publication date; revisions do not create new disclosures. Year, severity and scope sets overlap and are nonadditive. `Unresolved` below counts claims without established model bindings, not missing advisories.

| Vendor / family | Scope | Window | Observed advisories | Affected advisories | Distinct CVEs | Affected CVEs | Scoped drafts | Unresolved claims | Remediation events |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| cisco / IOS XE | os_family | all | 1 | 1 | 1 | 1 | 0 | 1 | 1 |
| aruba / AOS-CX | os_family | all | 19 | 16 | 110 | 104 | 0 | 873 | 1 |
| arista / EOS | os_family | all | 51 | 48 | 97 | 62 | 23 | 456 | 1 |
| cisco / IOS XE | os_family | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| arista / EOS | os_family | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| cisco / IOS XE | os_family | 2021 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | 2021 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| arista / EOS | os_family | 2021 | 2 | 1 | 4 | 1 | 0 | 4 | 0 |
| cisco / IOS XE | os_family | 2022 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | 2022 | 7 | 4 | 40 | 34 | 0 | 241 | 1 |
| arista / EOS | os_family | 2022 | 6 | 5 | 8 | 6 | 0 | 38 | 0 |
| cisco / IOS XE | os_family | 2023 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | 2023 | 3 | 3 | 6 | 6 | 0 | 36 | 0 |
| arista / EOS | os_family | 2023 | 3 | 3 | 7 | 4 | 3 | 178 | 0 |
| cisco / IOS XE | os_family | 2024 | 1 | 1 | 1 | 1 | 0 | 1 | 1 |
| aruba / AOS-CX | os_family | 2024 | 3 | 3 | 4 | 4 | 0 | 27 | 0 |
| arista / EOS | os_family | 2024 | 4 | 3 | 8 | 4 | 3 | 9 | 1 |
| cisco / IOS XE | os_family | 2025 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | 2025 | 3 | 3 | 17 | 17 | 0 | 156 | 0 |
| arista / EOS | os_family | 2025 | 12 | 12 | 20 | 14 | 5 | 67 | 0 |
| cisco / IOS XE | os_family | 2026 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | os_family | 2026 | 3 | 3 | 43 | 43 | 0 | 413 | 0 |
| arista / EOS | os_family | 2026 | 24 | 24 | 50 | 33 | 12 | 160 | 0 |
| cisco / IOS XE | model_qualified | all | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | model_qualified | all | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| arista / EOS | model_qualified | all | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| cisco / IOS XE | model_qualified | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| aruba / AOS-CX | model_qualified | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| arista / EOS | model_qualified | undated | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

For **each individual year 2021, 2022, 2023, 2024, 2025 and 2026**, every vendor’s model-qualified observed/affected advisories, CVEs, drafts and remediation events are **0**. The same is true of the model-qualified pre/post selections. These zeros reflect missing explicit bindings; no automatic model, version or slash-label matching was applied.

### Drafts and extraction boundaries

| Vendor | All retained drafts | Family-scoped drafts | Family unresolved | Model not qualified | Unknown initial date |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cisco | 0 | 0 | 0 | 0 | 0 |
| Aruba | 0 | 0 | 0 | 0 | 0 |
| Arista | 37 | 23 | 14 | 37 | 0 |

The 37 Arista draft statuses remain literally `draft`; no alternative HTML page promotes them to final. Scoped drafts are not a vendor-wide draft denominator. Unknown models/families remain unknown even when a publisher supplied a date.

Typed evidence still reports 5 Cisco layout gaps (two vendor-authored CVE records, one release-note PDF and two generic HTML sources), and 33 Arista layout gaps (3 reviewed management-appliance, 5 older product/model, 3 generic HTML, 3 non-CVE notices, 5 affected-software, 12 sibling-software and 2 informational-summary formats). Many describe non-study products or older controls; these are bridge limitations, not proof the publisher omitted EOS information. Aruba has no typed layout gap among its retained CSAF documents.

Comparison with core normalized EOS statements identified five in-period reviewed routes that were unnecessarily excluded by the original bridge: Arista 0061, 0062, 0094, 0140 and 0147. Exact-route bridges now preserve the core parser’s CVE/shared scope and locators. Local HTML branch keys are not asserted as publisher product IDs, and shared platform text is not crossjoined. Generic/unreviewed HTML remains unsupported.

[Arista 0100](https://www.arista.com/en/support/advisories-notices/security-advisory/19904-security-advisory-0100) supplies a positive remediation witness: explicit affected EOS claims and separate CVE-specific fixed EOS sections for CVE-2024-6387 and CVE-2024-6409. The reviewed section binding now yields **one advisory remediation event** containing those two CVEs. Fixed-only claims remain separate; this establishes neither a target model nor a fix-availability date. Cisco’s one event is the retained explicit IOS XE statement. [Aruba ARUBA-PSA-2022-004](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-004.json) explicitly identifies numeric AOS-CX upgrade releases and CVE-specific product IDs. Narrow recognition of that affirmative release-list statement now yields one advisory remediation event for CVE-2021-41002; planned/future, negated and unbound statements still cannot qualify. The publisher’s separate UEFI warning concerns a different advisory. No version matching or availability date is inferred.

## Scores, KEV and validation

Bounded official fallback made **41 requests: 20 successful CVE records, 20 successful NVD records and one CVE `source_missing` result**. Short persisted cooldowns were honored; the missing CVE-2026-10040 source was not repeatedly forced. The affected CVEs in the final scope have at least one available score for Cisco **1/1**, Aruba **104/104**, and Arista **61/62**. Arista CVE-2026-10040 remains Unknown. Provider/version/origin/preferred facets remain nonadditive; different product-specific statements can overlap. Scores are reported values with structural validation, not independent rescoring or product-affectedness evidence.

The official KEV source is available at this generation’s evaluation time. Reader-time freshness can subsequently make membership unknown without changing retained inputs.

| Validation sample | Cisco | Aruba | Arista | Total |
| --- | --- | --- | --- | --- |
| Fresh staging, exact bytes | 1/5 | 5/5 | 0/6 | 6/16 |
| Fresh staging, reviewed section matches after byte changes | 0/5 | 0/5 | 6/6 | 6/16 |
| Fresh staging, either accepted match | 1/5 (20%) | 5/5 (100%) | 6/6 (100%) | 12/16 (75%) |
| Separately preserved historical exact-byte replay | 5/5 | 5/5 | 6/6 | 16/16 (100%) |

Fresh Cisco cases `switching-cisco-2`, `switching-cisco-3`, `switching-cisco-4` and `switching-cisco-5` are `source_missing`: the fresh vault lacks the exact sample representations. This is not an extraction disagreement. Fresh Arista cases match the reviewed advisory-body scope while complete page hashes changed; they are not full-byte passes. The historical 16-case replay uses separately preserved earlier captures and does not fill fresh collection gaps. The historical source-only Cisco conditional row and bundle membership also replayed successfully. **Independent human review remains pending** for all of these automated checks; missing categories and source/layout coverage prevent a completeness claim.

## Publication and release evidence

Definition fingerprint: `5224471b014fccc278f985d08328926bac29ebc6bfb96d25f98972f91be6fd33`.
Retained-source receipt-set fingerprint: `a44ca6dec81306be08a2619d65237d428c54312d1d9180ef2740c53a56c63e38`. The fingerprint covers the privately retained URL/hash/retrieval metadata; raw receipts are not exported.

| Vendor | Normalizer fingerprint |
| --- | --- |
| cisco | `a740e8223289262d` |
| aruba | `7acf6ab26d8079e5` |
| arista | `7e32fc035d60b79c` |

| Delivery artifact | Bytes |
| --- | ---: |
| switching-comparison.json | 50903075 |
| switching-evidence.json | 49621952 |
| snapshot.json | 24258067 |
| snapshot.json.gz | 961757 |
| data/index.json | 748473 |
| Largest content-addressed part | 1124627 |
| Compact monitor checked parts/schemas | 2931216 |
| Complete local generation | 256544500 |

The local publication passed strict projection/schema/semantic checks and the standalone monitor. Existing 512,000-byte target parts, 8,000,000-byte hard parts, 2,000,000-byte index and 20,000,000-byte monitor limits were unchanged. Full study inputs are a separate large explicit download; whole-study hydration is substantially larger than the compact monitor. Repeated full-input validation made the operational year-matrix helper slow; the final matrix reused the production row reducer after publication validation. That initial staging build did not include the later reader optimization described below.

Local Python, Node, lint, formatting, wheel/plugin, container and clean source-export checks are recorded in the task handoff. Remote Python 3.11/3.13 and container CI remains pending the feature branch review/push. No product version, production publication transition or hosted source-pin activation occurred.


## Final-review local verification

The collection observations above remain the original `78e96c4f70ef44e6b3fe7bc9fbc7755d`
generation. A local rebuild from the same dedicated staging vault, without any new
collection or score attempts, produced generation `a057ceafda454d459a7f36d99a158421`
at `2026-11-04T17:16:49.320082+00:00`. Observation end remains 2026-11-04;
all 7,603 retained claims and the reported vendor counts are preserved. Earlier
staging generations and their receipts remain retained. This follow-up was not deployed.

Strict browser evidence checks exposed a Python/JavaScript numeric spelling
difference in claim IDs (`5.0` versus `5`). The unreleased study now fingerprints
finite numbers with a shared exact binary64 decimal-token format. Some claim IDs
and corresponding part hashes changed; reported score values, source hashes,
source observations and the study definition fingerprint did not change. No raw
source bytes or operational receipts are included here.

A fresh isolated Chromium session against the final local assets measured
**4,247 ms initial study hydration**, including strict validation, and **48–59 ms
model selection**, compared with the earlier measured 4,657 ms and 9,021 ms.
Arista/post selection took 47 ms; full OS-family reselection took 86 ms. Four
selections, expansion from 25 to 50 claim details and explicit KEV re-evaluation
made **zero additional part requests**. Initial DOM markup was 152,584 bytes;
closed evidence detail is generated on expansion in bounded batches. Counts
remained 1/16/48 affected advisories and 0/0/0 model-qualified advisories. No script
errors or horizontal overflow at 390-pixel width were observed; keyboard expansion
and the no-exposure caveat were checked. Initial validation still loads the full
study; the improvement concerns repeated interaction, not smaller source inputs.

The final compact monitor was fresh, with KEV and switching available, 26 checked
parts and 2,931,319 checked bytes. It did not fetch full history or study inputs.
The largest content-addressed part remained 1,124,627 bytes. Existing part, index
and monitor budgets were unchanged.

| Final artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| switching-comparison.json | 50903075 | `53b75aaaa8a082fa10e1a8185fc1887c429197478f89003631ea315f2f3e0942` |
| switching-evidence.json | 49621952 | `f508b6f0ffd2003d21d7824b16d9feb86d944abf7e7ce955ebd42b4d15d7ffd6` |
| data/index.json | 748473 | `9248ae6f89375888838aa7384bd3274fe322999468c960e12f1d63014bae8e6c` |
| app.js | 106756 | `7ccfcd8a9b45dafbe84842171d473d517f0e60bb18c0e1603204f780ffd74c0b` |
| delivery.js | 9914 | `22281bb36ec83e312666356b34a94658280ee30cfa898a20055fc301f3b656c8` |
| switching-contracts.js | 59648 | `d28b6244ad71f6d4b3c15cfc92a613f2e0c669697c7e34a9fd26c25417c06ec9` |
| switching.js | 34825 | `1666e556cc64e1f84e1e98b3aec63d8b4f4c9aeefe87e1dd87f557db177e1ccb` |
| switching-view.js | 15826 | `52bae3aedef3cd27047f98053795ba908ff66ed6475e7634be48c0cdf0f65101` |

Cisco authenticated history remains unavailable, Aruba pre-2022 coverage remains
unestablished, and the 53 Arista parse failures, drafts, unresolved target models,
missing score source and pending independent human review remain explicit limits.
Local automated acceptance does not replace final-head remote CI or human review.
