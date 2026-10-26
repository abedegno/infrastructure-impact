# Check Point release evidence: initial review

Reviewed 26 October 2026. No concealed-fix finding is asserted.

Two official public download listings identify the same firmware build with
different platform scope and publisher dates:

| Public listing | Scope | Publisher date |
| --- | --- | --- |
| [134275](https://support.checkpoint.com/results/download/134275) | R81.10.10 Build 996002993; 1500 / 1570R | 2024-07-18 |
| [134302](https://support.checkpoint.com/results/download/134302) | R81.10.10 Build 996002993; 1600 / 1800 / 1900 / 2000 | 2024-07-21 |

The collector retains each page's exact bytes and fingerprint, and normalizes the
public title, build, models, date, filename and publisher-provided artifact SHA-256.
No firmware is downloaded. The listing may require entitlement for file access;
its date is not independently observed historical download availability. The
records do not create CVE assessments or automatically verify fix candidates.
Platform-specific dates must not be collapsed into one vendor-wide release date.

The detailed applicability sources [sk182459](https://support.checkpoint.com/results/sk/sk182459)
and [sk181833](https://support.checkpoint.com/results/sk/sk181833) remain inaccessible
to the hosted collector because their responses contain interactive AWS bot
verification. Existing local retained captures support the reviewed benchmark
cases, but those private captures are not uploaded to fill the cloud gaps. The
active public advisory index remains a separate, bounded source. A supported
vendor export or approved collector access is needed for reliable detailed cloud
collection; no challenge-solving or access-control workaround is implemented.
