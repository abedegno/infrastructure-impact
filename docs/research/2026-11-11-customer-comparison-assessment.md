# Customer assessment: CVE volume and switching patching load

As of the 11 November 2026 [evidence audit](2026-11-11-comparison-evidence-audit.md), **Cisco has more observed affected CVEs in this project's switching OS-family sample: 199, versus 104 for Aruba and 70 for Arista.** That answers a bounded observation question. It does not establish that Cisco publishes more CVEs company-wide, that every CVE applies to the customer's switches, or that Cisco requires more customer upgrades.

## Why might the observed counts differ?

The dataset cannot attribute the difference to a cause yet. Plausible explanations to test include differences in component and feature exposure, product scope, independent scrutiny, internal vulnerability discovery, disclosure practices and how vendors group related issues into CVEs and advisories. Collection coverage is also unequal: expected applicable-advisory totals are unknown for all three vendors, Aruba's current index does not cover 2021, and Arista has pending archive work.

There is documented discovery and disclosure context, checked against the primary statements on 11 November:

- Cisco was named in the [7 April Glasswing launch](https://www.anthropic.com/glasswing). This establishes participation, not how many observed IOS XE CVEs it caused.
- [Arista's 2 September statement](https://blogs.arista.com/blog/racing-against-machine-speed-threats) also describes Glasswing participation and AI-assisted discovery, with elevated advisory volumes and grouped releases expected. AI-assisted discovery is not a Cisco-only explanation; this remains vendor-reported context.
- [Cisco's disclosure policy](https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure) changed in July 2026. It describes grouping bugs with a shared weakness into umbrella CVEs, scheduled hardening disclosures and less detailed disclosure of low-risk findings. This changes the counting unit and visibility within the study period; one CVE need not equal one defect.

Discovery programmes could increase findings and published fixes. Membership or a before/after increase alone cannot show that a particular programme caused the observed difference. An analysis would need dated discovery attribution, comparable product coverage and consistent counting units. The project currently establishes none of those causal conditions. The April programme launch and July disclosure-policy change must not be treated as the same event.

## Why is CVE volume a poor security-quality metric?

A CVE is a disclosed vulnerability identity, not a unit of customer risk or maintenance effort. One advisory can cover many CVEs; one release can resolve many advisories. Severity, exploitation, reachable features, configuration and model applicability affect operational relevance. CVE assignment and grouping practices also affect counts. More disclosure can reflect greater scrutiny and more transparent reporting.

Conversely, a low count can reflect fewer vulnerabilities, narrower products, less scrutiny, less disclosure or collection gaps. The count alone cannot distinguish these explanations. Zero observations are not evidence of no exposure.

The current 159 / 6 / 6 remediation-publication observations are also **not comparable customer upgrade counts**. The source set contains partial release histories and incomplete grouping/link evidence. Do not present this ratio as Cisco creating roughly 26 times the patching burden. Even the newly recovered Cisco `17.15.1` fix reference has no established release date or applicability to a particular installed chassis/configuration.

## Could a vendor fix vulnerabilities without naming the CVE?

That is a research question this project can investigate, but missing disclosure does not establish a silent security fix or deliberate concealment. Supporting evidence would need exact affected product/build context, a documented vulnerable-to-fixed change or owned security-fix statement, and a defensible search of the vendor's notices and release history. A component version change alone is insufficient because of backports, build options and unused code. Authorized private firmware/SBOM evidence is not yet available for this pilot.

No finding in this audit establishes intentional withholding by any of the three vendors.

## What should the customer monitor?

Track applicable high-severity and KEV-listed vulnerabilities, exposure duration where dates are supported, available mitigations, supported fixed releases and the number of required maintenance events for the actual deployed models and configurations. Keep discovery/disclosure counts alongside source completeness and evidence quality rather than converting them into a vendor ranking.

**Customer wording:** “Cisco has more disclosed CVEs in our currently collected switching sample. We cannot use that volume alone to conclude Cisco is less secure or requires more upgrades: coverage and product applicability are incomplete, and disclosure intensity affects the count. We recommend comparing applicable exploited/severe vulnerabilities and supported remediation options for the installed estate, while retaining the disclosure counts as context.”

Independent evidence review remains pending. Neither a claim that the vendors are equivalent nor a claim that one is concealing vulnerabilities is supported by this dataset.
