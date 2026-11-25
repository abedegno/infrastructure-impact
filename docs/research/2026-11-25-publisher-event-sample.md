# Publisher-event sample linked to switching upgrade targets

Research date: 25 November 2026. Automated primary-source research; independent
human review pending. Scope: IOS XE 17.12, AOS-CX 10.13 and EOS 4.33,
2024–2026. Cisco 17.9.6 is an explicitly separate control case.

## Findings

| Publisher evidence                                | What it establishes                                                                                                                             | What it does not establish                                                                                     |
| ------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Arista FN0103, dated 1 July 2025                  | Public summary explicitly announces deferral of EOS 4.33.3F, citing bug 1165537 and all supported platforms                                     | Exact action date, replacement release, or membership of individual study models in the supported-platform set |
| Cisco FN74221, first published 17 January 2025    | Conditional Umbrella certificate problem for Catalyst 9200/9300, including explicitly named 17.12.1–17.12.4; prescribed certificate replacement | Withdrawal, a required software upgrade, or applicability to a device without the stated configuration         |
| Cisco FN74383                                     | Access-point upgrade/flash-space issue; the document has its own affected-products scope                                                        | Switching-model applicability merely because 17.12 release strings or switch indexes mention it                |
| Cisco C9300 17.12.7a resolved caveats             | Three listed resolved defects                                                                                                                   | Predecessor-release relationship, withdrawal, release date or a confirmed corrective respin                    |
| Cisco C9300 17.9.6a release notes, outside cohort | A fix for CSCwm57734 is explicitly listed                                                                                                       | 17.9.6 withdrawal, first affected release or the action/release dates                                          |

The [Arista public summary](https://www.arista.com/en/support/advisories-notices/fieldnotice?start=40)
provides a genuine release-level deferral signal even though the
[full FN0103 detail](https://www.arista.com/en/support/advisories-notices/field-notice/21651-field-notice-0103)
requires sign-in. The summary's date is the **notice date**, not a verified
instant when the release was deferred. The action date remains null.

The [Cisco FN74221](https://www.cisco.com/c/en/us/support/docs/field-notices/742/fn74221.html)
condition concerns API-key registration; token-based registration is excluded.
The certificate expiry date, 30 September 2024, is separate from the notice date.
This is configuration-remediation context, not another software patch event.

[FN74383](https://www.cisco.com/c/en/us/support/docs/field-notices/743/fn74383.html)
is a scope control. Read its affected-products evidence before assigning a
notice to switching models; shared software numbering is insufficient.

The [17.12 caveats](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/release_notes/ol-17-12-9300/caveats.html)
and [17.9 What's New](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/release_notes/ol-17-9-9300/whats_new_in_cisco_ios_cupertino_179x.html)
provide the two bug-fix controls above. Suffixes and document last-updated dates
must not be substituted for a withdrawal relationship or release date.

## Link to retained upgrade scenarios

The input is the retained public 14 November switching analysis, publication
`3591f3596d5e41fe8d50ac633b8357e1`. A fingerprinted rows-only projection retains
original target, date, scenario, policy and claim identifiers. It supplies 55
annotation rows for the three trains during the selected period.

- **Arista:** no step targets 4.33.3F. The retained EOS 4.33 targets are 4.33.4M
  and 4.33.5M. Do not propagate deferral to neighbouring releases or infer that
  either was the replacement. No observed target is shown to have been deferred
  by FN0103; incomplete coverage prevents saying that none ever was.
- **Cisco:** FN74221 has nine literal target matches across scenarios/policies,
  representing only two distinct date/target pairs: 17.12.3 on 27 March 2024
  and 17.12.4 on 25 September 2024. The notice was published after both steps.
  These are not nine distinct upgrades or nine affected devices. Device
  configuration and model applicability remain unresolved, and this does not
  add a withdrawal or software-upgrade event.
- **Aruba:** bounded primary-source research did not establish a new qualifying
  withdrawal or deferral. Historical status remains unknown; it is not a zero
  incident count.

## Evidence and reproducibility

The [machine-readable research packet](2026-11-25-publisher-event-sample.json)
contains five observations, exact source locators, notice/action date distinctions,
labelled capture fingerprints (including supplementary workaround and sign-in
evidence), the input projection fingerprint and all nine
conditional target annotations. This is a research packet, not production
collector output or an activated release-signals dataset.

Public content was readable through the web research service. Direct anonymous
requests returned a client-challenge page for the Arista index and HTTP 403 for
Cisco FN74221. The English field-notice RSS was readable but its `start=40`
parameter did not expose the older notice. No login, challenge bypass or
third-party advisory source was used.

Capture SHA-256 values identify retained web-tool excerpts, not original vendor
document bytes. Original-document fingerprints remain null. Full captures stay
outside Git. The facts are suitable for source review; a supported origin or
labelled complete rendered capture and source-specific verifier are still needed
before promotion to the production collector. No model/version inference,
human-review approval, hosted activation or live-site change was made.

Counts describe disclosure and collection, not vendor security quality. A larger
count may reflect more openness or scrutiny. This sample does not establish which
vendor has a greater operational upgrade burden.
