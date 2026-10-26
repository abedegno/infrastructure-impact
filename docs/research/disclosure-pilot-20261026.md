# Disclosure investigation pilot — 26 October 2026

Three case files separate exposure statements, chronology claims and missing
independent evidence. This is an automated primary-source research pass;
independent human review is pending. No case establishes intentional concealment.

| Case | Source-led result | Remaining limit |
| --- | --- | --- |
| HPE Cray / OpenSSH | The bulletin's firmware date precedes its bulletin date by 70 days. The release-details lead again returned an application shell. | No independently retained August availability, exact bundle/platform manifest or earlier-disclosure review. |
| Aruba AOS-CX / OpenSSH | The advisory identifies fixed branch 10.13.1031. The selected 4100i history URL returned an edge 403 in this pass. | No independent date for that exact hardware/release. A denial does not establish a missing vendor disclosure. |
| FortiProxy 7.2.8 / curl | The current change log reports CVE references added four days after its initial entry. An earlier-dated vendor curl advisory also exists. | Current publisher dates are not historical captures or firmware availability. Earlier advisory evidence counters an inference of nondisclosure from the later edit. |

HPE's [bulletin](https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbcr04733en_us&docLocale=en_US)
provides both firmware and bulletin date claims. Aruba's
[advisory](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04669.json)
and the selected [history lead](https://arubanetworking.hpe.com/techdocs/AOS-CX/Consolidated_RNs/4100i%20Release%20Notes/aos-cx-10-13-xx/version-history-43.html)
retain distinct roles.

For FortiProxy, compare the [resolved issues](https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/534553/resolved-issues),
[publisher change log](https://docs.fortinet.com/document/fortiproxy/7.2.8/release-notes/4/change-log)
and [FG-IR-23-385](https://www.fortiguard.com/psirt/FG-IR-23-385).
The change log labels its initial entry 8 December 2023 and addition of the two
curl references 12 December. The advisory's structured initial date is 14 November
with no timezone; its HTML timeline instead labels initial publication 7 November.
Neither claim is selected as proven first disclosure. The advisory's VM/platform
qualifications and planned-release wording must be retained.

The publisher-history plugin hook reads only reviewed change-log layouts and
projects dates, event kinds, CVE IDs and row locators into a common report. Source
bytes stay in the vault. This chronology is distinct from the local revision
timeline: retrospective publisher entries are not old snapshots captured by us.
Case files link relevant events and earlier-dated vendor documents with hashes.
They remain `incomplete_evidence`; true disclosure/fix timing stays suppressed.

Detailed investigation records ship in the public `research/` directory. Current
runtime fingerprints can differ from the dated reviewed versions. A changed source
requires re-review; a newly empty page or removed reference never proves concealment.
