# Remediation dates and deterministic replay

Reviewed 27 October 2026. This is a parser-correction review of retained publisher
bytes, not independent human validation or a finding about vendor disclosure.

## Problem and correction

The shared remediation classifier compared source dates with the current system
date. Replaying identical bytes with an unchanged parser in June 2024 classified
an October 2024 target as planned; an October 2026 replay classified it as a
vendor-reported fix. Elapsed collection time supplied the only new information.

The classifier now uses the document's publisher update date, or its initial date
when no update date is supplied. Contradictory chronology, missing/invalid date
context and a month-only target overlapping the document month remain unknown.
Explicit plan expressions remain planned. These states describe publisher claims
as of that document, not whether a download became available later.

## Retained-source findings

The comparison reparsed 388 supported advisories without network requests or
database writes. Nine retained documents were unsupported by the current parser
and were left unchanged. All differences between the old and corrected parsers
were remediation availability labels: 34 claims changed from vendor-reported
fixed to planned, and 38 to unknown, across these five documents. Counts are
normalized assertions, including repeated scoped rows, not distinct products or
independent observations.

| Publisher document                                                                                                                | Retained SHA-256                                                   | Date context requiring care                                                                                                             |
| --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------- |
| [Aruba 2022-012](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-012.json)                                  | `f116fe548a9cee7d9990e751e56994bb35dbed9124e2d2812b0c6b387d21d404` | Current document date 2022-08-30; remediation date 2023-08-30.                                                                          |
| [Aruba 2022-014](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-014.json)                                  | `81d30102e3004d9876bcfaf1ea897d424b289da2798d8adccbcb3733fdfa8e00` | Current document date 2022-09-27; remediation date 2023-09-27.                                                                          |
| [Aruba 2024-001](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_2024-001.json)                                  | `e6e902496b1e731f8fd0989d45bedc9a30453eb5445e1865eb980e364a439331` | Current date 2023-01-01 precedes initial date 2024-02-27; that chronology cannot establish availability.                                |
| [Aruba 2024-005](https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_2024-005.json)                                  | `f5b90ba44593e3f3ff45e1bc4f2877c20d9c084de944c7d044029e04608de0fd` | Current document date 2024-03-05; remediation date 2024-05-07.                                                                          |
| [Cisco OpenSSL advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-W9sdCc2a) | `e24f1e881ad619b48f0696ee4b8c120ce2515c38940879c164881c4ec3a72114` | Current document date 2022-11-23; one row has month-only November 2022 targets, another mixes available options with a May 2023 target. |

A future remediation date can reflect a publisher data error. It is not proof of
an actual release plan or historical release availability. Mixed release options
remain visible in the source expression; the classifier does not split them into
invented build-level availability claims.

## Verification and limits

Regression tests exercise identical inputs under clocks before and after target
dates, multiple month targets, missing/invalid dates, contradictory chronology,
calendar-day precision and the CSAF/CNA/HPE/legacy HTML call sites. Existing
non-fix and partial-mitigation categories retain their precedence.

Historical revisions keep their original parser identity until explicitly
reprocessed or collected again. Reprocessing retained bytes creates a parser
reinterpretation, preserving the first capture time. It does not demonstrate a
publisher edit, first disclosure, an undisclosed fix, or intentional concealment.
The independent human review and vendor comparison prerequisites remain pending.
