# Reliability staircase delivery — 27 November 2026

This completes the approved implementation following the phase-one stop point.
Deployment acceptance is recorded separately. Independent human review remains
pending. Counts describe disclosure and collection, not vendor quality; missing
evidence is unknown, never zero.

## Published default and selected views

Scientific publication now derives a default reliability join from the same
generation's complete source-owned upgrade requirements. It expands only the
configured IOS XE 17.12, AOS-CX 10.13 and EOS 4.33 constraints, retains pre-2024
walk state, and annotates distinct in-period date/target pairs through 2026.
Scenario/policy duplicates become references on one pair, not extra upgrades.
It does not materialize another whole selected analysis report or change any
upgrade count. The writer rechecks default annotations against its source context;
a publication discriminator alone cannot authorise a hand-labelled selected view.

The report declares the train/date limits and original study selection in
`upgrade_selection`. `published_staircase_version: 1` distinguishes this default
from an arbitrary caller selection. The static and native readers accept this
bounded, authenticated context. Explicit selected analysis clears that marker and
replaces annotations. Metric denominators and the reliability catalogue are
independent of study selection. Older untagged roots remain readable.

Each marker shows exact catalogue presence, a suffix-only Cisco lead, or no
observed record. A suffix variant is not an exact target and never inherits
actions or notices. Related release and timing fields distinguish notice date,
action date, follow-up software date, release-to-release gap and gap from the
upgrade step. A missing action date cannot establish a later withdrawal.
All joins retain stated source scope and unknown model applicability.

Complete new-version annotation objects also appear in CSV payloads, including
the catalogue marker and source evidence. Source links resolve against the same
generation's receipt table, with original and excerpt fingerprints kept separate.

## Version references and dates

The [phase-one findings](2026-11-27-reliability-version-gaps.json) add three literal
version references to the candidate catalogue: Cisco 17.12.7 from the Catalyst
9300 software-image table, and Aruba 10.13.1031/1161 from official fixed-version
advisory text. The latter remain OS-family references without invented models.
Their software release and announcement dates remain unknown. There are now 43
unique version records: Cisco 9, Aruba 26 and Arista 8. Every one of the original
51 model/source observations remains available beneath the deduplicated records.
The phase-one 40-record preview remains unchanged as a historical artifact.

The [public-date investigation](2026-11-27-reliability-public-dates.md) found no
admissible new binary release dates for the requested Cisco or Arista models.
Other-model Cisco dates, hardware-series dates, document updates, train-level
Arista dates and RSS announcement dates were not promoted. Cisco 17.9.6 withdrawal
and deferral remain unverified. This bounded search outcome does not prove that
such evidence does not exist. No login or challenge bypass was attempted.

No new denominator or cross-vendor rate is supported. Aruba's observed research
version counts remain 11 / 8 / 5 by year; the corrected 2024 possible-respin
90-day count remains two distinct versions. Missing timing remains unknown.

## Validation and publication boundary

Tests cover catalogue match types, scope mismatch, no action transfer from suffix
variants, distinct step grouping, separate timing, configured bounds, source
identity, retained pre-period walk state, writer discrimination, full CSV payloads,
both publication formats, lazy readers and native/browser parity. The public-date
packet retains receipt hashes and rejected date meanings. Review status is pending.

Source changes and hosted activation are separate operations. The approved release
uses the existing GitHub Pages collection workflow with a new source pin; schedules,
permissions, secrets, scientific profile and delivery profile are unchanged.
