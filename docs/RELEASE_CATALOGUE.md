# Release catalogue: first delivery

This offline dataset implements round 4 steps 1–4. The approved
[second-delivery report](RELEASE_RELIABILITY.md) packages the extracted facts for
new publication generations; it does not activate vendor collection. Independent
human review is pending.
Counts describe disclosure and collection, not vendor quality. Missing evidence
is unknown, never zero.

The [dated catalogue](research/2026-11-25-release-catalogue.json) follows
`infrastructure_impact/schemas/release-catalogue-v1.json`. It retains source
receipts separately from releases, notices, explicit status statements and coverage
judgements. Each fact references a receipt and includes a quote and document
locator. Original-document hashes and research-excerpt hashes are different fields;
blocked/challenge response hashes exist only in the vendor research access receipts.
A source can have a day-precision retrieval date; no artificial midnight timestamp
is added. A release can have an unknown release date and a stated announcement
date. Notice, action and release dates never substitute for one another.

Original-document provenance is eligible for production observations, subject to
source permissions and review. Research excerpts remain research-only. Neither
origin capture nor a passing automated check means human review is complete.
No production collectors are activated by these files.

## Reproduce and inspect

From the repository root, using the project environment:

```sh
python -m checks.build_release_catalogue
python -m infrastructure_impact.release_catalogue_cli \
  --catalogue docs/research/2026-11-25-release-catalogue.json \
  --output /tmp/release-catalogue-summary.json
pytest tests/test_release_catalogue.py tests/test_release_catalogue_packets.py -q
```

The dated build mapping imports only extracted facts from the three research
packets. It never reads raw documents, credentials, the default vault or a network
source. It excludes Cisco access-point and other-train controls and the HPE
8325/9300 notice. The hardware Cisco notice remains hardware context, with its
conflicting notice date unknown; both date statements remain in the research
packet. Short quotes and exact fingerprints can be audited against captures cached
outside Git. Do not commit those full captures. Cache references use
`$RELEASE_RELIABILITY_CACHE`, an operator-selected directory outside Git; they
do not disclose a workstation path or local identity.

The reusable CLI accepts any conforming catalogue and an optional `--config`.
`infrastructure_impact/resources/release-catalogue-trains.json` selects the period,
model scopes and same-base rules. Adding a train for an existing vendor does not
require changing the analysis. A new source layout needs its own verified reader
or explicitly checked offline extraction; configuration does not grant source access.
The older `release-signals` event contract is unchanged.

## Follow-up rules and coverage

Each configured train supplies an explicit vendor `respin_rule`, alongside its
maintenance-line pattern and stated model scope. Cisco pairs letter suffixes with
their preceding regular numeric base; EOS pairs sub-releases with a preceding
regular base retaining the same F/M suffix. AOS-CX regular builds are divisible
by ten; ordinary 1000, 1010 and 1020 maintenance releases do not become respins.
Non-decadal 1003 and 1005 pair with 1000, not with each other. The expected regular
build is recorded; a missing 1100 for 1101 is collection-absence evidence only.
Candidate pairs need dated inputs to enter 30/90-day counts. Undated candidates
or missing regular anchors retain null intervals and review entries, not a zero
or invented predecessor date. Historical reports without `respin_rule` preserve
their old derivation, including the now-superseded broad Aruba grouping.
Timing alone never establishes a corrective reason.
A corrective relationship needs a separately quoted publisher statement for the
same family, model and exact release pair. Model-specific dates and evidence do
not transfer to other models. Shared strings never establish platform support.

New packaged catalogues contain one record per vendor/train/version. Stated
platforms and all evidence are retained in the union; optional original
`observations` preserve model-specific dates, date unknowns and evidence classes.
Their union is validated and cannot add an unstated model or date.
The summary reports distinct dated version identities, not summed model rows.
Research dates are counted separately. All current denominators are null because
complete, original, dated release enumeration has not been established. A coverage
claim of complete also requires every configured model, original coverage receipts,
closed enumeration and no unresolved release dates. Undated identities remain
visible and cannot be assigned to a year. The 2026 period is year-to-date.
The second-delivery report exposes these limits through optional publication
roots, tables and source-linked upgrade context. Current rates remain unavailable;
no cross-vendor ranking follows. See [release reliability](RELEASE_RELIABILITY.md).

## Targeted coverage follow-up

The [coverage-pass report](research/2026-11-25-round4-coverage-pass.md) records
eight Cisco dates scoped to other Catalyst platforms and Arista's 4.33 train
start date. These supplements do not supply target-model release denominators
and are not automatically imported into the frozen first-delivery catalogue.
The source packets retain explicit scope, date meanings and access outcomes.
