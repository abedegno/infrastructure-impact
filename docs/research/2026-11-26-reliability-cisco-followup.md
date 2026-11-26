# Cisco reliability coverage follow-up

Research date: 26 November 2026. **Independent review pending. Research only.**

Six remaining indexed notices now have bounded detail-page evidence. Four are
excluded by explicit older software scope; two supply conditional context. No new
qualifying 17.12 switch incident or model-specific release date was established.
The sixteen Catalyst 9200/9300 family/version date rows remain unknown.

| Notice | Evidence and treatment |
| --- | --- |
| [FN72524](https://www.cisco.com/c/en/us/support/docs/field-notices/725/fn72524.html) | AP image-certificate failure; C9300/C9300L explicitly named only as embedded wireless controllers managing affected IOS APs. No C9200 scope or affected 17.12 switch release established. |
| [FN72323](https://www.cisco.com/c/en/us/support/docs/field-notices/723/fn72323.html) | Listed affected IOS XE 17 versions are 17.1–17.4; stated fixes include 17.3.4/17.4.2/17.5.1/17.6.1/17.7.1 or later. No affected 17.12 release established. |
| [FN70359](https://www.cisco.com/c/en/us/support/docs/field-notices/703/fn70359.html) | C9300 is explicitly in scope, but affected releases are 16.3.x and 16.6.x. Exclude from IOS XE 17.12 incidents. |
| [FN72578](https://www.cisco.com/c/en/us/support/docs/field-notices/725/fn72578.html) | Conditional Smart Licensing Using Policy CPU/memory issue. Listed affected versions run from 17.3.2a through selected 17.7.1, without 17.12. |
| [FN70489](https://www.cisco.com/c/en/us/support/docs/field-notices/704/fn70489.html) | IOS XE affected-product row explicitly limits scope to releases before 16.9.1. Exclude from IOS XE 17.12 incidents. |
| [FN72511](https://www.cisco.com/c/en/us/support/docs/field-notices/725/fn72511.html) | Default SSH rejection of RSA keys below 2048 bits applies from 17.11.1 onward; thus relevant to 17.12 as general configuration context. Affected table lists only 17.11.1/17.11.1a; no explicit 17.12 subrelease or C9200/C9300 family list in captured body. C9300 breadcrumb/index supports discovery, not model applicability. |

FN72524 expressly includes C9300/C9300L embedded wireless controllers only when
controlling affected IOS APs. Its index association therefore has a concrete
conditional explanation; it does not establish a defective 17.12 switch image.
FN72511's prose extends the SSH default change to later releases, while its table
names 17.11.1/17.11.1a. This distinction is retained rather than inventing 17.12
subrelease or family specificity.

The previous [release-date supplement](2026-11-25-round4-coverage-cisco.md)
remains unchanged: other Catalyst platform dates cannot establish C9200/C9300
dates. The new official-domain queries returned series inception and documentation
index dates, not usable release dates. Neither notice dates nor recommendation,
page-update or other-platform dates were substituted. A wireless-controller
removal snippet discovered during search remains outside study scope. Historical
notice completeness and study-scope withdrawals remain unknown; zero newly
qualifying incidents is not a vendor incident rate.

The [JSON evidence packet](2026-11-26-reliability-cisco-followup.json) records exact
locators, short excerpts, retrieval/capture timestamps and SHA256 fingerprints.
Actual tool responses and separate excerpts are outside Git at
`$RELIABILITY_COVERAGE_CACHE/cisco`.
These are parsed web-tool captures, not full origin HTML; original origin hashes
are explicitly null. Cached public originals retain their earlier provenance.

Stopped after two search batches, six distinct notice detail opens and four
find calls on those already opened pages. No access refusal, login, challenge
bypass, mirror or hidden endpoint was used. Cached Cisco robots rules permit the
selected public paths; terms do not authorize production collection. No product
code, packaged catalogue, policy, workflow or schema was changed.
