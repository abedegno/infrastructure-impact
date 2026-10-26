# Benchmark and extraction evaluation

The declared cohort has **24 CVEs across 13 component families**:
Log4j, OpenSSL, OpenSSH, curl, Linux, PHP, XZ, libwebp, HTTP/2, zlib, Expat, Python
and Go. Its authoritative definition is `resources/benchmark-cohort.json` inside
the package; the dashboard reads that definition from its publication. It is a
purposive sample, including applicability exceptions and precautionary fixes.
It is not a representative sample for ranking vendor security.

`resources/benchmark-cases.json` contains **47 declared mapping expectations** over
primary sources from Arista, Palo Alto Networks, Check Point, Fortinet, HPE, Cisco and Aruba.
Each identifies its vendor, CVE, exact source URL, product selector, expected status,
optional version/scope constraint, rationale, review method and review date.
These cases were reviewed by an automated assistant against primary vendor text,
not independently adjudicated by multiple human reviewers. Not every vendor/cohort
pair has a curated expectation.

Run `impact evaluate` against a collected vault. `--fail-on-disagreement` exits
nonzero when a declared case is absent or disagrees. Publications include
`benchmark.json` with pass/missing/disagreement states and exact source fingerprints.
Cases require the expected scoped statement. Thirty-four cases also declare forbidden
statuses: a correct unaffected claim cannot mask an additional affected, fixed or
investigating claim for the same selected product and CVE. A violation reports
`forbidden_claim` and fails the CLI check. `negative_boundaries` and
`forbidden_claim_count` describe these declared checks, not a precision estimate.
Additional output is not exhaustively labelled, so **global precision is not estimated**. A source
revision can invalidate a case and requires re-review, not silently changing its
expected label to match the parser.

Cisco cases cover the ISE exception and shared IoT Field Network Director table in
[the November 2022 OpenSSL advisory](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-openssl-W9sdCc2a).
Aruba cases cover unaffected AOS-CX switches for both OpenSSL CVEs in
[ARUBA-PSA-2022-017](https://csaf.arubanetworking.hpe.com/2022/hpe_aruba_networking_-_2022-017.txt).
Forbidden statuses apply only to explicitly reviewed product boundaries; they are
not added to affected products with legitimate fixed/unaffected version branches.

The enlarged evaluation found and corrected nested Arista heading/date handling
and a Panorama per-CVE exception in a shared Log4j table. Synthetic offline tests
protect these scope boundaries. Publisher assertions still require product/version
and configuration context before operational use.

Fourteen additional OpenSSH cases cover Aruba fixed/affected version boundaries,
legacy AOS-CX, cloud/support-token versus local mode, Rocky Linux 9 deployment
scope, AOS-S and Fabric Composer, plus Arista EOS train exceptions. `claim_context`
selects exact retained product-tree pairs; `claim_version_contains` selects a
reviewed source expression before forbidden-status checks. These selectors do not
implement version arithmetic or generalize a branch conclusion to other branches.
