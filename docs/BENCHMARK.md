# Benchmark and extraction evaluation

The declared cohort has **24 CVEs across 13 component families**:
Log4j, OpenSSL, OpenSSH, curl, Linux, PHP, XZ, libwebp, HTTP/2, zlib, Expat, Python
and Go. Its authoritative definition is `resources/benchmark-cohort.json` inside
the package; the dashboard reads that definition from its publication. It is a
purposive sample, including applicability exceptions and precautionary fixes.
It is not a representative sample for ranking vendor security.

`resources/benchmark-cases.json` contains **27 declared mapping expectations** over
primary sources from Arista, Palo Alto Networks, Check Point, Fortinet and HPE.
Each identifies its vendor, CVE, exact source URL, product selector, expected status,
optional version/scope constraint, rationale, review method and review date.
These cases were reviewed by an automated assistant against primary vendor text,
not independently adjudicated by multiple human reviewers. Cisco and Aruba remain
in the wider collection; not every vendor/cohort pair has a curated expectation.

Run `impact evaluate` against a collected vault. `--fail-on-disagreement` exits
nonzero when a declared case is absent or disagrees. Publications include
`benchmark.json` with pass/missing/disagreement states and exact source fingerprints.
This measures presence of the expected scoped statements. Additional output is
not exhaustively labelled, so **global precision is not estimated**. A source
revision can invalidate a case and requires re-review, not silently changing its
expected label to match the parser.

The enlarged evaluation found and corrected nested Arista heading/date handling
and a Panorama per-CVE exception in a shared Log4j table. Synthetic offline tests
protect these scope boundaries. Publisher assertions still require product/version
and configuration context before operational use.
