# Research methodology

## Product impact

An upstream CVE identifies vulnerable software, but does not enumerate every
appliance embedding it. Count a downstream product only when a primary vendor
statement, scoped release note or other reviewed product/version evidence links
it to the CVE. Preserve the original scope, platform, configuration and locator.
Do not infer impact from a library name, scanner signature, CPE substring or
another vendor's advisory. Protection signatures are not product-exposure claims.

Structured exports can omit data visible on publisher pages. The pilot recovered
Cisco product tables and Palo Alto per-CVE fix tables from reviewed HTML where
their structured representations were incomplete. Empty CSAF envelopes and RSS
titles establish discovery, not product applicability. Check Point's detailed SK
article can take precedence over its abbreviated active index.

## Comparing vendors

All vendors share one selected CVE denominator. Counts are distinct CVEs with at
least one documented product statement, not counts of version rows. Columns can
overlap across products. Shared-bulletin applicability is labelled separately.
Draft sources are excluded from comparison. Missing-in-dataset, checked-no-match,
unparsed discovery and failed collection are different conditions.

The default eleven-CVE/six-component benchmark is purposive, not representative.
It has no installed-base, full portfolio or tested-dependency denominator. It
cannot establish which vendor is inherently more secure. Source breadth and
disclosure practice affect the counts. HTTP availability and schema conformance
do not establish comprehensive coverage or truth.

## Disclosure evidence

Observable leads include security changes without a CVE reference, CVEs added
between locally observed source revisions, and reviewed fixed-version evidence
predating the earliest collected advisory. A firmware label or planned patch is
not proof that a fix was publicly available on that date. The earliest collected
advisory is not necessarily the earliest disclosure anywhere.

The HPE Cray/OpenSSH case remains an unverified reported-date candidate. Its
investigation record lists attempted corroboration and missing original release
records. No intentional-concealment finding is established. Do not convert
absence of a statement or a failed fetch into a claim of concealment.

Parser fingerprints, raw-source hashes and source-view classifications prevent
code changes or alternative exports from becoming false publisher alerts. A
parser and source changing together can require manual attribution; conservative
suppression is preferable to asserting a disclosure event that was not observed.

## Corrections and limits

The dashboard downloads a correction proposal; it does not claim to submit one.
Operators can queue it using `impact research import-correction FILE`. Proposals
remain private and pending until primary evidence is reviewed. Correct the
adapter/configuration, add a regression fixture, replay, audit and republish.
Never apply contributor claims as vendor assessments without review.

Not implemented: independent firmware binary/SBOM analysis, signature verification,
full publisher CSAF schema conformance, universal appliance version comparison,
and automated inventory applicability. These are explicit boundaries, not inferred
security guarantees. Existing aggregators overlap this domain; the contribution
here is product scope, provenance, coverage transparency and evidence review.
