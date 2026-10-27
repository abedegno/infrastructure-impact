# Fortinet OpenSSH advisory scope — 27 October 2026

The [FG-IR-24-258 HTML advisory](https://www.fortiguard.com/psirt/FG-IR-24-258)
contains explicit assessment lists that are absent from its advertised structured
counterpart. This is a source-format difference; it does not establish intent.
The shared reviewed-source policy preserves separate captures and selects the
reviewed primary scope from either an HTML or direct structured entry point.

The reviewed HTML normalizes 125 statements:

- 101 version-table rows: 51 affected and 50 explicitly not affected.
- 21 explicit not-impacted products, including FortiOS and FortiProxy.
- One investigation statement for FortiNDR.
- Two publisher remediation statements, retained as fixed-only evidence.

The structured counterpart normalizes 135 statements. These totals do not identify
unique physical products or comparable inventory denominators. Selecting HTML is
not a maximum-row-count rule. Both captures retain their own URL, SHA-256, capture
time, parser fingerprint and statement count in the source-choice audit.

## Preserved boundaries

The parser requires the exact advisory identity, title, metadata CVE, local
summary heading, metadata-table boundary and version/affected/solution columns.
Historical CVEs in the upstream OpenSSH version explanation do not supply
additional appliance claims. Changed nested conditions or unfamiliar assessment
paragraphs fail instead of silently extending the recognized scope.

Several FortiManager Cloud train labels occur more than once with disjoint
explicit ranges. Each range remains a separate identity and literal expression;
no arithmetic or union fills the gaps. Duplicate ranges or a train-wide
unaffected statement conflicting with an affected range require review.

An `all versions` expression stays tied to its literal train. Upgrade strings
remain publisher remediation claims. `upcoming` stays planned, migration-only
solutions do not establish an available fixed build, and an unaffected row's
`Not Applicable` is not a fix.

The post-table investigation and not-impacted lists are separate from the version
table. Combined labels such as FortiCASB/FortiCNP remain combined; the collector
does not invent independently counted inventory units. Unlisted products stay
unknown. The global OS/library/ASLR qualifications and SSH prerequisites retain
source pointers and review requirements. Exploitability wording is not converted
to blanket unaffectedness.

The two fixed-only paragraphs report remediation without customer action. They
do not independently prove prior exposure, available appliance firmware or a
particular deployment mode. The normalized product labels remain literal; the
collector does not infer a cloud deployment simply from those statements.

## Selection and comparison

The canonical primary route is `www.fortiguard.com`; the reviewed HTML mirror is
canonicalized to it. A direct structured request for this known advisory identity
also resolves through the reviewed primary policy, so a later pass cannot silently
replace the fuller assessment lists with the narrower counterpart. Contradictory
structured CVE identity fails before that follow-up. Unknown advisory identities
keep the existing vendor resolver behavior.

The OpenSSH study can now show an explicit FortiOS unaffected publisher statement
where it previously had only a vendor reference without family assessment. The
frozen candidate cohort does not change. Product-build/deployment equivalence,
source coverage, lifecycle windows and independent human adjudication remain
unverified, and rates/rankings remain suppressed.

Synthetic tests cover disjoint ranges, explicit unknown/investigating/unaffected
states, planned and fixed-only evidence, composite names, source boundaries,
alternate failures, direct CSAF stability and public projection. This review does
not change or certify the original independent human-review packet.
