# Vendor coverage and review gaps

The **Vendor gaps** dashboard view and `vendor-gaps.json` combine collection,
archive and source-review gaps for the whole publication. They do not follow the
selected CVE cohort. The read-only reader exposes `/api/v1/vendor-gaps` and accepts
one optional `vendor` filter. The strict contract is `schemas/vendor-gaps-v1.json`.

Rows preserve the installed vendor roster, including vendors without a reviewed
sample. They show retained advisory and metadata-only counts, notices without CVE
identifiers, configured-source freshness, latest retained URL errors, pending and
failed archive items, and raw-byte/section-review outcomes separately. A zero-sized
review sample is not an accuracy result. Source errors are the latest retained
check per URL, including older historical or formerly configured URLs; inspect
check dates before interpreting a row as a present outage.

Source-error and unlinked-notice link lists are bounded to 100 per vendor, with
explicit truncation flags. Totals remain visible. Source-error, unresolved-review
and no-CVE filters narrow vendors displayed; they do not establish rates, security
rankings or disclosure completeness. Human adjudication remains pending.

The report is rebuilt from the public projection and fresh extraction checks,
rather than copying caller-supplied reports or review notes. It contains no reviewer
identity, private annotation, raw source bytes or correction submission. Static
cohort delivery retains this global report, so a narrow CVE selection cannot hide
unrelated collection gaps. Publication IDs and generated times bind static exports.
