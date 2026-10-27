"""Source-linked investigation queue; all conclusions require separate review."""

from .investigations import investigation

QUESTIONS = (
    (
        "exact_product_build_and_cve_link",
        "Does retained evidence link this exact product, build, component variant and CVE to a security fix, rather than routine maintenance?",
    ),
    (
        "independent_release_availability",
        "What independent retained release listing or download observation establishes public availability of this exact build on the claimed date?",
    ),
    (
        "earlier_disclosure_search",
        "Which official advisories, release channels, archives and customer notices were searched, over what period, and what remains inaccessible?",
    ),
    (
        "historical_document_availability",
        "Do historical captures establish when the relevant statement became public, separately from current publisher date claims?",
    ),
    (
        "independent_adjudication",
        "Has an independent reviewer assessed scope, chronology, counter-evidence and plausible alternative explanations?",
    ),
)


def disclosure_review(data):
    cases = []
    report = data.get("fix_leads", {})
    for lead in report.get("leads", []):
        urls = {e["source_url"] for e in lead["evidence"]}
        related = [
            c
            for c in data.get("casefiles", {}).get("cases", [])
            if c["vendor"] == lead["vendor"]
            and set(c["selected_cve_ids"]) & set(lead["cve_ids"])
            and urls & set(c["advisory_urls"] + c["release_source_leads"])
        ]
        counter = {}
        for case in related:
            for evidence in case.get("earlier_dated_vendor_documents", []):
                if not set(evidence.get("cve_ids", [])) & set(lead["cve_ids"]):
                    continue
                key = evidence["source_url"], evidence["source_sha256"]
                counter[key] = dict(
                    source_url=key[0],
                    source_sha256=key[1],
                    observed_at=None,
                    publisher_date_claim=evidence["publisher_published_at"],
                )
        cases.append(
            dict(
                id="review-" + lead["id"],
                lead_id=lead["id"],
                investigation=investigation(lead),
                vendor=lead["vendor"],
                product=lead["product"],
                kind=lead["kind"],
                details=lead["details"],
                cve_ids=lead["cve_ids"],
                state="review_required",
                next_action="review_counter_evidence"
                if counter
                else "verify_change_and_scope"
                if lead["kind"] in {"component_version_changed", "security_statement_without_cve"}
                else "establish_availability_and_disclosure",
                evidence=[
                    {
                        k: e.get(k)
                        for k in (
                            "source_url",
                            "source_sha256",
                            "observed_at",
                            "publisher_date_claim",
                        )
                    }
                    for e in lead["evidence"]
                ],
                related_case_ids=sorted(c["id"] for c in related),
                earlier_document_counter_evidence=list(counter.values()),
                checklist=[
                    dict(code=code, state="not_established", question=question)
                    for code, question in QUESTIONS
                ],
                alternative_explanations=list(lead["alternative_explanations"]),
                concealment="not_established",
            )
        )
    return dict(
        schema_version=1,
        cases=cases,
        leads_truncated=bool(report.get("leads_truncated")),
        independent_human_review_completed=False,
        method="Investigation queue derived from eligible public fix leads. Related cases require exact source, vendor and CVE overlap; earlier-dated documents are counter-evidence, not verified historical availability. Action labels order review tasks, not vendor suspicion or severity. A component version change alone has no established CVE linkage or security purpose. All five evidence gates remain unestablished until separate source-led review; this queue never changes review decisions, verifies fixes or infers concealment. Absence of a lead is not absence of a security fix.",
    )
