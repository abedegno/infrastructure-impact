"""Bounded CSAF note ownership, independent of collection and study selection.

A date era is not publisher attribution to a disclosure programme. No source
bullet, CVE or table-row count is interpreted as a count of underlying bugs.
"""

import re
from datetime import UTC, date, datetime

VERSION = "cisco-owned-disclosure-v1"
CVE = r"CVE-\d{4}-\d{4,}"
ROW = re.compile(rf"\b({CVE})\s+(10(?:\.0)?|[0-9](?:\.[0-9])?)\s+(CWE-\d+)\b")


def initial_day(value):
    """Keep input literal elsewhere; only valid day/aware timestamp proves an era."""
    if not isinstance(value, str):
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            return date.fromisoformat(value).isoformat()
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if "T" in value and parsed.tzinfo:
            return parsed.astimezone(UTC).date().isoformat()
    except ValueError:
        pass
    return None


def extract_cisco_disclosure(data):
    """Return document-level metadata and issues; never mutate source input.

    This parser recognises the owned Summary/Details form. Unrecognised forms
    remain unavailable, rather than being inferred from the advisory title.
    """
    doc = data.get("document", {})
    tracking = doc.get("tracking", {})
    notes = doc.get("notes", [])
    issues = []
    if len(notes) > 100 or any(len(n.get("text", "")) > 200000 for n in notes):
        return {"disclosure_metadata": None, "issues": ["disclosure_note_bound_exceeded"]}

    def owned(title):
        matches = [
            (i, n["text"])
            for i, n in enumerate(notes)
            if n.get("title") == title and isinstance(n.get("text"), str)
        ]
        return matches[0] if len(matches) == 1 else (None, None)

    si, summary = owned("Summary")
    di, details = owned("Details")
    grouping = None
    if summary:
        paragraphs = re.split(r"\r?\n\s*\r?\n", summary)
        grouping = next(
            (
                p
                for p in paragraphs
                if re.search(
                    r"Cisco has grouped these issues by their underlying vulnerability class.*"
                    r"Common Weakness Enumeration.*assigned a single Common Vulnerabilities and "
                    r"Exposures identifier",
                    p,
                    re.S,
                )
            ),
            None,
        )
    highest = None
    rows = []
    if details:
        highest = next(
            (
                s.strip()
                for s in re.split(r"\r?\n", details)
                if "maximum potential severity of the single most impactful underlying bug within that specific CWE category"
                in s
            ),
            None,
        )
        rows = ROW.findall(details)
    owners = sorted({v["cve"] for v in data.get("vulnerabilities", []) if v.get("cve")})
    umbrella = []
    if grouping and highest:
        row_ids = [r[0] for r in rows]
        valid = (
            sorted(row_ids) == owners
            and len(row_ids) == len(set(row_ids))
            and len({r[2] for r in rows}) == len(rows)
            and bool(rows)
        )
        # The Details highest score must agree with its exact CVE's structured
        # score; array order and another CVE's score cannot establish ownership.
        for cid, score, cwe in rows:
            vulns = [v for v in data.get("vulnerabilities", []) if v.get("cve") == cid]
            scores = {
                s[k].get("baseScore")
                for v in vulns
                for s in v.get("scores", [])
                for k in ("cvss_v3", "cvss_v4")
                if k in s
            }
            valid &= len(vulns) == 1 and scores == {float(score)}
            if vulns and vulns[0].get("cwe"):
                valid &= vulns[0]["cwe"].get("id") == cwe
        if valid:
            umbrella = [
                dict(
                    cve_id=cid,
                    cwe_id=cwe,
                    highest_cvss=float(score),
                    locator=f"/document/notes/{di}/text[cve={cid}]",
                )
                for cid, score, cwe in sorted(rows)
            ]
        else:
            issues.append("disclosure_details_ownership_unresolved")
    literal = tracking.get("initial_release_date")
    day = initial_day(literal)
    hardening = bool(re.search(r"\bSecurity Hardening Release\b", doc.get("title", "")))
    advisory_type = "security_hardening" if hardening else "unknown"
    classification, basis, locator = None, "unknown", None
    if summary and re.search(
        r"(?:These vulnerabilities|This vulnerability) (?:are|is) in third-party (?:open-source )?software",
        summary,
        re.I,
    ):
        classification, basis, locator = (
            "outside_policy",
            "third_party_exception",
            f"/document/notes/{si}/text",
        )
    elif summary and re.search(r"(?:under|part of) Cisco.s risk-based disclosure", summary, re.I):
        classification, basis, locator = "risk_based", "explicit", f"/document/notes/{si}/text"
    elif day and day < "2026-07-01":
        classification, basis = "pre_risk_based", "dated_rule"
    elif day and hardening and umbrella:
        classification, basis = "risk_based", "date_and_type_rule"
    bundle = None
    if hardening and umbrella:
        bundle = dict(
            id=tracking["id"],
            kind="security_hardening",
            initial_published_at=literal,
            date_locator="/document/tracking/initial_release_date",
            advisory_ids=[tracking["id"]],
            cve_ids=owners,
        )
    return dict(
        disclosure_metadata=dict(
            parser=VERSION,
            advisory_id=tracking.get("id"),
            advisory_type=advisory_type,
            initial_published_at=literal,
            date_precision="day"
            if day and len(literal) == 10
            else "timestamp"
            if day
            else "unknown",
            method=dict(classification=classification, basis=basis, locator=locator),
            grouping_wording=grouping if umbrella else None,
            grouping_locator=f"/document/notes/{si}/text" if umbrella else None,
            highest_cvss_wording=highest if umbrella else None,
            highest_cvss_locator=f"/document/notes/{di}/text" if umbrella else None,
            umbrella_cves=umbrella,
            bug_count=None,
            bug_count_status="not_disclosed",
            bundle=bundle,
        ),
        issues=issues,
    )


def validate_binding(meta, record):
    if (
        record["vendor"] != "cisco"
        or meta["advisory_id"] != record["advisory_id"]
        or meta["initial_published_at"] != record["published_at"]
    ):
        raise ValueError("Disclosure advisory identity mismatch")
    day = initial_day(meta["initial_published_at"])
    precision = (
        "day"
        if day and len(meta["initial_published_at"]) == 10
        else "timestamp"
        if day
        else "unknown"
    )
    if meta["date_precision"] != precision:
        raise ValueError("Disclosure date precision mismatch")
    method = meta["method"]
    expected = {
        "unknown": None,
        "explicit": "risk_based",
        "dated_rule": "pre_risk_based",
        "date_and_type_rule": "risk_based",
        "third_party_exception": "outside_policy",
    }
    if (
        method["classification"] != expected[method["basis"]]
        or (method["basis"] == "dated_rule" and (not day or day >= "2026-07-01"))
        or (
            method["basis"] == "date_and_type_rule"
            and (
                not day
                or day < "2026-07-01"
                or meta["advisory_type"] != "security_hardening"
                or not meta["umbrella_cves"]
            )
        )
        or (method["basis"] in {"explicit", "third_party_exception"} and not method["locator"])
    ):
        raise ValueError("Disclosure method basis mismatch")
    ids = [v["cve_id"] for v in meta["umbrella_cves"]]
    if len(ids) != len(set(ids)) or not set(ids).issubset(record["cves"]):
        raise ValueError("Disclosure CVE ownership mismatch")
    if ids and not all(
        meta[k]
        for k in (
            "grouping_wording",
            "grouping_locator",
            "highest_cvss_wording",
            "highest_cvss_locator",
        )
    ):
        raise ValueError("Disclosure source wording missing")
    b = meta["bundle"]
    if b and (
        b["id"] != record["advisory_id"]
        or b["advisory_ids"] != [record["advisory_id"]]
        or b["cve_ids"] != sorted(record["cves"])
        or sorted(ids) != b["cve_ids"]
        or b["initial_published_at"] != record["published_at"]
    ):
        raise ValueError("Disclosure bundle ownership mismatch")
