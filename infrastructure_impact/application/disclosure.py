"""Disclosure review signals with traceable evidence, never inferred intent."""

import json
import re

from ..adapters.compat import HTML, cves, pdf_text
from ..storage.repository import evidence, latest
from .comparison import parse_date

SECURITY = re.compile(
    r"\b(security fix|security update|vulnerabilit\w*|buffer overflow|use.after.free|authentication bypass|remote code execution)\b",
    re.I,
)


def import_release_note(db, raw, url, vendor, product, published_at=None):
    text = pdf_text(raw, layout=True) if raw.startswith(b"%PDF") else HTML(raw).root.text()
    with db:
        ev = evidence(db, raw, url, "release_notes")
        db.execute(
            "INSERT OR IGNORE INTO documents(evidence_id,vendor,product,document_type,published_at,source_url,text) VALUES(?,?,?,?,?,?,?)",
            (ev["id"], vendor, product, "release_notes", published_at, url, text),
        )


def signals(db):
    result = []
    # Only latest revision of each release-note source/product is reviewed.
    docs = db.execute(
        "SELECT * FROM documents WHERE id IN (SELECT MAX(id) FROM documents GROUP BY vendor,product,source_url)"
    )
    for doc in docs:
        if SECURITY.search(doc["text"]) and not cves(doc["text"]):
            match = SECURITY.search(doc["text"])
            result.append(
                {
                    "kind": "security_change_without_cve_reference",
                    "vendor": doc["vendor"],
                    "product": doc["product"],
                    "confidence": "review_required",
                    "source_url": doc["source_url"],
                    "evidence_id": doc["evidence_id"],
                    "excerpt": doc["text"][max(0, match.start() - 90) : match.end() + 140],
                    "explanation": "Security-related language without an explicit CVE in this collected release document. Could concern hardening or an issue without a CVE. No vulnerability or concealment inferred.",
                }
            )
    for row in db.execute(
        "SELECT * FROM changes WHERE kind='cve_reference_added' ORDER BY id DESC"
    ):
        r = db.execute(
            "SELECT source_url FROM revisions WHERE id=?", (row["revision_id"],)
        ).fetchone()
        result.append(
            {
                "kind": "cve_reference_added",
                "vendor": row["vendor"],
                "source_url": r["source_url"],
                "confidence": "observed_revision",
                "observed_at": row["observed_at"],
                "details": json.loads(row["details"]),
                "explanation": "CVE association added between locally collected source revisions. This does not establish whether another earlier disclosure existed.",
            }
        )
    # Research observations are separate from confirmed product affectedness.
    records = latest(db)
    for r in records:
        released = parse_date(r.get("reported_fix_date"))
        published = parse_date(r.get("published_at"))
        if released and published and released < published:
            result.append(
                {
                    "kind": "reported_firmware_date_predates_bulletin",
                    "vendor": r["vendor"],
                    "product": "; ".join(sorted({a["product"] for a in r["assessments"]})),
                    "cve_id": ", ".join(r["cves"]),
                    "released_at": r["reported_fix_date"],
                    "advisory_date": r["published_at"],
                    "source_url": r["source_url"],
                    "evidence_id": r["evidence_id"],
                    "confidence": "unverified_release_date_candidate",
                    "explanation": "The bulletin labels fixed firmware with an earlier date. Public availability on that date and absence of earlier disclosures have not been verified. This is a research lead, not proof of a silent fix or concealment.",
                }
            )
    for f in db.execute("SELECT * FROM fix_evidence WHERE review_status='verified'"):
        released = parse_date(f["released_at"])
        matches = [
            r
            for r in records
            if r["vendor"] == f["vendor"]
            and f["cve_id"] in r["cves"]
            and any(
                a["product"] == f["product"] and a["cve_id"] == f["cve_id"]
                for a in r["assessments"]
            )
            and parse_date(r.get("published_at"))
        ]
        if not released or not matches:
            continue
        first = min(matches, key=lambda r: parse_date(r["published_at"]))
        if released >= parse_date(first["published_at"]):
            continue
        result.append(
            {
                "kind": "fix_predates_collected_advisory",
                "vendor": f["vendor"],
                "product": f["product"],
                "cve_id": f["cve_id"],
                "version": f["version"],
                "released_at": f["released_at"],
                "advisory_date": first["published_at"],
                "source_url": first["source_url"],
                "release_evidence_id": f["release_evidence_id"],
                "link_evidence_id": f["link_evidence_id"],
                "basis": f["basis"],
                "confidence": "verified_evidence_review_required",
                "explanation": "Reviewed release and CVE/product-link evidence predates the earliest advisory in this sample. Earlier disclosures may exist elsewhere; intent is not established.",
            }
        )
    return result


def add_fix_evidence(
    db, vendor, product, cve_id, version, released_at, release_evidence_id, link_evidence_id, basis
):
    """Register a candidate; never mark it verified automatically."""
    if (
        not cves(cve_id)
        or cves(cve_id) != [cve_id]
        or not parse_date(released_at)
        or not basis.strip()
    ):
        raise ValueError("Explicit CVE, valid release date, and linkage basis required")
    with db:
        signals(db)  # ensure research table exists
        for eid in (release_evidence_id, link_evidence_id):
            if not db.execute("SELECT id FROM evidence WHERE id=?", (eid,)).fetchone():
                raise ValueError("Evidence snapshot does not exist")
        db.execute(
            "INSERT INTO fix_evidence(vendor,product,cve_id,version,released_at,release_evidence_id,link_evidence_id,basis) VALUES(?,?,?,?,?,?,?,?)",
            (
                vendor,
                product,
                cve_id,
                version,
                released_at,
                release_evidence_id,
                link_evidence_id,
                basis,
            ),
        )
