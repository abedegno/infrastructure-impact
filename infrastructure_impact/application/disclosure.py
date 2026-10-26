"""Disclosure review signals with traceable evidence, never inferred intent."""

import json
import re

from ..adapters.compat import HTML, cves, pdf_text
from ..storage.repository import evidence, latest, now
from .comparison import parse_date

SECURITY = re.compile(
    r"\b(security fix|security update|vulnerabilit\w*|buffer overflow|use.after.free|authentication bypass|remote code execution)\b",
    re.I,
)


def latest_documents(db):
    records = {}
    for row in db.execute("SELECT * FROM documents ORDER BY id"):
        records[(row["vendor"], row["product"], row["source_url"])] = dict(row)
    for row in db.execute(
        "SELECT d.* FROM document_observations o JOIN documents d ON d.id=o.document_id ORDER BY o.id"
    ):
        records[(row["vendor"], row["product"], row["source_url"])] = dict(row)
    return list(records.values())


def import_release_note(db, raw, url, vendor, product, published_at=None):
    text = pdf_text(raw, layout=True) if raw.startswith(b"%PDF") else HTML(raw).root.text()
    with db:
        previous = next(
            (
                d
                for d in latest_documents(db)
                if d["vendor"] == vendor and d["product"] == product and d["source_url"] == url
            ),
            None,
        )
        ev = evidence(db, raw, url, "release_notes")
        db.execute(
            "INSERT OR IGNORE INTO documents(evidence_id,vendor,product,document_type,published_at,source_url,text) VALUES(?,?,?,?,?,?,?)",
            (ev["id"], vendor, product, "release_notes", published_at, url, text),
        )
        current = db.execute(
            "SELECT * FROM documents WHERE evidence_id=? AND vendor=? AND product=?",
            (ev["id"], vendor, product),
        ).fetchone()
        if not previous or previous["id"] != current["id"]:
            db.execute(
                "INSERT INTO document_observations(document_id,observed_at) VALUES(?,?)",
                (current["id"], now()),
            )
        if previous and previous["id"] != current["id"]:
            before, after = set(cves(previous["text"])), set(cves(text))
            db.execute(
                "INSERT INTO document_changes(document_id,previous_document_id,observed_at,cves_added,cves_removed,security_language_added) VALUES(?,?,?,?,?,?)",
                (
                    current["id"],
                    previous["id"],
                    now(),
                    json.dumps(sorted(after - before)),
                    json.dumps(sorted(before - after)),
                    bool(SECURITY.search(text) and not SECURITY.search(previous["text"])),
                ),
            )


def signals(db):
    result = []
    for row in db.execute(
        "SELECT c.*,d.vendor,d.product,d.source_url,d.evidence_id,p.evidence_id AS previous_evidence_id FROM document_changes c JOIN documents d ON d.id=c.document_id JOIN documents p ON p.id=c.previous_document_id ORDER BY c.id DESC"
    ):
        result.append(
            {
                "kind": "release_note_revision",
                "vendor": row["vendor"],
                "product": row["product"],
                "source_url": row["source_url"],
                "evidence_id": row["evidence_id"],
                "previous_evidence_id": row["previous_evidence_id"],
                "observed_at": row["observed_at"],
                "cves_added": json.loads(row["cves_added"]),
                "cves_removed": json.loads(row["cves_removed"]),
                "security_language_added": bool(row["security_language_added"]),
                "confidence": "observed_revision",
                "explanation": "Differences between retained release-note snapshots. Capture times do not establish first public availability or intent.",
            }
        )
    # Only latest revision of each release-note source/product is reviewed.
    docs = latest_documents(db)
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


def register_observation(db, evidence_id, vendor, product, version, released_at, kind, locator):
    from ..collection.transport import allowed

    ev = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not ev or not allowed(ev["source_url"], vendor):
        raise ValueError("Retained official vendor evidence is required")
    if kind not in ("publisher_date_claim", "public_release_listing", "observed_download"):
        raise ValueError("Unsupported availability observation type")
    if not parse_date(released_at) or not all(v.strip() for v in (product, version, locator)):
        raise ValueError("Product, version, date and exact source locator are required")
    with db:
        return db.execute(
            "INSERT INTO release_observations(evidence_id,vendor,product,version,released_at,observation_type,locator,recorded_at) VALUES(?,?,?,?,?,?,?,?)",
            (evidence_id, vendor, product, version, released_at, kind, locator, now()),
        ).lastrowid


def verify_candidate(db, fix_id, observation_id, earlier_disclosure_search, note):
    fix = db.execute("SELECT * FROM fix_evidence WHERE id=?", (fix_id,)).fetchone()
    observation = db.execute(
        "SELECT * FROM release_observations WHERE id=?", (observation_id,)
    ).fetchone()
    if not fix or not observation or not earlier_disclosure_search.strip() or not note.strip():
        raise ValueError(
            "Candidate, availability observation, earlier-disclosure search and review note required"
        )
    if observation["observation_type"] == "publisher_date_claim":
        raise ValueError("A publisher date claim alone cannot verify public release availability")
    if (
        any(fix[k] != observation[k] for k in ("vendor", "product", "version", "released_at"))
        or fix["release_evidence_id"] != observation["evidence_id"]
    ):
        raise ValueError(
            "Availability observation does not match the candidate product/version/date/evidence"
        )
    release = db.execute(
        "SELECT source_url,sha256 FROM evidence WHERE id=?", (fix["release_evidence_id"],)
    ).fetchone()
    link = db.execute(
        "SELECT source_url,sha256 FROM evidence WHERE id=?", (fix["link_evidence_id"],)
    ).fetchone()
    if release["source_url"] == link["source_url"] or release["sha256"] == link["sha256"]:
        raise ValueError(
            "Independent release-availability and product/CVE-link evidence are required"
        )
    with db:
        db.execute(
            "INSERT INTO fix_review_checks(fix_id,observation_id,earlier_disclosure_search,reviewer_note,reviewed_at) VALUES(?,?,?,?,?)",
            (fix_id, observation_id, earlier_disclosure_search, note, now()),
        )
        db.execute("UPDATE fix_evidence SET review_status='verified' WHERE id=?", (fix_id,))
