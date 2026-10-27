"""Register release-note evidence and explicitly review possible disclosure gaps."""

import argparse
import hashlib
import json
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit

from .adapters.compat import cves
from .application.disclosure import (
    add_fix_evidence,
    import_release_note,
    register_observation,
    signals,
    verify_candidate,
)
from .storage.repository import VENDORS, connect, now


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cohort = sub.add_parser(
        "cohort-validate",
        help="Validate a frozen product-scope definition without opening the vault",
    )
    cohort.add_argument("file", type=Path)
    note = sub.add_parser("release-note")
    note.add_argument("file", type=Path)
    note.add_argument("--url", required=True)
    note.add_argument("--vendor", required=True)
    note.add_argument("--product", required=True)
    note.add_argument("--published-at")
    browser = sub.add_parser(
        "import-browser-capture",
        help="Import labelled rendered-article evidence; does not mark HTTP collection healthy",
    )
    browser.add_argument("file", type=Path)
    browser.add_argument("--expected-version")
    sub.add_parser("browser-captures", help="List private browser capture summaries")
    fix = sub.add_parser("fix-candidate")
    for arg in ("vendor", "product", "cve-id", "version", "released-at", "basis"):
        fix.add_argument("--" + arg, required=True)
    fix.add_argument("--release-evidence-id", type=int, required=True)
    fix.add_argument("--link-evidence-id", type=int, required=True)
    review = sub.add_parser("review-fix")
    review.add_argument("id", type=int)
    review.add_argument("--status", choices=["verified", "rejected", "unreviewed"], required=True)
    review.add_argument("--note", required=True)
    review.add_argument("--observation-id", type=int)
    review.add_argument("--earlier-disclosure-search")
    observation = sub.add_parser("release-observation")
    observation.add_argument("--evidence-id", required=True, type=int)
    for field in ("vendor", "product", "version", "released-at", "kind", "locator"):
        observation.add_argument("--" + field, required=True)
    correction = sub.add_parser(
        "import-correction",
        help="Queue a downloaded proposal for review without altering assessments",
    )
    correction.add_argument("file", type=Path)
    args = parser.parse_args(argv)
    if args.command == "cohort-validate":
        from .application.product_cohorts import definition

        with args.file.open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            parser.error("Product cohort definition exceeds 1 MB")
        value = definition(json.loads(raw))
        print(
            json.dumps(
                {
                    "valid": True,
                    "definition_sha256": value["definition_sha256"],
                    "cohorts": len(value["cohorts"]),
                }
            )
        )
        return
    with closing(connect()) as db, db:
        if args.command == "import-browser-capture":
            from .application.browser_capture import MAX_CAPTURE_BYTES, import_capture

            with args.file.open("rb") as stream:
                raw = stream.read(MAX_CAPTURE_BYTES + 1)
            print(
                json.dumps(
                    import_capture(db, raw, expected_version=args.expected_version), indent=2
                )
            )
        elif args.command == "browser-captures":
            from .application.browser_capture import captures

            print(json.dumps(captures(db), indent=2))
        elif args.command == "release-note":
            import_release_note(
                db, args.file.read_bytes(), args.url, args.vendor, args.product, args.published_at
            )
        elif args.command == "release-observation":
            observation_id = register_observation(
                db,
                args.evidence_id,
                args.vendor,
                args.product,
                args.version,
                args.released_at,
                args.kind,
                args.locator,
            )
            print(json.dumps({"release_observation_id": observation_id}))
        elif args.command == "fix-candidate":
            add_fix_evidence(
                db,
                args.vendor,
                args.product,
                args.cve_id,
                args.version,
                args.released_at,
                args.release_evidence_id,
                args.link_evidence_id,
                args.basis,
            )
        elif args.command == "import-correction":
            raw = args.file.read_bytes()
            if len(raw) > 50000:
                parser.error("Correction proposal exceeds 50 KB")
            proposal = json.loads(raw)
            if (
                proposal.get("kind") != "assessment_correction"
                or proposal.get("vendor") not in VENDORS
                or cves(proposal.get("cve_id", "")) != [proposal.get("cve_id")]
                or urlsplit(proposal.get("source_url", "")).scheme != "https"
                or not proposal.get("explanation", "").strip()
                or not proposal.get("product", "").strip()
            ):
                parser.error("Expected vendor, exact CVE, product, HTTPS source and explanation")
            db.execute(
                "CREATE TABLE IF NOT EXISTS correction_proposals(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE,received_at TEXT,proposal TEXT,review_status TEXT DEFAULT 'pending')"
            )
            db.execute(
                "INSERT OR IGNORE INTO correction_proposals(sha256,received_at,proposal) VALUES(?,?,?)",
                (hashlib.sha256(raw).hexdigest(), now(), json.dumps(proposal)),
            )
        else:
            signals(db)
            db.execute(
                "CREATE TABLE IF NOT EXISTS research_reviews(id INTEGER PRIMARY KEY,fix_id INTEGER,note TEXT,status TEXT,reviewed_at TEXT)"
            )
            if not db.execute("SELECT id FROM fix_evidence WHERE id=?", (args.id,)).fetchone():
                parser.error("Candidate does not exist")
            if not args.note.strip():
                parser.error("Review explanation required")
            if args.status == "verified":
                verify_candidate(
                    db,
                    args.id,
                    args.observation_id,
                    args.earlier_disclosure_search or "",
                    args.note,
                )
            else:
                db.execute(
                    "UPDATE fix_evidence SET review_status=? WHERE id=?", (args.status, args.id)
                )
            db.execute(
                "INSERT INTO research_reviews(fix_id,note,status,reviewed_at) VALUES(?,?,?,?)",
                (args.id, args.note, args.status, now()),
            )
    if args.command not in ("import-browser-capture", "browser-captures"):
        print("Evidence/review saved. A verified date gap does not establish intent.")
