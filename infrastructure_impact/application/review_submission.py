"""Audit a private independent-review proposal without changing public evidence."""

import json
from datetime import datetime, timezone

from jsonschema import Draft202012Validator, FormatChecker

from ..settings import PACKAGE
from .eligibility import timestamp
from .extraction_validation import packet_sha256


def submission_template(packet):
    return dict(
        schema_version=1,
        packet_sha256=packet["packet_sha256"],
        reviewer=dict(kind=None, display_name=None, reviewed_at=None, independence_statement=None),
        adjudications=[
            dict(
                id=q["id"],
                source_sha256=None,
                product_scope=None,
                status=None,
                versions=None,
                configuration_qualifiers=None,
                remediation=None,
                date_basis=None,
                rationale=None,
            )
            for d in packet["documents"]
            for q in d["questions"]
        ],
    )


def audit_submission(submission, packet, now=None):
    schema = json.loads((PACKAGE / "schemas/review-submission-v1.json").read_text())
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    error = next(validator.iter_errors(submission), None)
    if error:
        raise ValueError(
            "Invalid review submission fields or bounds: "
            + "/".join(str(p) for p in error.absolute_path)
        )
    if (
        packet.get("packet_sha256") != packet_sha256(packet)
        or submission["packet_sha256"] != packet["packet_sha256"]
    ):
        raise ValueError("Review submission does not bind to this unchanged review packet")
    reviewed = timestamp(submission["reviewer"]["reviewed_at"])
    if not reviewed or reviewed > (now or datetime.now(timezone.utc)):
        raise ValueError("Review date must be a past timezone-qualified timestamp")
    questions = {}
    for document in packet["documents"]:
        for question in document["questions"]:
            if question["id"] in questions:
                raise ValueError("Review packet question IDs must be unique")
            questions[question["id"]] = {
                document["reviewed_source_sha256"],
                *document["current_source_fingerprints"],
            }
    seen, rows = set(), []
    for answer in submission["adjudications"]:
        identity = answer["id"]
        if identity in seen or identity not in questions:
            raise ValueError("Unknown or duplicate adjudication ID")
        seen.add(identity)
        if answer["status"] != "not_adjudicated" and not answer["source_sha256"]:
            raise ValueError(
                "An adjudicated product statement requires its exact source fingerprint"
            )
        rows.append(
            dict(
                id=identity,
                declared_product_status=answer["status"],
                source_binding="not_adjudicated"
                if answer["status"] == "not_adjudicated"
                else "retained_source_matches"
                if answer["source_sha256"] in questions[identity]
                else "source_not_in_packet",
            )
        )
    return dict(
        schema_version=1,
        packet_sha256=packet["packet_sha256"],
        submission_status="requires_maintainer_review",
        declared_reviewer_kind=submission["reviewer"]["kind"],
        reviewer_independence_verified=False,
        independent_human_review_completed=False,
        adjudications=rows,
        not_submitted_ids=sorted(set(questions) - seen),
        reviewer_content_published=False,
        assessments_changed=False,
        metric_eligibility_changed=False,
        method="Private proposal audit only. Reviewer identity, independence and semantic conclusions are not machine-certified. Names and rationale are excluded from this audit output. A source mismatch requires a new evidence review; no expected labels, assessments or comparison eligibility are changed.",
    )
