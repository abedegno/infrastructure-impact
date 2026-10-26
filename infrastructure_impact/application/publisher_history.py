"""Project bounded publisher documentation chronologies from retained sources."""

import json

from jsonschema import Draft202012Validator, FormatChecker

from ..collection.transport import allowed
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from .disclosure import latest_documents


def publisher_history(db):
    documents = []
    for doc in latest_documents(db):
        hook = default_registry().get(doc["vendor"]).parse_document_history
        if not hook:
            continue
        evidence = db.execute("SELECT * FROM evidence WHERE id=?", (doc["evidence_id"],)).fetchone()
        row = dict(
            vendor=doc["vendor"],
            source_url=doc["source_url"],
            source_sha256=evidence["sha256"],
            observed_at=evidence["observed_at"],
            events=[],
            product=doc["product"],
            version=None,
        )
        try:
            history = hook(evidence["raw"], doc["source_url"], doc["vendor"])
            if history is None:
                continue
            row.update(**history, state="parsed")
        except (ValueError, KeyError):
            row["state"] = "unsupported_or_invalid_document"
        documents.append(row)
    return dict(
        schema_version=1,
        documents=documents,
        method="Dates are claims in the current retained publisher document. They are not historical captures, first disclosure, firmware availability, or verified fix dates. A documentation edit does not establish concealment. Unsupported layouts remain visible.",
    )


def public_history(report, urls):
    schema = json.loads((PACKAGE / "schemas/publisher-history-v1.json").read_text())
    keys = schema["properties"]["documents"]["items"]["properties"]
    documents = [
        {k: d[k] for k in keys} for d in report.get("documents", []) if d["source_url"] in urls
    ]
    result = dict(
        schema_version=1,
        method=report.get(
            "method",
            "Publisher-reported documentation chronology; not verified release availability.",
        ),
        documents=documents,
    )
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(result)
    if any(not allowed(d["source_url"], d["vendor"]) for d in documents):
        raise ValueError("Publisher history must use official HTTPS sources")
    return result
