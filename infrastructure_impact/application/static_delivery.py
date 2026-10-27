"""Content-addressed cohort delivery derived solely from the public projection.

Keep the full snapshot for downloads and the Python reader. Browser requests use
one index, shared metadata and only the selected cohort's evidence. Source changes
are fetched separately. Every part is bound to the publication and its bytes.
"""

import json
from hashlib import sha256

TARGET_BYTES = 512_000
MAX_PART_BYTES = 8_000_000
MAX_INDEX_BYTES = 2_000_000


def encode(value):
    return (
        json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n"
    ).encode()


def product_label_context(records, vendor):
    """Publisher family context for display; literal label identities stay intact."""
    labels = {}
    for record in records:
        if record["vendor"] != vendor or record.get("document_status") == "draft":
            continue
        for claim in record["assessments"]:
            entry = labels.setdefault(claim["product"], dict(families=set(), unscoped=False))
            family = claim.get("product_family")
            if family:
                entry["families"].add(family)
            else:
                entry["unscoped"] = True
    return {
        label: dict(families=sorted(entry["families"]), unscoped=entry["unscoped"])
        for label, entry in sorted(labels.items())
    }


def write_static_delivery(destination, data):
    folder = destination / "data"
    folder.mkdir(exist_ok=True)
    identity = dict(
        schema_version=1, publication=data["publication"], generated_at=data["generated_at"]
    )

    def write_part(value):
        raw = encode(dict(**identity, data=value))
        if len(raw) > MAX_PART_BYTES:
            raise ValueError(
                "Static evidence part exceeds 8 MB; split the oversized row before publication"
            )
        digest = sha256(raw).hexdigest()
        path = "data/" + digest + ".json"
        (destination / path).write_bytes(raw)
        return dict(path=path, sha256=digest, bytes=len(raw))

    def chunks(rows):
        parts, batch, size = [], [], 0
        for row in rows:
            length = len(encode(row))
            if batch and size + length > TARGET_BYTES:
                parts.append(write_part(batch))
                batch, size = [], 0
            batch.append(row)
            size += length
        if batch:
            parts.append(write_part(batch))
        return parts

    by_cve = {
        cid: []
        for cid in sorted(
            set(data["all_cves"])
            | set(data["benchmark_cohort"])
            | {c["cve_id"] for c in data["coverage"]}
        )
    }
    for i, record in enumerate(data["records"]):
        for cid in record["cves"]:
            by_cve.setdefault(cid, []).append(
                dict(
                    kind="record",
                    index=i,
                    record={k: v for k, v in record.items() if k != "assessments"},
                    assessments=[
                        [j, a] for j, a in enumerate(record["assessments"]) if a["cve_id"] == cid
                    ],
                )
            )
    for row in data["coverage"]:
        by_cve.setdefault(row["cve_id"], []).append(dict(kind="coverage", value=row))
    for card in data["scorecards"]["vendors"]:
        for case in card["cases"]:
            by_cve.setdefault(case["cve_id"], []).append(
                dict(kind="scorecard", vendor=card["vendor"], value=case)
            )
    for i, event in enumerate(data["timeline"]["events"]):
        by_cve.setdefault(event["cve_id"], []).append(dict(kind="timeline", index=i, value=event))
    omitted = {"records", "coverage", "timeline", "scorecards", "comparison_eligibility", "changes"}
    common = {k: v for k, v in data.items() if k not in omitted}
    common["records"], common["coverage"], common["changes"] = [], [], []
    common["timeline"] = {**data["timeline"], "events": []}
    common["scorecards"] = {
        **data["scorecards"],
        "vendors": [{**v, "cases": []} for v in data["scorecards"]["vendors"]],
    }
    common["draft_advisories_count"] = sum(
        r.get("document_status") == "draft" for r in data["records"]
    )
    common["record_vendors"] = sorted({r["vendor"] for r in data["records"]})
    common["non_draft_record_vendors"] = sorted(
        {r["vendor"] for r in data["records"] if r.get("document_status") != "draft"}
    )
    common["product_label_index"] = {
        vendor: dict(
            context=product_label_context(data["records"], vendor),
            all=sorted(
                {
                    a["product"]
                    for r in data["records"]
                    if r["vendor"] == vendor and r.get("document_status") != "draft"
                    for a in r["assessments"]
                }
            ),
            groups={
                g["group"]: g["product_labels"]
                for g in next(
                    v for v in data["product_groups"]["vendors"] if v["vendor"] == vendor
                )["groups"]
            },
        )
        for vendor in data["vendors"]
    }
    # A complete record catalog supplies product-label scope; fetching a narrow
    # cohort must never silently narrow comparison denominators or hide vendors.
    index = dict(
        **identity,
        bootstrap=write_part(common),
        cohorts={cid: chunks(rows) for cid, rows in by_cve.items()},
        changes=chunks(data["changes"]),
    )
    full = (destination / "snapshot.json").read_bytes()
    index["full"] = dict(path="snapshot.json", sha256=sha256(full).hexdigest(), bytes=len(full))
    from jsonschema import Draft202012Validator, FormatChecker

    from ..settings import PACKAGE

    Draft202012Validator(
        json.loads((PACKAGE / "schemas/static-index-v1.json").read_text()),
        format_checker=FormatChecker(),
    ).validate(index)
    raw = encode(index)
    if len(raw) > MAX_INDEX_BYTES:
        raise ValueError("Static cohort index exceeds 2 MB; partition its index before publication")
    (folder / "index.json").write_bytes(raw)
    return index
