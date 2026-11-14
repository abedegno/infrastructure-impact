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
MAX_SUMMARY_BYTES = 128_000_000


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


def write_static_delivery(destination, data, *, publication_v2=None):
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

    def summary_delivery(value):
        if len(encode(dict(**identity, data=value))) <= MAX_PART_BYTES:
            return dict(summary=write_part(value))
        raw = encode(value)
        if len(raw) > MAX_SUMMARY_BYTES:
            raise ValueError("Switching summary exceeds 128 MB reconstruction budget")
        text = raw.decode("utf-8")
        # Unicode code points remain whole. A JSON string costs at most six
        # UTF-8 bytes per code point, including escaping, plus its envelope.
        width = min(TARGET_BYTES, (MAX_PART_BYTES - len(encode(dict(**identity, data="")))) // 6)
        if width < 1:
            raise ValueError("Static summary fragment envelope exceeds 8 MB")
        return dict(
            summary_fragments=dict(
                parts=[write_part(text[i : i + width]) for i in range(0, len(text), width)],
                sha256=sha256(raw).hexdigest(),
                bytes=len(raw),
            )
        )

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
    omitted = {
        "records",
        "coverage",
        "timeline",
        "scorecards",
        "comparison_eligibility",
        "changes",
        "switching_evidence",
        "switching_comparison",
        "switching_release_history",
        "switching_analysis",
        "retained_advisories",
        "current_evidence",
    }
    common = {k: v for k, v in data.items() if k not in omitted}
    if "current_evidence" in data:
        common["current_evidence_version"] = 1
    common["retained_index"] = [
        dict(
            decision_id=w["decision_id"],
            vendor=w["record"]["vendor"],
            cves=w["record"]["cves"],
            assessments=[
                dict(
                    cve_id=a["cve_id"],
                    product=a["product"],
                    status=a["status"],
                    search_text=" ".join(
                        (
                            a["product"],
                            json.dumps(
                                a.get("versions", []), separators=(",", ":"), ensure_ascii=False
                            ),
                            " ".join(x[1] for x in a.get("product_context", []))
                            if a.get("product_context") is not None
                            else "undefined",
                        )
                    ),
                )
                for a in w["record"]["assessments"]
            ],
        )
        for w in data.get("retained_advisories", [])
    ]
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
    if "switching_analysis" in data:
        index["switching_analysis"] = summary_delivery(data["switching_analysis"])
    if "current_evidence" in data:
        retained_parts = chunks(data.get("retained_advisories", []))
        index["current_evidence"] = dict(
            schema_version=1,
            report=write_part(data["current_evidence"]),
            retained=[
                dict(
                    decision_ids=[
                        w["decision_id"]
                        for w in json.loads((destination / part["path"]).read_text())["data"]
                    ],
                    cve_ids=sorted(
                        {
                            cid
                            for w in json.loads((destination / part["path"]).read_text())["data"]
                            for cid in w["record"]["cves"]
                        }
                    ),
                    part=part,
                )
                for part in retained_parts
            ],
        )
    if (
        publication_v2 is None
        and "switching_comparison" in data
        and data["switching_comparison"].get("representation") != "summary"
    ):
        from .switching_comparison import summary

        report = data["switching_comparison"]
        evidence, kev = report["inputs"]["evidence"], report["inputs"]["kev"]
        claim_parts = chunks(evidence["claims"])
        claim_index = []
        for part in claim_parts:
            claims = json.loads((destination / part["path"]).read_text())["data"]
            claim_index.append(dict(claim_ids=[c["claim_id"] for c in claims], part=part))
        from .switching_evidence import _validate

        metadata = dict(
            representation="switching-inputs",
            evidence={
                k: v
                for k, v in evidence.items()
                if k not in ("claims", "coverage", "score_availability")
            },
            kev={k: v for k, v in kev.items() if k != "entries"},
        )
        _validate(metadata, "switching-inputs-v1.json")
        index["switching"] = dict(
            **summary_delivery(summary(report)),
            inputs=write_part(metadata),
            claims=claim_index,
            evidence_metadata=chunks(
                [
                    dict(kind=kind, value=value)
                    for kind in ("coverage", "score_availability")
                    for value in evidence.get(kind, [])
                ]
            ),
            has_score_availability="score_availability" in evidence,
            kev_entries=chunks([dict(cve_id=k, entry=v) for k, v in kev["entries"].items()]),
        )
    if publication_v2 is None:
        full = (destination / "snapshot.json").read_bytes()
        index["full"] = dict(path="snapshot.json", sha256=sha256(full).hexdigest(), bytes=len(full))
    else:
        index["schema_version"] = 2
        index["publication_v2"] = publication_v2
    if len(encode(index)) > MAX_INDEX_BYTES and index.get("switching", {}).get("claims"):
        study = index["switching"]
        study["claim_catalog"] = chunks(study.pop("claims"))
    from jsonschema import Draft202012Validator, FormatChecker

    from ..settings import PACKAGE

    Draft202012Validator(
        json.loads(
            (
                PACKAGE
                / (
                    "schemas/static-index-v2.json"
                    if publication_v2
                    else "schemas/static-index-v1.json"
                )
            ).read_text()
        ),
        format_checker=FormatChecker(),
    ).validate(index)
    raw = encode(index)
    if len(raw) > MAX_INDEX_BYTES:
        raise ValueError("Static cohort index exceeds 2 MB; partition its index before publication")
    (folder / "index.json").write_bytes(raw)
    return index
