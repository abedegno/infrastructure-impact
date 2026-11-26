"""Opt-in vendor-complete projections of validated public analysis.

These are delivery objects, never replacement source reports. Native publication
verification regenerates them from the complete source; readers also validate the
compiled payload and its explicit vendor domain before selection.
"""

import copy
import re

from .. import publication_codec as codec
from . import switching_analysis as analysis
from . import switching_comparison as comparison

MANIFEST = "switching-analysis-delivery.json"
VENDORS = tuple(comparison.VENDORS)
FIELDS = {
    "schema_version",
    "representation",
    "publication",
    "generated_at",
    "definition_sha256",
    "observation_end",
    "source_content_sha256",
    "vendor",
    "payload",
    "counts",
    "content_sha256",
}


def root_name(vendor):
    if vendor not in VENDORS:
        raise ValueError("Unknown analysis delivery vendor")
    return f"switching-analysis-vendor-{vendor}.json"


def _digest(value):
    return analysis._hash({k: v for k, v in value.items() if k != "content_sha256"})


def _counts(payload):
    return dict(
        claims=len(payload["claims"]),
        members=len(payload["requirements"]["members"]),
        requirements=len(payload["requirements"]["requirements"]),
    )


def _derive(source, vendor):
    root_name(vendor)
    payload = copy.deepcopy(source)
    payload["claims"] = {k: v for k, v in payload["claims"].items() if v["vendor"] == vendor}
    r = payload["requirements"]
    r["members"] = {k: v for k, v in r["members"].items() if v["vendor"] == vendor}
    r["requirements"] = [q for q in r["requirements"] if q["claim_id"] in r["members"]]
    refs = {c["source_ref"] for c in payload["claims"].values()}
    for m in r["members"].values():
        refs.update(m[k] for k in ("source_ref", "severity_facets_ref"))
    for q in r["requirements"]:
        refs.update(q[k] for k in ("proof_ref", "train_binding_ref"))
    r["facts"] = {k: v for k, v in r["facts"].items() if k in refs}
    member_cves = {}
    for m in r["members"].values():
        member_cves.setdefault((m["vendor"], m["advisory_id"]), set()).add(m["cve_id"])
    r["source_groups"] = [
        g
        for g in r["source_groups"]
        if member_cves.get((g["vendor"], g["advisory_id"]), set()).intersection(g["cve_ids"])
    ]
    groups = {q["inference"]["group_id"] for q in r["requirements"] if q["inference"]}
    r["inference_groups"] = [g for g in r["inference_groups"] if g["group_id"] in groups]
    r["membership_count"] = len(r["members"])
    r["membership_sha256"] = analysis._hash(r["members"])
    r["content_sha256"] = _digest(r)
    selected = analysis.selection_context(source, dict(vendor=vendor))["selection"]
    payload["disclosure"] = analysis._disclosure_selected(
        source["disclosure"], selected, analysis._selected_claims(source, selected)
    )
    payload["kev_reconciliation"] = analysis._kev_selected(source, selected)
    # Existing compiled validation requires complete child contexts, relative to
    # the payload's claims. Selection subsequently replaces these contexts.
    complete = analysis.selection_context(payload, {})["selection"]
    for name in ("disclosure", "kev_reconciliation"):
        payload[name]["selection"] = copy.deepcopy(complete)
    payload["content_sha256"] = _digest(payload)
    out = {
        k: copy.deepcopy(source[k])
        for k in ("publication", "generated_at", "definition_sha256", "observation_end")
    }
    out.update(
        schema_version=1,
        representation="compiled-analysis-vendor",
        vendor=vendor,
        source_content_sha256=source["content_sha256"],
        payload=payload,
        counts=_counts(payload),
    )
    out["content_sha256"] = _digest(out)
    return out


def project_vendor(source, vendor, *, max_bytes=codec.MAX_SELECTED):
    """Validate the complete public source before deriving any projection."""
    analysis.validate_report(source)
    out = _derive(source, vendor)
    validate_vendor(out, max_bytes=max_bytes)
    return out


def validate_vendor(envelope, *, source=None, max_bytes=codec.MAX_SELECTED):
    codec.charge_value(envelope, codec.Budget(min(max_bytes, codec.MAX_SELECTED)))
    if (
        set(envelope) != FIELDS
        or type(envelope["schema_version"]) is not int
        or envelope["schema_version"] != 1
        or envelope["representation"] != "compiled-analysis-vendor"
        or not isinstance(envelope["source_content_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", envelope["source_content_sha256"])
    ):
        raise ValueError("Invalid analysis delivery envelope")
    vendor, payload = envelope["vendor"], envelope["payload"]
    root_name(vendor)
    for key in ("publication", "generated_at", "definition_sha256", "observation_end"):
        if payload[key] != envelope[key]:
            raise ValueError("Analysis delivery identity differs")
    if (
        envelope["content_sha256"] != _digest(envelope)
        or envelope["counts"] != _counts(payload)
        or any(type(n) is not int or n < 0 for n in envelope["counts"].values())
    ):
        raise ValueError("Analysis delivery fingerprint/counts differ")
    analysis.validate_report(payload)
    if (
        any(c["vendor"] != vendor for c in payload["claims"].values())
        or any(m["vendor"] != vendor for m in payload["requirements"]["members"].values())
        or any(
            e["mapping"]["vendor"] not in (None, vendor)
            for e in payload["kev_reconciliation"]["entries"]
        )
    ):
        raise ValueError("Analysis delivery vendor domain differs")
    if source is not None:
        analysis.validate_report(source)
        if envelope != _derive(source, vendor):
            raise ValueError("Analysis delivery source closure differs")
    return envelope


def select_vendor(envelope, study, *, max_bytes=codec.MAX_SELECTED):
    validate_vendor(envelope)
    if study["selection"]["requested_vendor"] != envelope["vendor"]:
        raise ValueError("Analysis delivery selected vendor differs")
    return analysis.select_report(envelope["payload"], study, max_bytes=max_bytes)


def delivery_views(source):
    """Derive every optional root from one freshly validated full public report."""
    analysis.validate_report(source)
    manifest = {
        k: copy.deepcopy(source[k])
        for k in ("publication", "generated_at", "definition_sha256", "observation_end")
    }
    manifest.update(
        schema_version=1,
        representation="analysis-vendor-delivery",
        source_content_sha256=source["content_sha256"],
        vendors={},
    )
    views = {}
    for vendor in VENDORS:
        envelope = _derive(source, vendor)
        validate_vendor(envelope)
        name = root_name(vendor)
        views[name] = envelope
        manifest["vendors"][vendor] = dict(
            root=name, content_sha256=envelope["content_sha256"], counts=envelope["counts"]
        )
    manifest["content_sha256"] = _digest(manifest)
    codec.charge_value(manifest, codec.Budget(2_000_000))
    views[MANIFEST] = manifest
    return views
