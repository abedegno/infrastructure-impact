"""Two exact reviewed representation conflicts; never an advisory/CVE alias.

The registry validates private frames before this callback. Reparse those bytes
here: retained normalized fields and selection error codes cannot prove scope.
"""

import base64
import json
from hashlib import sha256
from urllib.parse import urljoin

from ..adapters import arista_sa0137 as sa137
from ..adapters.arista_reconciliation import CSAF103, CSAF103_ID, URL103
from ..adapters.arista_reconciliation import parse as reviewed_html
from ..adapters.arista_scoped import article
from ..adapters.common import HTML
from ..adapters.standards import csaf
from ..application.evidence_identity import record_key
from .shared import structured

REVIEWED_SHA256 = "3491af5ed3486c8e74fd04cd432a5072bf0938733cd059d9d24e7f3f2355ef74"
PRIMARY_ID = "19917-security-advisory-0103"
PRIMARY_CVES = ["CVE-2024-6858"]
LEGACY_CVES = ["CVE-2023-5501"]
PRIMARY_LOCATOR = "tracking header / Affected Software"
ALTERNATE_LOCATOR = "document.tracking.id / vulnerabilities[].cve"
_CAPTURE_FIELDS = ("source_url", "source_sha256", "evidence_id", "source_observed_at")


def _capture_identity(frame):
    return {k: frame[k] for k in _CAPTURE_FIELDS}


def _record_matches_frame(record, frame):
    return (
        record.get("source_url") == frame["source_url"]
        and record.get("sha256") == frame["source_sha256"]
        and type(record.get("evidence_id")) is int
        and record["evidence_id"] == frame["evidence_id"]
        and record.get("source_observed_at") == frame["source_observed_at"]
    )


def _primary_is_reviewed(raw):
    primary = reviewed_html(raw, URL103, "arista")
    if primary["advisory_id"] != PRIMARY_ID or primary["cves"] != PRIMARY_CVES:
        return False
    # Bind the advertised pair to the reviewed article heading, as collection
    # does. A navigation/footer link cannot authenticate this alternate.
    node, _ = article(raw, URL103, "0103")
    heading = next(n for n in node.find({"h2"}) if n.text().startswith("Security Advisory "))
    links = list(
        dict.fromkeys(
            urljoin(URL103, n.attrs.get("href", ""))
            for n in heading.find({"a"})
            if "csaf" in n.attrs.get("href", "").lower()
            and n.attrs.get("href", "").lower().endswith(".json")
        )
    )
    return links == [CSAF103]


def _alternate_proves_conflict(raw):
    # Comparison only. This intentionally never calls the guarded Arista
    # normalizer and never returns its assessments as current claims.
    data = json.loads(raw)
    entries = data.get("vulnerabilities")
    if (
        not isinstance(entries, list)
        or not entries
        or any(not isinstance(v, dict) or v.get("cve") != LEGACY_CVES[0] for v in entries)
        or data.get("document", {}).get("tracking", {}).get("id") != CSAF103_ID
    ):
        return False
    alternate = structured(raw, CSAF103, "arista")
    return alternate["advisory_id"] == CSAF103_ID and alternate["cves"] == LEGACY_CVES


def _proofs(records, context, target):
    selections = [
        s
        for s in context["selections"]
        if s["vendor"] == "arista" and s["requested_url"] in (URL103, CSAF103)
    ]
    if not selections:
        return None
    selected = [v for s in selections for v in s["views"] if v["selected"]]
    if (
        len(selected) != len(selections)
        or any(v["source_url"] != URL103 for v in selected)
        or any(_capture_identity(v) != _capture_identity(selected[0]) for v in selected)
    ):
        return None
    primary_frames = [
        f for f in context["sources"] if _capture_identity(f) == _capture_identity(selected[0])
    ]
    alternate_frames = [f for f in context["sources"] if _record_matches_frame(target, f)]
    if len(primary_frames) != 1 or len(alternate_frames) != 1:
        return None
    primary_frame, alternate_frame = primary_frames[0], alternate_frames[0]
    primary_records = [r for r in records if _record_matches_frame(r, primary_frame)]
    if not primary_records or any(
        r["vendor"] != "arista" or r["advisory_id"] != PRIMARY_ID or r.get("cves") != PRIMARY_CVES
        for r in primary_records
    ):
        return None
    try:
        if not _primary_is_reviewed(base64.b64decode(primary_frame["raw_b64"], validate=True)):
            return None
        if not _alternate_proves_conflict(
            base64.b64decode(alternate_frame["raw_b64"], validate=True)
        ):
            return None
    except Exception:
        # Private parser diagnostics must not cross the public hook boundary.
        return None
    return [
        {**_capture_identity(primary_frame), "locator": PRIMARY_LOCATOR},
        {**_capture_identity(alternate_frame), "locator": ALTERNATE_LOCATOR},
    ]


def _decide103(records, selection_context):
    """Exclude only exact reviewed bytes with independently proven paired scopes."""
    decisions, issues = [], []
    for record in records:
        if not (
            record.get("vendor") == "arista"
            and record.get("advisory_id") == CSAF103_ID
            and record.get("source_url") == CSAF103
            and record.get("cves") == LEGACY_CVES
            and record.get("sha256") == REVIEWED_SHA256
        ):
            continue
        key = record_key(record)
        proofs = _proofs(records, selection_context, record)
        if proofs is None:
            issues.append({"target_key": key, "code": "proof_unresolved"})
        else:
            decisions.append({"target_key": key, "proofs": proofs})
    return {"decisions": decisions, "issues": issues}


PRIMARY137_LOCATOR = (
    "Affected Software / EOS Versions; Affected Platforms; Required Configuration for Exploitation"
)
ALTERNATE137_LOCATOR = "document.tracking / product_tree / vulnerabilities[].product_status"


def _proofs137(records, context, target):
    selections = [
        s
        for s in context["selections"]
        if s["vendor"] == "arista" and s["requested_url"] in {sa137.URL, sa137.CSAF}
    ]
    if not selections:
        return None
    identity = None
    for selection in selections:
        selected = [v for v in selection["views"] if v["selected"]]
        alternates = [
            v for v in selection["views"] if not v["selected"] and _record_matches_frame(target, v)
        ]
        if len(selected) != 1 or selected[0]["source_url"] != sa137.URL or len(alternates) != 1:
            return None
        if identity is not None and identity != _capture_identity(selected[0]):
            return None
        identity = _capture_identity(selected[0])
    primary_frames = [f for f in context["sources"] if _capture_identity(f) == identity]
    alternate_frames = [f for f in context["sources"] if _record_matches_frame(target, f)]
    if len(primary_frames) != 1 or len(alternate_frames) != 1:
        return None
    primary_frame, alternate_frame = primary_frames[0], alternate_frames[0]
    primary_records = [r for r in records if _record_matches_frame(r, primary_frame)]
    if not primary_records or any(
        r.get("vendor") != "arista"
        or r.get("advisory_id") != sa137.ID
        or r.get("cves") != sa137.CVES
        for r in primary_records
    ):
        return None
    try:
        primary_raw = base64.b64decode(primary_frame["raw_b64"], validate=True)
        alternate_raw = base64.b64decode(alternate_frame["raw_b64"], validate=True)
        if (
            sha256(primary_raw).hexdigest() != primary_frame["source_sha256"]
            or sha256(alternate_raw).hexdigest() != sa137.REVIEWED_SHA256
        ):
            return None
        parsed = sa137.parse(primary_raw, sa137.URL, "arista")
        if (
            parsed["advisory_id"] != sa137.ID
            or parsed["cves"] != sa137.CVES
            or not sa137.draft_shape(alternate_raw)
        ):
            return None
        node, _ = article(primary_raw, sa137.URL, "0137")
        heading = next(n for n in node.find({"h2"}) if n.text().startswith("Security Advisory "))
        links = list(
            dict.fromkeys(
                urljoin(sa137.URL, n.attrs.get("href", ""))
                for n in heading.find({"a"})
                if "csaf" in n.attrs.get("href", "").lower()
                and n.attrs.get("href", "").lower().endswith(".json")
            )
        )
        if links != [sa137.CSAF]:
            return None
        alternate = structured(alternate_raw, sa137.CSAF, "arista")
        if alternate["advisory_id"] != sa137.CSAF_ID or alternate["cves"] != sa137.CVES:
            return None
    except Exception:
        return None
    return [
        {**_capture_identity(primary_frame), "locator": PRIMARY137_LOCATOR},
        {**_capture_identity(alternate_frame), "locator": ALTERNATE137_LOCATOR},
    ]


def decide(records, selection_context):
    """Bounded combined policy; unmatched/future SA-0137 bytes stay unresolved."""
    result = _decide103(records, selection_context)
    for record in records:
        if record.get("vendor") != "arista" or record.get("source_url") != sa137.CSAF:
            continue
        proofs = None
        if (
            record.get("advisory_id") == sa137.CSAF_ID
            and record.get("cves") == sa137.CVES
            and record.get("sha256") == sa137.REVIEWED_SHA256
        ):
            proofs = _proofs137(records, selection_context, record)
        key = record_key(record)
        if proofs is None:
            result["issues"].append({"target_key": key, "code": "proof_unresolved"})
        else:
            result["decisions"].append({"target_key": key, "proofs": proofs})
    return result


decide.policy_id = "arista-reviewed-representation-scope-conflict"
decide.policy_version = "2"
decide.reason_text = (
    "Exact reviewed retained Arista CSAF captures conflict with independently proven selected "
    "HTML scope: SA-0103 tracks a different literal CVE; SA-0137 is a draft EOS 1.0.0 "
    "placeholder rather than the HTML's conditional platform scope. Retained evidence is "
    "excluded only with complete paired capture proof. No identity or remediation transfer is inferred. "
    "SA-0103 policy version 1 audit history remains retained."
)
decide.proof_sources = (URL103, CSAF103, sa137.URL, sa137.CSAF)
decide.proof_locators = (
    PRIMARY_LOCATOR,
    ALTERNATE_LOCATOR,
    PRIMARY137_LOCATOR,
    ALTERNATE137_LOCATOR,
)
decide.proof_captures = (
    {"source_url": CSAF103, "source_sha256": REVIEWED_SHA256},
    {"source_url": sa137.CSAF, "source_sha256": sa137.REVIEWED_SHA256},
)
decide.policy_dependencies = (
    reviewed_html,
    article,
    HTML,
    structured,
    csaf,
    record_key,
    sa137.parse,
    sa137.draft_shape,
)
