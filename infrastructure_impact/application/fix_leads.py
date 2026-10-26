"""Dated, bounded research leads. Never infer a hidden fix, exposure or intent."""

import hashlib
import json
import re
from collections import defaultdict

from ..adapters.common import HTML, cves
from ..collection.transport import allowed
from ..plugins.registry import default_registry
from ..storage.observations import history as retrieval_history
from .disclosure import latest_documents

SECTIONS = {
    "resolved issues",
    "security fixes",
    "security updates",
    "common vulnerabilities and exposures",
    "open source components",
    "third-party components",
    "component versions",
    "updated components",
    "software components",
}
SECURITY = re.compile(
    r"\b(security fix|security update|vulnerabilit\w*|authentication bypass|buffer overflow|use.after.free|remote code execution)\b",
    re.I,
)
COMPONENT = r"(OpenSSL|OpenSSH|curl|PHP|nginx|libxml2)"
VERSION = r"(\d+(?:\.\d+){1,3}[a-z]?(?:[-+][A-Za-z0-9.]+)?)"
ALTERNATIVES = [
    "Routine maintenance or dependency refresh rather than a security fix.",
    "Hardening, backports, packaging changes or corrections to documentation.",
    "A separate earlier advisory, issue tracker or release channel may already disclose the issue.",
    "Publisher date claims and local capture dates can differ from public availability.",
]
SECTION_SCOPE = "Literal references in reviewed document sections; exact appliance, patch applicability and backport status are unverified."


def scoped_document(raw, url, vendor):
    parser = default_registry().get(vendor).parse_component_inventory
    if parser:
        try:
            result = parser(raw, url, vendor)
        except ValueError:
            return dict(
                state="component_inventory_layout_requires_review",
                blocks=[],
                components={},
                component_scope=SECTION_SCOPE,
            )
        if result is not None:
            return result
    return scoped_release(raw)


def scoped_release(raw):
    if raw.startswith(b"%PDF"):
        return dict(state="unsupported_pdf_section_scope", blocks=[], components={})
    root = HTML(raw).root
    blocks = []
    active = None
    depth = 0
    for node in root.find({"h1", "h2", "h3", "h4", "p", "li", "tr", "pre"}):
        text = node.text()
        if node.tag in {"h1", "h2", "h3", "h4"}:
            level = int(node.tag[1])
            if text.casefold() in SECTIONS:
                active = text
                depth = level
            elif active and level <= depth:
                active = None
            continue
        if not active or not text:
            continue
        parent = node.parent
        nested = False
        while parent:
            if parent.tag in {"p", "li", "tr", "pre"}:
                nested = True
                break
            parent = parent.parent
        if nested:
            continue
        blocks.append(
            dict(
                locator=active + " / block " + str(len(blocks) + 1),
                text=text[:2000],
                cves=cves(text),
            )
        )
        if len(blocks) >= 200:
            break
    components = defaultdict(set)
    for block in blocks:
        text = block["text"]
        if block["locator"].split(" / ")[0].casefold() in {
            "open source components",
            "third-party components",
            "component versions",
            "updated components",
            "software components",
        }:
            patterns = [COMPONENT + r"\s+(?:version\s+)?" + VERSION]
        else:
            patterns = [
                r"(?:bundled|includes|ships with|updated to|upgraded to)\s+"
                + COMPONENT
                + r"\s+(?:version\s+)?"
                + VERSION,
                COMPONENT + r"\s+(?:was\s+)?(?:updated|upgraded)\s+to\s+" + VERSION,
            ]
        for pattern in patterns:
            for name, version in re.findall(pattern, text, re.I):
                components[name.casefold()].add(version)
    return dict(
        state="scoped" if blocks else "no_reviewed_release_section",
        blocks=blocks,
        components={k: sorted(v) for k, v in components.items()},
    )


def evidence_inputs(db):
    snapshots = defaultdict(list)
    rows = db.execute(
        "SELECT o.id AS observation_id,o.observed_at AS capture,d.*,e.sha256,e.raw FROM document_observations o JOIN documents d ON d.id=o.document_id JOIN evidence e ON e.id=d.evidence_id ORDER BY o.id DESC LIMIT 400"
    )
    for row in rows:
        key = row["vendor"], row["product"], row["source_url"]
        group = snapshots[key]
        if len(group) >= 2 or any(s["document_id"] == row["id"] for s in group):
            continue
        group.append(
            dict(
                document_id=row["id"],
                source_url=row["source_url"],
                source_sha256=row["sha256"],
                observed_at=row["capture"],
                publisher_date_claim=row["published_at"],
                analysis=scoped_document(row["raw"], row["source_url"], row["vendor"]),
            )
        )
    # Older retained documents may predate document-observation logging.
    # Their first retained source timestamp supplies a baseline, never a prior capture.
    for document in latest_documents(db):
        key = document["vendor"], document["product"], document["source_url"]
        if snapshots.get(key):
            continue
        ev = db.execute("SELECT * FROM evidence WHERE id=?", (document["evidence_id"],)).fetchone()
        snapshots[key].append(
            dict(
                document_id=document["id"],
                source_url=document["source_url"],
                source_sha256=ev["sha256"],
                observed_at=ev["observed_at"],
                publisher_date_claim=document["published_at"],
                analysis=scoped_document(ev["raw"], document["source_url"], document["vendor"]),
            )
        )
    advisory = []
    for row in db.execute(
        "SELECT c.*,r.source_url,r.evidence_id FROM changes c JOIN revisions r ON r.id=c.revision_id WHERE c.kind='cve_reference_added' ORDER BY c.id DESC LIMIT 100"
    ):
        previous = db.execute(
            "SELECT evidence_id,observed_at FROM revisions WHERE vendor=? AND advisory_id=? AND id<? AND source_url=? ORDER BY id DESC LIMIT 1",
            (row["vendor"], row["advisory_id"], row["revision_id"], row["source_url"]),
        ).fetchone()
        if not previous:
            continue
        ev = db.execute("SELECT sha256 FROM evidence WHERE id=?", (row["evidence_id"],)).fetchone()
        before = db.execute(
            "SELECT sha256 FROM evidence WHERE id=?", (previous["evidence_id"],)
        ).fetchone()
        advisory.append(
            dict(
                vendor=row["vendor"],
                product=row["advisory_id"],
                source_url=row["source_url"],
                cves=json.loads(row["details"]).get("cves", []),
                before=dict(
                    source_url=row["source_url"],
                    source_sha256=before["sha256"],
                    observed_at=previous["observed_at"],
                    publisher_date_claim=None,
                ),
                after=dict(
                    source_url=row["source_url"],
                    source_sha256=ev["sha256"],
                    observed_at=row["observed_at"],
                    publisher_date_claim=None,
                ),
            )
        )
    return dict(
        release_sources=[
            dict(
                vendor=k[0],
                product=k[1],
                source_url=k[2],
                snapshots=v,
                retrieval_history=retrieval_history(db, k[0], k[2]),
            )
            for k, v in snapshots.items()
        ],
        advisory_changes=advisory,
        observation_scan_limit=400,
        observation_scan_truncated=db.execute(
            "SELECT count(*) FROM document_observations"
        ).fetchone()[0]
        > 400,
    )


def public_retrieval_history(value):
    if value is None:
        return None
    # Public metadata only. No cache headers, response bodies, local IDs or
    # operator fields may cross this boundary, even from an installed plugin.
    summary = {
        key: value[key]
        for key in (
            "logged_checks",
            "distinct_fingerprints",
            "same_as_previous_checks",
            "http_304_checks",
            "first_logged_check_at",
            "last_logged_check_at",
            "checks_truncated",
            "method",
        )
    }
    summary["checks"] = [
        {key: check[key] for key in ("checked_at", "source_sha256", "http_status", "content_state")}
        for check in value["checks"][:12]
    ]
    summary["checks_truncated"] = bool(value["checks_truncated"] or len(value["checks"]) > 12)
    return summary


def public_inputs(inputs, urls, records):
    known = {(r["vendor"], r["source_url"]) for r in records}
    releases = []
    for source in inputs.get("release_sources", []):
        if source["source_url"] not in urls or not allowed(source["source_url"], source["vendor"]):
            continue
        snapshots = []
        for s in source["snapshots"][:2]:
            snapshot = {
                k: s[k]
                for k in ["source_url", "source_sha256", "observed_at", "publisher_date_claim"]
            }
            analysis = s["analysis"]
            snapshot["analysis"] = dict(
                state=analysis["state"],
                component_scope=analysis.get("component_scope", SECTION_SCOPE),
                blocks=[
                    {k: b[k] for k in ["locator", "text", "cves"]} for b in analysis["blocks"][:200]
                ],
                components={
                    k: list(v)
                    for k, v in analysis["components"].items()
                    if k in {"openssl", "openssh", "curl", "php", "nginx", "libxml2"}
                },
            )
            snapshots.append(snapshot)
        releases.append(
            dict(
                vendor=source["vendor"],
                product=source["product"],
                source_url=source["source_url"],
                snapshots=snapshots,
                retrieval_history=public_retrieval_history(source.get("retrieval_history")),
            )
        )
    changes = []
    for change in inputs.get("advisory_changes", []):
        if (change["vendor"], change["source_url"]) in known and allowed(
            change["source_url"], change["vendor"]
        ):
            changes.append(
                {
                    k: change[k]
                    for k in ["vendor", "product", "source_url", "cves", "before", "after"]
                }
            )
    return dict(
        release_sources=releases,
        advisory_changes=changes,
        observation_scan_limit=400,
        observation_scan_truncated=bool(inputs.get("observation_scan_truncated")),
    )


def leads(data):
    inputs = data.get("research", {}).get("lead_inputs", {})
    result = []
    gaps = []
    source_rows = []

    def evidence(s):
        return {
            k: s.get(k)
            for k in ["source_url", "source_sha256", "observed_at", "publisher_date_claim"]
        }

    def add(kind, vendor, product, detail, sources, ids=(), component=None):
        identity = json.dumps(
            [kind, vendor, product, detail, [s["source_sha256"] for s in sources]], sort_keys=True
        )
        result.append(
            dict(
                id=hashlib.sha256(identity.encode()).hexdigest()[:24],
                kind=kind,
                vendor=vendor,
                product=product,
                component=component,
                details=detail,
                cve_ids=sorted(set(ids)),
                evidence=sources,
                state="investigation_required",
                concealment="not_established",
                alternative_explanations=ALTERNATIVES,
                missing_evidence=[
                    "Verify product/version applicability and the exact security change.",
                    "Independently establish public release availability and earlier disclosure history.",
                    "Obtain publisher clarification or independently reviewed linkage before drawing a conclusion.",
                ],
            )
        )

    for source in inputs.get("release_sources", []):
        snapshots = source["snapshots"]
        if not snapshots:
            continue
        current = snapshots[0]
        previous = snapshots[1] if len(snapshots) > 1 else None
        analysis = current["analysis"]
        checks = source.get("retrieval_history") or {}
        last_check = next(iter(checks.get("checks", [])), None)
        source_rows.append(
            dict(
                vendor=source["vendor"],
                product=source["product"],
                source_url=source["source_url"],
                snapshots=len(snapshots),
                analysis_state=analysis["state"],
                components=analysis["components"],
                component_scope=analysis.get("component_scope", SECTION_SCOPE),
                current_evidence=evidence(current),
                retrieval_history=public_retrieval_history(source.get("retrieval_history")),
                latest_retrieval_matches_analyzed_snapshot=None
                if last_check is None
                else last_check["source_sha256"] == current["source_sha256"],
            )
        )
        if not analysis["components"]:
            gaps.append(
                dict(
                    vendor=source["vendor"],
                    source_url=source["source_url"],
                    reason="no_explicit_component_versions_in_reviewed_sections",
                )
            )
        if analysis["state"] != "scoped":
            gaps.append(
                dict(
                    vendor=source["vendor"],
                    source_url=source["source_url"],
                    reason=analysis["state"],
                )
            )
        if not previous:
            gaps.append(
                dict(
                    vendor=source["vendor"],
                    source_url=source["source_url"],
                    reason="no_comparable_prior_snapshot",
                )
            )
        for block in analysis["blocks"]:
            if (
                SECURITY.search(block["text"])
                and not block["cves"]
                and not re.search(r"\bCVE(?:s|'s)?\b", block["text"], re.I)
            ):
                add(
                    "security_statement_without_cve",
                    source["vendor"],
                    source["product"],
                    block["locator"] + ": " + block["text"][:600],
                    [evidence(current)],
                )
        if not previous or previous["analysis"]["state"] != "scoped":
            continue
        if analysis.get("component_scope", SECTION_SCOPE) != previous["analysis"].get(
            "component_scope", SECTION_SCOPE
        ):
            gaps.append(
                dict(
                    vendor=source["vendor"],
                    source_url=source["source_url"],
                    reason="component_scope_changed_requires_review",
                )
            )
            continue
        for name, versions in analysis["components"].items():
            before = previous["analysis"]["components"].get(name, [])
            if len(before) == len(versions) == 1 and before != versions:
                add(
                    "component_version_changed",
                    source["vendor"],
                    source["product"],
                    f"Publisher component reference changed from {before[0]} to {versions[0]}; version ordering and security purpose are not inferred.",
                    [evidence(previous), evidence(current)],
                    component=name,
                )
            elif len(before) > 1 or len(versions) > 1:
                gaps.append(
                    dict(
                        vendor=source["vendor"],
                        source_url=source["source_url"],
                        reason="ambiguous_component_version_scope",
                    )
                )
        old = {cid for block in previous["analysis"]["blocks"] for cid in block["cves"]}
        added = {cid for block in analysis["blocks"] for cid in block["cves"]} - old
        if added:
            add(
                "release_note_cve_reference_added",
                source["vendor"],
                source["product"],
                "CVE references added between two locally observed, scoped release-note snapshots; not first disclosure or fix availability.",
                [evidence(previous), evidence(current)],
                added,
            )
    for change in inputs.get("advisory_changes", []):
        add(
            "advisory_cve_reference_added",
            change["vendor"],
            change["product"],
            "Association added between observed publisher advisory revisions; another earlier disclosure may exist.",
            [evidence(change["before"]), evidence(change["after"])],
            change["cves"],
        )
    for case in data.get("casefiles", {}).get("cases", []):
        if not case.get("reported_date_gaps") and not case.get("reported_documentation_offsets"):
            continue
        sources = [
            dict(
                source_url=e["source_url"],
                source_sha256=e["source_sha256"],
                observed_at=e.get("observed_at"),
                publisher_date_claim=e.get("publisher_published_at"),
            )
            for e in case["evidence"]
        ]
        date_claims = [
            "Publisher firmware date "
            + str(e["publisher_reported_fix_date"])
            + "; bulletin date "
            + str(e.get("publisher_published_at"))
            + "."
            for e in case["evidence"]
            if e.get("publisher_reported_fix_date")
        ]
        date_claims += [
            "Publisher documentation dates: initial "
            + offset["initial_document_date"]
            + "; CVE reference added "
            + offset["reference_added_date"]
            + "."
            for offset in case.get("reported_documentation_offsets", [])
        ]
        if case.get("earlier_dated_vendor_documents"):
            date_claims.append(
                "An earlier-dated vendor advisory is retained as counter-evidence to inferring nondisclosure from a later documentation edit."
            )
            for earlier in case["earlier_dated_vendor_documents"]:
                record = next(
                    (
                        r
                        for r in data["records"]
                        if r["source_url"] == earlier["source_url"]
                        and r["sha256"] == earlier["source_sha256"]
                    ),
                    {},
                )
                sources.append(
                    dict(
                        source_url=earlier["source_url"],
                        source_sha256=earlier["source_sha256"],
                        observed_at=record.get("source_observed_at"),
                        publisher_date_claim=earlier["publisher_published_at"],
                    )
                )
        for history in case.get("publisher_document_histories", []):
            if any(
                offset["source_url"] == history["source_url"]
                for offset in case.get("reported_documentation_offsets", [])
            ):
                sources.append(
                    dict(
                        source_url=history["source_url"],
                        source_sha256=history["source_sha256"],
                        observed_at=history["observed_at"],
                        publisher_date_claim=None,
                    )
                )
        date_claims = list(dict.fromkeys(date_claims))
        sources = list({(s["source_url"], s["source_sha256"]): s for s in sources}.values())
        if sources:
            add(
                "publisher_reported_chronology",
                case["vendor"],
                case["product_scope"],
                case["question"]
                + " "
                + " ".join(date_claims)
                + " Dates are current publisher claims, not historical captures or independent release availability.",
                sources,
                case["selected_cve_ids"],
            )
    return dict(
        schema_version=1,
        leads=result[:200],
        sources=source_rows,
        leads_truncated=len(result) > 200,
        analysis_gaps=gaps,
        observation_scan_truncated=bool(inputs.get("observation_scan_truncated")),
        independent_human_review_completed=False,
        method="Whole-publication eligible sources, independent of the selected browser cohort. Bounded research leads from named release sections, literal component versions, observed advisory associations and registered publisher chronology cases. Snapshot capture dates are not release dates. Component changes need comparable snapshots; ambiguous versions remain gaps. No vulnerability, undisclosed security fix, first disclosure or intentional concealment is inferred. Independent review remains pending.",
    )
