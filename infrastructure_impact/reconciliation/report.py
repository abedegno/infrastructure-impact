"""Strict, offline reconciliation reports and exclusive local export pairs."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import tempfile
from datetime import date
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator

from . import state
from .baseline import _route, load_baseline
from .selectors import _date_window

LIMITATIONS = [
    "Local discovery and collection presence only; human review pending.",
    "Scan completion does not establish coverage completeness.",
    "No appliance exposure, affectedness, version matching, patch date or concealment inference.",
    "CNA and ADP branches remain separate; dimensions count distinct CVEs within each bucket.",
    "Registry publication dates and fetched vendor publication dates are separate.",
    "Unknown URL identities never match; unfetched publisher hyperlinks are not collection evidence.",
]


class ReportError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _identity(value, field):
    return _digest({key: item for key, item in value.items() if key != field})


def _finding_identity(finding):
    evidence = {
        key: value
        for key, value in finding.items()
        if key not in {"finding_id", "baseline", "references"}
    }
    evidence["references"] = [
        {key: reference[key] for key in ("locator", "literal_json")}
        for reference in finding["references"]
    ]
    return _digest(evidence)


def _day(value):
    if _date_window(value, date.min, date.max) == "unknown":
        return None
    try:
        return date.fromisoformat(value[:10]).isoformat()
    except ValueError:
        return None


def _presence(cve, vendor, family, baseline):
    current = [r for r in baseline["revisions"] if r["latest"] and cve in r["cves"]]
    vendor_rows = [r for r in current if r["vendor"] == vendor]
    family_rows = [
        r
        for r in vendor_rows
        if any(a["cve_id"] == cve and family in a["families"] for a in r["assessments"])
    ]
    return dict(
        cve_anywhere=bool(current),
        cve_vendor=bool(vendor_rows),
        cve_family=bool(family_rows),
        current_revision_ids=sorted(r["revision_id"] for r in current),
        vendor_revision_ids=sorted(r["revision_id"] for r in vendor_rows),
        family_revision_ids=sorted(r["revision_id"] for r in family_rows),
        historical_revision_ids=sorted(
            r["revision_id"] for r in baseline["revisions"] if not r["latest"] and cve in r["cves"]
        ),
    )


def _reference_url(row):
    """Project only string URL values; literal_json retains original types."""
    value = row.get("url") if isinstance(row, dict) else None
    return value if isinstance(value, str) else None


def _reference(row, locator, baseline):
    url = _reference_url(row)
    route = _route(url)
    result = dict(
        locator=locator,
        literal_json=_canonical(row),
        url=url,
        route_identity=route,
        collection_state="missing_reference" if row is None else "unknown_identity",
        revision_ids=[],
        evidence_ids=[],
        queue_ids=[],
        check_ids=[],
        selection_ids=[],
        observation_ids=[],
        vendor_publication_dates=[],
        registry_publication_dates=[],
    )
    if route is None:
        return result
    # Actual fetched bindings and explicit retained selection views only. A normalized
    # advisory_url is deliberately absent from every membership predicate here.
    evidence_ids = {e["evidence_id"] for e in baseline["evidence"] if e["source_url"] == route}
    selections = [
        s for s in baseline["source_selections"] if s["latest"] and s["requested_url"] == route
    ]
    for selection in selections:
        evidence_ids.update(v["evidence_id"] for v in selection["views"])
    evidence_ids.update(
        c["evidence_id"]
        for c in baseline["cache"]
        if c["source_url"] == route and c["evidence_id"] is not None
    )
    queue = [q for q in baseline["queue"] if route in (q["requested_url"], q["resolved_url"])]
    observations = [o for o in baseline["source_observations"] if o["source_url"] == route]
    evidence_ids.update(q["evidence_id"] for q in queue if q["evidence_id"] is not None)
    evidence_ids.update(o["evidence_id"] for o in observations)
    revisions = [
        r
        for r in baseline["revisions"]
        if r["source_url"] == route or r["evidence_id"] in evidence_ids
    ]
    evidence_ids.update(r["evidence_id"] for r in revisions)
    checks = [c for c in baseline["source_checks"] if c["source_url"] == route]
    result.update(
        revision_ids=sorted(r["revision_id"] for r in revisions),
        evidence_ids=sorted(evidence_ids),
        queue_ids=sorted(q["item_id"] for q in queue),
        check_ids=sorted(c["check_id"] for c in checks),
        selection_ids=sorted(s["selection_id"] for s in selections),
        observation_ids=sorted(o["observation_id"] for o in observations),
    )
    for revision in revisions:
        actual = revision["source_url"]
        if actual is None:
            continue
        kind = (
            "registry_publication_dates"
            if actual.startswith("https://cveawg.mitre.org/")
            else "vendor_publication_dates"
        )
        result[kind].append(
            dict(
                revision_id=revision["revision_id"],
                source_url=actual,
                published_at=revision["published_at"],
                updated_at=revision["updated_at"],
            )
        )
    result["collection_state"] = (
        "normalized"
        if revisions
        else "retained_unparsed"
        if evidence_ids
        else "error"
        if any(c["outcome"] == "error" for c in checks) or any(q["state"] == "error" for q in queue)
        else "pending"
        if any(q["state"] == "pending" for q in queue)
        else "observed_without_retention"
        if checks or queue
        else "configured_unobserved"
        if any(c["source_url"] == route for c in baseline["configured_sources"])
        else "unobserved"
    )
    return result


def _statuses(product):
    if product is None:
        return ["unknown"]
    values = [product.get("defaultStatus")] + [v.get("status") for v in product.get("versions", [])]
    return sorted({v for v in values if isinstance(v, str)}) or ["unknown"]


def _counts(findings):
    dimensions = {
        key: {}
        for key in (
            "discovery_class",
            "family",
            "status",
            "collection_state",
            "publication_year",
            "date_window_state",
        )
    }
    for finding in findings:
        values = dict(
            discovery_class=[finding["discovery_class"]],
            family=[finding["family"]],
            status=finding["statuses"],
            collection_state=sorted({r["collection_state"] for r in finding["references"]}),
            publication_year=[
                finding["registry_publication_day"][:4]
                if finding["registry_publication_day"]
                else "unknown"
            ],
            date_window_state=[finding["date_window_state"]],
        )
        for dimension, keys in values.items():
            for key in keys:
                dimensions[dimension].setdefault(key, set()).add(finding["cve_id"])
    return dict(
        findings=len(findings),
        unique_cves=len({f["cve_id"] for f in findings}),
        dimensions={
            key: [dict(value=value, unique_cves=len(ids)) for value, ids in sorted(buckets.items())]
            for key, buckets in dimensions.items()
        },
    )


def _build(reader, baseline):
    identity = reader.identity
    outcomes = {r["position"]: r for r in reader.iter_outcomes() if r["finding_count"]}
    findings = []
    for row in reader.iter_findings():
        outcome = outcomes[row["position"]]
        meta = outcome["metadata"]
        evidence = row["finding"]
        references = [
            _reference(ref["row"], ref["locator"], baseline) for ref in evidence["references"]
        ]
        if not references:
            references = [_reference(None, None, baseline)]
        finding = dict(
            cve_id=meta["cve_id"],
            source_url=meta["source_url"],
            source_locator=meta["source_locator"],
            source_sha256=outcome["source_sha256"],
            git_oid=outcome["entry"]["oid"],
            position=row["position"],
            ordinal=row["ordinal"],
            family=evidence["family"],
            vendor_id=evidence["vendor_id"],
            discovery_class=evidence["discovery_class"],
            container_type=evidence["container_type"],
            container_index=evidence["container_index"],
            container_locator=evidence["container_locator"],
            product_locator=evidence["product_locator"],
            product_json=_canonical(evidence["product"]),
            provider_identity_json=_canonical(evidence["provider_identity"]),
            matching_rules_json=_canonical(evidence["matching_rules"]),
            cpe_applicability_json=_canonical(evidence["container_cpe_applicability"]),
            trusted_vendor_cna=evidence["trusted_vendor_cna"],
            statuses=_statuses(evidence["product"]),
            registry_dates_json=_canonical(meta["dates"]),
            registry_publication_day=_day(meta["dates"]["datePublished"]),
            date_window_state=meta["date_window_state"],
            references=references,
            baseline=_presence(meta["cve_id"], evidence["vendor_id"], evidence["family"], baseline),
        )
        finding["finding_id"] = _finding_identity(finding)
        findings.append(finding)
    progress = reader.progress
    progress["coverage_complete"] = None
    report = dict(
        schema_version=1,
        snapshot={
            k: identity[k]
            for k in (
                "commit",
                "tree",
                "receipt_sha256",
                "total",
                "inventory_entries",
                "inventory_bytes",
            )
        },
        selector=dict(version=identity["selector_version"], sha256=identity["selector_hash"]),
        scanner=dict(
            version=identity["scanner_version"], workspace_format_version=identity["format_version"]
        ),
        baseline=dict(
            fingerprint=baseline["fingerprint"],
            config_sha256=baseline["config_sha256"],
            generation=None,
        ),
        window=dict(start_date=identity["start_date"], end_date=identity["end_date"]),
        scan=progress,
        counts=_counts(findings),
        findings=findings,
        limitations=LIMITATIONS.copy(),
    )
    report["report_id"] = _identity(report, "report_id")
    validate_report(report)
    return report


def build_report(*, workspace: Path, baseline_path: Path) -> dict:
    baseline = load_baseline(baseline_path)
    with state.open_workspace(workspace) as reader:
        return _build(reader, baseline)


def validate_report(report: dict) -> None:
    try:
        schema = json.loads(
            files("infrastructure_impact")
            .joinpath("schemas/cve-reconciliation-v1.json")
            .read_text()
        )
        Draft202012Validator(schema).validate(report)
        if report["report_id"] != _identity(report, "report_id") or report["counts"] != _counts(
            report["findings"]
        ):
            raise ValueError
        scan = report["scan"]
        snapshot = report["snapshot"]
        if (
            scan["total"] != snapshot["total"]
            or scan["attempted"] != scan["cursor"]
            or scan["remaining"] != scan["total"] - scan["attempted"]
            or scan["attempted"]
            != sum(
                scan[k]
                for k in (
                    "parsed",
                    "invalid",
                    "unsupported",
                    "rejected",
                    "oversized",
                    "missing_object",
                )
            )
            or scan["unresolved"]
            != sum(scan[k] for k in ("invalid", "unsupported", "oversized", "missing_object"))
            or scan["scan_complete"] != (scan["remaining"] == 0)
            or scan["stop_reason"] != ("complete" if scan["scan_complete"] else "incomplete")
            or scan["candidate_findings"] != len(report["findings"])
        ):
            raise ValueError
        start, end = (
            date.fromisoformat(report["window"][key]) for key in ("start_date", "end_date")
        )
        if (
            start > end
            or report["window"]["start_date"] != start.isoformat()
            or report["window"]["end_date"] != end.isoformat()
            or snapshot["inventory_entries"] < snapshot["total"]
            or report["limitations"] != LIMITATIONS
        ):
            raise ValueError
        previous = (-1, -1)
        ids = set()
        vendors = {"cisco-iosxe": "cisco", "aruba-aoscx": "aruba", "arista-eos": "arista"}
        for finding in report["findings"]:
            pair = (finding["position"], finding["ordinal"])
            if (
                pair <= previous
                or finding["position"] >= scan["cursor"]
                or finding["finding_id"] in ids
            ):
                raise ValueError
            if finding["ordinal"] != (previous[1] + 1 if previous[0] == pair[0] else 0):
                raise ValueError
            previous = pair
            ids.add(finding["finding_id"])
            if (
                finding["finding_id"] != _finding_identity(finding)
                or vendors[finding["family"]] != finding["vendor_id"]
            ):
                raise ValueError
            container = (
                "/containers/cna"
                if finding["container_type"] == "cna"
                else "/containers/adp/" + str(finding["container_index"])
            )
            if finding["container_locator"] != container or (
                finding["container_type"] == "cna" and finding["container_index"] != 0
            ):
                raise ValueError
            if finding["product_locator"] is not None and not finding["product_locator"].startswith(
                container + "/affected/"
            ):
                raise ValueError
            prefix = (
                "https://raw.githubusercontent.com/CVEProject/cvelistV5/" + snapshot["commit"] + "/"
            )
            if finding["source_url"] != prefix + finding["source_locator"]:
                raise ValueError
            match = re.fullmatch(r"CVE-([0-9]{4})-([0-9]{4,})", finding["cve_id"])
            year, number = match.groups()
            expected_path = f"cves/{year}/{number[:-3]}xxx/{finding['cve_id']}.json"
            if finding["source_locator"] != expected_path:
                raise ValueError
            dates = json.loads(finding["registry_dates_json"])
            product = json.loads(finding["product_json"])
            if set(dates) != {"dateReserved", "datePublished", "dateUpdated"} or finding[
                "statuses"
            ] != _statuses(product):
                raise ValueError
            day = _day(dates["datePublished"])
            window = (
                "unknown"
                if day is None
                else "inside"
                if start.isoformat() <= day <= end.isoformat()
                else "outside"
            )
            if finding["registry_publication_day"] != day or finding["date_window_state"] != window:
                raise ValueError
            for field in (
                "provider_identity_json",
                "matching_rules_json",
                "cpe_applicability_json",
                "product_json",
                "registry_dates_json",
            ):
                if _canonical(json.loads(finding[field])) != finding[field]:
                    raise ValueError
            presence = finding["baseline"]
            for flag, key in [
                ("cve_anywhere", "current_revision_ids"),
                ("cve_vendor", "vendor_revision_ids"),
                ("cve_family", "family_revision_ids"),
            ]:
                if presence[flag] != bool(presence[key]):
                    raise ValueError
            if (
                not set(presence["family_revision_ids"])
                <= set(presence["vendor_revision_ids"])
                <= set(presence["current_revision_ids"])
            ):
                raise ValueError
            if set(presence["current_revision_ids"]) & set(presence["historical_revision_ids"]):
                raise ValueError
            for reference_index, reference in enumerate(finding["references"]):
                literal = json.loads(reference["literal_json"])
                if reference["url"] != _reference_url(literal) or reference[
                    "route_identity"
                ] != _route(reference["url"]):
                    raise ValueError
                if _canonical(literal) != reference["literal_json"] or (
                    literal is not None and not isinstance(literal, dict)
                ):
                    raise ValueError
                if literal is not None and (
                    reference["locator"] != container + "/references/" + str(reference_index)
                ):
                    raise ValueError
                status = reference["collection_state"]
                if reference["route_identity"] is None and any(
                    reference[k]
                    for k in (
                        "revision_ids",
                        "evidence_ids",
                        "queue_ids",
                        "check_ids",
                        "selection_ids",
                        "observation_ids",
                        "vendor_publication_dates",
                        "registry_publication_dates",
                    )
                ):
                    raise ValueError
                if literal is None:
                    if status != "missing_reference" or len(finding["references"]) != 1:
                        raise ValueError
                elif reference["route_identity"] is None and status != "unknown_identity":
                    raise ValueError
                if (status == "normalized") != bool(reference["revision_ids"]):
                    raise ValueError
                if (status == "retained_unparsed") != (
                    bool(reference["evidence_ids"]) and not reference["revision_ids"]
                ):
                    raise ValueError
                if (status == "unknown_identity") != (
                    literal is not None and reference["route_identity"] is None
                ):
                    raise ValueError
                if (status == "missing_reference") != (literal is None):
                    raise ValueError
                if literal is None and reference["locator"] is not None:
                    raise ValueError
                if status == "pending" and not reference["queue_ids"]:
                    raise ValueError
                if status == "error" and not (reference["queue_ids"] or reference["check_ids"]):
                    raise ValueError
                for kind in ("registry_publication_dates", "vendor_publication_dates"):
                    for item in reference[kind]:
                        if (
                            item["revision_id"] not in reference["revision_ids"]
                            or _route(item["source_url"]) != item["source_url"]
                            or (
                                item["source_url"].startswith("https://cveawg.mitre.org/")
                                != (kind == "registry_publication_dates")
                            )
                        ):
                            raise ValueError
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise ReportError("invalid_report") from error
    except Exception as error:
        # jsonschema errors carry untrusted evidence; expose a stable diagnostic only.
        from jsonschema import ValidationError

        if isinstance(error, ValidationError):
            raise ReportError("invalid_report") from None
        raise


def _safe_cell(value):
    if value is None:
        return ""
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        return "'" + text
    return text


def _csv_bytes(report):
    fields = [
        "row_type",
        "report_id",
        "finding_id",
        "scan_complete",
        "coverage_complete",
        "attempted",
        "remaining",
        "stop_reason",
        "cve_id",
        "family",
        "discovery_class",
        "statuses",
        "product",
        "reference_url",
        "reference_locator",
        "collection_state",
        "cve_anywhere",
        "cve_vendor",
        "cve_family",
        "registry_publication_day",
        "date_window_state",
        "source_url",
        "source_locator",
        "source_sha256",
        "container_locator",
        "product_locator",
        "product_json",
        "registry_dates_json",
        "reference_literal_json",
        "vendor_publication_dates_json",
        "registry_reference_publication_dates_json",
    ]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    common = dict(
        report_id=report["report_id"],
        scan_complete=str(report["scan"]["scan_complete"]).lower(),
        coverage_complete="null",
        **{k: report["scan"][k] for k in ("attempted", "remaining", "stop_reason")},
    )
    if not report["findings"]:
        writer.writerow(common | dict(row_type="summary"))
    for finding in report["findings"]:
        product = json.loads(finding["product_json"])
        for reference in finding["references"]:
            row = common | {
                k: finding[k]
                for k in (
                    "finding_id",
                    "cve_id",
                    "family",
                    "discovery_class",
                    "registry_publication_day",
                    "date_window_state",
                )
            }
            row.update(
                row_type="finding_reference",
                statuses=";".join(finding["statuses"]),
                product=product.get("product", "") if product else "",
                reference_url=reference["url"],
                reference_locator=reference["locator"],
                collection_state=reference["collection_state"],
                **{
                    k: str(finding["baseline"][k]).lower()
                    for k in ("cve_anywhere", "cve_vendor", "cve_family")
                },
            )
            row.update(
                {
                    key: finding[key]
                    for key in (
                        "source_url",
                        "source_locator",
                        "source_sha256",
                        "container_locator",
                        "product_locator",
                        "product_json",
                        "registry_dates_json",
                    )
                }
            )
            row.update(
                reference_literal_json=reference["literal_json"],
                vendor_publication_dates_json=_canonical(reference["vendor_publication_dates"]),
                registry_reference_publication_dates_json=_canonical(
                    reference["registry_publication_dates"]
                ),
            )
            writer.writerow({k: _safe_cell(v) for k, v in row.items()})
    return output.getvalue().encode()


def _output_paths(json_path, csv_path, workspace, baseline_path):
    paths = [Path(json_path).absolute(), Path(csv_path).absolute()]
    if paths[0].resolve() == paths[1].resolve():
        raise ReportError("unsafe_output_path")
    protected = [Path(baseline_path).resolve()]
    protected += [
        p.with_name(p.name + suffix)
        for p in protected.copy()
        for suffix in ("-wal", "-shm", "-journal")
    ]
    root = workspace.resolve()
    for path in paths:
        if (
            any(p.is_symlink() for p in (path, *path.parents))
            or path.exists()
            or not path.parent.is_dir()
        ):
            raise ReportError("unsafe_output_path")
        resolved = path.resolve()
        if resolved in protected:
            raise ReportError("unsafe_output_path")
        # Only the dedicated reports directory is writable inside a scan workspace.
        if resolved.is_relative_to(root) and not resolved.is_relative_to(root / "reports"):
            raise ReportError("unsafe_output_path")
    return paths


def write_report(
    report: dict, *, json_path: Path, csv_path: Path, workspace: Path, baseline_path: Path
) -> None:
    """Exclusive new outputs; CSV first, JSON commit marker last. Never overwrite.

    A caught publication failure removes our files. Process death can leave a CSV
    orphan: without matching JSON it is not a committed pair and retry refuses it.
    """
    validate_report(report)
    workspace = Path(workspace)
    paths = _output_paths(json_path, csv_path, workspace, baseline_path)
    stages = []
    published = []
    with state._lock(workspace, write=True):
        state.retained_bytes(workspace)
        # Reuse the exact verified reader under the already held exclusive lock.
        identity = state._read_identity(workspace / "identity.json")
        db = state._connect(workspace.resolve() / "state.sqlite3", readonly=True)
        try:
            db.execute("BEGIN")
            view = state.Workspace(workspace, db, identity)
            captures = view.verify()
            if {p.name for p in (workspace / "captures").iterdir()} != captures:
                raise state.StateError("capture_integrity")
            fresh = _build(state.CommittedWorkspace(view, captures), load_baseline(baseline_path))
            if fresh != report:
                raise ReportError("stale_report")
        finally:
            db.close()
        paths = _output_paths(*paths, workspace, baseline_path)
        payloads = [(_canonical(report) + "\n").encode(), _csv_bytes(report)]
        required = sum(
            len(raw)
            for path, raw in zip(paths, payloads)
            if path.resolve().is_relative_to(workspace.resolve())
        )
        if (
            state.retained_bytes(workspace) + identity["inventory_bytes"] + required
            > state.MAX_WORKSPACE_BYTES
        ):
            raise state.StorageLimit("workspace_limit")
        try:
            for path, raw in zip(paths, payloads):
                fd, name = tempfile.mkstemp(prefix=".reconciliation-", dir=path.parent)
                stage = Path(name)
                stages.append(stage)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
            for index in (1, 0):
                # link is no-clobber atomic publication; unlink staging immediately,
                # avoiding double logical accounting within the workspace.
                os.link(stages[index], paths[index])
                published.append(paths[index])
                stages[index].unlink()
                state._sync_directory(paths[index].parent)
        except BaseException as error:
            for path in reversed(published):
                path.unlink(missing_ok=True)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            raise ReportError("report_write_failed") from None
        finally:
            for stage in stages:
                stage.unlink(missing_ok=True)
