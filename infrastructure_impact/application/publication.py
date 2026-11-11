"""Validated, immutable public generations with an atomic current pointer."""

import gzip
import io
import json
import os
import re
import shutil
import tempfile
from contextlib import closing
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from ..domain import validate_advisory
from ..exports import csv_export
from ..phase_events import phase
from ..settings import PACKAGE, Paths
from ..storage.repository import connect
from .casefiles import casefiles
from .cohort import COHORT, coverage
from .eligibility import eligibility, monitor_summary, report_validator
from .extraction_validation import review_packet, validation_report
from .families import completeness
from .fix_leads import leads, public_inputs
from .kev import build_report, select_report
from .kev import validate_report as validate_kev
from .product_groups import product_groups
from .product_groups import validate_report as validate_groups
from .publisher_history import public_history
from .query import state
from .readiness import readiness
from .release_assets import validate_asset


def _switching_projection_input(value):
    """Validate the complete JSON boundary; borrow native claims until allowlist copying."""

    surrogate = re.compile(r"[\ud800-\udfff]")

    def native(item):
        if type(item) is dict:
            return all(
                type(k) is str and not surrogate.search(k) and native(v) for k, v in item.items()
            )
        if type(item) is list:
            return all(native(v) for v in item)
        if type(item) is str:
            return not surrogate.search(item)
        return type(item) in (int, float, bool, type(None))

    try:
        is_native = native(value)
    except RecursionError:
        # Cycles and deep trees must retain the legacy JSON boundary's outcome.
        is_native = False
    if not is_native:
        # Normalize subclasses before Python's streamed encoder can invoke their
        # custom container methods; retain tuple/key and surrogate normalization.
        value = json.loads(json.dumps(value, allow_nan=False))
    else:
        # Discard chunks instead of retaining a second evidence-sized encoding.
        for _ in json.JSONEncoder(allow_nan=False).iterencode(value):
            pass
    # Only the header is assigned to (score_availability); nested input stays
    # read-only until switching_evidence._project makes its owned allowlist copy.
    return value.copy() if type(value) is dict else value


@phase("publication.projection")
def public_projection(data, public_release_urls=(), *, publication_format="v1"):
    """The publication boundary never copies raw evidence or private review notes."""
    from ..plugins.registry import default_registry
    from .current_evidence import partition
    from .current_views import rebuild, validate_partition
    from .evidence_identity import record_key
    from .publication_v2 import publication_format as validate_format

    validate_format(publication_format)
    # Consume private frames before any general clone or public serialization.
    release_input = data["research"].get("release_input", [])
    switching_input = data["research"].get("switching_input")
    research = {
        k: v
        for k, v in data["research"].items()
        if k not in {"current_evidence_input", "release_input", "switching_input"}
    }
    # Supplied reports are never authority at the public boundary.
    data = {k: v for k, v in data.items() if k != "switching_release_history"}
    context = data["research"].get("current_evidence_input", {"selections": [], "sources": []})
    union = data["records"] + [w["record"] for w in data.get("retained_advisories", [])]
    computed = partition(
        union,
        context,
        registry=default_registry(),
        publication=data.get("publication"),
        generated_at=data["generated_at"],
    )
    if "current_evidence" in data:
        validate_partition(data)
        if data["current_evidence"] != computed["current_evidence"]:
            raise ValueError("Supplied current-evidence decisions differ from retained proofs")
        if {w["decision_id"] for w in data.get("retained_advisories", [])} != {
            w["decision_id"] for w in computed["retained_advisories"]
        }:
            raise ValueError("Supplied retained partition differs from recomputed decisions")
    elif data.get("retained_advisories"):
        raise ValueError("Retained exclusions require decision references")
    switching_input = _switching_projection_input(switching_input)
    data = json.loads(json.dumps({**data, "research": research}, allow_nan=False))
    data = rebuild(data, computed, switching_input=switching_input)
    from ..adapters.cvss import public_metrics

    has_score_input = "score_input" in data["research"]
    score_input = data["research"].pop("score_input", {})
    current_keys = {record_key(r) for r in data["records"]}
    for record in data["records"] + [w["record"] for w in data["retained_advisories"]]:
        validate_advisory(record)
        record["notes"] = []
        historical = record_key(record) not in current_keys
        entries = score_input.get("retained_advisories" if historical else "advisories", [])
        scores = [
            c
            for entry in entries
            if entry.get("vendor") == record["vendor"]
            and entry.get("advisory_id") == record["advisory_id"]
            for c in entry.get("claims", [])
        ]
        if historical:
            scores = [
                c
                for c in scores
                if c.get("source", {}).get("source_url") == record["source_url"]
                and c.get("source", {}).get("source_sha256") == record["sha256"]
                and c.get("revision") == str(record["revision_id"])
            ]
        scores += score_input.get("fallback", {}).get("claims", [])
        record["metrics"] = public_metrics([c for c in scores if c.get("cve_id") in record["cves"]])
        record["timeline"] = []
        record.pop("extensions", None)
        for assessment in record["assessments"]:
            assessment.pop("extensions", None)
    switching_input = data["research"].pop("switching_input", None)
    kev_input = data["research"].pop("kev_input", None)
    scope = sorted(set(data["retained_cves"]) | set(data["benchmark_cohort"]))
    data["kev"] = (
        build_report(
            kev_input, scope, publication=data.get("publication"), generated_at=data["generated_at"]
        )
        if kev_input is not None
        else select_report(data.get("kev"), scope, evaluated_at=data["generated_at"])
    )
    data["kev"]["publication"] = data.get("publication")
    data["kev"]["generated_at"] = data["generated_at"]
    from .switching_comparison import build_report as build_switching
    from .switching_comparison import day
    from .switching_evidence import definition, project

    # Old publications predate this study; they remain readable without a study asset.
    observation_end = day(data["generated_at"])
    if switching_input is not None and observation_end >= definition()["start_date"]:
        if has_score_input:
            switching_input["score_availability"] = switching_score_availability(
                score_input, switching_input, data["records"]
            )
        if publication_format == "v2":
            from .switching_comparison import _project_comparison

            data["switching_evidence"], data["switching_comparison"] = _project_comparison(
                switching_input,
                data["kev"],
                definition=definition(),
                publication=data.get("publication"),
                generated_at=data["generated_at"],
                observation_end=observation_end,
            )
        else:
            data["switching_evidence"] = project(
                switching_input,
                publication=data.get("publication"),
                generated_at=data["generated_at"],
            )
            data["switching_comparison"] = build_switching(
                data["switching_evidence"],
                data["kev"],
                definition=definition(),
                publication=data.get("publication"),
                generated_at=data["generated_at"],
                observation_end=observation_end,
            )
    if switching_input is not None and observation_end >= definition()["start_date"]:
        from .switching_releases import build as build_releases

        data["switching_release_history"] = build_releases(
            data["switching_evidence"],
            release_input,
            publication=data.get("publication"),
            generated_at=data["generated_at"],
            observation_end=observation_end,
        )
    data["research"].pop("browser_captures", None)
    data["research"]["fix_candidates"] = []
    data["research"]["release_assets"] = [
        r
        for r in data["research"].get("release_assets", [])
        if r["source_url"] in public_release_urls
    ]
    data["research"]["release_documents"] = [
        d for d in data["research"]["release_documents"] if d["source_url"] in public_release_urls
    ]
    from .source_selections import public_selections

    data["source_audit"]["source_selections"] = public_selections(
        data["source_audit"].get("source_selections", []),
        data["records"] + [w["record"] for w in data["retained_advisories"]],
    )
    data["publisher_history"] = public_history(
        data.get("publisher_history", {}), public_release_urls
    )
    for asset in data["research"]["release_assets"]:
        validate_asset(
            {
                k: v
                for k, v in asset.items()
                if k not in ("evidence_id", "source_sha256", "observed_at")
            }
        )
    data["signals"] = [
        s
        for s in data["signals"]
        if s["kind"] in ("reported_firmware_date_predates_bulletin", "cve_reference_added")
        or s.get("source_url") in public_release_urls
    ]
    for signal in data["signals"]:
        signal.pop("basis", None)
    known_sources = {
        (r["source_url"], r["sha256"])
        for r in data["records"] + [w["record"] for w in data["retained_advisories"]]
    }
    data["reviewed_source_scopes"] = [
        {k: s[k] for k in ("source_url", "source_sha256", "scheme", "scope_sha256")}
        for s in data.get("reviewed_source_scopes", [])
        if (s.get("source_url"), s.get("source_sha256")) in known_sources
        and re.fullmatch(r"[a-f0-9]{64}", s.get("scope_sha256", ""))
    ]
    from .vendor_gaps import vendor_gaps

    data["casefiles"] = casefiles(data)
    data["product_groups"] = product_groups(data)
    data["extraction_validation"] = validation_report(
        data["records"],
        scopes=data["reviewed_source_scopes"],
        retained_advisories=data["retained_advisories"],
    )
    from .switching_validation import rebuild as rebuild_switching_validation

    rebuild_switching_validation(data)
    data["vendor_gaps"] = vendor_gaps(data)
    data["review_packet"] = review_packet(
        data["records"] + [w["record"] for w in data["retained_advisories"]]
    )
    data["comparison_eligibility"] = eligibility(data, data["comparison"]["cohort"])
    data["family_completeness"] = completeness(data)
    data["comparison_readiness"] = readiness(data)
    inputs = public_inputs(
        data["research"].pop("lead_inputs", {}), public_release_urls, data["records"]
    )
    data["fix_leads"] = leads({**data, "research": {**data["research"], "lead_inputs": inputs}})
    from .component_studies import component_studies
    from .component_studies import public_inputs as public_study_inputs

    study_inputs = public_study_inputs(data["research"].pop("study_inputs", []))
    data["component_studies"] = component_studies(
        {**data, "research": {"study_inputs": study_inputs}}
    )
    from .disclosure_review import disclosure_review
    from .product_cohorts import product_cohorts
    from .research_dossiers import research_dossiers

    data["product_cohorts"] = product_cohorts(data)
    data["disclosure_review"] = disclosure_review(data)
    data["research_dossiers"] = research_dossiers(data)
    data["delays"] = []
    data["snapshot_notice"] = (
        "Dated public-source evidence; not a representative vendor security ranking. No finding of intentional concealment."
    )
    return data


@phase("publication.writing")
def write_bundle(destination, data, *, publication_format="v1"):
    from .publication_v2 import publication_format as validate_format

    validate_format(publication_format)
    if publication_format == "v2" and "switching_row_sources" in data:
        raise ValueError("Published Source membership is writer-owned")
    from .current_evidence import report_bytes
    from .current_views import validate_partition
    from .research_reports import validate

    validate_partition(data, require_targets=True)
    if {"current_evidence_input", "score_input", "release_input"}.intersection(
        data.get("research", {})
    ):
        raise ValueError("Private evidence input cannot be published")
    validate_kev(data["kev"])
    if (
        data["kev"]["publication"] != data["publication"]
        or data["kev"]["generated_at"] != data["generated_at"]
        or data["kev"]["evaluated_at"] != data["generated_at"]
    ):
        raise ValueError("KEV report must match enclosing publication identity and time")
    validate(data)
    report_validator().validate(data["comparison_eligibility"])
    validate_groups(data["product_groups"])
    from .switching_comparison import summary
    from .switching_evidence import validate_comparison, validate_evidence

    row_sources = None
    if "switching_comparison" in data:
        if publication_format == "v2":
            from .switching_evidence import _validate_comparison_evidence

            _validate_comparison_evidence(
                data["switching_comparison"],
                data["switching_evidence"],
                publication=data["publication"],
                generated_at=data["generated_at"],
            )
            from .switching_row_sources import derive

            row_sources = derive(data["switching_comparison"])
        else:
            validate_comparison(
                data["switching_comparison"],
                publication=data["publication"],
                generated_at=data["generated_at"],
            )
            validate_evidence(
                data["switching_evidence"],
                publication=data["publication"],
                generated_at=data["generated_at"],
            )
        if (
            data["switching_comparison"]["evaluated_at"] != data["generated_at"]
            or data["switching_comparison"]["inputs"]["kev"]["evaluated_at"] != data["generated_at"]
        ):
            raise ValueError("Published switching evaluation must match generation time")
        if data["switching_evidence"] != data["switching_comparison"]["inputs"]["evidence"]:
            raise ValueError("Switching asset and comparison evidence disagree")
    if "switching_release_history" in data:
        from .switching_releases import validate_current_references
        from .switching_releases import validate_report as validate_releases

        validate_releases(
            data["switching_release_history"],
            publication=data["publication"],
            generated_at=data["generated_at"],
        )
        comparison = data.get("switching_comparison")
        if comparison is None or (
            data["switching_release_history"]["observation_end"] != comparison["observation_end"]
            or data["switching_release_history"]["definition_sha256"]
            != comparison["selection"]["definition_sha256"]
        ):
            raise ValueError(
                "Release history observation bound or definition differs from comparison"
            )
        validate_current_references(data["switching_release_history"], data["switching_evidence"])
    if publication_format == "v2":
        from .publication_v2 import _write_bundle as write_v2

        return write_v2(destination, data, row_sources)
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "current-evidence.json").write_bytes(report_bytes(data["current_evidence"]))
    compact = {
        k: v
        for k, v in data.items()
        if k not in ("switching_evidence", "switching_release_history")
    }
    if "switching_release_history" in data:
        (destination / "switching-release-history.json").write_text(
            json.dumps(data["switching_release_history"], allow_nan=False)
        )
    if "switching_comparison" in data:
        compact["switching_comparison"] = summary(data["switching_comparison"])
        for name in ("switching_evidence", "switching_comparison"):
            (destination / (name.replace("_", "-") + ".json")).write_text(json.dumps(data[name]))
    snapshot = (json.dumps(compact, separators=(",", ":")) + "\n").encode("utf-8")
    (destination / "snapshot.json").write_bytes(snapshot)
    compressed = io.BytesIO()
    # Empty filename and fixed time make the same public bytes reproducible.
    with gzip.GzipFile(fileobj=compressed, mode="wb", filename="", mtime=0) as archive:
        archive.write(snapshot)
    (destination / "snapshot.json.gz").write_bytes(compressed.getvalue())
    (destination / "impact.csv").write_text(csv_export(data))
    (destination / "release-assets.json").write_text(
        json.dumps(data["research"].get("release_assets", []))
    )
    (destination / "catalogue.json").write_text(json.dumps(data.get("catalogue", {})))
    for name in (
        "scorecards",
        "timeline",
        "source_audit",
        "vendor_gaps",
        "casefiles",
        "comparison_eligibility",
        "product_groups",
        "extraction_validation",
        "switching_validation",
        "switching_review_packet",
        "review_packet",
        "publisher_history",
        "family_completeness",
        "comparison_readiness",
        "fix_leads",
        "component_studies",
        "product_cohorts",
        "disclosure_review",
        "research_dossiers",
        "kev",
    ):
        (destination / (name.replace("_", "-") + ".json")).write_text(
            json.dumps(
                {
                    **data.get(name, {}),
                    "publication": data["publication"],
                    "generated_at": data["generated_at"],
                }
            )
        )
    # Derive the monitor sidecar from the same validated bytes kept for explicit downloads.
    # Both files and their hashes become visible only with the atomic generation pointer.
    eligibility_summary = monitor_summary(
        (destination / "comparison-eligibility.json").read_bytes(),
        publication=data["publication"],
        generated_at=data["generated_at"],
        vendors=data["vendors"],
    )
    (destination / "comparison-eligibility-summary.json").write_text(
        json.dumps(eligibility_summary, separators=(",", ":")) + "\n"
    )
    (destination / "benchmark.json").write_text(json.dumps(data.get("benchmark", {})))
    for record in data["records"] + [w["record"] for w in data["retained_advisories"]]:
        path = destination / "evidence" / f"{record['evidence_id']}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    k: record.get(k)
                    for k in (
                        "evidence_id",
                        "source_url",
                        "sha256",
                        "source_observed_at",
                        "observed_at",
                        "source_format",
                    )
                }
            )
        )
    for change in data["changes"]:
        path = destination / "changes" / f"{change['id']}.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(change))
    write_reader_assets(destination, data)
    from .static_delivery import write_static_delivery

    write_static_delivery(destination, data)
    write_manifest(destination, data)


def write_manifest(destination, data):
    manifest = {
        str(p.relative_to(destination)): sha256(p.read_bytes()).hexdigest()
        for p in sorted(destination.rglob("*"))
        if p.is_file()
    }
    (destination / "manifest.json").write_text(
        json.dumps({"generation": data["publication"]["id"], "sha256": manifest}, indent=2)
    )


def write_reader_assets(destination, data, *, publication_format="v1"):
    for name in (
        *(("publication-v2.js",) if publication_format == "v2" else ()),
        "lossless-json.js",
        "current-evidence.js",
        "app.js",
        "style.css",
        "research-dossiers.js",
        "kev.js",
        "switching-contracts.js",
        "switching.js",
        "switching-view.js",
        "customer-comparison.js",
        "snapshot.js",
        "delivery.js",
    ):
        shutil.copyfile(PACKAGE / "web" / name, destination / name)
    html = (
        (PACKAGE / "web/index.html")
        .read_text()
        .replace(
            '<script defer src="/app.js">',
            '<script defer src="/delivery.js"></script><script defer src="/kev.js"></script><script defer src="/switching.js"></script><script defer src="/switching-view.js"></script><script defer src="/customer-comparison.js"></script><script defer src="/snapshot.js"></script><script defer src="/app.js">',
        )
    )
    if publication_format == "v2":
        html = html.replace(
            '<script defer src="/delivery.js">',
            '<script defer src="/publication-v2.js"></script><script defer src="/delivery.js">',
        )
        html = html.replace("/snapshot.json.gz", "/snapshot-v2.json.gz")
    # Immutable script/style paths avoid mixing old cached readers with a new
    # delivery contract. Root names remain available for existing integrations.
    (destination / "assets").mkdir(exist_ok=True)
    for name in (
        *(("publication-v2.js",) if publication_format == "v2" else ()),
        "lossless-json.js",
        "current-evidence.js",
        "app.js",
        "research-dossiers.js",
        "kev.js",
        "switching-contracts.js",
        "switching.js",
        "switching-view.js",
        "customer-comparison.js",
        "snapshot.js",
        "delivery.js",
        "style.css",
    ):
        raw = (destination / name).read_bytes()
        asset = "assets/" + sha256(raw).hexdigest() + Path(name).suffix
        (destination / asset).write_bytes(raw)
        html = html.replace('"/' + name + '"', '"/' + asset + '"')
    html = html.replace("LOCAL RESEARCH PILOT", "EVIDENCE PUBLICATION")
    html = re.sub(r'(id="archive-export")\s+hidden\b', r"\1", html)
    notice = '<div class="notice">Evidence publication generated ' + data["generated_at"][:10]
    notice += ". Review source dates and coverage. Collection status is shown under Collection health.</div>"
    base_path = os.environ.get("IMPACT_BASE_PATH", "/")
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*", base_path):
        raise ValueError("Base path must be a safe absolute directory path")
    html = html.replace('<div id="summary"', notice + '<div id="summary"')
    html = html.replace('href="/', 'href="' + base_path).replace('src="/', 'src="' + base_path)
    (destination / "index.html").write_text(html)
    (destination / ".nojekyll").touch()
    (destination / "research").mkdir(exist_ok=True)
    for name in (
        "cohort-report.txt",
        "hpe-timing-investigation.txt",
        "fortiproxy-curl-investigation.txt",
        "aruba-cx-investigation.txt",
        "juniper-security-rebuilds.txt",
    ):
        source = (
            Paths.from_env().home / "benchmark" / name
            if name == "cohort-report.txt"
            else PACKAGE / "resources" / name
        )
        if not source.exists():
            source = PACKAGE / "resources" / name
        if source.exists():
            shutil.copyfile(source, destination / "research" / name)
    schema = destination / "schemas/advisory-v2.json"
    schema.parent.mkdir(exist_ok=True)
    shutil.copyfile(PACKAGE / "schemas/advisory-v2.json", schema)
    shutil.copyfile(
        PACKAGE / "schemas/release-asset-v1.json", destination / "schemas/release-asset-v1.json"
    )
    shutil.copyfile(
        PACKAGE / "schemas/comparison-eligibility-v1.json",
        destination / "schemas/comparison-eligibility-v1.json",
    )
    for name in (
        "current-evidence-v1.json",
        "comparison-eligibility-summary-v1.json",
        "product-groups-v1.json",
        "publisher-history-v1.json",
        "extraction-review-v1.json",
        "review-submission-v1.json",
        "static-index-v1.json",
        *(("static-index-v2.json",) if publication_format == "v2" else ()),
        # The customer schema union references overview and range definitions in v1 too.
        "publication-v2.json",
        "switching-overview-v2.json",
        "vendor-gaps-v1.json",
        "family-completeness-v1.json",
        "comparison-readiness-v1.json",
        "fix-leads-v1.json",
        "component-studies-v1.json",
        "source-selection-v1.json",
        "component-inventory-v1.json",
        "product-cohort-definition-v1.json",
        "build-inventory-submission-v1.json",
        "product-cohorts-v1.json",
        "disclosure-review-v1.json",
        "kev-v1.json",
        "switching-study-v1.json",
        "switching-evidence-v1.json",
        "switching-comparison-v1.json",
        "switching-summary-v1.json",
        "switching-release-history-v1.json",
        "customer-comparison-v1.json",
        "switching-inputs-v1.json",
        "research-dossiers-v1.json",
        "research-dossier-definition-v1.json",
    ):
        shutil.copyfile(PACKAGE / "schemas" / name, destination / "schemas" / name)
    shutil.copyfile(
        PACKAGE / "resources/switching-study.json", destination / "switching-study.json"
    )
    shutil.copyfile(PACKAGE / "resources/openapi.json", destination / "openapi.json")
    (destination / "_headers").write_text(
        "/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\n"
    )


def publish(data, root=None, public_release_urls=(), *, publication_format="v1"):
    from .publication_v2 import publication_format as validate_format

    validate_format(publication_format)
    root = Path(root or Paths.from_env().publications)
    generations = root / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    generation = uuid4().hex
    from .current_evidence import validate_report

    if "current_evidence" in data:
        validate_report(
            data["current_evidence"],
            publication=data.get("publication"),
            generated_at=data["generated_at"],
        )
    data = {**data, "publication": {"id": generation, "advisory_schema_version": 2}}
    if "current_evidence" in data:
        data["current_evidence"] = {**data["current_evidence"], "publication": data["publication"]}
    data = public_projection(
        data,
        public_release_urls,
        **({"publication_format": "v2"} if publication_format == "v2" else {}),
    )
    stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=generations))
    try:
        write_bundle(stage, data, publication_format=publication_format)
        stage.chmod(0o755)  # The separate reader container mounts only this public directory.
        final = generations / generation
        stage.rename(final)
        pointer = root / (".current-" + generation)
        pointer.symlink_to(Path("generations") / generation, target_is_directory=True)
        os.replace(pointer, root / "current")
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return final


def build(output=None, *, publication_format="v1"):
    """Publish from the evidence vault and export a static reader bundle."""
    from ..collection.config import load_config

    paths = Paths.from_env()
    with closing(connect(read_only=True)) as db:
        data = state(db)
        data["coverage"] = coverage(
            db, data["records"], sorted(set(data["all_cves"]) | set(COHORT))
        )
    if publication_format == "v2":
        from .reporting import _report_from_state

        _report_from_state(data)
    public_urls = [d["url"] for d in load_config().get("release_documents", [])]
    generation = publish(
        data, public_release_urls=public_urls, publication_format=publication_format
    )
    destination = Path(output or paths.snapshot)
    # Deployment archives need regular assets, not an external current symlink.
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(generation, destination, dirs_exist_ok=True)
    print(
        json.dumps(
            {
                "generation": generation.name,
                "destination": str(destination),
                "advisories": len(data["records"]),
            }
        )
    )
    return generation


def switching_score_availability(score_input, switching_input, records):
    """Explicit public diagnostics; metadata cannot establish study affectedness."""
    allowed_issues = {
        "score_unavailable",
        "score_invalid",
        "score_format_unsupported",
        "source_normalization_unavailable",
        "score_extraction_failed",
        "base_invalid",
        "base_missing",
        "base_severity_disagreement",
        "vector_missing",
        "vector_invalid",
        "vector_base_metrics_missing",
        "vector_duplicate_metric",
        "vector_order_invalid",
        "vector_version_disagreement",
        "version_invalid",
        "score_form_version_disagreement",
        "structured_metric_disagreement",
        "consistency_not_verified",
    }
    states = {
        "unknown",
        "ok",
        "rate_limited",
        "source_missing",
        "invalid_record",
        "network_error",
        "request_state_unresolved",
    }
    # Resolve source contexts once rather than rescanning all study claims per entry.
    contexts_by_source = {}
    for claim in switching_input.get("claims", []):
        key = (claim["vendor"], claim["advisory_id"], claim["source"]["source_url"])
        contexts_by_source.setdefault(key, []).append(
            (claim["cve_id"], claim["product_id"], "study_claim")
        )
    contexts_by_advisory = {}
    for record in records:
        key = (record["vendor"], record["advisory_id"])
        contexts_by_advisory.setdefault(key, []).extend(
            (cid, None, "source_only_unclassified") for cid in record["cves"]
        )
    fallback = score_input.get("fallback", {})
    fallback_by_cve = {}
    for score in fallback.get("claims", []):
        if score.get("cve_id") is not None and score.get("scope") == "cve_specific":
            fallback_by_cve.setdefault(score["cve_id"], []).append(score)
    attempts_by_cve = {}
    for attempt in fallback.get("attempts", []):
        if attempt.get("source") in ("nvd", "cve_record") and attempt.get("state") in states:
            attempts_by_cve.setdefault(attempt.get("cve_id"), []).append(attempt)

    result = []
    for entry in score_input.get("advisories", []):
        if entry["vendor"] not in ("cisco", "aruba", "arista"):
            continue
        key = (entry["vendor"], entry["advisory_id"], entry["source_url"])
        contexts = contexts_by_source.get(key) or contexts_by_advisory.get(key[:2], [])
        entry_by_cve = {}
        for score in entry.get("claims", []):
            if score.get("cve_id") is not None and score.get("scope") == "cve_specific":
                entry_by_cve.setdefault(score["cve_id"], []).append(score)
        entry_issues = {
            issue["code"]
            for issue in entry.get("issues", [])
            if isinstance(issue, dict) and issue.get("code") in allowed_issues
        }
        for cid, product, context in sorted(
            set(contexts), key=lambda x: (x[0] or "", x[1] or "", x[2])
        ):
            candidates = [
                score
                for score in entry_by_cve.get(cid, []) + fallback_by_cve.get(cid, [])
                if (not score.get("product_ids") or product in score["product_ids"])
                and (
                    score.get("origin") != "vendor_advisory"
                    or score["source"]["source_url"] == entry["source_url"]
                )
            ]
            issues = set(entry_issues)
            issues.update(i for s in candidates for i in s.get("issues", []) if i in allowed_issues)
            state = (
                "available"
                if any(s.get("validation") == "valid" for s in candidates)
                else "incomplete"
                if any(s.get("validation") == "incomplete" for s in candidates)
                else "invalid"
                if candidates
                else "unavailable"
            )
            if not candidates:
                issues.add("score_unavailable")
            attempts = [
                {k: a.get(k) for k in ("source", "cve_id", "state", "checked_at", "retry_at")}
                for a in attempts_by_cve.get(cid, [])
            ]
            source = entry.get("source")
            source = (
                {
                    k: source.get(k)
                    for k in ("source_url", "source_sha256", "retrieved_at", "source_locator")
                }
                if source
                else None
            )
            result.append(
                dict(
                    vendor=entry["vendor"],
                    advisory_id=entry["advisory_id"],
                    source_url=entry["source_url"],
                    cve_id=cid,
                    product_id=product,
                    context=context,
                    source=source,
                    state=state,
                    issues=sorted(issues),
                    attempts=attempts,
                )
            )
    return result
