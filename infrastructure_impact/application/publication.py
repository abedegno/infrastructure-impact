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
from ..settings import PACKAGE, Paths
from ..storage.repository import connect
from .casefiles import casefiles
from .cohort import COHORT, coverage
from .eligibility import eligibility, report_validator
from .extraction_validation import review_packet, validation_report
from .families import completeness
from .fix_leads import leads, public_inputs
from .product_groups import product_groups
from .product_groups import validate_report as validate_groups
from .publisher_history import public_history
from .query import state
from .readiness import readiness
from .release_assets import validate_asset


def public_projection(data, public_release_urls=()):
    """The publication boundary never copies raw evidence or private review notes."""
    data = json.loads(json.dumps(data, allow_nan=False))
    for record in data["records"]:
        validate_advisory(record)
        record["notes"] = []
        record["metrics"] = []
        record["timeline"] = []
        record.pop("extensions", None)
        for assessment in record["assessments"]:
            assessment.pop("extensions", None)
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
        data["source_audit"].get("source_selections", []), data["records"]
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
    known_sources = {(r["source_url"], r["sha256"]) for r in data["records"]}
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
        data["records"], scopes=data["reviewed_source_scopes"]
    )
    data["vendor_gaps"] = vendor_gaps(data)
    data["review_packet"] = review_packet(data["records"])
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
    data["delays"] = []
    data["snapshot_notice"] = (
        "Dated public-source evidence; not a representative vendor security ranking. No finding of intentional concealment."
    )
    return data


def write_bundle(destination, data):
    from .research_reports import validate

    validate(data)
    report_validator().validate(data["comparison_eligibility"])
    validate_groups(data["product_groups"])
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    snapshot = (json.dumps(data, separators=(",", ":")) + "\n").encode("utf-8")
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
        "review_packet",
        "publisher_history",
        "family_completeness",
        "comparison_readiness",
        "fix_leads",
        "component_studies",
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
    (destination / "benchmark.json").write_text(json.dumps(data.get("benchmark", {})))
    for record in data["records"]:
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
    for name in ("app.js", "style.css", "snapshot.js", "delivery.js"):
        shutil.copyfile(PACKAGE / "web" / name, destination / name)
    html = (
        (PACKAGE / "web/index.html")
        .read_text()
        .replace(
            '<script defer src="/app.js">',
            '<script defer src="/delivery.js"></script><script defer src="/snapshot.js"></script><script defer src="/app.js">',
        )
    )
    # Immutable script/style paths avoid mixing old cached readers with a new
    # delivery contract. Root names remain available for existing integrations.
    (destination / "assets").mkdir(exist_ok=True)
    for name in ("app.js", "snapshot.js", "delivery.js", "style.css"):
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
        "product-groups-v1.json",
        "publisher-history-v1.json",
        "extraction-review-v1.json",
        "review-submission-v1.json",
        "static-index-v1.json",
        "vendor-gaps-v1.json",
        "family-completeness-v1.json",
        "comparison-readiness-v1.json",
        "fix-leads-v1.json",
        "component-studies-v1.json",
        "source-selection-v1.json",
        "component-inventory-v1.json",
    ):
        shutil.copyfile(PACKAGE / "schemas" / name, destination / "schemas" / name)
    shutil.copyfile(PACKAGE / "resources/openapi.json", destination / "openapi.json")
    (destination / "_headers").write_text(
        "/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\n"
    )
    from .static_delivery import write_static_delivery

    write_static_delivery(destination, data)
    manifest = {
        str(p.relative_to(destination)): sha256(p.read_bytes()).hexdigest()
        for p in sorted(destination.rglob("*"))
        if p.is_file()
    }
    (destination / "manifest.json").write_text(
        json.dumps({"generation": data["publication"]["id"], "sha256": manifest}, indent=2)
    )


def publish(data, root=None, public_release_urls=()):
    root = Path(root or Paths.from_env().publications)
    generations = root / "generations"
    generations.mkdir(parents=True, exist_ok=True)
    generation = uuid4().hex
    data = public_projection(data, public_release_urls)
    data["publication"] = {"id": generation, "advisory_schema_version": 2}
    stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=generations))
    try:
        write_bundle(stage, data)
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


def build(output=None):
    """Publish from the evidence vault and export a static reader bundle."""
    from ..collection.config import load_config

    paths = Paths.from_env()
    with closing(connect(read_only=True)) as db:
        data = state(db)
        data["coverage"] = coverage(
            db, data["records"], sorted(set(data["all_cves"]) | set(COHORT))
        )
    public_urls = [d["url"] for d in load_config().get("release_documents", [])]
    generation = publish(data, public_release_urls=public_urls)
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
