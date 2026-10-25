"""Validated, immutable public generations with an atomic current pointer."""

import json
import os
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
from .cohort import COHORT, coverage
from .query import state


def public_projection(data, public_release_urls=()):
    """The publication boundary never copies raw evidence or private review notes."""
    data = json.loads(json.dumps(data))
    for record in data["records"]:
        validate_advisory(record)
        record["notes"] = []
        record["metrics"] = []
        record["timeline"] = []
        record.pop("extensions", None)
        for assessment in record["assessments"]:
            assessment.pop("extensions", None)
    data["research"]["fix_candidates"] = []
    data["research"]["release_documents"] = [
        d for d in data["research"]["release_documents"] if d["source_url"] in public_release_urls
    ]
    data["signals"] = [
        s
        for s in data["signals"]
        if s["kind"] in ("reported_firmware_date_predates_bulletin", "cve_reference_added")
        or s.get("source_url") in public_release_urls
    ]
    for signal in data["signals"]:
        signal.pop("basis", None)
    data["snapshot_notice"] = (
        "Dated public-source evidence; not a representative vendor security ranking. No finding of intentional concealment."
    )
    return data


def write_bundle(destination, data):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "snapshot.json").write_text(json.dumps(data, separators=(",", ":")) + "\n")
    (destination / "impact.csv").write_text(csv_export(data))
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
    for name in ("app.js", "style.css", "snapshot.js"):
        shutil.copyfile(PACKAGE / "web" / name, destination / name)
    html = (
        (PACKAGE / "web/index.html")
        .read_text()
        .replace(
            '<script defer src="/app.js">',
            '<script defer src="/snapshot.js"></script><script defer src="/app.js">',
        )
    )
    html = html.replace("LOCAL RESEARCH PILOT", "EVIDENCE PUBLICATION")
    notice = '<div class="notice">Evidence publication generated ' + data["generated_at"][:10]
    notice += ". Review source dates and coverage. Collection status is shown under Collection health.</div>"
    (destination / "index.html").write_text(
        html.replace('<div id="summary"', notice + '<div id="summary"')
    )
    (destination / "research").mkdir(exist_ok=True)
    for name in ("cohort-report.txt", "hpe-timing-investigation.txt"):
        source = Paths.from_env().home / "benchmark" / name
        if not source.exists():
            source = PACKAGE / "resources" / name
        if source.exists():
            shutil.copyfile(source, destination / "research" / name)
    schema = destination / "schemas/advisory-v2.json"
    schema.parent.mkdir(exist_ok=True)
    shutil.copyfile(PACKAGE / "schemas/advisory-v2.json", schema)
    shutil.copyfile(PACKAGE / "resources/openapi.json", destination / "openapi.json")
    (destination / "_headers").write_text(
        "/*\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: no-referrer\n  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\n"
    )
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
    """Publish from the evidence vault and optionally export the Sites artifact."""
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
    # Sites needs regular assets, not a symlink outside the deployment archive.
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
