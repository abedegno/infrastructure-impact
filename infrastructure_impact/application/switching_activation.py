"""Closed, one-off runner glue for the reviewed switching activation.

Only disposable restored recovery is opened. Public receipts contain closed facts
and digests; stock staging, fresh-worker validation and recovery promotion apply.
"""

import argparse
import json
import os
import re
import shutil
import sqlite3
import tempfile
from contextlib import closing, contextmanager, redirect_stderr, redirect_stdout
from hashlib import sha256
from pathlib import Path

PROFILE_ID = "switching-readiness-2026-11-09-v1"
MAX_RECEIPT_BYTES = 2_000_000
ERP_URL = "https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056"
ERP_SHA256 = "3ca993c5411757fe2567f966978c329f54c138b8139231b4d8161201e6563cb2"
ERP_SIZE = 173383
ARUBA_URL = "https://csaf.arubanetworking.hpe.com/2021/hpe_aruba_networking_-_2021-019.txt"
ARUBA_SHA256 = "8d1abe635fbabc246c475f22e8ea6ee05c5a09501be1ef9a8b2384aa553b6199"
ARUBA_CVES = (
    "CVE-2021-4104",
    "CVE-2021-44228",
    "CVE-2021-44832",
    "CVE-2021-45046",
    "CVE-2021-45105",
)
# Prior public capture provenance only. Stock _fetch keeps genuine acquisition /
# retained evidence time; this metadata never writes an HTTP observation.
PRIOR_CAPTURE = "2026-11-05T17:19:45.400667+00:00"
ARISTA = tuple(
    (
        identity,
        "https://www.arista.com/en/support/advisories-notices/security-advisory/" + identity,
        cves,
    )
    for identity, cves in (
        ("23115-security-advisory-0128", ("CVE-2025-8872",)),
        ("24847-security-advisory-0201", ("CVE-2026-111943",)),
    )
)


def encoded(value):
    raw = (
        json.dumps(value, sort_keys=True, allow_nan=False, separators=(",", ":")) + "\n"
    ).encode()
    if len(raw) > MAX_RECEIPT_BYTES:
        raise ValueError("receipt_size")
    return raw


ANCHOR_ID = "cisco-sa-dhcp-dos-T3CXPO9z"
ANCHOR_SHA256 = "12b27df5cfedde1fc0c3f1359c26304e61a5ad8683ab594d5b1a441815fb09d7"


def selected_profile():
    from ..collection.target_import_profiles import (
        PROFILE_ID as INSTALLED_PROFILE,
    )
    from ..collection.target_import_profiles import (
        TargetImportProfile,
        TargetImportTarget,
        profile,
    )

    anchors = [t for t in profile(INSTALLED_PROFILE).targets if t.advisory_id == ANCHOR_ID]
    if (
        len(anchors) != 1
        or anchors[0].vendor != "cisco"
        or anchors[0].source_sha256 != ANCHOR_SHA256
        or anchors[0].cve_ids != ("CVE-2024-20259",)
    ):
        raise ValueError("anchor_definition")
    return TargetImportProfile(
        PROFILE_ID,
        "1",
        (
            TargetImportTarget(
                "aruba",
                "ARUBA-PSA-2021-019",
                ARUBA_URL,
                ARUBA_URL,
                ARUBA_SHA256,
                ARUBA_CVES,
                PRIOR_CAPTURE,
                PRIOR_CAPTURE,
            ),
            anchors[0],
        ),
        2,
    )


def retained_anchor(db, selected):
    """The stock schema needs both vendors; the Cisco member is cache-only.

    Require current exact bytes and unchanged facts before stock staging can use
    this anchor. No fallback request can occur when _fetch finds this evidence.
    """
    from ..plugins.registry import default_registry
    from ..storage.capture_cache import from_evidence

    target = selected.targets[1]
    capture = from_evidence(db, target.fetch_url, target.source_sha256, selected.max_document_bytes)
    row = db.execute(
        "SELECT r.*,e.sha256,e.source_url AS capture_url FROM revisions r "
        "JOIN evidence e ON e.id=r.evidence_id WHERE r.vendor='cisco' AND r.advisory_id=? "
        "ORDER BY r.id DESC LIMIT 1",
        (ANCHOR_ID,),
    ).fetchone()
    if (
        capture is None
        or row is None
        or row["source_url"] != target.fetch_url
        or row["capture_url"] != target.fetch_url
        or row["sha256"] != target.source_sha256
    ):
        raise ValueError("missing_anchor")
    previous = json.loads(row["normalized"])
    normalized = default_registry().normalize(capture["raw"], target.fetch_url, "cisco")
    if (
        normalized["advisory_id"] != ANCHOR_ID
        or sorted(normalized["cves"]) != list(target.cve_ids)
        or {k: v for k, v in previous.items() if k != "adapter_version"}
        != {k: v for k, v in normalized.items() if k != "adapter_version"}
    ):
        raise ValueError("anchor_factual_drift")


@contextmanager
def profile_lookup(selected):
    """Supply one validated profile to stock preview; never alter validation."""
    from . import target_import

    original = target_import.registered_profile

    def lookup(name):
        return selected if name == PROFILE_ID else original(name)

    target_import.registered_profile = lookup
    try:
        yield
    finally:
        target_import.registered_profile = original


def retained_arista(db):
    """Validate both current retained identities before allowing either write."""
    found = []
    for identity, url, expected_cves in ARISTA:
        row = db.execute(
            "SELECT r.*,e.raw,e.sha256,e.source_url AS capture_url,e.observed_at AS capture_time "
            "FROM revisions r JOIN evidence e ON e.id=r.evidence_id "
            "WHERE r.vendor='arista' AND r.advisory_id=? ORDER BY r.id DESC LIMIT 1",
            (identity,),
        ).fetchone()
        if row is None:
            raise ValueError("missing_retained_identity")
        record = json.loads(row["normalized"])
        raw = row["raw"]
        if (
            row["source_url"] != url
            or row["capture_url"] != url
            or (record.get("vendor"), record.get("advisory_id"), record.get("source_url"))
            != ("arista", identity, url)
            or sorted(record.get("cves", [])) != list(expected_cves)
            or not isinstance(raw, bytes)
            or len(raw) > 3_000_000
            or b"<html" not in raw[:10000].lower()
            or sha256(raw).hexdigest() != row["sha256"]
        ):
            raise ValueError("retained_identity")
        found.append((record | {"evidence_id": row["evidence_id"]}, raw, expected_cves))
    return found


def manifest_digest(state):
    manifest = state / "current.json"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 1_000_000:
        raise ValueError("recovery_manifest")
    with manifest.open("rb") as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("recovery_manifest")
    return sha256(raw).hexdigest()


def preview(database, state):
    from ..adapters.switching import bindings_resource
    from ..plugins.registry import default_registry
    from . import target_import

    commit = os.environ.get("IMPACT_SOURCE_COMMIT", "")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("source_commit")
    accepted_manifest = manifest_digest(state)
    selected = selected_profile()
    with profile_lookup(selected):
        stock = target_import.preview(database, PROFILE_ID)
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        retained_arista(db)
        retained_anchor(db, selected)
        count = db.execute(
            "SELECT COUNT(*) FROM (SELECT MAX(id) FROM revisions GROUP BY vendor,advisory_id)"
        ).fetchone()[0]
    definitions = {
        "arista": ARISTA,
        "erp": {"url": ERP_URL, "sha256": ERP_SHA256, "bytes": ERP_SIZE},
        "target": selected.metadata(),
        "bindings": bindings_resource(),
        "max_sources": 2,
        "max_attempts_per_source": 2,
        "max_total_attempts": 4,
    }
    value = {
        "format": "impact-switching-activation-preview",
        "schema_version": 1,
        "profile_id": PROFILE_ID,
        "source_commit": commit,
        "accepted_manifest_sha256": accepted_manifest,
        "stock_inventory_fingerprint": stock["fingerprint"],
        "normalizer_fingerprints": {
            vendor: default_registry().fingerprint(vendor)
            for vendor in ("arista", "aruba", "cisco")
        },
        "definitions_sha256": sha256(encoded(definitions)).hexdigest(),
        "current_record_count": count,
        "retained_reparse_count": 2,
        "source_only_count": 1,
        "target_count": 2,
        "new_target_count": 1,
        "cached_anchor_count": 1,
        "target": selected.targets[0].metadata(),
        "max_sources": 2,
        "max_attempts_per_source": 2,
        "max_total_attempts": 4,
    }
    return value | {"fingerprint": sha256(encoded(value)).hexdigest()}


def reparse(database):
    from ..plugins.registry import default_registry
    from ..storage.repository import connect, ingest
    from .replay import normalized_record

    with closing(connect(database)) as db:
        ready = []
        for record, raw, expected in retained_arista(db):
            document = normalized_record(default_registry(), record, raw)
            if sorted(document["cves"]) != list(expected):
                raise ValueError("reparse_cves")
            ready.append((record, raw, document))
        for record, raw, document in ready:
            ingest(db, raw, record["source_url"], lambda *a, document=document: document, "arista")


def capture_erp(database):
    from ..adapters.switching import bindings_resource, extract
    from ..collection import transport
    from ..collection.transport_budget import TransportBudget
    from ..storage.repository import connect

    budget = TransportBudget(2, 80_000_000)
    with closing(connect(database)) as db:
        raw = transport.fetch(
            db,
            ERP_URL,
            "cisco",
            max_bytes=3_000_000,
            allowed_urls=frozenset({ERP_URL}),
            budget=budget,
            forbid_redirects=True,
        )
        if len(raw) != ERP_SIZE or sha256(raw).hexdigest() != ERP_SHA256 or budget.attempts > 2:
            raise ValueError("erp_source_drift")
        entries = [
            e
            for e in bindings_resource()["entries"]
            if e["source_url"] == ERP_URL
            and e["source_sha256"] == ERP_SHA256
            and e["vendor"] == "cisco"
        ]
        research = extract(raw, ERP_URL, "cisco", {"advisory_id": "ERP-75056"})
        if len(entries) != 1 or "bundle" not in entries[0]:
            raise ValueError("erp_binding")
        expected = entries[0]["bundle"]
        bundles = research.get("bundles", [])
        if (
            research.get("issues")
            or research.get("claims")
            or len(bundles) != 1
            or bundles[0]["publisher_id"] != "ERP-75056"
            or sorted(bundles[0]["member_advisory_ids"]) != sorted(expected["member_advisory_ids"])
            or len(set(bundles[0]["member_advisory_ids"])) != 13
        ):
            raise ValueError("erp_members")
        # fetch must have retained an authentic HTTP observation; never synthesize
        # an advisory revision or replay-time observation for source-only bytes.
        observed = db.execute(
            "SELECT e.sha256 FROM source_observations o JOIN evidence e ON e.id=o.evidence_id "
            "WHERE o.vendor='cisco' AND o.source_url=? ORDER BY o.id DESC LIMIT 1",
            (ERP_URL,),
        ).fetchone()
        if observed is None or observed[0] != ERP_SHA256:
            raise ValueError("erp_observation")
    return budget.attempts


@contextmanager
def environment(home, database, output, base_path):
    from ..settings import PACKAGE

    values = {
        "IMPACT_HOME": str(home),
        "IMPACT_DATABASE": str(database),
        "IMPACT_SOURCES": str(PACKAGE / "resources/sources.json"),
        "IMPACT_SNAPSHOT": str(output),
        "IMPACT_PUBLICATIONS": str(home / "publications"),
        "IMPACT_BASE_PATH": base_path,
        "IMPACT_DELIVERY_MODE": "scheduled_static",
    }
    previous = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for k, value in previous.items():
            if value is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = value


class ClosedParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("controls")


def controls(argv):
    from ..recovery_policy import DEFAULT_PROFILE, VAULT_PROFILES, vault_limit
    from .target_import_contracts import validate_base_path

    names = [a.split("=", 1)[0] for a in argv if a.startswith("--")]
    if len(names) != len(set(names)):
        raise ValueError("duplicate_control")
    parser = ClosedParser(add_help=False, allow_abbrev=False)
    for name in ("state-dir", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--encrypted-state", action="store_true", required=True)
    parser.add_argument("--recovery-storage", choices=("github-draft",), required=True)
    parser.add_argument("--recovery-repository")
    parser.add_argument("--publication-format", choices=("v2",), required=True)
    parser.add_argument("--maintenance-profile", choices=(PROFILE_ID,), required=True)
    parser.add_argument("--maintenance-mode", choices=("preview", "apply"), required=True)
    parser.add_argument("--maintenance-preview-fingerprint", default="")
    parser.add_argument("--schedule-utc", default="08:37")
    parser.add_argument("--backup-compression", choices=("xz", "gzip"), default="xz")
    parser.add_argument("--vault-profile", choices=tuple(VAULT_PROFILES), default=DEFAULT_PROFILE)
    args = parser.parse_args(argv)
    validate_base_path(args.base_path)
    if not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", args.schedule_utc):
        raise ValueError("schedule")
    fingerprint = args.maintenance_preview_fingerprint
    if (args.maintenance_mode == "apply" and not re.fullmatch(r"[a-f0-9]{64}", fingerprint)) or (
        args.maintenance_mode == "preview" and fingerprint
    ):
        raise ValueError("fingerprint")
    for path in (args.state_dir, args.output):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("paths")
    args.state_dir, args.output = args.state_dir.resolve(), args.output.resolve()
    if (
        args.output.exists()
        or args.state_dir.is_relative_to(args.output)
        or args.output.is_relative_to(args.state_dir)
    ):
        raise ValueError("paths")
    return args, vault_limit(args.vault_profile)


def main(argv):
    """Emit only closed metadata, including failures; never propagate raw errors."""
    from ops import hosted_job as hosted

    step = "controls"
    try:
        args, limit = controls(argv)
        key = os.environ.get("IMPACT_STATE_KEY")
        if not key or not re.fullmatch(r"[a-f0-9]{40}", os.environ.get("IMPACT_SOURCE_COMMIT", "")):
            raise ValueError("runner_controls")
        from ..storage.remote_recovery import GitHubDraftStore

        if hosted.state_backend(args.state_dir) != "github-draft-release-v1":
            raise ValueError("recovery_backend")
        store = GitHubDraftStore(args.recovery_repository or os.environ.get("GITHUB_REPOSITORY"))
        step = "restore"
        recovery_digest = manifest_digest(args.state_dir)
        # Keep failed preparation/candidates private on the runner for diagnosis.
        home = Path(tempfile.mkdtemp(prefix="impact-switching-")).resolve()
        database = home / "data/intel.sqlite3"
        # File-backed private log avoids unbounded memory and is never emitted.
        with (
            tempfile.TemporaryFile(mode="w+") as log,
            environment(home, database, args.output, args.base_path),
            redirect_stdout(log),
            redirect_stderr(log),
        ):
            if not hosted.restore_current(
                args.state_dir, database, key, store=store, vault_limit_bytes=limit
            ):
                raise ValueError("missing_recovery")
            if manifest_digest(args.state_dir) != recovery_digest:
                raise ValueError("recovery_changed")
            step = "preview"
            accepted = preview(database, args.state_dir)
            if args.maintenance_mode == "preview":
                raw = encoded(accepted)
                args.output.mkdir(parents=True)
                (args.output / "maintenance-preview.json").write_bytes(raw)
                hosted.workflow_effect("mode", "preview")
                hosted.workflow_effect("preview_ready")
            else:
                if accepted["fingerprint"] != args.maintenance_preview_fingerprint:
                    raise ValueError("stale_preview")
                step = "preparation"
                from ..storage.locking import writer_lock
                from . import target_import, target_import_stage
                from .target_import_contracts import result_bytes, validate_preview

                # This scope ends before stock stage takes the same writer lock.
                with writer_lock(home=home) as acquired:
                    if not acquired:
                        raise ValueError("writer_lock")
                    if preview(database, args.state_dir)["fingerprint"] != accepted["fingerprint"]:
                        raise ValueError("stale_preview")
                    reparse(database)
                    erp_attempts = capture_erp(database)
                selected = selected_profile()
                with profile_lookup(selected):
                    internal = validate_preview(
                        target_import.preview(database, PROFILE_ID), selected
                    )
                stage = home.parent / (home.name + "-candidate")
                step = "staging"
                result = target_import_stage.stage(
                    database,
                    selected,
                    internal["fingerprint"],
                    stage,
                    lock_home=home,
                    accepted_preview=internal,
                    base_path=args.base_path,
                    publication_format="v2",
                )
                result = json.loads(
                    result_bytes(result, selected=selected, publication_format="v2")
                )
                if (
                    result["outcome"] != "completed"
                    or result["fingerprint"] != internal["fingerprint"]
                    or result["counters"]["http_attempts"] > 2
                    or erp_attempts > 2
                ):
                    raise ValueError("candidate")
                staged = stage / result["staged_database"]
                step = "capacity"
                if staged.stat().st_size > limit:
                    raise ValueError("capacity")
                if manifest_digest(args.state_dir) != recovery_digest:
                    raise ValueError("recovery_changed")
                step = "backup"
                hosted.workflow_effect("mode", "apply")
                hosted.backup_verified(
                    args.state_dir, staged, key, store=store, args=args, limit=limit
                )
                step = "public_copy"
                shutil.copytree(stage / result["public_directory"], args.output)
                hosted.workflow_effect("publish_ready")
                shutil.rmtree(stage, ignore_errors=True)
        shutil.rmtree(home, ignore_errors=True)
        print(
            encoded(
                {
                    "mode": args.maintenance_mode,
                    "outcome": "preview" if args.maintenance_mode == "preview" else "completed",
                    "profile_id": PROFILE_ID,
                }
            ).decode(),
            end="",
        )
        return 0
    except Exception:
        print(
            encoded({"outcome": "error", "profile_id": PROFILE_ID, "stage": step}).decode(), end=""
        )
        return 1
