"""Private, fresh-interpreter complete-candidate gate; never promotes or acquires evidence."""

import gzip
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from contextlib import closing
from hashlib import sha256
from pathlib import Path

from ..settings import PACKAGE

REQUEST = "target-import-request.json"
RESULT = "target-import-verification.json"
MAX_CONTEXT = 2_000_000
MAX_RESULT = 16_384
CHECKS = ("audit_passed", "capacity_passed", "candidate_validated")


class CapacityFailure(ValueError):
    pass


class MonitorUnavailable(ValueError):
    pass


def _read_json(path, limit):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate key")
            value[key] = item
        return value

    def constant(_):
        raise ValueError("nonfinite number")

    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise CapacityFailure("JSON size")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def _measure(path, limit=128_000_000):
    size, digest = 0, sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(min(1_048_576, limit + 1 - size)):
            size += len(chunk)
            if size > limit:
                raise CapacityFailure("file size")
            digest.update(chunk)
    return size, digest.hexdigest()


def _paths(database, public):
    database, public = Path(database).absolute(), Path(public).absolute()
    home = database.parent.parent / "home"
    root = database.parent.parent.parent
    if database != root / "private/data/intel.sqlite3" or public != root / "public":
        raise ValueError("stage layout")
    for path in (
        database,
        public,
        home,
        home / REQUEST,
        home / RESULT,
        home / "target-import-context.json",
        home / "publications",
        home / "benchmark",
    ):
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError("stage symlink")
    if not database.is_file() or not home.is_dir():
        raise ValueError("missing stage")
    return database.resolve(), public.resolve(), home.resolve()


def _base_path(home):
    from .target_import_contracts import validate_base_path

    context = _read_json(home / "target-import-context.json", MAX_CONTEXT)
    return validate_base_path(context["base_path"])


def _environment(database, public, home, *, base_path="/"):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("IMPACT_", "PYTHON"))}
    env.update(
        IMPACT_HOME=str(home),
        IMPACT_DATABASE=str(database),
        IMPACT_SOURCES=str(PACKAGE / "resources/sources.json"),
        IMPACT_SNAPSHOT=str(public),
        IMPACT_PUBLICATIONS=str(home / "publications"),
        IMPACT_BASE_PATH=base_path,
    )
    return env


def _empty(outcome="worker_failed", *, publication_format="v1"):
    from .publication_v2 import publication_format as validate_format

    validate_format(publication_format)
    return {
        **({"schema_version": 2, "publication_format": "v2"} if publication_format == "v2" else {}),
        **dict.fromkeys(CHECKS),
        "candidate": {
            "outcome": outcome,
            **(
                {"archive_scope": "snapshot-v1", "representation": "publication-v2-physical"}
                if publication_format == "v2"
                else {}
            ),
            "generation": None,
            "manifest_sha256": None,
            **dict.fromkeys(
                (
                    "public_bytes",
                    "expanded_bytes",
                    "compressed_bytes",
                    "default_checked_bytes",
                    "default_monitor_passed",
                    "archive_monitor_passed",
                    "parity_passed",
                )
            ),
        },
    }


def validate_result(value, *, publication_format="v1"):
    """The worker may return only this finite, sanitized closed result."""
    from jsonschema import Draft202012Validator

    from .publication_v2 import publication_format as validate_format

    validate_format(publication_format)
    schema = _read_json(
        PACKAGE
        / (
            "schemas/target-import-result-v2.json"
            if publication_format == "v2"
            else "schemas/target-import-result-v1.json"
        ),
        MAX_CONTEXT,
    )
    extra = {"schema_version", "publication_format"} if publication_format == "v2" else set()
    if publication_format == "v2" and (
        value.get("schema_version") != 2
        or type(value.get("schema_version")) is not int
        or value.get("publication_format") != "v2"
    ):
        raise ValueError("worker result format")
    if not isinstance(value, dict) or set(value) != {*CHECKS, "candidate", *extra}:
        raise ValueError("worker result fields")
    for key in CHECKS:
        if value[key] is not None and type(value[key]) is not bool:
            raise ValueError("worker result check")
    Draft202012Validator(schema["properties"]["candidate"]).validate(value["candidate"])
    if value["candidate"] is None:
        raise ValueError("missing worker details")
    passed = value["candidate"]["outcome"] == "passed"
    if passed != all(value[k] is True for k in CHECKS):
        raise ValueError("worker result outcome")
    if passed and any(value["candidate"][k] is None for k in value["candidate"]):
        raise ValueError("incomplete worker result")
    if passed and not all(
        value["candidate"][k] is True
        for k in ("default_monitor_passed", "archive_monitor_passed", "parity_passed")
    ):
        raise ValueError("unverified worker result")
    if passed and any(
        value["candidate"][key] > limit
        for key, limit in (
            ("expanded_bytes", 128_000_000),
            ("compressed_bytes", 8_000_000),
            ("default_checked_bytes", 20_000_000),
        )
    ):
        raise ValueError("worker capacity result")
    return value


def verify(database: Path, public: Path, profile, *, publication_format="v1") -> dict:
    """Dispatch only the trusted installed module, with stage settings before imports."""
    failure = _empty(publication_format=publication_format)
    try:
        database, public, home = _paths(database, public)
        if public.exists() or (home / "publications").exists() or (home / "benchmark").exists():
            raise ValueError("candidate output already exists")
        request = {
            "format": "impact-target-import-worker",
            "schema_version": 1,
            "profile": profile.metadata(),
        }
        if publication_format == "v2":
            request.update(schema_version=2, publication_format="v2")
        raw = (json.dumps(request, allow_nan=False) + "\n").encode()
        if len(raw) > MAX_CONTEXT:
            raise CapacityFailure("request size")
        # Exclusive private request/result files prevent stale-success reuse.
        with (home / REQUEST).open("xb") as stream:
            stream.write(raw)
        (home / REQUEST).chmod(0o600)
        if (home / RESULT).exists():
            raise ValueError("stale worker result")
        with (home / "target-import-worker.log").open("xb") as log:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-m",
                    __name__,
                    "--worker",
                    str(database),
                    str(public),
                    *(["v2"] if publication_format == "v2" else []),
                ],
                cwd=home,
                env=_environment(database, public, home, base_path=_base_path(home)),
                stdout=log,
                stderr=log,
                timeout=2400,
                check=False,
            )
        if completed.returncode:
            return failure
        return validate_result(
            _read_json(home / RESULT, MAX_RESULT), publication_format=publication_format
        )
    except Exception:
        return failure


def _monitor_path():
    folder = PACKAGE / "_standalone"
    if not folder.exists():
        # Known source tree equivalent only; never search CWD or executable PATH.
        root = PACKAGE.parent
        if (
            not (root / "pyproject.toml").is_file()
            or not (root / "checks/package_probe.py").is_file()
        ):
            raise MonitorUnavailable("monitor pair missing")
        folder = root / "checks"
    if not all(
        (folder / name).is_file() and not (folder / name).is_symlink()
        for name in ("public_health.py", "switching_health.py")
    ):
        raise MonitorUnavailable("monitor pair missing")
    canonical = PACKAGE / "publication_codec.py"
    shipped = folder / "publication_codec.py" if folder.name == "_standalone" else canonical
    if (
        not shipped.is_file()
        or shipped.is_symlink()
        or shipped.read_bytes() != canonical.read_bytes()
    ):
        raise MonitorUnavailable("canonical codec missing or changed")
    return folder / "public_health.py"


def _preserved(database, home, selected, *, publication_format="v1"):
    from ..plugins.registry import default_registry
    from .evidence_identity import record_key
    from .target_import import binding_fingerprint, source_config_fingerprint
    from .target_import_stage import _pipeline_values, _quoted, _retained_rows

    context = _read_json(home / "target-import-context.json", MAX_CONTEXT)
    if publication_format == "v2":
        from .publication_v2 import validate

        validate(context, "target-import-context-v2.json")
    elif "publication_format" in context:
        raise ValueError("context format")
    binding = context["binding"]
    if (
        context["format"] != "impact-target-import-context"
        or context["schema_version"] != (2 if publication_format == "v2" else 1)
        or _base_path(home) != os.environ.get("IMPACT_BASE_PATH", "/")
        or binding != context["observed_binding"]
        or binding["fingerprint"] != binding_fingerprint(binding)
        or binding["manifest_fingerprint"] != selected.fingerprint
        or binding["source_config_fingerprint"] != source_config_fingerprint()
        or binding["normalizer_fingerprints"]
        != {v: default_registry().fingerprint(v) for v in {t.vendor for t in selected.targets}}
    ):
        raise ValueError("context binding")
    proof = context["preservation"]
    if (
        proof["source_unchanged"] is not True
        or proof["existing_rows_unchanged"] is not True
        or proof["source_before"] != proof["source_after"]
        or proof["allowed_cache_urls"] != sorted(selected.allowed_urls)
        or len(context["targets"]) != len(selected.targets)
    ):
        raise ValueError("preservation context")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        if _retained_rows(db, selected, proof["baseline_tables"]) != proof["baseline_tables"]:
            raise ValueError("retained rows changed")
        from datetime import datetime

        started = datetime.fromisoformat(context["operation_started_at"])
        finished = datetime.fromisoformat(context["operation_finished_at"])
        if started.tzinfo is None or finished.tzinfo is None or finished < started:
            raise ValueError("pipeline timestamps")
        if type(context["pipeline_run_id"]) is not int:
            raise ValueError("pipeline identity")
        expected_pipeline = {
            "id": context["pipeline_run_id"],
            **_pipeline_values(
                selected,
                context["targets"],
                binding["fingerprint"],
                context["operation_started_at"],
                context["operation_finished_at"],
            ),
        }
        appendable = {"evidence", "source_observations", "http_cache", "revisions", "changes"}
        for table, baseline in proof["baseline_tables"].items():
            rows = db.execute(
                f"SELECT * FROM {_quoted(table)} WHERE rowid>?", (baseline["max_rowid"],)
            ).fetchall()
            if table == "pipeline_runs":
                if len(rows) != 1 or dict(rows[0]) != expected_pipeline:
                    raise ValueError("exact-target pipeline mismatch")
                continue
            if rows and table not in appendable:
                raise ValueError("unrequested table append")
            if table in ("evidence", "source_observations", "http_cache"):
                for row in rows:
                    url = row["url"] if table == "http_cache" else row["source_url"]
                    target = next((t for t in selected.targets if t.fetch_url == url), None)
                    if target is None:
                        raise ValueError("unrequested capture")
                    if table == "evidence":
                        if row["sha256"] != target.source_sha256:
                            raise ValueError("capture identity")
                    else:
                        ev = db.execute(
                            "SELECT source_url,sha256 FROM evidence WHERE id=?",
                            (row["evidence_id"],),
                        ).fetchone()
                        if ev is None or tuple(ev) != (target.fetch_url, target.source_sha256):
                            raise ValueError("capture reference")
        allowed = {(t.vendor, t.advisory_id) for t in selected.targets}
        for row in db.execute(
            "SELECT * FROM changes WHERE rowid>?",
            (proof["baseline_tables"]["changes"]["max_rowid"],),
        ):
            if (row["vendor"], row["advisory_id"]) not in allowed:
                raise ValueError("unrequested change")
        for row in db.execute(
            "SELECT * FROM revisions WHERE rowid>?",
            (proof["baseline_tables"]["revisions"]["max_rowid"],),
        ):
            if (row["vendor"], row["advisory_id"]) not in allowed:
                raise ValueError("unrequested revision")
        for target, facts in zip(selected.targets, context["targets"]):
            if (
                any(
                    facts[k] != target.metadata()[k]
                    for k in ("vendor", "advisory_id", "fetch_url", "source_sha256")
                )
                or facts["status"] not in ("imported", "unchanged")
                or facts["failure_code"] is not None
            ):
                raise ValueError("target context")
            row = db.execute(
                "SELECT r.*,r.id AS revision_id,e.raw,e.sha256,e.source_url AS capture_url "
                "FROM revisions r JOIN evidence e ON e.id=r.evidence_id "
                "WHERE r.vendor=? AND r.advisory_id=? ORDER BY r.id DESC LIMIT 1",
                (target.vendor, target.advisory_id),
            ).fetchone()
            if (
                row is None
                or row["source_url"] != target.fetch_url
                or row["capture_url"] != target.fetch_url
                or row["sha256"] != target.source_sha256
                or facts["after_keys"] != [record_key(dict(row))]
            ):
                raise ValueError("target identity")
            appended = db.execute(
                "SELECT COUNT(*) FROM revisions WHERE rowid>? AND vendor=? AND advisory_id=?",
                (
                    proof["baseline_tables"]["revisions"]["max_rowid"],
                    target.vendor,
                    target.advisory_id,
                ),
            ).fetchone()[0]
            if appended != (1 if facts["status"] == "imported" else 0):
                raise ValueError("target ingestion status mismatch")
            normalized = json.loads(row["normalized"])
            if sorted(normalized["cves"]) != list(
                target.cve_ids
            ) or normalized != default_registry().normalize(
                row["raw"], target.fetch_url, target.vendor
            ):
                raise ValueError("target normalization")


def _inspect_bundle(public, facts):
    """Measure every artifact and verify manifest, installed schemas and every part."""
    from jsonschema import Draft202012Validator

    manifest = _read_json(public / "manifest.json", 2_000_000)
    if set(manifest) != {"generation", "sha256"} or not re.fullmatch(
        "[a-f0-9]{32}", manifest["generation"]
    ):
        raise ValueError("manifest identity")
    files = {str(p.relative_to(public)): p for p in public.rglob("*") if p.is_file()}
    if any(p.is_symlink() for p in public.rglob("*")) or set(files) != {
        *manifest["sha256"],
        "manifest.json",
    }:
        raise ValueError("manifest file inventory")
    facts["generation"] = manifest["generation"]
    facts["manifest_sha256"] = _measure(public / "manifest.json", 2_000_000)[1]
    facts["public_bytes"] = sum(path.stat().st_size for path in files.values())
    for key, name in (
        ("expanded_bytes", "snapshot.json"),
        ("compressed_bytes", "snapshot.json.gz"),
    ):
        if name in files:
            facts[key] = files[name].stat().st_size
    # This closed importer targets GitHub Pages; cap the whole published site.
    if facts["public_bytes"] > 1_000_000_000:
        raise CapacityFailure("public site size")
    total = 0
    for name, path in files.items():
        limit = 8_000_000 if name == "snapshot.json.gz" else 128_000_000
        size, digest = _measure(path, limit)
        total += size
        if name != "manifest.json" and digest != manifest["sha256"][name]:
            raise ValueError("manifest hash")
        if name.startswith("schemas/"):
            if not (PACKAGE / name).is_file() or digest != _measure(PACKAGE / name)[1]:
                raise ValueError("schema changed")
        if name == "snapshot.json":
            facts["expanded_bytes"] = size
        if name == "snapshot.json.gz":
            facts["compressed_bytes"] = size
    facts["public_bytes"] = total
    if facts["expanded_bytes"] is None or facts["compressed_bytes"] is None:
        raise ValueError("missing archive")
    size, digest = 0, sha256()
    with gzip.open(public / "snapshot.json.gz", "rb") as stream:
        while chunk := stream.read(min(1_048_576, 128_000_001 - size)):
            size += len(chunk)
            if size > 128_000_000:
                raise CapacityFailure("expanded archive")
            digest.update(chunk)
    if size != facts["expanded_bytes"] or digest.hexdigest() != manifest["sha256"]["snapshot.json"]:
        raise ValueError("archive mismatch")
    index = _read_json(public / "data/index.json", 2_000_000)
    Draft202012Validator(
        _read_json(PACKAGE / "schemas/static-index-v1.json", MAX_CONTEXT)
    ).validate(index)
    if index["publication"]["id"] != manifest["generation"]:
        raise ValueError("generation mismatch")

    def descriptors(value):
        if isinstance(value, dict):
            if {"path", "sha256", "bytes"} <= value.keys():
                path = value["path"]
                if (
                    path not in files
                    or _measure(files[path])[0] != value["bytes"]
                    or manifest["sha256"][path] != value["sha256"]
                ):
                    raise ValueError("part binding")
                if path.startswith("data/"):
                    part = _read_json(files[path], 8_000_000)
                    if (
                        set(part) != {"schema_version", "publication", "generated_at", "data"}
                        or part["schema_version"] != 1
                        or any(part[k] != index[k] for k in ("publication", "generated_at"))
                    ):
                        raise ValueError("part identity")
            for item in value.values():
                descriptors(item)
        elif isinstance(value, list):
            for item in value:
                descriptors(item)

    descriptors(index)
    return _read_json(public / "snapshot.json", 128_000_000)


def _parity(database, public, home, snapshot):
    from ..collection.config import load_config
    from ..exports import assessment_export, csv_export, select, switching_csv
    from ..storage.repository import connect
    from .kev import KevUnavailable
    from .publication import public_projection, write_bundle
    from .query import state
    from .switching_comparison import select_report, summary

    with closing(connect(database, read_only=True)) as db:
        native = state(db)
    native["publication"] = snapshot["publication"]
    native["current_evidence"]["publication"] = snapshot["publication"]
    projected = public_projection(
        native, [d["url"] for d in load_config().get("release_documents", [])]
    )
    compact = {k: v for k, v in projected.items() if k != "switching_evidence"}
    compact["switching_comparison"] = summary(projected["switching_comparison"])
    if compact != snapshot:
        raise ValueError("native public facts differ")
    if (public / "impact.csv").read_bytes() != csv_export(projected).encode():
        raise ValueError("public CSV differs")
    for cohort in (None, [], sorted(set(snapshot["all_cves"]))):
        for kev_only in (False, True):
            selections = []
            for data in (projected, snapshot):
                try:
                    selections.append(
                        select(
                            data, cohort, kev_only=kev_only, evaluated_at=snapshot["generated_at"]
                        )
                    )
                except KevUnavailable:
                    selections.append(None)
            left, right = selections
            if left is None or right is None:
                if left is not right:
                    raise ValueError("KEV availability parity")
                continue
            if (
                assessment_export(left)["records"] != assessment_export(right)["records"]
                or left["kev"] != right["kev"]
                or csv_export(left) != csv_export(right)
            ):
                raise ValueError("selection parity")
    published = _read_json(public / "switching-comparison.json", 128_000_000)
    if (
        published != projected["switching_comparison"]
        or _read_json(public / "switching-evidence.json", 128_000_000)
        != projected["switching_evidence"]
    ):
        raise ValueError("switching scope differs")
    for scope in ("os_family", "model_qualified"):
        left = select_report(
            projected["switching_comparison"],
            scope_level=scope,
            evaluated_at=snapshot["generated_at"],
        )
        right = select_report(published, scope_level=scope, evaluated_at=snapshot["generated_at"])
        if left != right or switching_csv(left) != switching_csv(right):
            raise ValueError("switching selection parity")
    # Rebuild the entire public-only bundle from independently queried native facts.
    # This binds every lazy browser part, download and asset, and rejects extra files.
    with tempfile.TemporaryDirectory(dir=home) as temporary:
        root = Path(temporary)
        write_bundle(root, projected)
        if _read_json(root / "manifest.json", MAX_CONTEXT) != _read_json(
            public / "manifest.json", MAX_CONTEXT
        ):
            raise ValueError("complete public bundle parity")


def _monitors(public, home, facts, *, base_path="/"):
    from functools import partial
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    from threading import Thread
    from urllib.parse import unquote, urlsplit

    from .target_import_contracts import validate_base_path

    base_path = validate_base_path(base_path)
    monitor = _monitor_path()

    class Handler(SimpleHTTPRequestHandler):
        def _scoped(self):
            parsed = urlsplit(self.path)
            path = unquote(parsed.path, errors="strict")
            if (
                self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}"
                or parsed.scheme
                or parsed.netloc
                or parsed.query
                or parsed.fragment
                or not path.startswith(base_path)
                or "\\" in path
                or "\0" in path
                or any(part in (".", "..") for part in path.split("/"))
            ):
                self.send_error(404)
                return False
            self.path = path[len(base_path) - 1 :]
            return True

        def do_GET(self):
            if self._scoped():
                super().do_GET()

        def do_HEAD(self):
            if self._scoped():
                super().do_HEAD()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=str(public)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for archive in (False, True):
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                run = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(monitor),
                        "http://127.0.0.1:" + str(server.server_port) + base_path,
                        "--generation",
                        facts["generation"],
                        *(["--verify-archive"] if archive else []),
                    ],
                    cwd=home,
                    stdout=output,
                    stderr=errors,
                    timeout=300,
                    check=False,
                )
                if run.returncode:
                    errors.seek(0)
                    message = errors.read(16_384)
                    print(message.decode("utf-8", errors="replace"), file=sys.stderr)
                    if b"exceeds monitor budget" in message:
                        raise CapacityFailure("monitor capacity")
                    raise ValueError("monitor rejected")
                output.seek(0)
                raw = output.read(MAX_RESULT + 1)
                if len(raw) > MAX_RESULT:
                    raise ValueError("monitor result size")
                result = json.loads(raw)
                if result["publication"] != facts["generation"]:
                    raise ValueError("monitor generation")
                if archive:
                    if result["compressed_archive_verified"] is not True:
                        raise ValueError("archive unverified")
                    facts["archive_monitor_passed"] = True
                else:
                    facts["default_checked_bytes"] = result["checked_default_bytes"]
                    facts["default_monitor_passed"] = True
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _worker(database, public, *, publication_format="v1"):
    result = _empty("validation_failed", publication_format=publication_format)
    database, public, home = _paths(database, public)
    os.environ.clear()
    os.environ.update(_environment(database, public, home, base_path=_base_path(home)))
    try:
        from ..collection.target_import_profiles import from_manifest

        request = _read_json(home / REQUEST, MAX_CONTEXT)
        if (
            set(request)
            != {
                "format",
                "schema_version",
                "profile",
                *({"publication_format"} if publication_format == "v2" else set()),
            }
            or request["format"] != "impact-target-import-worker"
            or type(request["schema_version"]) is not int
            or request["schema_version"] != (2 if publication_format == "v2" else 1)
            or (publication_format == "v2" and request.get("publication_format") != "v2")
        ):
            raise ValueError("worker request")
        selected = from_manifest(request["profile"])
        _preserved(
            database,
            home,
            selected,
            **({"publication_format": "v2"} if publication_format == "v2" else {}),
        )
        _monitor_path()
        from ..storage.audit import audit

        try:
            audit()
        except Exception:
            result.update(audit_passed=False)
            result["candidate"]["outcome"] = "audit_failed"
            return result
        result["audit_passed"] = True
        from ..storage.repository import now
        from . import query, source_audit
        from .publication import build
        from .reporting import report

        evaluated = now()
        query.now = lambda: evaluated
        source_audit.now = lambda: evaluated
        report()
        build(public, **({"publication_format": "v2"} if publication_format == "v2" else {}))
        if publication_format == "v2":
            from .publication_v2 import inspect_bundle, native_parity

            reader = inspect_bundle(public, result["candidate"])
            native_parity(database, public, home, reader)
        else:
            snapshot = _inspect_bundle(public, result["candidate"])
            _parity(database, public, home, snapshot)
        result["candidate"]["parity_passed"] = True
        _monitors(public, home, result["candidate"], base_path=_base_path(home))
        _preserved(
            database,
            home,
            selected,
            **({"publication_format": "v2"} if publication_format == "v2" else {}),
        )
        result.update(capacity_passed=True, candidate_validated=True)
        result["candidate"]["outcome"] = "passed"
    except CapacityFailure:
        result.update(capacity_passed=False, candidate_validated=False)
        result["candidate"]["outcome"] = "capacity_failed"
    except MonitorUnavailable:
        result["candidate_validated"] = False
        result["candidate"]["outcome"] = "monitor_unavailable"
    except Exception:
        import traceback

        traceback.print_exc()  # Stage-private diagnostics; never part of the receipt.
        result["candidate_validated"] = False
    return result


def main():
    if (
        len(sys.argv) not in (4, 5)
        or sys.argv[1] != "--worker"
        or (len(sys.argv) == 5 and sys.argv[4] != "v2")
    ):
        raise SystemExit("internal candidate worker only")
    database, public, home = _paths(Path(sys.argv[2]), Path(sys.argv[3]))
    publication_format = "v2" if len(sys.argv) == 5 else "v1"
    result = validate_result(
        _worker(
            database, public, **({"publication_format": "v2"} if publication_format == "v2" else {})
        ),
        publication_format=publication_format,
    )
    raw = (json.dumps(result, allow_nan=False) + "\n").encode()
    if len(raw) > MAX_RESULT:
        raise ValueError("worker result size")
    with (home / RESULT).open("xb") as stream:
        stream.write(raw)
    (home / RESULT).chmod(0o600)


if __name__ == "__main__":
    main()
