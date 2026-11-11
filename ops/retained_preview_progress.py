"""Bounded metadata-only supervision of the fixed offline retained preview helper."""

import argparse
import json
import math
import os
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from functools import lru_cache
from pathlib import Path

MAX_PROGRESS = 16_384
MAX_READ = 65_536
MAX_EVENTS = 32
MAX_SAMPLES = 80
PHASES = frozenset(
    {
        "retained.sources",
        "retained.audit",
        "publication.query",
        "publication.projection",
        "publication.writing",
        "publication.inspection",
        "publication.native_parity",
        "publication.native_roots",
        "publication.native_queries",
        "publication.native_expected",
        "publication.native_reader",
    }
)
FAILURES = frozenset(
    {
        "stream_deadline",
        "byte_budget",
        "query_mismatch",
        "schema",
        "memory",
        "recursion",
        "unclassified",
    }
)
ROOT = Path(__file__).resolve().parents[1]


def _require(ok):
    if not ok:
        raise ValueError("invalid retained progress metadata")


def _number(value, maximum):
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= maximum


@lru_cache(maxsize=1)
def public_files():
    """Trusted installed public code only; never discover code from worker input."""
    import jsonschema

    files = {}
    names = (
        "manage_schedule",
        "hosted_job",
        "target_import_job",
        "switching_fix_preview",
        "retained_preview_progress",
    )
    paths = [(ROOT / f"ops/{name}.py", f"ops/{name}.py") for name in names]
    package = ROOT / "infrastructure_impact"
    paths.extend((p, p.relative_to(ROOT).as_posix()) for p in package.rglob("*.py"))
    schema = Path(jsonschema.__file__).resolve().parent
    paths.extend(
        (p, "jsonschema/" + p.relative_to(schema).as_posix()) for p in schema.rglob("*.py")
    )
    for path, relative in paths:
        if path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)):
            files[str(path.resolve())] = (relative, len(path.read_bytes().splitlines()))
    return files


def _location(value):
    _require(type(value) is dict and value.keys() == {"file", "line"})
    name, line = value["file"], value["line"]
    _require(type(name) is str and type(line) is int)
    if name == "external":
        _require(line == 0)
    else:
        bounds = {relative: lines for relative, lines in public_files().values()}
        _require(name in bounds and 1 <= line <= bounds[name])
    return {"file": name, "line": line}


def frame_location(frame):
    """Read code filename and line only, never values, names or source text."""
    point = public_files().get(frame.f_code.co_filename)
    line = frame.f_lineno
    if point is not None and type(line) is int and 1 <= line <= point[1]:
        return {"file": point[0], "line": line}
    return {"file": "external", "line": 0}


def _event(value):
    _require(type(value) is dict)
    if value.get("event") == "phase":
        required = {"event", "phase", "state", "elapsed_seconds"}
        optional = {"failure_code", "process_cpu_seconds", "peak_resident_bytes"}
        _require(required <= value.keys() <= required | optional)
        _require(type(value["phase"]) is str and value["phase"] in PHASES)
        _require(value["state"] in ("started", "completed", "failed"))
        _require(_number(value["elapsed_seconds"], 86_400))
        if "failure_code" in value:
            _require(value["state"] == "failed" and value["failure_code"] in FAILURES)
        if "process_cpu_seconds" in value:
            _require(_number(value["process_cpu_seconds"], 86_400))
        if "peak_resident_bytes" in value:
            _require(
                type(value["peak_resident_bytes"]) is int
                and 0 <= value["peak_resident_bytes"] <= 2**50
            )
    else:
        _require(
            value.keys() == {"event", "total_samples", "locations"} and value["event"] == "samples"
        )
        _require(type(value["total_samples"]) is int and 1 <= value["total_samples"] <= MAX_SAMPLES)
        locations = value["locations"]
        _require(type(locations) is list and 1 <= len(locations) <= 3)
        seen, total = set(), 0
        for point in locations:
            _require(type(point) is dict and point.keys() == {"file", "line", "count"})
            _location({k: point[k] for k in ("file", "line")})
            _require(type(point["count"]) is int and 1 <= point["count"] <= MAX_SAMPLES)
            key = point["file"], point["line"]
            _require(key not in seen)
            seen.add(key)
            total += point["count"]
        _require(total <= value["total_samples"])
    return value


def progress_bytes(value):
    """Fresh closed validation before every notice, store and artifact projection."""
    _require(type(value) is dict and value.keys() == {"schema_version", "events"})
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    _require(type(value["events"]) is list and len(value["events"]) <= MAX_EVENTS)
    for event in value["events"]:
        _event(event)
    raw = json.dumps(value, allow_nan=False, separators=(",", ":")).encode() + b"\n"
    _require(len(raw) <= MAX_PROGRESS)
    return raw


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value)
        value[key] = item
    return value


class Projector:
    def __init__(self):
        self.events = []
        self.seen = set()
        self.counts = Counter()
        self.samples = 0
        self.emitted_samples = 0
        self.last_aggregate = 0
        self.pending = b""
        self.discard = False

    def bytes(self):
        return progress_bytes({"schema_version": 1, "events": self.events})

    def feed(self, raw, *, now):
        _require(type(raw) is bytes and len(raw) <= MAX_READ)
        for part in raw.splitlines(keepends=True):
            complete = part.endswith(b"\n")
            if not self.discard:
                if len(self.pending) + len(part) > 4096:
                    self.pending = b""
                    self.discard = True
                else:
                    self.pending += part
            if complete:
                if not self.discard:
                    self._line(self.pending)
                self.pending = b""
                self.discard = False
        self.flush_samples(now=now)

    def _line(self, raw):
        try:
            value = json.loads(raw, object_pairs_hook=_pairs)
            _require(type(value) is dict)
            if value.get("event") == "sample":
                _require(value.keys() == {"event", "file", "line"})
                location = _location({k: value[k] for k in ("file", "line")})
                if self.samples < MAX_SAMPLES:
                    self.samples += 1
                    self.counts[location["file"], location["line"]] += 1
            else:
                _event(value)
                _require(value["event"] == "phase")
                key = value["phase"], value["state"]
                if key not in self.seen and len(self.events) < MAX_EVENTS - 1:
                    self.seen.add(key)
                    self.events.append(value)
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            pass

    def flush_samples(self, *, now, final=False):
        if self.samples == self.emitted_samples or (not final and now - self.last_aggregate < 120):
            return
        points = sorted(self.counts.items(), key=lambda item: (-item[1], item[0]))[:3]
        event = dict(
            event="samples",
            total_samples=self.samples,
            locations=[dict(file=name, line=line, count=count) for (name, line), count in points],
        )
        self.events = [e for e in self.events if e["event"] != "samples"]
        self.events.append(event)
        self.emitted_samples = self.samples
        self.last_aggregate = now


def _safe_path(path):
    path = Path(os.path.abspath(path))
    _require(not any(p.is_symlink() for p in (path, *path.parents)))
    _require(path.parent.is_dir())
    return path


class ProgressFile:
    def __init__(self, path):
        self.path = _safe_path(path)
        directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(
                self.path.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            with os.fdopen(fd, "wb") as stream:
                stream.write(progress_bytes({"schema_version": 1, "events": []}))
                info = os.fstat(stream.fileno())
                self.identity = info.st_dev, info.st_ino
        except FileExistsError:
            raise ValueError("invalid retained progress path") from None
        finally:
            os.close(directory)

    def write(self, value):
        raw = progress_bytes(value)
        path = _safe_path(self.path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        name = ".retained-progress-" + secrets.token_hex(16)
        created = False
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            _require((info.st_dev, info.st_ino) == self.identity)
            fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
            )
            created = True
            with os.fdopen(fd, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
                info = os.fstat(stream.fileno())
            os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            created = False
            self.identity = info.st_dev, info.st_ino
        finally:
            if created:
                os.unlink(name, dir_fd=directory)
            os.close(directory)


def read_progress(path):
    path = _safe_path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= MAX_PROGRESS)
        _require(-60 <= time.time() - info.st_mtime <= 3600)
        raw = stream.read(MAX_PROGRESS + 1)
    _require(len(raw) <= MAX_PROGRESS)
    return json.loads(progress_bytes(json.loads(raw, object_pairs_hook=_pairs)))


class Sampler:
    """Diagnostic-only sampling of the worker's own main Python thread."""

    def __init__(self, stream):
        self.stream = stream
        self.stop = threading.Event()
        self.count = 0
        self.main = threading.main_thread().ident
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def sample(self, frame):
        if self.count < MAX_SAMPLES:
            value = dict(event="sample", **frame_location(frame))
            print(json.dumps(value, separators=(",", ":")), file=self.stream, flush=True)
            self.count += 1

    def _loop(self):
        while self.count < MAX_SAMPLES and not self.stop.wait(30):
            frame = None
            try:
                frame = sys._current_frames().get(self.main)
                if frame is not None:
                    self.sample(frame)
            except Exception:
                pass  # Diagnostic I/O cannot alter helper acceptance.
            finally:
                del frame

    def __enter__(self):
        public_files()
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=1)


def _stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def run(database, public, output, source_commit, progress):
    progress_path = Path(progress).resolve()
    _require(progress_path not in {Path(database).resolve(), Path(output).resolve()})
    _require(not progress_path.is_relative_to(Path(public).resolve()))
    writer = ProgressFile(progress)
    projector = Projector()
    argv = [sys.executable, str(ROOT / "ops/switching_fix_preview.py")]
    for name, value in (
        ("database", database),
        ("public", public),
        ("output", output),
        ("source-commit", source_commit),
    ):
        argv.extend(("--" + name, str(value)))
    argv.append("--diagnostic-sampling")
    previous = {}

    def interrupted(*_):
        raise KeyboardInterrupt

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="retained-worker-") as directory:
            with (
                (Path(directory) / "stdout").open("w+b") as stdout,
                (Path(directory) / "stderr").open("wb") as stderr,
                (Path(directory) / "stderr").open("rb") as reader,
            ):
                child = subprocess.Popen(argv, stdout=stdout, stderr=stderr)
                started, offset, emitted, notices = time.monotonic(), 0, b"", 0
                try:
                    while True:
                        code = child.poll()
                        reader.seek(offset)
                        raw = reader.read(MAX_READ)
                        offset += len(raw)
                        now = time.monotonic() - started
                        projector.feed(raw, now=now)
                        if code is not None and len(raw) < MAX_READ:
                            projector.flush_samples(now=now, final=True)
                        safe = projector.bytes()
                        if safe != emitted:
                            writer.write(json.loads(safe))
                            if notices < MAX_EVENTS:
                                print(safe.decode().rstrip(), file=sys.stderr, flush=True)
                                notices += 1
                            emitted = safe
                        if code is not None and len(raw) < MAX_READ:
                            return code
                        time.sleep(1)
                finally:
                    _stop(child)
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "public", "output", "source-commit", "progress"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        return run(args.database, args.public, args.output, args.source_commit, args.progress)
    except KeyboardInterrupt:
        return 130
    except Exception:
        print("retained preview driver failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
