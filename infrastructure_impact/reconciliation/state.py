"""Single-writer, bounded local scan state and a verified read-only report view.

SQLite DELETE journals are used deliberately. Before a transaction, three times
its maximum database size plus 64 KiB is reserved for database/journal overhead.
The full accepted inventory byte count is charged as additional headroom, even
though entries are supplied by the snapshot rather than copied into this store.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import zlib
from contextlib import contextmanager
from pathlib import Path

MAX_FINDINGS = 100_000
MAX_WORKSPACE_BYTES = 1_000_000_000
_OVERHEAD = 65_536
_PAGE = 4096
# Finite binary64 JSON numbers need at most 24 ASCII bytes. Each source
# numeric token consumes at least one byte. This factor also dominates string
# expansion from non-UTF-8 source encodings; integer/punctuation spelling cannot
# grow. Metadata retains disjoint source fields once.
# Keep fixed scanner/locator overhead separate from that conservative 24x bound.
_MAX_OUTCOME_BYTES = 24 * 2_000_000 + 16_384
# More than zlib's default compressBound overhead, including incompressible input.
_MAX_COMPRESSED_BYTES = _MAX_OUTCOME_BYTES + _MAX_OUTCOME_BYTES // 100 + 64
_INITIAL_DATABASE_BYTES = 6 * _PAGE
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = (
    "parsed",
    "invalid",
    "unsupported_version",
    "rejected_record",
    "oversized",
    "missing_object",
)


class StateError(ValueError):
    """Stable diagnostic without source text or local paths."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class StorageLimit(StateError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _encode_outcome(row):
    raw = canonical(row).encode()
    if len(raw) > _MAX_OUTCOME_BYTES:
        raise StateError("outcome_encoding_limit")
    return zlib.compress(raw), len(raw), digest(raw)


def _decode_outcome(encoded, length, sha):
    if (
        type(length) is not int
        or not 0 <= length <= _MAX_OUTCOME_BYTES
        or not isinstance(encoded, bytes)
        or len(encoded) > _MAX_COMPRESSED_BYTES
    ):
        raise StateError("state_integrity")
    try:
        decoder = zlib.decompressobj()
        # The allocation bound is enforced by zlib, before materializing output.
        raw = decoder.decompress(encoded, length + 1)
        if (
            len(raw) != length
            or not decoder.eof
            or decoder.unused_data
            or decoder.unconsumed_tail
            or digest(raw) != sha
        ):
            raise StateError("state_integrity")
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise StateError("state_integrity")
        return row
    except (zlib.error, ValueError, UnicodeError, RecursionError):
        raise StateError("state_integrity") from None


def _file(path):
    try:
        info = path.lstat()
    except OSError:
        raise StateError("unsafe_workspace") from None
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise StateError("unsafe_workspace")
    return info.st_size


def retained_bytes(workspace):
    total = 0
    for path in workspace.rglob("*"):
        if path.is_symlink():
            raise StateError("unsafe_workspace")
        if path.is_dir():
            continue
        total += _file(path)
        if total > MAX_WORKSPACE_BYTES:
            raise StorageLimit("workspace_limit")
    return total


def validate_paths(workspace, repository, receipt):
    """Reject aliases into input worktrees, Git stores, receipts and their parents."""
    from .snapshot import _git_small

    workspace = Path(workspace)
    resolved = workspace.resolve()
    if any(part.is_symlink() for part in (workspace, *workspace.parents)):
        raise StateError("unsafe_workspace")
    repo = repository.resolve()
    git_dir = Path(os.fsdecode(_git_small(repo, "rev-parse", "--absolute-git-dir"))).resolve()
    common = Path(os.fsdecode(_git_small(repo, "rev-parse", "--git-common-dir")))
    if not common.is_absolute():
        common = repo / common
    for base in (repo, git_dir, common.resolve()):
        if resolved.is_relative_to(base) or base.is_relative_to(resolved):
            raise StateError("unsafe_workspace")
    for path in (receipt, receipt.with_name(receipt.name + ".raw.json")):
        actual = path.resolve()
        if actual == resolved or actual.is_relative_to(resolved):
            raise StateError("unsafe_workspace")
    return resolved


@contextmanager
def _lock(workspace, *, write):
    if any(part.is_symlink() for part in (workspace, *workspace.parents)) or not workspace.is_dir():
        raise StateError("unsafe_workspace")
    flags = os.O_RDWR | os.O_CREAT if write else os.O_RDONLY
    try:
        fd = os.open(workspace / ".lock", flags | os.O_NOFOLLOW, 0o600)
    except OSError:
        raise StateError("unsafe_workspace") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise StateError("unsafe_workspace")
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateError("workspace_locked") from None
        yield
    finally:
        os.close(fd)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    _sync_directory(path.parent)


class Workspace:
    def __init__(self, path, db, identity):
        self.path, self.db, self.identity = path, db, identity
        self.cursor = 0
        self.findings = 0
        self.consumed = 0
        self.counts = dict.fromkeys(_OUTCOMES, 0)
        self._fixed_bytes = 0
        self._new_capture_bytes = 0

    def _meta(self, key):
        row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        if row is None:
            raise StateError("state_integrity")
        return json.loads(row[0])

    def verify(self, entries=None):
        """Stream all committed data; no trusted aggregate can bypass retained evidence."""
        try:
            if self.db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise StateError("state_integrity")
            if self._meta("identity") != self.identity:
                raise StateError("state_integrity")
            cursor = findings = consumed = 0
            counts = dict.fromkeys(_OUTCOMES, 0)
            captures = set()
            for row in self.iter_outcomes():
                if row["position"] != cursor or row["outcome"] not in counts:
                    raise StateError("state_integrity")
                if entries is not None:
                    entry = entries[cursor]
                    if row["entry"] != dict(
                        path=entry.path, cve_id=entry.cve_id, oid=entry.oid, size=entry.size
                    ):
                        raise StateError("state_integrity")
                outcome_hash = hashlib.sha256(canonical(row).encode())
                found = 0
                for ordinal, payload, sha in self.db.execute(
                    "SELECT ordinal,payload,sha256 FROM findings WHERE position=? ORDER BY ordinal",
                    (cursor,),
                ):
                    if ordinal != found or digest(payload.encode()) != sha:
                        raise StateError("state_integrity")
                    outcome_hash.update(sha.encode())
                    found += 1
                expected = self.db.execute(
                    "SELECT sha256 FROM outcomes WHERE position=?", (cursor,)
                ).fetchone()[0]
                if outcome_hash.digest() != expected or found != row["finding_count"]:
                    raise StateError("state_integrity")
                capture = row["capture_sha256"]
                if bool(capture) != bool(found):
                    raise StateError("state_integrity")
                if capture:
                    raw = self.read_capture(capture)
                    if len(raw) != row["entry"]["size"] or capture != row["source_sha256"]:
                        raise StateError("state_integrity")
                    oid = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
                    if oid != row["entry"]["oid"]:
                        raise StateError("state_integrity")
                    captures.add(capture + ".json")
                cursor += 1
                findings += found
                consumed += row["consumed_bytes"]
                counts[row["outcome"]] += 1
            if (
                cursor != self._meta("cursor")
                or findings != self._meta("findings")
                or consumed != self._meta("consumed_bytes")
                or counts != self._meta("counts")
                or cursor > self.identity["total"]
                or findings > MAX_FINDINGS
                or self.db.execute("SELECT count(*) FROM findings").fetchone()[0] != findings
            ):
                raise StateError("state_integrity")
            self.cursor, self.findings, self.consumed, self.counts = (
                cursor,
                findings,
                consumed,
                counts,
            )
            return captures
        except (sqlite3.Error, ValueError, TypeError, KeyError, IndexError, OSError):
            raise StateError("state_integrity") from None

    def iter_outcomes(self):
        """Yield entry/outcome/metadata dictionaries in committed inventory order."""
        for encoded, length, sha in self.db.execute(
            "SELECT CASE WHEN length(payload)<=? THEN payload ELSE NULL END,"
            "raw_bytes,raw_sha256 FROM outcomes ORDER BY position",
            (_MAX_COMPRESSED_BYTES,),
        ):
            if not isinstance(sha, bytes) or len(sha) != 32:
                raise StateError("state_integrity")
            yield _decode_outcome(encoded, length, sha.hex())

    def iter_findings(self):
        """Yield {position, ordinal, finding}; each finding keeps the Task2 shape."""
        for position, ordinal, payload in self.db.execute(
            "SELECT position,ordinal,payload FROM findings ORDER BY position,ordinal"
        ):
            yield {"position": position, "ordinal": ordinal, "finding": json.loads(payload)}

    def read_capture(self, source_sha256):
        from .snapshot import MAX_RECORD_BYTES

        if not isinstance(source_sha256, str) or not _HASH.fullmatch(source_sha256):
            raise StateError("capture_integrity")
        path = self.path / "captures" / (source_sha256 + ".json")
        if _file(path) > MAX_RECORD_BYTES:
            raise StateError("capture_integrity")
        raw = path.read_bytes()
        if digest(raw) != source_sha256:
            raise StateError("capture_integrity")
        return raw

    @property
    def progress(self):
        return self.receipt("complete" if self.cursor == self.identity["total"] else "incomplete")

    def receipt(self, reason):
        return dict(
            format_version=1,
            total=self.identity["total"],
            attempted=self.cursor,
            parsed=self.counts["parsed"],
            invalid=self.counts["invalid"],
            unsupported=self.counts["unsupported_version"],
            rejected=self.counts["rejected_record"],
            oversized=self.counts["oversized"],
            missing_object=self.counts["missing_object"],
            unresolved=sum(
                self.counts[k]
                for k in ("invalid", "unsupported_version", "oversized", "missing_object")
            ),
            remaining=self.identity["total"] - self.cursor,
            cursor=self.cursor,
            candidate_findings=self.findings,
            consumed_bytes=self.consumed,
            retained_bytes=retained_bytes(self.path),
            stop_reason=reason,
            scan_complete=self.cursor == self.identity["total"],
            coverage_complete=False,
        )

    def _working_bytes(self):
        # The exclusive lock owns all writes during this invocation. Resume performs
        # a full filesystem census; per-record accounting only stats known files.
        temporary = sum(
            (self.path / name).stat().st_size
            for name in ("pending.jsonl", "pending.capture")
            if (self.path / name).exists()
        )
        return (
            self._fixed_bytes
            + _file(self.path / "state.sqlite3")
            + temporary
            + self._new_capture_bytes
        )

    def _reserve(self, extra=0):
        size = _file(self.path / "state.sqlite3")
        retained = self._working_bytes()
        if (
            retained + 2 * size + _OVERHEAD + self.identity["inventory_bytes"] + extra
            > MAX_WORKSPACE_BYTES
        ):
            raise StorageLimit("workspace_limit")

    def stage(self, result):
        """Serialize each finding incrementally; never dump an amplified entire result."""
        if self.findings + len(result["findings"]) > MAX_FINDINGS:
            raise StorageLimit("candidate_limit")
        stage = self.path / "pending.jsonl"
        encoder = json.JSONEncoder(
            sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        self._reserve()
        remaining = MAX_WORKSPACE_BYTES - (
            self._working_bytes()
            + 2 * _file(self.path / "state.sqlite3")
            + _OVERHEAD
            + self.identity["inventory_bytes"]
        )
        written = 0
        try:
            with stage.open("xb") as handle:
                for finding in result["findings"]:
                    for chunk in encoder.iterencode(finding):
                        raw = chunk.encode()
                        written += len(raw)
                        if written + 1 > remaining:
                            raise StorageLimit("workspace_limit")
                        handle.write(raw)
                    handle.write(b"\n")
                    written += 1
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            stage.unlink(missing_ok=True)
            raise
        return stage

    def commit_record(self, entry, result, raw, stage):
        """Capture first, then commit findings/outcome/cursor as one SQLite transaction."""
        count = len(result["findings"])
        capture = result["source_sha256"] if count else None
        created = None
        try:
            if capture:
                self._reserve(len(raw))
                created = self.path / "captures" / (capture + ".json")
                pending_capture = self.path / "pending.capture"
                _write_new(pending_capture, raw)
                os.replace(pending_capture, created)
                self._new_capture_bytes = len(raw)
                _sync_directory(created.parent)
            self._reserve()
            db_size = _file(self.path / "state.sqlite3")
            other = self._working_bytes() - db_size
            max_pages = (
                MAX_WORKSPACE_BYTES - other - _OVERHEAD - self.identity["inventory_bytes"]
            ) // (3 * _PAGE)
            self.db.execute(f"PRAGMA max_page_count={max_pages}")
            metadata = {key: value for key, value in result.items() if key != "findings"}
            row = dict(
                position=self.cursor,
                entry=dict(path=entry.path, cve_id=entry.cve_id, oid=entry.oid, size=entry.size),
                outcome=result["outcome"],
                source_sha256=result["source_sha256"],
                consumed_bytes=len(raw) if raw else 0,
                capture_sha256=capture,
                finding_count=count,
                metadata=metadata,
            )
            payload = canonical(row)
            sha = hashlib.sha256(payload.encode())
            encoded, raw_bytes, raw_sha = _encode_outcome(row)
            counts = self.counts | {row["outcome"]: self.counts[row["outcome"]] + 1}
            with self.db:
                with stage.open("r", encoding="utf-8") as handle:
                    for ordinal, line in enumerate(handle):
                        finding = line.rstrip("\n")
                        finding_hash = digest(finding.encode())
                        sha.update(finding_hash.encode())
                        self.db.execute(
                            "INSERT INTO findings VALUES(?,?,?,?)",
                            (self.cursor, ordinal, finding, finding_hash),
                        )
                self.db.execute(
                    "INSERT INTO outcomes VALUES(?,?,?,?,?)",
                    (self.cursor, encoded, raw_bytes, bytes.fromhex(raw_sha), sha.digest()),
                )
                for key, value in dict(
                    cursor=self.cursor + 1,
                    findings=self.findings + count,
                    consumed_bytes=self.consumed + row["consumed_bytes"],
                    counts=counts,
                ).items():
                    self.db.execute("UPDATE meta SET value=? WHERE key=?", (canonical(value), key))
            self.cursor += 1
            self.findings += count
            self.consumed += row["consumed_bytes"]
            self.counts = counts
            self._fixed_bytes += self._new_capture_bytes
            created = None
        except sqlite3.DatabaseError as error:
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise StorageLimit("workspace_limit") from None
            raise StateError("state_write_failed") from None
        finally:
            stage.unlink(missing_ok=True)
            (self.path / "pending.capture").unlink(missing_ok=True)
            if created is not None:
                created.unlink(missing_ok=True)
            self._new_capture_bytes = 0


def _connect(path, *, readonly):
    _file(path)
    db = sqlite3.connect(path.as_uri() + ("?mode=ro" if readonly else "?mode=rw"), uri=True)
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA temp_store=MEMORY")
    if db.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
        db.close()
        raise StateError("state_integrity")
    return db


def _read_identity(path):
    if _file(path) > 16_384:
        raise StateError("state_integrity")
    try:
        return json.loads(path.read_bytes())
    except (ValueError, UnicodeError):
        raise StateError("state_integrity") from None


def _reserve_initialization(path, identity, *, new_identity_bytes=0):
    # Run for fresh and interrupted initialization. Existing reports/staging/lock
    # bytes remain charged before any new identity/database/journal bytes exist.
    if (
        retained_bytes(path)
        + new_identity_bytes
        + identity["inventory_bytes"]
        + _OVERHEAD
        + 3 * _INITIAL_DATABASE_BYTES
        > MAX_WORKSPACE_BYTES
    ):
        raise StorageLimit("workspace_limit")


@contextmanager
def writable_workspace(path, identity, entries):
    path.mkdir(parents=True, exist_ok=True)
    with _lock(path, write=True):
        retained_bytes(path)
        identity_file = path / "identity.json"
        database = path / "state.sqlite3"
        if identity_file.exists():
            if _read_identity(identity_file) != identity:
                raise StateError("identity_mismatch")
        else:
            if any(item.name not in {".lock", "pending.identity"} for item in path.iterdir()):
                raise StateError("unsafe_workspace")
            _reserve_initialization(
                path, identity, new_identity_bytes=len(canonical(identity).encode())
            )
            pending_identity = path / "pending.identity"
            pending_identity.unlink(missing_ok=True)
            _write_new(pending_identity, canonical(identity).encode())
            os.replace(pending_identity, identity_file)
            _sync_directory(path)
        if not database.exists():
            _reserve_initialization(path, identity)
            # No committed state exists yet: discard only reserved initialization
            # staging files, then atomically publish a fully initialized database.
            pending_database = path / "pending.sqlite3"
            for name in ("pending.sqlite3", "pending.sqlite3-journal"):
                (path / name).unlink(missing_ok=True)
            db = sqlite3.connect(pending_database)
            db.executescript("""
                PRAGMA page_size=4096;
                PRAGMA max_page_count=6;
                PRAGMA journal_mode=DELETE;
                CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE outcomes(position INTEGER PRIMARY KEY,payload BLOB NOT NULL,
                                      raw_bytes INTEGER NOT NULL,raw_sha256 BLOB NOT NULL,sha256 BLOB NOT NULL);
                CREATE TABLE findings(position INTEGER,ordinal INTEGER,payload TEXT NOT NULL,sha256 TEXT NOT NULL,
                                      PRIMARY KEY(position,ordinal));
            """)
            with db:
                for key, value in dict(
                    identity=identity,
                    cursor=0,
                    findings=0,
                    consumed_bytes=0,
                    counts=dict.fromkeys(_OUTCOMES, 0),
                ).items():
                    db.execute("INSERT INTO meta VALUES(?,?)", (key, canonical(value)))
            db.close()
            with pending_database.open("rb") as handle:
                os.fsync(handle.fileno())
            os.replace(pending_database, database)
            _sync_directory(path)
        captures = path / "captures"
        captures.mkdir(exist_ok=True)
        if captures.is_symlink():
            raise StateError("unsafe_workspace")
        db = _connect(database, readonly=False)
        try:
            view = Workspace(path, db, identity)
            committed = view.verify(entries)
            for capture in captures.iterdir():
                if capture.name not in committed:
                    # An interrupted capture is discarded only after hash and next-entry membership checks.
                    raw = view.read_capture(capture.stem)
                    if view.cursor >= len(entries):
                        raise StateError("capture_integrity")
                    entry = entries[view.cursor]
                    oid = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
                    if oid != entry.oid or len(raw) != entry.size:
                        raise StateError("capture_integrity")
                    capture.unlink()
            (path / "pending.jsonl").unlink(missing_ok=True)
            (path / "pending.capture").unlink(missing_ok=True)
            view._fixed_bytes = retained_bytes(path) - _file(database)
            yield view
        finally:
            db.close()


class CommittedWorkspace:
    """Report-facing read API; no source paths and no mutation methods."""

    def __init__(self, view, captures):
        self._view = view
        self._captures = frozenset(captures)

    @property
    def identity(self):
        return dict(self._view.identity)

    @property
    def progress(self):
        return self._view.progress

    def iter_outcomes(self):
        return self._view.iter_outcomes()

    def iter_findings(self):
        return self._view.iter_findings()

    def read_capture(self, source_sha256):
        if not isinstance(source_sha256, str) or source_sha256 + ".json" not in self._captures:
            raise StateError("capture_not_committed")
        return self._view.read_capture(source_sha256)


@contextmanager
def open_workspace(workspace: Path):
    """Hold a shared lock and yield a validated, committed, read-only Workspace view.

    No repository, receipt path or network is needed. Caller must consume iterators
    inside the context. Captures may only be read by committed source SHA-256.
    """
    path = Path(workspace)
    with _lock(path, write=False):
        retained_bytes(path)
        identity = _read_identity(path / "identity.json")
        db = _connect(path.resolve() / "state.sqlite3", readonly=True)
        try:
            db.execute("BEGIN")
            view = Workspace(path, db, identity)
            committed = view.verify()
            if {item.name for item in (path / "captures").iterdir()} != committed:
                raise StateError("capture_integrity")
            yield CommittedWorkspace(view, committed)
        finally:
            db.close()
