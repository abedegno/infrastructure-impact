"""Bounded official commit verification followed by entirely offline Git reads.

Verification is explicit and anonymous. A receipt and its adjacent ``.raw.json``
response are evidence of that verification, not a signature against local edits.
Only immutable objects are read; the index and working tree are never consulted.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import stat
import subprocess
from bisect import bisect_left
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

MAX_HTTP_BYTES = 1_000_000
MAX_TREE_ENTRIES = 2_000_000
MAX_INVENTORY_BYTES = 128_000_000
MAX_RECORD_BYTES = 2_000_000
MAX_RECEIPT_BYTES = 16_384
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_CVE = re.compile(r"CVE-([0-9]{4})-([0-9]{4,})\.json\Z")
_API = "https://api.github.com/repos/CVEProject/cvelistV5"
_RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5"


class SnapshotError(ValueError):
    """Safe, stable failure code; never includes source paths or Git stderr."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _pin(value: str) -> str:
    if not isinstance(value, str) or not _COMMIT.fullmatch(value):
        raise SnapshotError("invalid_commit")
    return value


def _git_env() -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        GIT_NO_LAZY_FETCH="1",
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_COUNT="0",
    )
    return env


@contextmanager
def _git(repository: Path, *args: str):
    process = None
    try:
        process = subprocess.Popen(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.allow=never",
                "-C",
                str(repository),
                *args,
            ],
            env=_git_env(),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        yield process
        if process.wait(timeout=25) != 0:
            raise SnapshotError("git_object_unavailable")
    except (OSError, subprocess.SubprocessError):
        raise SnapshotError("git_object_unavailable") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            for stream in (process.stdin, process.stdout):
                if stream is not None:
                    stream.close()


def _git_small(repository: Path, *args: str) -> bytes:
    with _git(repository, *args) as process:
        process.stdin.close()
        data = process.stdout.read(MAX_RECEIPT_BYTES + 1)
        if len(data) > MAX_RECEIPT_BYTES:
            raise SnapshotError("git_output_limit")
    return data.rstrip(b"\n")


def _object(repository: Path, oid: str, kind: str, max_bytes: int) -> bytes:
    with _git(repository, "cat-file", "--batch") as process:
        process.stdin.write((oid + "\n").encode("ascii"))
        process.stdin.close()
        header = process.stdout.readline(256).rstrip(b"\n").split(b" ")
        if len(header) != 3 or header[:2] != [oid.encode("ascii"), kind.encode("ascii")]:
            raise SnapshotError("git_object_unavailable")
        try:
            size = int(header[2])
        except ValueError:
            raise SnapshotError("git_object_unavailable") from None
        if size < 0 or size > max_bytes:
            raise SnapshotError("blob_byte_limit" if kind == "blob" else "git_object_limit")
        data = process.stdout.read(size + 1)
        if len(data) != size + 1 or data[-1:] != b"\n" or process.stdout.read(1):
            raise SnapshotError("git_object_unavailable")
    data = data[:-1]
    identity = hashlib.sha1(f"{kind} {size}\0".encode() + data).hexdigest()
    if identity != oid:
        raise SnapshotError("git_object_identity_mismatch")
    return data


def _local_tree(repository: Path, commit: str) -> str:
    data = _object(repository, commit, "commit", MAX_HTTP_BYTES)
    first = data.split(b"\n", 1)[0]
    try:
        tree = first.removeprefix(b"tree ").decode("ascii")
    except UnicodeError:
        raise SnapshotError("invalid_local_commit") from None
    if not first.startswith(b"tree ") or not _COMMIT.fullmatch(tree):
        raise SnapshotError("invalid_local_commit")
    if _git_small(repository, "cat-file", "-t", tree) != b"tree":
        raise SnapshotError("git_object_unavailable")
    return tree


def _raw_path(receipt: Path) -> Path:
    return receipt.with_name(receipt.name + ".raw.json")


def _paths(repository: Path, receipt: Path) -> tuple[Path, Path]:
    """Reject outputs within either worktree or Git storage, including symlink aliases."""
    try:
        root = repository.resolve(strict=True)
        git_dir = Path(os.fsdecode(_git_small(root, "rev-parse", "--absolute-git-dir")))
        common = Path(os.fsdecode(_git_small(root, "rev-parse", "--git-common-dir")))
        if not common.is_absolute():
            common = root / common
        inputs = (root, git_dir.resolve(), common.resolve())
        raw = _raw_path(receipt)
        for path in (receipt, raw):
            resolved = path.resolve()
            if path.is_symlink() or any(resolved.is_relative_to(base) for base in inputs):
                raise SnapshotError("unsafe_receipt_path")
        return receipt, raw
    except (OSError, ValueError, RuntimeError) as error:
        if isinstance(error, SnapshotError):
            raise
        raise SnapshotError("unsafe_receipt_path") from None


def _read_file(path: Path, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SnapshotError("unsafe_receipt_path")
            if info.st_size > limit:
                raise SnapshotError("receipt_byte_limit")
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise SnapshotError("receipt_byte_limit")
            return data
    except OSError:
        raise SnapshotError("receipt_unavailable") from None


def _json(data: bytes) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SnapshotError("invalid_verification_json")
            value[key] = item
        return value

    try:
        value = json.loads(data, object_pairs_hook=unique)
        if not isinstance(value, dict):
            raise SnapshotError("invalid_verification_json")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise SnapshotError("invalid_verification_json") from None


def _official_identity(raw: bytes, commit: str, tree: str) -> None:
    value = _json(raw)
    try:
        official_tree = value["commit"]["tree"]
        valid = (
            value["sha"] == commit
            and value["url"] == f"{_API}/commits/{commit}"
            and official_tree["sha"] == tree
            and official_tree["url"] == f"{_API}/git/trees/{tree}"
        )
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise SnapshotError("official_identity_mismatch")


def _write_new(path: Path, data: bytes) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
    except OSError:
        raise SnapshotError("receipt_write_failed") from None


def verify_snapshot(repository: Path, commit: str, receipt_path: Path) -> dict:
    """Make one exact-route bounded anonymous request and retain its verification receipt.

    The caller supplies an existing output directory, outside the input repository.
    Existing receipt or raw files are never overwritten, and no Git objects are fetched.
    """
    commit = _pin(commit)
    receipt_path, raw_path = _paths(repository, receipt_path)
    tree = _local_tree(repository, commit)
    if receipt_path.exists() or raw_path.exists():
        raise SnapshotError("receipt_already_exists")
    connection = None
    try:
        connection = http.client.HTTPSConnection("api.github.com", timeout=25)
        connection.request(
            "GET",
            f"/repos/CVEProject/cvelistV5/commits/{commit}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "infrastructure-impact-snapshot",
            },
        )
        response = connection.getresponse()
        try:
            if response.status != 200:
                raise SnapshotError("verification_http_status")
            raw = response.read(MAX_HTTP_BYTES + 1)
            if len(raw) > MAX_HTTP_BYTES:
                raise SnapshotError("verification_byte_limit")
        finally:
            response.close()
    except (OSError, http.client.HTTPException):
        raise SnapshotError("verification_unavailable") from None
    finally:
        if connection is not None:
            connection.close()
    _official_identity(raw, commit, tree)
    receipt = {
        "format_version": 1,
        "request_url": f"{_API}/commits/{commit}",
        "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "commit": commit,
        "tree": tree,
    }
    _write_new(raw_path, raw)
    _write_new(receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
    return receipt


@dataclass(frozen=True)
class Entry:
    path: str
    cve_id: str
    oid: str
    size: int

    def source_url(self, commit: str) -> str:
        return f"{_RAW}/{_pin(commit)}/{self.path}"


@dataclass(frozen=True)
class Snapshot:
    commit: str
    tree: str
    receipt_sha256: str
    inventory_entries: int
    inventory_bytes: int
    _repository: Path
    _entries: tuple[Entry, ...]

    def iter_entries(self) -> Iterator[Entry]:
        return iter(self._entries)

    @contextmanager
    def blob_reader(self):
        """One offline batch child, with no prefetch; closes even on early exit."""
        with _git(self._repository, "cat-file", "--batch") as process:
            reader = _BlobReader(self, process)
            try:
                yield reader
                process.stdin.close()
                if process.stdout.read(1):
                    raise SnapshotError("git_batch_protocol")
            finally:
                reader.closed = True

    def read_blob(self, entry: Entry, *, max_bytes: int) -> bytes:
        if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_RECORD_BYTES:
            raise SnapshotError("invalid_blob_limit")
        position = bisect_left(self._entries, entry.path, key=lambda item: item.path)
        if position == len(self._entries) or self._entries[position] != entry:
            raise SnapshotError("entry_not_in_snapshot")
        if entry.size > max_bytes:
            raise SnapshotError("blob_byte_limit")
        data = _object(self._repository, entry.oid, "blob", max_bytes)
        if len(data) != entry.size:
            raise SnapshotError("git_object_identity_mismatch")
        return data


class _BlobReader:
    def __init__(self, snapshot, process):
        self.snapshot = snapshot
        self.process = process
        self.closed = False

    def read_blob(self, entry: Entry, *, max_bytes: int) -> bytes:
        if self.closed:
            raise SnapshotError("reader_closed")
        if type(max_bytes) is not int or not 0 <= max_bytes <= MAX_RECORD_BYTES:
            raise SnapshotError("invalid_blob_limit")
        entries = self.snapshot._entries
        position = bisect_left(entries, entry.path, key=lambda item: item.path)
        if position == len(entries) or entries[position] != entry:
            raise SnapshotError("entry_not_in_snapshot")
        if entry.size > max_bytes:
            raise SnapshotError("blob_byte_limit")
        self.process.stdin.write((entry.oid + "\n").encode("ascii"))
        self.process.stdin.flush()
        header = self.process.stdout.readline(256)
        if header == f"{entry.oid} missing\n".encode("ascii"):
            raise SnapshotError("git_object_unavailable")
        if header != f"{entry.oid} blob {entry.size}\n".encode("ascii"):
            raise SnapshotError("git_batch_protocol")
        framed = self.process.stdout.read(entry.size + 1)
        if len(framed) != entry.size + 1 or framed[-1:] != b"\n":
            raise SnapshotError("git_batch_protocol")
        raw = framed[:-1]
        oid = hashlib.sha1(f"blob {entry.size}\0".encode() + raw).hexdigest()
        if oid != entry.oid:
            raise SnapshotError("git_object_identity_mismatch")
        return raw


def _inventory(repository: Path, tree: str) -> tuple[tuple[Entry, ...], int, int]:
    entries = []
    ids = set()
    count = total = 0
    pending = b""
    with _git(repository, "ls-tree", "-r", "-t", "-z", "-l", "--full-tree", tree) as process:
        process.stdin.close()
        while chunk := process.stdout.read(65_536):
            total += len(chunk)
            if total > MAX_INVENTORY_BYTES:
                raise SnapshotError("inventory_byte_limit")
            records = (pending + chunk).split(b"\0")
            pending = records.pop()
            for record in records:
                count += 1
                if count > MAX_TREE_ENTRIES:
                    raise SnapshotError("inventory_entry_limit")
                try:
                    metadata, raw_path = record.split(b"\t", 1)
                    mode, kind, oid, size = metadata.split()
                    path = raw_path.decode("utf-8")
                except (ValueError, UnicodeError):
                    raise SnapshotError("invalid_tree_entry") from None
                if mode == b"120000":
                    raise SnapshotError("tree_symlink")
                if path in {"cves/delta.json", "cves/deltaLog.json"}:
                    if mode != b"100644" or kind != b"blob":
                        raise SnapshotError("invalid_record_mode")
                    continue
                name = path.rsplit("/", 1)[-1]
                match = _CVE.fullmatch(name)
                record_like = (
                    name.casefold().startswith("cve-")
                    or path.startswith("cves/")
                    and name.casefold().endswith(".json")
                )
                if not record_like:
                    continue
                if not match:
                    raise SnapshotError("invalid_record_path")
                year, number = match.groups()
                cve_id = name[:-5]
                if cve_id in ids:
                    raise SnapshotError("duplicate_cve_id")
                ids.add(cve_id)
                bucket = number[:-3].lstrip("0") or "0"
                expected = f"cves/{year}/{bucket}xxx/{name}"
                if path != expected or (len(number) > 4 and number.startswith("0")):
                    raise SnapshotError("invalid_record_path")
                if mode != b"100644" or kind != b"blob":
                    raise SnapshotError("invalid_record_mode")
                try:
                    oid_text = oid.decode("ascii")
                except UnicodeError:
                    raise SnapshotError("invalid_tree_entry") from None
                try:
                    size = int(size)
                except ValueError:
                    raise SnapshotError("invalid_tree_entry") from None
                if not _COMMIT.fullmatch(oid_text) or size < 0:
                    raise SnapshotError("invalid_tree_entry")
                entries.append(Entry(path, cve_id, oid_text, size))
        if pending:
            raise SnapshotError("invalid_tree_entry")
    return tuple(sorted(entries, key=lambda entry: entry.path)), count, total


def open_snapshot(repository: Path, commit: str, receipt_path: Path) -> Snapshot:
    """Validate retained evidence and the entire bounded tree without any network access."""
    commit = _pin(commit)
    receipt_path, raw_path = _paths(repository, receipt_path)
    receipt_bytes = _read_file(receipt_path, MAX_RECEIPT_BYTES)
    receipt = _json(receipt_bytes)
    raw = _read_file(raw_path, MAX_HTTP_BYTES)
    tree = _local_tree(repository, commit)
    try:
        retrieved = receipt["retrieved_at"]
        if not isinstance(retrieved, str) or not retrieved.endswith("Z"):
            raise ValueError
        when = datetime.fromisoformat(retrieved[:-1] + "+00:00")
        if when > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ValueError
        valid = (
            type(receipt["format_version"]) is int
            and receipt["format_version"] == 1
            and receipt["commit"] == commit
            and receipt["tree"] == tree
            and receipt["request_url"] == f"{_API}/commits/{commit}"
        )
    except (KeyError, TypeError, ValueError):
        raise SnapshotError("invalid_receipt") from None
    if not valid:
        raise SnapshotError("receipt_identity_mismatch")
    if receipt.get("raw_sha256") != hashlib.sha256(raw).hexdigest():
        raise SnapshotError("raw_hash_mismatch")
    _official_identity(raw, commit, tree)
    entries, count, total = _inventory(repository, tree)
    return Snapshot(
        commit,
        tree,
        hashlib.sha256(receipt_bytes).hexdigest(),
        count,
        total,
        repository.resolve(),
        entries,
    )
