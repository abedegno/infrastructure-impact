"""Read and retain original bodies for the three fixed release-reliability sources."""

import hashlib
import json
import os
import re
import socket
import stat
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from http.client import HTTPException, HTTPSConnection
from pathlib import Path
from queue import Empty, Queue
from threading import Thread
from time import monotonic, sleep
from urllib.parse import urlsplit
from xml.etree import ElementTree

from ..release_catalogue_cli import MAX_BYTES, read_json
from ..release_signals_cli import _dataset_lock, _json_bytes, _staged_file
from ..settings import PACKAGE
from .errors import AccessVerificationRequired, CiscoAccessError, failure_code
from .release_signals import (
    MAX_DOCUMENT_BYTES,
    _document,
    _html_sections,
    _table_rows,
    parse_arista_releases,
)

SOURCES = json.loads((PACKAGE / "resources/reliability-refresh-sources.json").read_text())
ROBOTS = "https://www.cisco.com/robots.txt"
AGENT = "Infrastructure-Impact"
NETWORK_URLS = frozenset({ROBOTS} | {s["url"] for s in SOURCES.values() if s["vendor"] == "cisco"})
SUCCESS = frozenset({"captured", "changed", "restored", "unchanged", "not_modified"})
_OUTCOMES = (
    SUCCESS
    | CiscoAccessError.CODES
    | {
        "access_verification_required",
        "cache_body_invalid",
        "network_disabled",
        "policy_review_required",
        "robots_denied",
        "robots_unavailable",
        "unsupported_or_invalid_document",
    }
)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CISCO_RELEASE = re.compile(r"Dublin (17\.12\.[0-9]{1,8}[a-z]?)", re.ASCII)
_CISCO_HISTORY = re.compile(
    r"(?:Dublin 17\.(?:10|11)|Cupertino 17\.[789]|Bengaluru 17\.[456]|Amsterdam 17\.[123])"
    r"\.[0-9]{1,8}[a-z]?",
    re.ASCII,
)
_STAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})",
    re.ASCII,
)
_ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]*"')
_VALIDATOR_NAMES = {"ETag": "If-None-Match", "Last-Modified": "If-Modified-Since"}
_MAX_ROBOTS_DELAY = 60
_MAX_ROBOTS_BYTES = 512_000
_HTTP_DEADLINE = 25


def timestamp(value):
    if not isinstance(value, str) or not _STAMP.fullmatch(value):
        raise ValueError("Receipt requires an ISO 8601 timestamp with timezone")
    return datetime.fromisoformat(value).astimezone(UTC)


@dataclass(frozen=True)
class Observation:
    version: str
    models: tuple[str, ...]
    quote: str
    locator: str
    announcement_date: str | None = None
    pub_date: str | None = None


def _cisco_observations(source, raw):
    sections = _html_sections(raw)
    if not sections:
        raise ValueError("Unsupported Cisco HTML document")
    root = sections[0]
    while root.parent is not None:
        root = root.parent
    model = source["model"]
    series = f"Cisco Catalyst {model} Series Switches"
    title = f"Release Notes for {series}, Cisco IOS XE Dublin 17.12.x"
    heading = source["heading"]
    document_titles = [node.text() for node in root.find({"title"}) if node.parent.tag == "head"]
    page_titles = [node.text() for node in sections if node.tag == "h1"]
    if (
        document_titles != [f"{title} - {heading} [{series}] - Cisco"]
        or page_titles.count(title) != 1
    ):
        raise ValueError("Unsupported Cisco platform and release train title")
    tables = []
    in_chapter = False
    in_subsection = False
    for node in sections:
        if node.tag == "h1":
            in_chapter = node.text() == heading
        if node.tag != "table":
            in_subsection = in_chapter and node.tag == "h2" and node.text() == heading
        elif in_subsection:
            tables.append(node)
    if len(tables) != 1:
        raise ValueError("Expected one table in the Cisco ROMMON chapter")
    rows = _table_rows(tables[0])
    if len(rows) < 2 or rows[0] != source["columns"]:
        raise ValueError("Unsupported Cisco ROMMON table columns")
    observations = []
    for index, row in enumerate(rows[1:], 1):
        if len(row) != len(rows[0]) or not all(row[1:]):
            raise ValueError("Unsupported Cisco ROMMON release row")
        release = row[0]
        # Both chapters include history for earlier IOS XE trains in the same table.
        if _CISCO_HISTORY.fullmatch(release):
            continue
        match = _CISCO_RELEASE.fullmatch(release)
        if not match:
            raise ValueError("Unsupported Cisco ROMMON release row")
        observations.append(
            Observation(
                version=match[1],
                models=(f"Catalyst {model}",),
                quote=release,
                locator=f"{heading} / table body row {index} / Release",
            )
        )
    if not observations:
        raise ValueError("Cisco ROMMON table has no Dublin 17.12 release rows")
    return observations


def _arista_observations(raw, retrieved):
    events = parse_arista_releases(raw)
    # The strict reader validates the channel, item leaf and timestamp before lookup.
    items = ElementTree.fromstring(raw).findall("channel/item")
    observations = []
    for event in events:
        version = event["release"]
        # The signal parser checks shape; the catalogue uses ASCII versions up to 128 characters.
        if not version.isascii() or len(version) > 128:
            raise ValueError("Unsupported Arista catalogue release identity")
        locator = event["source_locator"]
        index = int(locator.partition("[")[2].partition("]")[0]) - 1
        literal = items[index].findtext("pubDate")
        posted = datetime.strptime(literal, "%Y-%m-%d %H:%M:%S %z")
        if posted > retrieved:
            raise ValueError("Arista announcement postdates the original capture")
        observations.append(
            Observation(version, (), event["statement"], locator, event["date"], literal)
        )
    return observations


def _read_observations(source, raw, retrieved):
    if source["vendor"] == "cisco":
        return _cisco_observations(source, raw)
    return _arista_observations(raw, retrieved)


def _plain_path(path):
    path = Path(path).absolute()
    # Accept the standard macOS aliases while rejecting caller-controlled symlinks.
    if path.parts[1:2] in {("tmp",), ("var",)}:
        alias = Path("/", path.parts[1])
        if alias.is_symlink() and alias.resolve() == Path("/private", alias.name):
            path = Path("/private", *path.parts[1:])
    if ".." in path.parts or any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("Path must not traverse a symlink or parent reference")
    return path


def regular_path(path):
    path = _plain_path(path)
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("Expected a regular, unaliased file")
    return path


def read_capture(path):
    return _regular_bytes(regular_path(path), MAX_DOCUMENT_BYTES)


def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError("Expected a bounded regular, unaliased file")
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("File exceeds size limit")
    return raw


def _outside_git(path):
    path = _plain_path(path)
    for parent in (path, *path.parents):
        git = parent / ".git"
        if git.exists() or git.is_symlink() or parent.name == ".git":
            raise ValueError("Raw cache must be outside Git workspaces")
    return path


def _write_json(path, value):
    path = regular_path(path)
    data = _json_bytes(value)
    if len(data) > MAX_BYTES:
        raise ValueError("Refresh state exceeds JSON size limit")
    with _staged_file(path, data) as staged:
        staged.replace(path)


def _validator_values(headers):
    clean = {}
    for key in _VALIDATOR_NAMES:
        matches = [value for name, value in headers.items() if name.casefold() == key.casefold()]
        if len(matches) != 1:
            continue
        value = matches[0]
        if not isinstance(value, str) or len(value) > 256 or not re.fullmatch(r"[ -~]+", value):
            continue
        if key == "ETag":
            if _ETAG.fullmatch(value):
                clean[key] = value
        else:
            try:
                if parsedate_to_datetime(value).utcoffset() == timedelta(0):
                    clean[key] = value
            except (ValueError, OverflowError):
                continue
    return clean


class RefreshCache:
    """Hold one atomic source manifest per route and immutable SHA-256 bodies."""

    def __init__(self, directory):
        self.directory = _outside_git(directory)
        if self.directory.exists() and not self.directory.is_dir():
            raise ValueError("Raw cache must be a directory")

    @contextmanager
    def locked(self):
        _outside_git(self.directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        with _dataset_lock(self.directory / "manifest"):
            yield

    def _state(self, source_id):
        source = SOURCES[source_id]
        path = regular_path(self.directory / f"{source_id}.json")
        empty = {
            "schema_version": 1,
            "source_id": source_id,
            "source_url": source["url"],
            "captures": {},
            "revisions": [],
            "latest_sha256": None,
            "validators": {},
            "last_check": None,
        }
        if not path.exists():
            return empty
        try:
            state = read_json(path)
            if (
                state.keys() != empty.keys()
                or state["schema_version"] != 1
                or state["source_id"] != source_id
                or state["source_url"] != source["url"]
                or _validator_values(state["validators"]) != state["validators"]
            ):
                raise ValueError
            check = state["last_check"]
            if check:
                timestamp(check["checked_at"])
                if check.keys() != {"checked_at", "status"} or check["status"] not in _OUTCOMES:
                    raise ValueError
            elif check is not None:
                raise ValueError
            seen = set()
            predecessor = None
            for revision in state["revisions"]:
                digest = revision["sha256"]
                timestamp(revision["observed_at"])
                if (
                    revision.keys() != {"sha256", "predecessor_sha256", "observed_at"}
                    or revision["predecessor_sha256"] != predecessor
                    or digest == predecessor
                    or not _DIGEST.fullmatch(digest)
                ):
                    raise ValueError
                seen.add(digest)
                predecessor = digest
            if seen != state["captures"].keys() or state["latest_sha256"] != predecessor:
                raise ValueError
            if predecessor is None and state["validators"]:
                raise ValueError
            for capture in state["captures"].values():
                timestamp(capture["retrieved_at"])
                if (
                    capture.keys() != {"retrieved_at", "origin", "byte_length", "media_type"}
                    or capture["origin"] not in {"operator", "network"}
                    or not 0 < capture["byte_length"] <= MAX_DOCUMENT_BYTES
                    or capture["media_type"] != source["media_type"]
                ):
                    raise ValueError
            return state
        except (ValueError, AttributeError, KeyError, TypeError, OverflowError, RecursionError):
            raise ValueError("Invalid refresh cache manifest") from None

    def _body_path(self, digest):
        bodies = _outside_git(self.directory / "bodies")
        return regular_path(bodies / digest)

    def _read(self, state, digest):
        capture = state["captures"][digest]
        try:
            raw = _regular_bytes(self._body_path(digest), MAX_DOCUMENT_BYTES)
            if len(raw) != capture["byte_length"] or hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError
            return _read_observations(
                SOURCES[state["source_id"]], raw, timestamp(capture["retrieved_at"])
            )
        except (ValueError, OSError, RecursionError):
            raise ValueError("Invalid or unavailable cache body") from None

    def snapshot(self):
        with self.locked():
            return {source_id: self._state(source_id) for source_id in SOURCES}

    def observations(self):
        """Take a consistent manifest snapshot and revalidate every retained body."""
        with self.locked():
            result = {}
            for source_id in SOURCES:
                state = self._state(source_id)
                captures = {digest: self._read(state, digest) for digest in state["captures"]}
                result[source_id] = state, captures
            return result

    def _record(self, state, outcome, checked):
        state["last_check"] = {"checked_at": checked.isoformat(), "status": outcome}
        _write_json(self.directory / f"{state['source_id']}.json", state)
        return outcome

    def _retain(self, state, raw, retrieved, origin, *, checked, validators=None):
        digest = hashlib.sha256(raw).hexdigest()
        source = SOURCES[state["source_id"]]
        prior = state["latest_sha256"]
        capture = state["captures"].get(digest)
        try:
            _read_observations(
                source, raw, timestamp(capture["retrieved_at"]) if capture else retrieved
            )
        except AccessVerificationRequired:
            return self._record(state, "access_verification_required", checked)
        except (ValueError, RecursionError):
            return self._record(state, "unsupported_or_invalid_document", checked)

        try:
            body = self._body_path(digest)
            if body.exists():
                if _regular_bytes(body, MAX_DOCUMENT_BYTES) != raw:
                    return self._record(state, "cache_body_invalid", checked)
            else:
                body.parent.mkdir(mode=0o700, exist_ok=True)
                with _staged_file(body, raw) as staged:
                    staged.replace(body)
        except ValueError:
            return self._record(state, "cache_body_invalid", checked)

        if capture is None:
            state["captures"][digest] = {
                "retrieved_at": retrieved.isoformat(),
                "origin": origin,
                "byte_length": len(raw),
                "media_type": source["media_type"],
            }
        if validators is not None or prior != digest:
            state["validators"] = validators or {}
        if digest == prior:
            outcome = "unchanged"
        else:
            state["revisions"].append(
                {
                    "sha256": digest,
                    "predecessor_sha256": prior,
                    "observed_at": checked.isoformat(),
                }
            )
            state["latest_sha256"] = digest
            outcome = "restored" if capture else "changed" if prior else "captured"
        return self._record(state, outcome, checked)

    def import_capture(self, source_id, raw, retrieved_at):
        retrieved = timestamp(retrieved_at)
        checked = datetime.now(UTC)
        if retrieved > checked:
            raise ValueError("Original retrieval timestamp is in the future")
        with self.locked():
            return self._retain(self._state(source_id), raw, retrieved, "operator", checked=checked)


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


def _exchange(connection, path, headers, deadline):
    connection.connect()
    if monotonic() >= deadline:
        raise CiscoAccessError("network_error")
    connection.request(
        "GET", path, headers={"User-Agent": AGENT, "Accept-Encoding": "identity", **headers}
    )
    with connection.getresponse() as response:
        if response.status != 200:
            return Response(response.status, response.headers, b"")
        if response.headers.get("Content-Encoding", "").lower() not in {"", "identity"}:
            raise CiscoAccessError("unsupported_response")
        limit = _MAX_ROBOTS_BYTES if path == "/robots.txt" else MAX_DOCUMENT_BYTES
        if response.length is not None and response.length > limit:
            raise CiscoAccessError("response_too_large")
        expected = response.length
        body = bytearray()
        while monotonic() < deadline and len(body) <= limit:
            chunk = response.read1(min(64 * 1024, limit + 1 - len(body)))
            if not chunk:
                if expected is not None and len(body) != expected:
                    raise CiscoAccessError("network_error")
                return Response(response.status, response.headers, bytes(body))
            body.extend(chunk)
        raise CiscoAccessError("response_too_large" if len(body) > limit else "network_error")


def fetch(url, headers):
    """Perform one direct HTTPS GET with an overall deadline and no redirect handling."""
    if url not in NETWORK_URLS or any(name not in _VALIDATOR_NAMES.values() for name in headers):
        raise CiscoAccessError("url_rejected")
    validators = {
        name: headers[conditional]
        for name, conditional in _VALIDATOR_NAMES.items()
        if conditional in headers
    }
    if _validator_values(validators) != validators:
        raise CiscoAccessError("unsupported_response")
    route = urlsplit(url)
    connection = HTTPSConnection(route.hostname, timeout=10)
    deadline = monotonic() + _HTTP_DEADLINE
    result = Queue(maxsize=1)

    def request():
        try:
            result.put(_exchange(connection, route.path, headers, deadline))
        except CiscoAccessError as error:
            result.put(error)
        except (OSError, HTTPException, ValueError):
            result.put(CiscoAccessError("network_error"))
        finally:
            connection.close()

    Thread(target=request, daemon=True).start()
    try:
        response = result.get(timeout=max(0, deadline - monotonic()))
    except Empty:
        endpoint = connection.sock
        if endpoint is not None:
            try:
                endpoint.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        raise CiscoAccessError("network_error") from None
    if isinstance(response, CiscoAccessError):
        raise response
    return response


def _receipt_allows(path, source_id, now):
    try:
        receipt = read_json(regular_path(path))
        if (
            set(receipt)
            != {
                "schema_version",
                "allowed_source_ids",
                "reviewed_at",
                "terms_url",
                "terms_locator",
                "terms_sha256",
            }
            or receipt["schema_version"] != 1
        ):
            return False
        sources = receipt["allowed_source_ids"]
        terms = receipt["terms_url"]
        locator = receipt["terms_locator"]
        reviewed = timestamp(receipt["reviewed_at"])
        url = urlsplit(terms)
        return (
            isinstance(sources, list)
            and all(
                isinstance(s, str) and s in SOURCES and SOURCES[s]["vendor"] == "cisco"
                for s in sources
            )
            and len(set(sources)) == len(sources)
            and source_id in sources
            and now - timedelta(days=30) <= reviewed <= now
            and isinstance(terms, str)
            and 0 < len(terms) <= 2048
            and url.scheme == "https"
            and url.netloc in {"www.cisco.com", "cisco.com"}
            and url.path.startswith("/")
            and not url.fragment
            and bool(re.fullmatch(r"[!-~]+", terms))
            and "\\" not in terms
            and isinstance(locator, str)
            and 0 < len(locator.strip()) <= 1024
            and locator.isprintable()
            and bool(_DIGEST.fullmatch(receipt["terms_sha256"]))
        )
    except (OSError, ValueError, TypeError, AttributeError, OverflowError, RecursionError):
        return False


def _media(headers):
    values = [value for key, value in headers.items() if key.lower() == "content-type"]
    return values[0].partition(";")[0].strip().lower() if len(values) == 1 else ""


def _robots_match(pattern, path):
    """Match anchored robots paths and wildcards without regex backtracking."""
    terminal = pattern.endswith("$")
    parts = (pattern[:-1] if terminal else pattern).split("*")
    if not path.startswith(parts[0]):
        return False
    if len(parts) == 1:
        return not terminal or path == parts[0]
    end = len(path)
    if terminal:
        if not path.endswith(parts[-1]):
            return False
        end -= len(parts.pop())
    start = len(parts[0])
    for part in parts[1:]:
        index = path.find(part, start, end)
        if index < 0:
            return False
        start = index + len(part)
    return start <= end


def _robots_rule(value):
    if not value.startswith("/") or len(value) > 2048 or any(c.isspace() for c in value):
        raise ValueError("Unsupported robots route")

    def octet(match):
        char = chr(int(match[0][1:], 16))
        if char.isascii() and (char.isalnum() or char in "-._~"):
            return char
        return match[0].upper()

    return re.sub(r"%[0-9a-fA-F]{2}", octet, value)


def _robots_policy(response, path):
    if (
        response.status != 200
        or _media(response.headers) != "text/plain"
        or len(response.body) > _MAX_ROBOTS_BYTES
    ):
        raise ValueError("Robots policy unavailable")
    _document(response.body)
    document = response.body.decode("utf-8-sig")
    if not re.fullmatch(r"[\t\r\n -\x7e\x80-\U0010ffff]+", document):
        raise ValueError("Invalid robots policy")
    groups = []
    agents, directives = [], []
    for raw_line in document.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        field, separator, value = line.partition(":")
        if not separator or not re.fullmatch(r"[a-zA-Z_-]+", field.strip()):
            raise ValueError("Unrecognized robots response")
        field, value = field.strip().lower(), value.strip()
        if field == "user-agent":
            if not re.fullmatch(r"(?:\*|[A-Za-z_-]+)", value, re.ASCII):
                raise ValueError("Invalid robots product token")
            if directives:
                groups.append((agents, directives))
                agents, directives = [], []
            agents.append(value.lower())
        elif field in {"allow", "disallow", "crawl-delay", "request-rate"}:
            if not agents:
                raise ValueError("Robots rules have no user-agent")
            directives.append((field, value))
    if agents:
        groups.append((agents, directives))
    selected = [rules for agents, rules in groups if AGENT.lower() in agents]
    if not selected:
        selected = [rules for agents, rules in groups if "*" in agents]
    if not any(selected):
        raise ValueError("No applicable robots policy group")
    delay = 1.0
    matches = []
    for rules in selected:
        for field, value in rules:
            if field in {"allow", "disallow"}:
                if value:
                    rule = _robots_rule(value)
                    if _robots_match(rule, path):
                        matches.append((len(rule.removesuffix("$")), field == "allow"))
            elif field == "crawl-delay" and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3})?", value):
                delay = max(delay, float(value))
            elif field == "request-rate" and re.fullmatch(
                r"[1-9][0-9]{0,3}/[1-9][0-9]{0,3}", value
            ):
                count, seconds = map(int, value.split("/"))
                delay = max(delay, seconds / count)
            else:
                raise ValueError("Unsupported robots request spacing")
    if delay > _MAX_ROBOTS_DELAY:
        raise ValueError("Robots delay exceeds bounded collection budget")
    return max(matches, default=(0, True))[1], delay


def _route_error(status):
    if status in (401, 403):
        return "access_denied"
    if status == 429:
        return "rate_limited"
    if 300 <= status < 400:
        return "redirect_rejected"
    return "http_error" if status >= 400 else "unsupported_response"


def _utc_now():
    return datetime.now(UTC)


class _RequestSpacing:
    """Persist Cisco request spacing across cooperating runs using the same cache."""

    def __init__(self, cache, clock, pause):
        self.path = regular_path(cache.directory / "cisco-spacing.json")
        self.clock = clock
        self.pause = pause
        self.last = None
        self.delay = 1.0
        if self.path.exists():
            try:
                state = read_json(self.path)
                self.last = timestamp(state["started_at"])
                self.delay = state["delay_seconds"]
                if (
                    set(state) != {"started_at", "delay_seconds"}
                    or not 1 <= self.delay <= _MAX_ROBOTS_DELAY
                ):
                    raise ValueError
            except (ValueError, KeyError, TypeError, OverflowError, RecursionError):
                raise ValueError("Invalid refresh request spacing state") from None

    def _save(self):
        _write_json(self.path, {"started_at": self.last.isoformat(), "delay_seconds": self.delay})

    def pace_for(self, delay):
        self.delay = max(delay, self.delay)
        self._save()

    def request(self, send, url, headers):
        if self.last is not None:
            remaining = self.delay - (self.clock() - self.last).total_seconds()
            if remaining > _MAX_ROBOTS_DELAY:
                raise CiscoAccessError("network_error")
            if remaining > 0:
                self.pause(remaining)
        self.last = self.clock()
        self._save()
        return send(url, headers)


def collect(cache, source_id, policy, *, request=fetch, now=_utc_now, sleep=sleep):
    """Check current policy, then perform at most one request to the exact Cisco route."""
    with cache.locked():
        source = SOURCES[source_id]
        state = cache._state(source_id)
        checked = now()
        if source["vendor"] != "cisco":
            return cache._record(state, "network_disabled", checked)
        if not _receipt_allows(policy, source_id, checked):
            return cache._record(state, "policy_review_required", checked)
        spacing = _RequestSpacing(cache, now, sleep)
        try:
            robots = spacing.request(request, ROBOTS, {})
            allowed, delay = _robots_policy(robots, urlsplit(source["url"]).path)
        except (OSError, ValueError):
            return cache._record(state, "robots_unavailable", now())
        spacing.pace_for(delay)
        if not allowed:
            return cache._record(state, "robots_denied", now())
        # The 30-day receipt can expire while waiting for robots or request spacing.
        if not _receipt_allows(policy, source_id, now() + timedelta(seconds=spacing.delay)):
            return cache._record(state, "policy_review_required", now())
        headers = {_VALIDATOR_NAMES[key]: value for key, value in state["validators"].items()}
        try:
            response = spacing.request(request, source["url"], headers)
        except (OSError, CiscoAccessError) as error:
            return cache._record(state, failure_code(error), now())
        checked = now()
        if response.status == 304:
            if not headers or not state["latest_sha256"]:
                return cache._record(state, "cache_body_invalid", checked)
            try:
                cache._read(state, state["latest_sha256"])
            except ValueError:
                return cache._record(state, "cache_body_invalid", checked)
            sent_tag = headers.get("If-None-Match")
            returned_tag = _validator_values(response.headers).get("ETag")
            if (
                sent_tag
                and returned_tag
                and sent_tag.removeprefix("W/") != returned_tag.removeprefix("W/")
            ):
                return cache._record(state, "unsupported_response", checked)
            # A 304 verifies the saved revision without supplying bytes for new validators.
            return cache._record(state, "not_modified", checked)
        if response.status != 200:
            return cache._record(state, _route_error(response.status), checked)
        if _media(response.headers) != source["media_type"]:
            try:
                _document(response.body)
            except AccessVerificationRequired:
                return cache._record(state, "access_verification_required", checked)
            except ValueError:
                pass
            return cache._record(state, "unsupported_response", checked)
        return cache._retain(
            state,
            response.body,
            checked,
            "network",
            checked=checked,
            validators=_validator_values(response.headers),
        )
