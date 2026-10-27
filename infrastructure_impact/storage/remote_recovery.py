"""Append-only opaque recovery assets in unpublished GitHub draft releases.

This transport never handles a key or a plaintext database. The hosted writer
authenticates ciphertext and exercises SQLite recovery before advancing state.
"""

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

BACKEND = "github-draft-release-v1"
LIMIT = 50 * 1024 * 1024
ARCHIVE = re.compile(r"vault-\d{8}T\d{12}Z\.sqlite3\.(?:gz|xz)\.fernet")
MARKER = "Infrastructure Impact encrypted collector recovery. Managed draft; do not publish."
CDN_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}


def validate_pointer(manifest, repository=None):
    remote = manifest.get("remote")
    if (
        manifest.get("storage_backend") != BACKEND
        or manifest.get("encryption") != "fernet-v1"
        or not isinstance(manifest.get("archive"), str)
        or not ARCHIVE.fullmatch(manifest["archive"])
        or not isinstance(manifest.get("sha256"), str)
        or not re.fullmatch(r"[a-f0-9]{64}", manifest["sha256"])
        or type(manifest.get("archive_bytes")) is not int
        or not 0 < manifest["archive_bytes"] <= LIMIT
        or not isinstance(remote, dict)
        or set(remote) != {"repository", "release_id", "asset_id", "tag"}
        or not isinstance(remote.get("repository"), str)
        or not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", remote["repository"]
        )
        or any(type(remote.get(k)) is not int or remote[k] < 1 for k in ("release_id", "asset_id"))
        or not isinstance(remote.get("tag"), str)
        or not re.fullmatch(r"collector-recovery-\d{4}-\d{2}-\d{2}", remote["tag"])
        or (repository is not None and remote["repository"] != repository)
    ):
        raise ValueError("Invalid remote recovery pointer or repository mismatch")
    return remote


class AssetRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        source, target = urlsplit(request.full_url), urlsplit(newurl)
        source_is_asset = (
            source.hostname == "api.github.com"
            and re.fullmatch(r"/repos/[^/]+/[^/]+/releases/assets/\d+", source.path)
        ) or source.hostname in CDN_HOSTS
        if (
            request.get_method() != "GET"
            or request.get_header("Accept") != "application/octet-stream"
            or not source_is_asset
            or target.scheme != "https"
            or target.hostname not in CDN_HOSTS
            or target.username
            or target.password
            or target.port not in (None, 443)
        ):
            raise ValueError("Unexpected recovery API redirect")
        # Construct a fresh request: no Authorization or other credential header
        # follows a signed download redirect, even to an approved GitHub CDN.
        return Request(
            newurl,
            headers={
                "Accept": "application/octet-stream",
                "User-Agent": "infrastructure-impact-recovery",
            },
        )


class GitHubDraftStore:
    def __init__(self, repository, token=None, *, opener=None):
        if not isinstance(repository, str) or not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", repository
        ):
            raise ValueError("Recovery requires an explicit owner/repository")
        self.repository = repository
        self.token = token or os.environ.get("GH_TOKEN")
        if not self.token:
            raise ValueError("Draft recovery storage requires GH_TOKEN")
        self.opener = opener or build_opener(AssetRedirects())

    def _request(self, url, *, method="GET", body=None, binary=False, upload=False):
        expected = "uploads.github.com" if upload else "api.github.com"
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != expected:
            raise ValueError("Recovery API origin is not approved")
        headers = {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/octet-stream" if binary else "application/vnd.github+json",
            "User-Agent": "infrastructure-impact-recovery",
        }
        if body is not None:
            headers["Content-Type"] = "application/octet-stream" if upload else "application/json"
        request = Request(url, data=body, headers=headers, method=method)
        try:
            return self.opener.open(request, timeout=60)
        except HTTPError as error:
            raise ValueError("Recovery API returned HTTP " + str(error.code)) from None
        except URLError:
            raise ValueError("Recovery API connection failed") from None

    def _json(self, endpoint, *, method="GET", payload=None, upload=None):
        origin = "https://uploads.github.com" if upload is not None else "https://api.github.com"
        body = (
            upload
            if upload is not None
            else json.dumps(payload).encode()
            if payload is not None
            else None
        )
        with self._request(
            origin + "/repos/" + self.repository + "/" + endpoint,
            method=method,
            body=body,
            upload=upload is not None,
        ) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Recovery API metadata exceeds its size budget")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise ValueError("Recovery API metadata is invalid") from None

    @staticmethod
    def _managed_release(release, tag):
        if (
            not isinstance(release, dict)
            or release.get("draft") is not True
            or release.get("tag_name") != tag
            or release.get("body") != MARKER
            or type(release.get("id")) is not int
            or release["id"] < 1
        ):
            raise ValueError("Recovery release is not the expected managed unpublished draft")
        return release

    def _release(self, tag):
        releases = self._json("releases?per_page=100")
        if not isinstance(releases, list):
            raise ValueError("Recovery release listing is invalid")
        matches = [r for r in releases if isinstance(r, dict) and r.get("tag_name") == tag]
        if len(matches) > 1:
            raise ValueError("Recovery draft tag is ambiguous")
        release = (
            matches[0]
            if matches
            else self._json(
                "releases",
                method="POST",
                payload={
                    "tag_name": tag,
                    "name": "Encrypted collector recovery "
                    + tag.removeprefix("collector-recovery-"),
                    "body": MARKER,
                    "draft": True,
                    "prerelease": True,
                    "make_latest": "false",
                },
            )
        )
        return self._managed_release(release, tag)

    @staticmethod
    def _asset(asset, manifest):
        if (
            not isinstance(asset, dict)
            or type(asset.get("id")) is not int
            or asset["id"] < 1
            or asset.get("name") != manifest["archive"]
            or asset.get("state") != "uploaded"
            or type(asset.get("size")) is not int
            or asset["size"] != manifest["archive_bytes"]
            or (
                asset.get("digest") is not None
                and asset["digest"] != "sha256:" + manifest["sha256"]
            )
        ):
            raise ValueError("Recovery asset metadata does not match the encrypted archive")
        return asset

    def publish(self, archive, manifest):
        # Only the writer's already-authenticated, bounded Fernet output belongs
        # here. The transport rejects plaintext metadata and obvious raw files.
        if (
            manifest.get("encryption") != "fernet-v1"
            or not isinstance(manifest.get("archive"), str)
            or not ARCHIVE.fullmatch(manifest.get("archive", ""))
            or archive.is_symlink()
            or not archive.is_file()
            or archive.stat().st_size > LIMIT
        ):
            raise ValueError("Remote recovery requires a bounded encrypted archive")
        raw = archive.read_bytes()
        if (
            not raw.startswith(b"gAAAA")
            or len(raw) != manifest.get("archive_bytes")
            or hashlib.sha256(raw).hexdigest() != manifest.get("sha256")
        ):
            raise ValueError("Encrypted recovery upload fingerprint mismatch")
        tag = "collector-recovery-" + datetime.now(timezone.utc).date().isoformat()
        release = self._release(tag)
        asset = self._asset(
            self._json(
                "releases/"
                + str(release["id"])
                + "/assets?"
                + urlencode({"name": manifest["archive"]}),
                method="POST",
                upload=raw,
            ),
            manifest,
        )
        result = {
            **manifest,
            "storage_backend": BACKEND,
            "remote": {
                "repository": self.repository,
                "release_id": release["id"],
                "asset_id": asset["id"],
                "tag": tag,
            },
        }
        validate_pointer(result, self.repository)
        return result

    def download(self, manifest, destination):
        remote = validate_pointer(manifest, self.repository)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        release = self._json("releases/" + str(remote["release_id"]))
        self._managed_release(release, remote["tag"])
        if release["id"] != remote["release_id"]:
            raise ValueError("Recovery release identity mismatch")
        # Bind the asset ID to this managed draft, not merely any repository asset.
        assets = self._json("releases/" + str(remote["release_id"]) + "/assets?per_page=100")
        # A daily draft can have more than 100 assets after repeated manual runs.
        # Bounded pagination fails closed instead of silently missing a checkpoint.
        for page in range(2, 11):
            if not isinstance(assets, list):
                raise ValueError("Recovery asset listing is invalid")
            if any(a.get("id") == remote["asset_id"] for a in assets if isinstance(a, dict)):
                break
            if len(assets) < (page - 1) * 100:
                break
            more = self._json(
                "releases/" + str(remote["release_id"]) + "/assets?per_page=100&page=" + str(page)
            )
            if not isinstance(more, list):
                raise ValueError("Recovery asset listing is invalid")
            assets += more
        matches = [a for a in assets if isinstance(a, dict) and a.get("id") == remote["asset_id"]]
        if len(matches) != 1:
            raise ValueError("Recovery asset missing from its managed draft")
        self._asset(matches[0], manifest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        pending = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix=".recovery-asset-", dir=destination.parent, delete=False
            ) as target:
                pending = Path(target.name)
                size, digest = 0, hashlib.sha256()
                url = (
                    "https://api.github.com/repos/"
                    + self.repository
                    + "/releases/assets/"
                    + str(remote["asset_id"])
                )
                with self._request(url, binary=True) as response:
                    while block := response.read(1024 * 1024):
                        size += len(block)
                        if size > manifest["archive_bytes"] or size > LIMIT:
                            raise ValueError("Recovery download exceeds its size budget")
                        digest.update(block)
                        target.write(block)
            if size != manifest["archive_bytes"] or digest.hexdigest() != manifest["sha256"]:
                raise ValueError("Recovery download size or fingerprint mismatch")
            os.link(pending, destination)
        finally:
            if pending is not None:
                pending.unlink(missing_ok=True)
        return destination
