"""Private literal SBOM observations, without firmware binding or CVE inference."""

import json
import os
import re
import stat
from functools import lru_cache
from hashlib import sha256

from jsonschema import Draft202012Validator

from ..settings import PACKAGE
from .strict_json import loads

MAX_BYTES = 15_000_000
MAX_COMPONENTS = 20_000
MAX_DEPTH = 32
SUPPORTED = {"CycloneDX": {"1.5", "1.6", "1.7"}, "SPDX": {"SPDX-2.2", "SPDX-2.3"}}


def text(value, *, required=False, limit=2048):
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("SBOM selected field requires bounded nonempty literal text")
    return value


def sequence(value):
    if not isinstance(value, list) or len(value) > MAX_COMPONENTS:
        raise ValueError("SBOM array exceeds supported structure or item budget")
    return value


def reference_list(items, kind):
    result, seen = [], set()
    for value in items:
        value = text(value, required=True, limit=4096)
        if not value.startswith(("pkg:",) if kind == "purl" else ("cpe:/", "cpe:2.3:")):
            raise ValueError("SBOM identifier does not use its declared literal format")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def hashes(items, *, algorithm, digest, locator):
    result, ignored = [], 0
    for index, item in enumerate(sequence(items)):
        if not isinstance(item, dict):
            raise ValueError("SBOM hash entry must be an object")
        name = text(item.get(algorithm), required=True, limit=64)
        value = text(item.get(digest), required=True, limit=256)
        normalized = {
            "SHA-256": "sha256",
            "SHA256": "sha256",
            "SHA-512": "sha512",
            "SHA512": "sha512",
        }.get(name)
        if normalized is None:
            ignored += 1
            continue
        if not re.fullmatch(
            "[a-fA-F0-9]{" + ("64" if normalized == "sha256" else "128") + "}", value
        ):
            raise ValueError(
                "SBOM SHA-256/SHA-512 observation has invalid digest length or characters"
            )
        result.append(
            dict(algorithm=normalized, value=value.lower(), locator=f"{locator}[{index}]")
        )
    return result, ignored


def observation(item, locator, *, reference, version, role, parent=None, spdx=False):
    if not isinstance(item, dict):
        raise ValueError("SBOM component/package must be an object")
    identity = text(item.get(reference), required=spdx)
    if spdx and not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", identity):
        raise ValueError("SPDX package requires a bounded local SPDX identifier")
    external = item.get("isExternal") if not spdx else None
    if external is not None and type(external) is not bool:
        raise ValueError("CycloneDX isExternal must be a boolean when supplied")
    if not spdx and "version" in item and "versionRange" in item:
        raise ValueError("CycloneDX version and versionRange cannot both be supplied")
    refs = sequence(item.get("externalRefs", [])) if spdx else []
    purls, cpes = [], []
    for ref in refs:
        if not isinstance(ref, dict):
            raise ValueError("SPDX external reference must be an object")
        category, kind = (
            text(ref.get("referenceCategory"), required=True),
            text(ref.get("referenceType"), required=True),
        )
        if category == "PACKAGE-MANAGER" and kind == "purl":
            purls.append(ref.get("referenceLocator"))
        if category == "SECURITY" and kind in {"cpe22Type", "cpe23Type"}:
            cpes.append(ref.get("referenceLocator"))
    if not spdx:
        if "purl" in item:
            purls.append(item["purl"])
        if "cpe" in item:
            cpes.append(item["cpe"])
    digest_rows, ignored_hashes = hashes(
        item.get("checksums" if spdx else "hashes", []),
        algorithm="algorithm" if spdx else "alg",
        digest="checksumValue" if spdx else "content",
        locator=locator + (".checksums" if spdx else ".hashes"),
    )
    return dict(
        locator=locator,
        parent_locator=parent,
        declared_reference=identity,
        role=role,
        name=text(item.get("name"), required=True, limit=1024),
        literal_version=text(item.get(version), limit=1024),
        declared_version_range=None if spdx else text(item.get("versionRange"), limit=4096),
        declared_type=text(item.get("primaryPackagePurpose" if spdx else "type"), limit=128),
        declared_group=None if spdx else text(item.get("group"), limit=1024),
        declared_scope=None if spdx else text(item.get("scope"), limit=128),
        declared_is_external=external,
        purls=reference_list(purls, "purl"),
        cpes=reference_list(cpes, "cpe"),
        package_hashes=digest_rows,
        hash_algorithms_not_normalized=ignored_hashes,
    )


def cyclonedx(document):
    metadata = document.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError("CycloneDX metadata must be an object")
    stack = [
        (c, f"$.components[{i}]", None, 0, "listed_component")
        for i, c in reversed(list(enumerate(sequence(document.get("components", [])))))
    ]
    if "component" in metadata:
        stack.append(
            (metadata["component"], "$.metadata.component", None, 0, "declared_document_subject")
        )
    rows, identities = [], set()
    while stack:
        item, locator, parent, depth, role = stack.pop()
        if isinstance(item, dict) and ("versionRange" in item or "isExternal" in item):
            if document["specVersion"] != "1.7":
                raise ValueError(
                    "External-component version-range observations require CycloneDX 1.7"
                )
            if "versionRange" in item and item.get("isExternal") is not True:
                raise ValueError(
                    "CycloneDX versionRange requires explicit external-component scope"
                )
            if role == "declared_document_subject" and item.get("isExternal") is True:
                raise ValueError("CycloneDX document subject cannot be an external component")
        if depth > MAX_DEPTH or len(rows) >= MAX_COMPONENTS:
            raise ValueError("SBOM component nesting or total item budget exceeded")
        row = observation(
            item, locator, reference="bom-ref", version="version", role=role, parent=parent
        )
        identity = row["declared_reference"]
        if identity is not None:
            if identity in identities:
                raise ValueError("Duplicate SBOM component reference")
            identities.add(identity)
        rows.append(row)
        for index, child in reversed(list(enumerate(sequence(item.get("components", []))))):
            stack.append(
                (child, f"{locator}.components[{index}]", locator, depth + 1, "listed_component")
            )
    return rows, text(metadata.get("timestamp"))


def spdx(document):
    if document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise ValueError("SPDX input requires its document identity")
    described = sequence(document.get("documentDescribes", []))
    if any(not isinstance(value, str) for value in described):
        raise ValueError("SPDX documentDescribes requires literal identifiers")
    described = set(described)
    rows, identities = [], {"SPDXRef-DOCUMENT"}
    for index, item in enumerate(sequence(document.get("packages", []))):
        role = (
            "declared_document_subject"
            if isinstance(item, dict)
            and isinstance(item.get("SPDXID"), str)
            and item.get("SPDXID") in described
            else "listed_component"
        )
        row = observation(
            item,
            f"$.packages[{index}]",
            reference="SPDXID",
            version="versionInfo",
            role=role,
            spdx=True,
        )
        identity = row["declared_reference"]
        if identity in identities:
            raise ValueError("Duplicate SPDX package/document identifier")
        identities.add(identity)
        rows.append(row)
    creation = document.get("creationInfo", {})
    if not isinstance(creation, dict):
        raise ValueError("SPDX creationInfo must be an object")
    return rows, text(creation.get("created"))


@lru_cache(maxsize=1)
def validator():
    schema = json.loads((PACKAGE / "schemas/sbom-observations-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def inspect(raw, *, component=None):
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError("SBOM inspection requires original JSON file bytes for provenance")
    document = loads(raw, budget=MAX_BYTES, label="SBOM")
    if not isinstance(document, dict):
        raise ValueError("SBOM must be a JSON object")
    if "bomFormat" in document and "spdxVersion" in document:
        raise ValueError("Ambiguous SBOM format declarations")
    if document.get("bomFormat") == "CycloneDX":
        kind, version = "CycloneDX", document.get("specVersion")
    elif "spdxVersion" in document:
        kind, version = "SPDX", document["spdxVersion"]
    else:
        raise ValueError("Expected an explicit supported CycloneDX or SPDX JSON declaration")
    if not isinstance(version, str) or version not in SUPPORTED[kind]:
        raise ValueError("Unsupported declared SBOM specification version")
    rows, created = (cyclonedx if kind == "CycloneDX" else spdx)(document)
    query = text(component, limit=1024)
    selected = rows if query is None else [r for r in rows if r["name"] == query]
    result = dict(
        schema_version=1,
        kind="private_sbom_observations",
        source_sha256=sha256(raw).hexdigest(),
        source_bytes=len(raw),
        format=kind,
        spec_version=version,
        document_created_at_claim=created,
        selected_component_name=query,
        observed_components=len(rows),
        returned_components=len(selected),
        components=selected,
        full_standards_validation_performed=False,
        inventory_verified=False,
        cve_assessments_created=False,
        metric_eligibility_changed=False,
        evidence_published=False,
        method="Private literal observations from selected fields in a supplied JSON document. Names match exactly and case-sensitively; duplicate instances are retained and references must be unique in parsed components. No external documents, links or dependencies are fetched. Document subjects, versions, scope and package hashes do not certify a shipped firmware image, build-to-component binding, patch state, configuration, inventory completeness or CVE applicability. Omitted fields stay null. Inherited scope, relationships, VEX/vulnerability assertions, signatures, licenses and lifecycle semantics are not validated. Empty matches do not establish component absence. No observation is imported into the vault or public publication.",
    )
    if next(validator().iter_errors(result), None) is not None:
        raise ValueError("Generated SBOM observation structure failed its contract")
    return result


def read_local(path):
    """Bounded, nonblocking regular-file read; no links or external resources."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError("SBOM input must be a regular file within the 15 MB byte budget")
            raw = stream.read(MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_BYTES:
        raise ValueError("SBOM input exceeds its 15 MB byte budget")
    return raw


def summary(report):
    """Project only bounded non-content fields, never future private additions."""
    if next(validator().iter_errors(report), None) is not None:
        raise ValueError("SBOM summary requires a valid observation report")
    keys = (
        "schema_version",
        "source_sha256",
        "source_bytes",
        "format",
        "spec_version",
        "observed_components",
        "returned_components",
        "full_standards_validation_performed",
        "inventory_verified",
        "cve_assessments_created",
        "metric_eligibility_changed",
        "evidence_published",
    )
    result = {key: report[key] for key in keys}
    result.update(
        kind="private_sbom_summary",
        method="Private artifact summary only. Component names, identifiers, values, selection and document creation claims are omitted. The artifact hash and counts still identify private evidence; they do not confer redistribution rights or certify inventory, CVE applicability or comparison eligibility.",
    )
    if next(validator().iter_errors(result), None) is not None:
        raise ValueError("Generated SBOM summary structure failed its contract")
    return result
