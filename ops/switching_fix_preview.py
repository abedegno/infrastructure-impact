"""Offline, read-only certification of the packaged retained switching fixes.

The feature baseline disables only the two new extraction helpers. It is not a
reproduction of an entire historical runtime. Receipts contain metadata only.
"""

import argparse
import hashlib
import json
import os
import re
import tempfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

MAX_RECEIPT = 65_536
BASE_PATH = "/infrastructure-impact/"
FAILURES = {
    "none",
    "database_missing",
    "database_changed",
    "source_missing",
    "source_drift",
    "affected_changed",
    "audit_failed",
    "candidate_failed",
    "capacity_failed",
}
COUNT_FIELDS = {"claims", "affected_cves", "fixed_cves", "reviewed_links"}
COHORT_FIELDS = {"advisories", "affected_cves", "claims", "remediation_events", "fixed_only_claims"}


def _empty(source_commit):
    from infrastructure_impact.application.import_candidate import _empty as candidate_empty

    return dict(
        schema_version=1,
        source_commit=source_commit,
        outcome="failed",
        failure_code="candidate_failed",
        network_requests=0,
        revisions_written=0,
        database_unchanged=False,
        sources=[],
        cohort=[],
        gates=candidate_empty(publication_format="v2"),
    )


def _count(value):
    claims = value["claims"]
    return dict(
        claims=len(claims),
        affected_cves=len({c["cve_id"] for c in claims if c["status"] == "affected"}),
        fixed_cves=len({c["cve_id"] for c in claims if c["status"] == "fixed"}),
        reviewed_links=sum(bool(r.get("scope_binding")) for c in claims for r in c["remediations"]),
    )


def _sources(db):
    from infrastructure_impact import remediation_bindings as reviewed
    from infrastructure_impact.adapters import switching
    from infrastructure_impact.application.switching_evidence import _latest_retained_source
    from infrastructure_impact.plugins.registry import default_registry

    sources = []
    for spec in reviewed.definition()["sources"]:
        vendor, url, advisory = spec["vendor"], spec["source_url"], spec["advisory_id"]
        row = _latest_retained_source(db, vendor, url)
        if row is None:
            raise ValueError("source_missing")
        digest = hashlib.sha256(row["raw"]).hexdigest()
        if digest != row["sha256"] or (
            spec["source_sha256"] is not None and digest != spec["source_sha256"]
        ):
            raise ValueError("source_drift")
        revision = db.execute(
            "SELECT * FROM revisions WHERE evidence_id=? AND vendor=? AND source_url=? AND advisory_id=? ORDER BY id DESC LIMIT 1",
            (row["id"], vendor, url, advisory),
        ).fetchone()
        # Do not invent a normalized representation for source-only captures.
        if revision is None:
            raise ValueError("source_missing")
        document = json.loads(revision["normalized"])
        if (
            document.get("advisory_id") != advisory
            or document.get("vendor", vendor) != vendor
            or document.get("source_url", url) != url
            or (
                spec["source_format"] is not None
                and document.get("source_format") != spec["source_format"]
            )
        ):
            raise ValueError("source_drift")
        registry = default_registry()
        with (
            patch.object(switching, "apply_csaf", lambda *_: []),
            patch.object(switching, "arista_assessments", lambda *_: ([], [])),
        ):
            before = registry.research_evidence(row["raw"], url, vendor, document)
        after = registry.research_evidence(row["raw"], url, vendor, document)
        if before is None or after is None:
            raise ValueError("source_drift")

        def stamp(value):
            if type(value) is dict:
                if "source_sha256" in value:
                    if value.get("source_url") != url or value["source_sha256"] != digest:
                        raise ValueError("source_drift")
                    value["retrieved_at"] = row["retrieved_at"]
                for child in value.values():
                    stamp(child)
            elif type(value) is list:
                for child in value:
                    stamp(child)

        def known_truncated(claim):
            return (claim["vendor"], claim["advisory_id"], claim["cve_id"]) == (
                "arista",
                "24074-security-advisory-0140",
                "CVE-2026-10040",
            ) and "evidence_text_truncated" in claim.get("issues", [])

        for value in (before, after):
            stamp(value)
            if "reviewed_fix_source_drift" in value.get("issues", []) or any(
                c["vendor"] != vendor
                or c["advisory_id"] != advisory
                or ("evidence_text_truncated" in c.get("issues", []) and not known_truncated(c))
                for c in value["claims"]
                if c["status"] == "affected"
            ):
                raise ValueError("source_drift")
            for claim in value["claims"]:
                claim["revision"] = str(revision["id"])
        old = [c for c in before["claims"] if c["status"] == "affected"]
        new = [c for c in after["claims"] if c["status"] == "affected"]

        def fields(claim):
            return {k: v for k, v in claim.items() if k not in {"remediations", "claim_id"}}

        if not old or [fields(c) for c in old] != [fields(c) for c in new]:
            raise ValueError("affected_changed")
        linked = []
        for previous, claim in zip(old, new):
            if any(rem not in claim["remediations"] for rem in previous["remediations"]):
                raise ValueError("affected_changed")
            for remediation in claim["remediations"]:
                if remediation in previous["remediations"]:
                    continue
                binding = remediation.get("scope_binding")
                if binding is None:
                    raise ValueError("source_drift")
                try:
                    reviewed.validate_link(claim, remediation, binding, after["claims"])
                except (ValueError, TypeError, KeyError):
                    raise ValueError("source_drift") from None
                linked.append(reviewed.rule_for(claim))
        truncated = [c for c in new if known_truncated(c)]
        if truncated:
            # The known 0140 truncated context can prove only the original fixed
            # sibling. No affected remediation/event may be inferred or copied.
            if len(truncated) != 1 or any(c["remediations"] for c in old + new):
                raise ValueError("source_drift")
            claim = truncated[0]
            rule = reviewed.rule_for(claim)
            siblings = [] if rule is None else reviewed.fixed_siblings(claim, rule, after["claims"])
            fixed = [c for c in after["claims"] if c["status"] == "fixed"]
            if len(siblings) != 1 or fixed != siblings:
                raise ValueError("source_drift")
            originals = siblings[0]["remediations"]
            if len(originals) != 1 or not reviewed.owned_remediation(
                siblings[0], originals[0], rule
            ):
                raise ValueError("source_drift")
        # Otherwise every registered HTML tuple must retain its validated link;
        # CSAF's complete raw hash already binds its full product/CVE scope.
        elif not linked or (
            spec["kind"] == "arista_marker_list" and len(linked) != len(spec["bindings"])
        ):
            raise ValueError("source_drift")
        sources.append(
            dict(
                vendor=vendor,
                advisory_id=advisory,
                source_url=url,
                source_sha256=digest,
                retrieved_at=row["retrieved_at"],
                affected_fields_unchanged=True,
                before=_count(before),
                after=_count(after),
            )
        )
    return sources


def _hash(database):
    digest = hashlib.sha256()
    with database.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.digest()


def preview(database, public, source_commit):
    """Validate the actual restored database without normalizing or writing it."""
    if type(source_commit) is not str or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("source_commit")
    database, public = Path(database).resolve(), Path(public).resolve()
    # Establish all application settings before importing application/storage code.
    public.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="retained-preview-", dir=public.parent) as temporary:
        home = Path(temporary)
        env = {
            k: v
            for k, v in os.environ.items()
            if k in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SYSTEMROOT"}
        }
        package = Path(__file__).resolve().parents[1] / "infrastructure_impact"
        env.update(
            IMPACT_HOME=str(home),
            IMPACT_DATABASE=str(database),
            IMPACT_SOURCES=str(package / "resources/sources.json"),
            IMPACT_PUBLICATIONS=str(home / "publications"),
            IMPACT_SNAPSHOT=str(public),
            IMPACT_BASE_PATH=BASE_PATH,
        )
        with patch.dict(os.environ, env, clear=True):
            result = _empty(source_commit)
            if not database.is_file():
                result["failure_code"] = "database_missing"
                return result
            before = _hash(database)
            try:
                from infrastructure_impact.storage.repository import connect, now

                with closing(connect(database, read_only=True)) as db:
                    result["sources"] = _sources(db)
                from infrastructure_impact.storage.audit import audit

                try:
                    audit()
                except Exception:
                    result["gates"]["audit_passed"] = False
                    result["gates"]["candidate"]["outcome"] = "audit_failed"
                    raise ValueError("audit_failed") from None
                gates = result["gates"]
                gates["audit_passed"] = True
                from infrastructure_impact.application import publication, query, source_audit
                from infrastructure_impact.application.import_candidate import _monitors
                from infrastructure_impact.application.publication_v2 import (
                    inspect_bundle,
                    native_parity,
                )

                evaluated = now()
                with (
                    patch.object(query, "now", lambda: evaluated),
                    patch.object(source_audit, "now", lambda: evaluated),
                ):
                    publication.build(public, publication_format="v2")
                    reader = inspect_bundle(public, gates["candidate"])
                    _monitors(public, home, gates["candidate"], base_path=BASE_PATH)
                    native_parity(database, public, home, reader)
                    gates["candidate"]["parity_passed"] = True
                    summary = reader.switching_overview(evaluated_at=evaluated)
                    result["cohort"] = [
                        dict(vendor=row["vendor"], **{k: row["counts"][k] for k in COHORT_FIELDS})
                        for row in summary["rows"]
                    ]
                gates.update(capacity_passed=True, candidate_validated=True)
                gates["candidate"]["outcome"] = "passed"
                result.update(outcome="passed", failure_code="none")
            except Exception as error:
                from infrastructure_impact.application.import_candidate import CapacityFailure

                code = (
                    str(error)
                    if type(error) is ValueError and str(error) in FAILURES - {"none"}
                    else "candidate_failed"
                )
                if isinstance(error, CapacityFailure):
                    code = "capacity_failed"
                    result["gates"]["capacity_passed"] = False
                result["gates"]["candidate_validated"] = False
                result.update(outcome="failed", failure_code=code)
            finally:
                result["database_unchanged"] = database.is_file() and before == _hash(database)
                if not result["database_unchanged"]:
                    result.update(outcome="failed", failure_code="database_changed")
                    result["gates"]["candidate_validated"] = False
                    result["gates"]["candidate"]["outcome"] = "validation_failed"
            receipt_bytes(result)
            return result


def receipt_bytes(value):
    """Fresh, closed metadata validation; never copy arbitrary source/receipt text."""
    from infrastructure_impact import remediation_bindings
    from infrastructure_impact.application.eligibility import timestamp
    from infrastructure_impact.application.import_candidate import validate_result

    def require(ok):
        if not ok:
            raise ValueError("invalid retained preview metadata")

    def count(value):
        require(type(value) is int and 0 <= value <= 9007199254740991)

    require(type(value) is dict and value.keys() == _empty(value.get("source_commit")).keys())
    raw = json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    require(len(raw) <= MAX_RECEIPT)
    require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    require(
        type(value["source_commit"]) is str
        and re.fullmatch(r"[0-9a-f]{40}", value["source_commit"]) is not None
    )
    require(value["outcome"] in {"passed", "failed"} and value["failure_code"] in FAILURES)
    require((value["outcome"] == "passed") == (value["failure_code"] == "none"))
    for key in ("network_requests", "revisions_written"):
        require(type(value[key]) is int and value[key] == 0)
    require(type(value["database_unchanged"]) is bool)
    validate_result(value["gates"], publication_format="v2")
    specs = remediation_bindings.definition()["sources"]
    identities = {(s["vendor"], s["advisory_id"], s["source_url"]) for s in specs}
    require(type(value["sources"]) is list and len(value["sources"]) <= len(specs))
    seen = set()
    for source in value["sources"]:
        require(
            type(source) is dict
            and source.keys()
            == {
                "vendor",
                "advisory_id",
                "source_url",
                "source_sha256",
                "retrieved_at",
                "affected_fields_unchanged",
                "before",
                "after",
            }
        )
        identity = tuple(source[k] for k in ("vendor", "advisory_id", "source_url"))
        require(identity in identities and identity not in seen)
        seen.add(identity)
        require(
            type(source["source_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", source["source_sha256"]) is not None
        )
        require(
            type(source["retrieved_at"]) is str
            and len(source["retrieved_at"]) <= 40
            and timestamp(source["retrieved_at"]) is not None
        )
        require(source["affected_fields_unchanged"] is True)
        for key in ("before", "after"):
            require(type(source[key]) is dict and source[key].keys() == COUNT_FIELDS)
            for number in source[key].values():
                count(number)
    require(type(value["cohort"]) is list and len(value["cohort"]) <= 3)
    vendors = set()
    for row in value["cohort"]:
        require(type(row) is dict and row.keys() == {"vendor", *COHORT_FIELDS})
        require(row["vendor"] in {"cisco", "aruba", "arista"} and row["vendor"] not in vendors)
        vendors.add(row["vendor"])
        for key in COHORT_FIELDS:
            count(row[key])
    if value["outcome"] == "passed":
        require(
            value["database_unchanged"]
            and seen == identities
            and vendors == {"cisco", "aruba", "arista"}
        )
        require(value["gates"]["candidate_validated"] is True)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "public", "output", "source-commit"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    value = preview(args.database, args.public, args.source_commit)
    with Path(args.output).open("xb") as output:
        output.write(receipt_bytes(value))
    return 0 if value["outcome"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
