"""Pure current/retained partitioning with a private, bounded policy boundary.

Hook metadata is local code: policy_id, policy_version, reason_text,
proof_sources (tuple of exact URLs), optional proof_locators (default document),
optional proof_captures (exact URL/SHA references), and policy_dependencies
(tuple of inspectable helper callables). Hooks receive
isolated vendor records and {selections: [...], sources: [private frames]}.
Only {decisions: [{target_key, proofs: [public proof]}], issues:
[{target_key, code: proof_unresolved}]} may cross back. Raw input never does.
"""

import base64
import binascii
import copy
import inspect
import json
import re
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..settings import PACKAGE
from .evidence_identity import canonical_json, record_identity, record_key

MAX_FRAME_BYTES = 2_000_000
MAX_CONTEXT_BYTES = 8_000_000
MAX_REPORT_BYTES = 2_000_000
MAX_DECISIONS = 1000
_UNSET = object()
_FRAME_FIELDS = {"source_url", "source_sha256", "evidence_id", "source_observed_at", "raw_b64"}
_PROOF_FIELDS = (_FRAME_FIELDS - {"raw_b64"}) | {"locator"}
_DISPOSITION = "excluded_from_current"
_REASON = "reviewed_representation_scope_conflict"


def _official(url, plugin):
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        valid = (
            parts.scheme == "https"
            and not parts.username
            and not parts.password
            and parts.port in (None, 443)
            and not parts.fragment
            and any(host == d or host.endswith("." + d) for d in plugin.domains)
            and plugin.url_filter(url)
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("Current-evidence proof must use an official registered route")


def _text(value, *, maximum=500):
    return type(value) is str and 1 <= len(value) <= maximum and bool(value.strip())


def policy_metadata(plugin):
    """Validate local declarations and fingerprint code independently of normalizers."""
    hook = plugin.current_evidence_policy
    if hook is None:
        return None
    if not callable(hook):
        raise ValueError("Current-evidence policy must be callable")
    policy_id = getattr(hook, "policy_id", None)
    version = getattr(hook, "policy_version", None)
    reason = getattr(hook, "reason_text", None)
    urls = getattr(hook, "proof_sources", None)
    locators = getattr(hook, "proof_locators", ("document",))
    dependencies = getattr(hook, "policy_dependencies", ())
    captures = getattr(hook, "proof_captures", ())
    if (
        not _text(policy_id, maximum=128)
        or not re.fullmatch("[a-z][a-z0-9_-]*", policy_id)
        or not _text(version, maximum=128)
        or not _text(reason)
        or type(urls) is not tuple
        or not 1 <= len(urls) <= 20
        or any(not _text(u, maximum=2048) for u in urls)
        or len(set(urls)) != len(urls)
        or type(locators) is not tuple
        or not 1 <= len(locators) <= 100
        or any(not _text(v, maximum=256) for v in locators)
        or len(set(locators)) != len(locators)
        or type(dependencies) is not tuple
        or any(not callable(d) for d in dependencies)
    ):
        raise ValueError("Invalid bounded current-evidence policy metadata")
    if type(captures) is not tuple or len(captures) > 20:
        raise ValueError("Invalid bounded policy capture references")
    capture_keys = set()
    for capture in captures:
        if (
            type(capture) is not dict
            or set(capture) != {"source_url", "source_sha256"}
            or capture["source_url"] not in urls
            or type(capture["source_sha256"]) is not str
            or not re.fullmatch("[a-f0-9]{64}", capture["source_sha256"])
        ):
            raise ValueError("Invalid registered exact policy capture identity")
        key = canonical_json(capture)
        if key in capture_keys:
            raise ValueError("Duplicate registered policy capture identity")
        capture_keys.add(key)
    for url in urls:
        _official(url, plugin)
    paths = {}
    for callback in (hook, plugin.url_filter, *dependencies):
        try:
            source = inspect.getsourcefile(callback)
        except TypeError as error:
            raise ValueError("Policy dependencies require inspectable Python source") from error
        if not source or not getattr(callback, "__module__", None):
            raise ValueError("Policy dependencies require inspectable Python source")
        path = Path(source).resolve()
        label = callback.__module__ + ":" + path.name
        paths[path] = min(label, paths.get(path, label))
    for relative in (
        "application/current_evidence.py",
        "application/evidence_identity.py",
        "plugins/registry.py",
        "plugins/contracts.py",
        "schemas/current-evidence-v1.json",
    ):
        paths[(PACKAGE / relative).resolve()] = "core:" + relative
    try:
        sources = sorted(
            [label, sha256(path.read_bytes()).hexdigest()] for path, label in paths.items()
        )
    except OSError as error:
        raise ValueError("Policy source unavailable") from error
    payload = {
        "vendor": plugin.id,
        "policy_id": policy_id,
        "version": version,
        "reason_text": reason,
        "official_domains": sorted(plugin.domains),
        "proof_sources": sorted(urls),
        "proof_locators": sorted(locators),
        "proof_captures": sorted(captures, key=canonical_json),
        "sources": sources,
    }
    return {
        "vendor": plugin.id,
        "policy_id": policy_id,
        "version": version,
        "fingerprint": sha256(canonical_json(payload)).hexdigest(),
        "reason_text": reason,
    }


def _source_identity(value):
    if (
        not _text(value.get("source_url"), maximum=2048)
        or type(value.get("source_sha256")) is not str
        or not re.fullmatch("[a-f0-9]{64}", value["source_sha256"])
        or type(value.get("evidence_id")) is not int
        or value["evidence_id"] < 1
        or not _text(value.get("source_observed_at"), maximum=64)
        or not FormatChecker().conforms(value["source_observed_at"], "date-time")
    ):
        raise ValueError("Invalid typed proof frame identity")


def validate_context(context, plugins):
    """Validate bytes and metadata before any hook receives private input."""
    if len(canonical_json(context)) > MAX_CONTEXT_BYTES:
        raise ValueError("Current-evidence private context exceeds byte limit")
    if type(context) is not dict or set(context) != {"selections", "sources"}:
        raise ValueError("Invalid private policy context fields")
    if type(context["sources"]) is not list or type(context["selections"]) is not list:
        raise ValueError("Invalid private policy context lists")
    seen = set()
    for frame in context["sources"]:
        if type(frame) is not dict or set(frame) != _FRAME_FIELDS:
            raise ValueError("Invalid private proof frame fields")
        _source_identity(frame)
        candidates = [
            p
            for p in plugins
            if p.current_evidence_policy is None
            or frame["source_url"] in p.current_evidence_policy.proof_sources
        ]
        if not any(_is_official(frame["source_url"], p) for p in candidates):
            raise ValueError("Proof frame is not a registered official policy source")
        key = canonical_json({k: frame[k] for k in _FRAME_FIELDS - {"raw_b64"}})
        if key in seen:
            raise ValueError("Duplicate private proof frame")
        seen.add(key)
        encoded = frame["raw_b64"]
        if type(encoded) is not str or len(encoded) > 4 * ((MAX_FRAME_BYTES + 2) // 3):
            raise ValueError("Private proof frame exceeds byte limit")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("Invalid private proof frame base64") from error
        if len(raw) > MAX_FRAME_BYTES:
            raise ValueError("Private proof frame exceeds byte limit")
        if base64.b64encode(raw).decode("ascii") != encoded:
            raise ValueError("Noncanonical private proof frame base64")
        if sha256(raw).hexdigest() != frame["source_sha256"]:
            raise ValueError("Private proof frame hash mismatch")
    for selection in context["selections"]:
        if (
            type(selection) is not dict
            or set(selection) != {"vendor", "requested_url", "selected_at", "reason", "views"}
            or not _text(selection["reason"])
            or not _text(selection["selected_at"], maximum=64)
            or not FormatChecker().conforms(selection["selected_at"], "date-time")
            or type(selection["views"]) is not list
            or not 1 <= len(selection["views"]) <= 20
        ):
            raise ValueError("Invalid private selection metadata")
        plugin = next((p for p in plugins if p.id == selection["vendor"]), None)
        if plugin is None or plugin.current_evidence_policy is None:
            raise ValueError("Selection metadata requires a registered policy")
        if selection["requested_url"] not in plugin.current_evidence_policy.proof_sources:
            raise ValueError("Selection metadata is outside registered policy sources")
        _official(selection["requested_url"], plugin)
        for view in selection["views"]:
            if type(view) is not dict or set(view) != (_FRAME_FIELDS - {"raw_b64"}) | {"selected"}:
                raise ValueError("Invalid private selection view")
            _source_identity(view)
            if type(view["selected"]) is not bool:
                raise ValueError("Invalid private selection flag")
            if view["source_url"] not in plugin.current_evidence_policy.proof_sources:
                raise ValueError("Selection view is outside registered policy sources")
            _official(view["source_url"], plugin)
        selected = [v for v in selection["views"] if v["selected"]]
        if (
            len(selected) != 1
            or canonical_json({k: selected[0][k] for k in _FRAME_FIELDS - {"raw_b64"}}) not in seen
        ):
            raise ValueError(
                "Private selected view must identify exactly one validated proof frame"
            )
    return copy.deepcopy(context)


def _is_official(url, plugin):
    try:
        _official(url, plugin)
        return True
    except ValueError:
        return False


def _decision_id(decision):
    return sha256(
        canonical_json(
            {
                k: decision[k]
                for k in (
                    "policy_id",
                    "policy_version",
                    "policy_fingerprint",
                    "target_key",
                    "proofs",
                )
            }
        )
    ).hexdigest()


def policy_decisions(plugin, records, selection_context):
    """Registry implementation: constrain hooks to local policy and retained facts."""
    policy = policy_metadata(plugin)
    if policy is None:
        return {"policy": None, "decisions": [], "issues": []}
    if any(r.get("vendor") != plugin.id for r in records):
        raise ValueError("Policy records must belong to exactly its registered vendor")
    known = {record_key(r) for r in records}
    if len(known) != len(records):
        raise ValueError("Duplicate retained record identity")
    context = validate_context(selection_context, [plugin])
    for selection in context["selections"]:
        for view in (v for v in selection["views"] if v["selected"]):
            matches = [
                r
                for r in records
                if r["source_url"] == view["source_url"] and r["sha256"] == view["source_sha256"]
            ]
            if not matches or not any(
                (
                    "evidence_id" not in r
                    or (type(r["evidence_id"]) is int and r["evidence_id"] == view["evidence_id"])
                )
                and (
                    "source_observed_at" not in r
                    or r["source_observed_at"] == view["source_observed_at"]
                )
                for r in matches
            ):
                raise ValueError("Private selected view must match a retained record identity")
    try:
        result = plugin.current_evidence_policy(copy.deepcopy(records), copy.deepcopy(context))
    except Exception:
        # Parser exceptions may contain response bodies; never expose them.
        raise ValueError("Current-evidence policy evaluation failed") from None
    # Canonical round-trip also rejects non-JSON and nonfinite hook values.
    result = json.loads(canonical_json(result))
    if (
        type(result) is not dict
        or set(result) != {"decisions", "issues"}
        or type(result["decisions"]) is not list
        or type(result["issues"]) is not list
        or len(result["decisions"]) > MAX_DECISIONS
        or len(result["issues"]) > MAX_DECISIONS
    ):
        raise ValueError("Invalid bounded policy decisions/issues")
    frames = {
        canonical_json({k: f[k] for k in _FRAME_FIELDS - {"raw_b64"}}) for f in context["sources"]
    }
    decisions, issues, seen = [], [], set()
    for candidate in result["decisions"]:
        if type(candidate) is not dict or set(candidate) != {"target_key", "proofs"}:
            raise ValueError("Policy decision contains unsupported fields/disposition")
        target = candidate["target_key"]
        if type(target) is not str or target not in known or target in seen:
            raise ValueError("Policy decision target must be exact, known and unique")
        seen.add(target)
        proofs = candidate["proofs"]
        if type(proofs) is not list or not 1 <= len(proofs) <= 20:
            raise ValueError("Policy decisions require bounded proof identities")
        missing = False
        proof_keys = set()
        for proof in proofs:
            if type(proof) is not dict or set(proof) != _PROOF_FIELDS:
                raise ValueError("Invalid public proof fields")
            _source_identity(proof)
            _official(proof["source_url"], plugin)
            if proof["source_url"] not in plugin.current_evidence_policy.proof_sources or proof[
                "locator"
            ] not in getattr(plugin.current_evidence_policy, "proof_locators", ("document",)):
                raise ValueError("Proof source/locator is not locally registered")
            key = canonical_json(proof)
            if key in proof_keys:
                raise ValueError("Duplicate policy proof")
            proof_keys.add(key)
            if canonical_json({k: proof[k] for k in _FRAME_FIELDS - {"raw_b64"}}) not in frames:
                missing = True
        if missing:
            issues.append(
                {
                    "vendor": plugin.id,
                    "policy_id": policy["policy_id"],
                    "target_key": target,
                    "code": "proof_unresolved",
                }
            )
            continue
        decision = {
            "vendor": plugin.id,
            "policy_id": policy["policy_id"],
            "policy_version": policy["version"],
            "policy_fingerprint": policy["fingerprint"],
            "target_key": target,
            "target": record_identity(next(r for r in records if record_key(r) == target)),
            "disposition": _DISPOSITION,
            "reason": _REASON,
            "reason_text": policy["reason_text"],
            "proofs": sorted(proofs, key=canonical_json),
        }
        decisions.append({"decision_id": _decision_id(decision), **decision})
    issue_keys = {(i["target_key"], i["code"]) for i in issues}
    for issue in result["issues"]:
        if (
            type(issue) is not dict
            or set(issue) != {"target_key", "code"}
            or type(issue["target_key"]) is not str
            or issue["target_key"] not in known
            or issue["code"] != "proof_unresolved"
            or (issue["target_key"], issue["code"]) in issue_keys
        ):
            raise ValueError(
                "Invalid policy issue: only known targets and registered codes allowed"
            )
        issue_keys.add((issue["target_key"], issue["code"]))
        issues.append({"vendor": plugin.id, "policy_id": policy["policy_id"], **issue})
    if any(i["target_key"] == d["target_key"] for i in issues for d in decisions):
        raise ValueError("Unresolved policy issues cannot accompany an exclusion")
    return {"policy": policy, "decisions": decisions, "issues": issues}


def partition(records, selection_context, *, registry, publication, generated_at):
    """Preserve the retained inventory while explicitly separating current claims."""
    keys = [record_key(r) for r in records]
    if len(set(keys)) != len(keys):
        raise ValueError("Duplicate retained record identity")
    vendors = sorted({r["vendor"] for r in records})
    installed = registry.names()
    plugins = [registry.get(v) for v in vendors if v in installed]
    context = validate_context(selection_context, plugins)
    policies, decisions, issues = [], [], []
    for plugin in plugins:
        urls = getattr(plugin.current_evidence_policy, "proof_sources", ())
        private = {
            "selections": [s for s in context["selections"] if s["vendor"] == plugin.id],
            "sources": [f for f in context["sources"] if f["source_url"] in urls],
        }
        result = registry.current_evidence_decisions(
            plugin.id, [r for r in records if r["vendor"] == plugin.id], private
        )
        if result["policy"] is not None:
            policies.append(result["policy"])
        decisions.extend(result["decisions"])
        issues.extend(result["issues"])
    excluded = {d["target_key"]: d["decision_id"] for d in decisions}
    current, retained = [], []
    for key, record in zip(keys, records):
        if key in excluded:
            retained.append(
                {
                    "record": copy.deepcopy(record),
                    "decision_id": excluded[key],
                    "record_scope": "retained_latest_excluded",
                }
            )
        else:
            current.append(copy.deepcopy(record))
    report = {
        "schema_version": 1,
        "availability": "available",
        "publication": copy.deepcopy(publication),
        "generated_at": generated_at,
        "policies": policies,
        "decisions": sorted(decisions, key=lambda d: d["decision_id"]),
        "issues": sorted(issues, key=canonical_json),
        "counts": {
            "current": len(current),
            "retained_total": len(records),
            "excluded": len(retained),
        },
    }
    validate_report(report, publication=publication, generated_at=generated_at)
    return {"records": current, "retained_advisories": retained, "current_evidence": report}


def collect_policy_input(db, records, *, registry):
    """Read only registered URLs; never scan the evidence inventory or retrieve HTTP."""
    context = {"selections": [], "sources": []}
    installed = registry.names()
    plugins = [registry.get(v) for v in sorted({r["vendor"] for r in records}) if v in installed]
    frames = set()
    has_selections = db.execute(
        "SELECT 1 FROM sqlite_master WHERE name='source_selections'"
    ).fetchone()
    for plugin in plugins:
        if policy_metadata(plugin) is None:
            continue
        urls = plugin.current_evidence_policy.proof_sources
        placeholders = ",".join("?" for _ in urls)
        if has_selections:
            selections = db.execute(
                "SELECT * FROM source_selections WHERE vendor=? AND requested_url IN ("
                + placeholders
                + ") "
                "AND id IN (SELECT MAX(id) FROM source_selections WHERE vendor=? AND requested_url IN ("
                + placeholders
                + ") GROUP BY requested_url) ORDER BY requested_url",
                (plugin.id, *urls, plugin.id, *urls),
            ).fetchall()
            for selection in selections:
                views = db.execute(
                    "SELECT e.id AS evidence_id,e.source_url,e.sha256 AS source_sha256,"
                    "e.observed_at AS source_observed_at FROM source_selection_views v "
                    "JOIN evidence e ON e.id=v.evidence_id WHERE v.selection_id=? "
                    "AND e.source_url IN (" + placeholders + ") ORDER BY v.id LIMIT 21",
                    (selection["id"], *urls),
                ).fetchall()
                if views:
                    context["selections"].append(
                        {
                            "vendor": plugin.id,
                            "requested_url": selection["requested_url"],
                            "selected_at": selection["observed_at"],
                            "reason": selection["reason"],
                            "views": [
                                {
                                    **dict(v),
                                    "selected": v["evidence_id"]
                                    == selection["selected_evidence_id"],
                                }
                                for v in views
                            ],
                        }
                    )
        evidence_ids = {
            v["evidence_id"]
            for s in context["selections"]
            if s["vendor"] == plugin.id
            for v in s["views"]
            if v["selected"]
        }
        captures = list(getattr(plugin.current_evidence_policy, "proof_captures", ()))
        for record in records:
            if record["vendor"] == plugin.id and record["source_url"] in urls:
                record_key(record)  # Require exact typed retained identity before lookup.
                captures.append(
                    {"source_url": record["source_url"], "source_sha256": record["sha256"]}
                )
        for capture in captures:
            row = db.execute(
                "SELECT id FROM evidence WHERE source_url=? AND sha256=?",
                (capture["source_url"], capture["source_sha256"]),
            ).fetchone()
            if row:
                evidence_ids.add(row["id"])
        for evidence_id in sorted(evidence_ids):
            if evidence_id in frames:
                continue
            row = db.execute(
                "SELECT id,source_url,sha256,observed_at,length(raw) AS bytes FROM evidence WHERE id=?",
                (evidence_id,),
            ).fetchone()
            if row["bytes"] > MAX_FRAME_BYTES:
                raise ValueError("Retained proof frame exceeds byte limit")
            raw = db.execute("SELECT raw FROM evidence WHERE id=?", (evidence_id,)).fetchone()[
                "raw"
            ]
            if not isinstance(raw, bytes):
                raise ValueError("Retained proof frame must contain bytes")
            context["sources"].append(
                {
                    "source_url": row["source_url"],
                    "source_sha256": row["sha256"],
                    "evidence_id": row["id"],
                    "source_observed_at": row["observed_at"],
                    "raw_b64": base64.b64encode(raw).decode("ascii"),
                }
            )
            frames.add(evidence_id)
            if len(canonical_json(context)) > MAX_CONTEXT_BYTES:
                raise ValueError("Current-evidence private context exceeds byte limit")
    return validate_context(context, plugins)


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads((PACKAGE / "schemas/current-evidence-v1.json").read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def report_bytes(report):
    """The sole public wire encoding, shared by validation, writers and monitors."""
    raw = canonical_json(report) + b"\n"
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Current-evidence report exceeds byte limit")
    return raw


def validate_report(report, *, publication=_UNSET, generated_at=_UNSET):
    report_bytes(report)
    try:
        _validator().validate(report)
    except ValidationError:
        # Schema failures must not echo untrusted/private values into logs.
        raise ValueError("Invalid current-evidence report schema") from None
    if publication is not _UNSET and report["publication"] != publication:
        raise ValueError("Current-evidence report publication mismatch")
    if generated_at is not _UNSET and report["generated_at"] != generated_at:
        raise ValueError("Current-evidence report generation time mismatch")
    policies = {(p["vendor"], p["policy_id"]): p for p in report["policies"]}
    if len(policies) != len(report["policies"]):
        raise ValueError("Duplicate current-evidence policy")
    seen, targets = set(), set()
    for decision in report["decisions"]:
        key = (decision["vendor"], decision["policy_id"])
        policy = policies.get(key)
        if (
            policy is None
            or record_key(decision["target"]) != decision["target_key"]
            or decision["target"]["vendor"] != decision["vendor"]
            or decision["policy_fingerprint"] != policy["fingerprint"]
            or decision["policy_version"] != policy["version"]
            or decision["reason_text"] != policy["reason_text"]
            or decision["decision_id"] != _decision_id(decision)
            or decision["decision_id"] in seen
            or decision["target_key"] in targets
            or decision["proofs"] != sorted(decision["proofs"], key=canonical_json)
            or len({canonical_json(p) for p in decision["proofs"]}) != len(decision["proofs"])
        ):
            raise ValueError("Current-evidence decision identity/policy mismatch")
        seen.add(decision["decision_id"])
        targets.add(decision["target_key"])
    issue_keys = set()
    for issue in report["issues"]:
        key = canonical_json(issue)
        if (
            (issue["vendor"], issue["policy_id"]) not in policies
            or key in issue_keys
            or issue["target_key"] in targets
        ):
            raise ValueError("Invalid current-evidence unresolved issue")
        issue_keys.add(key)
    counts = report["counts"]
    if report["availability"] == "available":
        if (
            counts["excluded"] != len(report["decisions"])
            or counts["current"] + counts["excluded"] != counts["retained_total"]
        ):
            raise ValueError("Current-evidence report counts mismatch")
    elif (
        any(v is not None for v in counts.values())
        or report["decisions"]
        or report["policies"]
        or report["issues"]
    ):
        raise ValueError("Unavailable current-evidence counts must be null")


def unavailable_report(*, publication, generated_at):
    report = {
        "schema_version": 1,
        "availability": "unavailable",
        "publication": copy.deepcopy(publication),
        "generated_at": generated_at,
        "policies": [],
        "decisions": [],
        "issues": [],
        "counts": {"current": None, "retained_total": None, "excluded": None},
    }
    validate_report(report, publication=publication, generated_at=generated_at)
    return report
