"""Monitor a static public publication without access to its private evidence vault."""

import argparse
import gzip
import hashlib
import io
import json
import re
from datetime import date, datetime, timezone
from urllib.error import HTTPError
from urllib.request import urlopen

try:
    from checks.switching_health import (
        SCHEMAS,
        validate_public_metrics,
        validate_schema,
        validate_switching_report,
    )
except ModuleNotFoundError:  # Direct standalone script, without an installed checkout.
    import runpy
    from pathlib import Path

    _switching = runpy.run_path(str(Path(__file__).with_name("switching_health.py")))
    SCHEMAS = _switching["SCHEMAS"]
    validate_switching_report = _switching["validate_switching_report"]
    validate_schema = _switching["validate_schema"]
    validate_public_metrics = _switching["validate_public_metrics"]


def validate_dossier_limits(report: dict) -> None:
    """Enforce this increment's public gates without installed application imports."""
    assert isinstance(report, dict) and isinstance(report.get("limits"), dict), (
        "Malformed research dossier report"
    )
    limits = report["limits"]
    for field in (
        "inventory_verified",
        "independent_human_review_completed",
        "independent_release_availability_verified",
        "earliest_disclosure_established",
        "concealment_established",
    ):
        assert limits.get(field) is False, f"Research dossier limit changed: {field}"
    for field in ("vendor_rate", "verified_fix_delay_days"):
        assert field in limits and limits[field] is None, f"Research dossier limit changed: {field}"


def validate_kev_report(report, publication, generated_at, scope):
    """Check the KEV v1 contract using only stdlib, including publication scope.

    Freshness here checks consistency at publication evaluation time. The reader's
    shared selector alone decides current membership; stale upstream data is not
    a site failure. Keep this gate aligned with schemas/kev-v1.json.
    """

    def obj(value, fields):
        assert isinstance(value, dict) and set(value) == set(fields.split()), "Malformed KEV object"

    def text(value):
        assert isinstance(value, str) and value.strip(), "Invalid KEV text"

    def timestamp(value):
        assert isinstance(value, str) and re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
            value,
        ), "Invalid KEV timestamp"
        try:
            return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
        except ValueError as error:
            raise AssertionError("Invalid KEV timestamp") from error

    def ids(value):
        assert isinstance(value, list) and all(
            isinstance(cid, str) and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,19}", cid) for cid in value
        ), "Invalid KEV CVE identity"
        assert value == sorted(set(value)), "Unsorted or duplicate KEV identities"

    obj(
        report,
        "schema_version publication generated_at evaluated_at source catalogue policy "
        "listed_cve_ids entries selection",
    )
    assert type(report["schema_version"]) is int and report["schema_version"] == 1
    obj(report["publication"], "id advisory_schema_version")
    text(report["publication"]["id"])
    assert type(report["publication"]["advisory_schema_version"]) is int
    assert report["publication"]["advisory_schema_version"] == 2
    assert report["publication"] == publication, "Mixed KEV generations"
    timestamp(report["generated_at"])
    evaluated = timestamp(report["evaluated_at"])
    assert report["generated_at"] == report["evaluated_at"] == generated_at, "Mixed KEV dates"
    policy = report["policy"]
    expected_policy = dict(
        max_bytes=8000000, max_entries=20000, fresh_for_seconds=129600, future_tolerance_seconds=300
    )
    assert policy == expected_policy and all(type(v) is int for v in policy.values()), (
        "KEV policy changed"
    )
    source = report["source"]
    obj(
        source,
        "id retrieval_url catalogue_url configured enabled availability latest_attempt checked_at",
    )
    assert source["id"] == "cisa-kev", "Wrong KEV source"
    assert source["retrieval_url"] == (
        "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
    ), "Wrong KEV mirror"
    assert source["catalogue_url"] == "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    configured, enabled = source["configured"], source["enabled"]
    assert configured is None or type(configured) is bool
    assert type(enabled) is bool if configured is not None else enabled is None
    checked = timestamp(source["checked_at"]) if source["checked_at"] is not None else None
    attempt = source["latest_attempt"]
    if attempt is not None:
        obj(attempt, "checked_at outcome error_code")
        timestamp(attempt["checked_at"])
        assert attempt["outcome"] in ("ok", "error")
        assert attempt["error_code"] is None or isinstance(attempt["error_code"], str)
    catalogue = report["catalogue"]
    index = report["listed_cve_ids"]
    ids(index)
    assert len(index) <= 20000, "Oversized KEV index"
    entries = report["entries"]
    assert isinstance(entries, dict) and len(entries) <= 20000
    assert set(entries) <= set(index) & set(scope), "Out-of-scope KEV details"
    if catalogue is None:
        assert not index and not entries, "KEV content without catalogue"
    else:
        obj(
            catalogue,
            "version released_at count sha256 revision_id source_observed_at parsed_at parser_version",
        )
        for field in ("version", "revision_id"):
            text(catalogue[field])
        for field in ("released_at", "source_observed_at", "parsed_at"):
            timestamp(catalogue[field])
        assert type(catalogue["count"]) is int and 1 <= catalogue["count"] == len(index) <= 20000
        assert isinstance(catalogue["sha256"], str) and re.fullmatch(
            r"[a-f0-9]{64}", catalogue["sha256"]
        )
        assert type(catalogue["parser_version"]) is int and catalogue["parser_version"] == 1
    for cid, entry in entries.items():
        obj(
            entry,
            "cveID vendorProject product vulnerabilityName shortDescription requiredAction "
            "dateAdded dueDate knownRansomwareCampaignUse forensicTriage notes cwes",
        )
        assert entry["cveID"] == cid, "Mismatched KEV detail identity"
        for field in (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
        ):
            text(entry[field])
        for field in ("knownRansomwareCampaignUse", "forensicTriage", "notes"):
            assert entry[field] is None or isinstance(entry[field], str)
        assert isinstance(entry["cwes"], list) and all(isinstance(c, str) for c in entry["cwes"])
        for field in ("dateAdded", "dueDate"):
            value = entry[field]
            assert isinstance(value, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value)
            try:
                date.fromisoformat(value)
            except ValueError as error:
                raise AssertionError("Invalid KEV date") from error
    if configured is None:
        assert enabled is None and checked is None and attempt is None and catalogue is None
        availability = "missing"
    elif not configured:
        availability = "not_configured"
    elif not enabled:
        availability = "disabled"
    elif catalogue is None or checked is None or attempt is None:
        availability = "missing"
    elif attempt["outcome"] != "ok":
        availability = "failed"
    else:
        age = (evaluated - checked).total_seconds()
        availability = "future" if age < -300 else "stale" if age > 129600 else "available"
    assert source["availability"] == availability, "Inconsistent KEV availability"
    selection = report["selection"]
    obj(selection, "requested_cve_ids effective_cve_ids kev_only membership")
    requested, effective = selection["requested_cve_ids"], selection["effective_cve_ids"]
    ids(requested)
    ids(effective)
    assert type(selection["kev_only"]) is bool
    assert requested == sorted(set(scope)), "KEV selection differs from publication scope"
    listed = set(index)
    membership = {
        cid: ("listed" if cid in listed else "not_listed")
        if availability == "available"
        else "unknown"
        for cid in requested
    }
    assert selection["membership"] == membership, "Inconsistent KEV membership"
    assert effective == (
        [cid for cid in requested if membership[cid] == "listed"]
        if selection["kev_only"]
        else requested
    ), "Inconsistent KEV selection"
    assert not selection["kev_only"] or availability == "available"


def validate_eligibility_summary(report, publication, generated_at, vendors, detail_sha256):
    """Check the closed v1 projection locally; this does not verify full case history."""

    def obj(value, fields):
        assert isinstance(value, dict) and set(value) == set(fields.split()), (
            "Malformed eligibility summary object"
        )

    obj(
        report,
        "schema_version representation publication generated_at source_detail "
        "expected_vendor_ids vendors",
    )
    assert type(report["schema_version"]) is int and report["schema_version"] == 1
    assert report["representation"] == "monitor_summary"
    obj(report["publication"], "id advisory_schema_version")
    identity = report["publication"]
    assert isinstance(identity["id"], str) and 1 <= len(identity["id"]) <= 128
    assert type(identity["advisory_schema_version"]) is int
    assert identity["advisory_schema_version"] == 2
    assert identity == publication, "Mixed eligibility summary generations"
    assert report["generated_at"] == generated_at, "Mixed eligibility summary dates"
    assert isinstance(generated_at, str) and re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])",
        generated_at,
    ), "Invalid eligibility summary timestamp"
    try:
        datetime.fromisoformat(generated_at.upper().replace("Z", "+00:00"))
    except ValueError as error:
        raise AssertionError("Invalid eligibility summary timestamp") from error
    obj(report["source_detail"], "path sha256")
    source = report["source_detail"]
    assert source["path"] == "comparison-eligibility.json"
    assert isinstance(source["sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", source["sha256"])
    assert source["sha256"] == detail_sha256, "Eligibility detail fingerprint differs from manifest"
    expected = report["expected_vendor_ids"]
    assert isinstance(expected, list) and 1 <= len(expected) <= 128
    assert all(isinstance(v, str) and 1 <= len(v) <= 128 for v in expected)
    assert expected == sorted(set(expected)) == sorted(vendors), (
        "Eligibility vendor membership changed"
    )
    rows = report["vendors"]
    assert isinstance(rows, list) and len(rows) == len(expected)
    actual = []
    for row in rows:
        obj(row, "vendor eligibility")
        assert isinstance(row["vendor"], str)
        actual.append(row["vendor"])
        obj(row["eligibility"], "rate_comparison first_disclosure_comparison fix_timing_comparison")
        assert all(value == "suppressed" for value in row["eligibility"].values()), (
            "Eligibility comparison gates changed"
        )
    assert actual == expected, "Eligibility vendors must match complete sorted membership"


def validate_current_evidence(report, publication, generated_at, schemas):
    """Check the bounded public decision ledger without importing the application."""
    canonical = lambda value: json.dumps(  # noqa: E731
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    digest = lambda value: hashlib.sha256(canonical(value)).hexdigest()  # noqa: E731
    assert len(canonical(report)) + 1 <= 2_000_000, "Oversized current-evidence report"
    validate_schema(report, "current-evidence-v1.json", schemas)
    assert report["publication"] == publication, "Mixed current-evidence generations"
    assert report["generated_at"] == generated_at, "Mixed current-evidence dates"
    policies = {(p["vendor"], p["policy_id"]): p for p in report["policies"]}
    assert len(policies) == len(report["policies"]), "Duplicate current-evidence policy"
    decisions, targets = {}, set()
    for decision in report["decisions"]:
        policy = policies.get((decision["vendor"], decision["policy_id"]))
        assert policy is not None, "Unregistered decision policy"
        assert decision["target"]["vendor"] == decision["vendor"]
        assert digest(decision["target"]) == decision["target_key"], "Invalid decision target"
        assert decision["policy_version"] == policy["version"]
        assert decision["policy_fingerprint"] == policy["fingerprint"]
        assert decision["reason_text"] == policy["reason_text"]
        assert decision["proofs"] == sorted(decision["proofs"], key=canonical)
        assert len({canonical(p) for p in decision["proofs"]}) == len(decision["proofs"])
        identity = {
            k: decision[k]
            for k in ("policy_id", "policy_version", "policy_fingerprint", "target_key", "proofs")
        }
        assert digest(identity) == decision["decision_id"], "Invalid decision identity"
        assert decision["decision_id"] not in decisions and decision["target_key"] not in targets
        decisions[decision["decision_id"]] = decision
        targets.add(decision["target_key"])
    issues = set()
    for issue in report["issues"]:
        assert (issue["vendor"], issue["policy_id"]) in policies
        assert issue["target_key"] not in targets and canonical(issue) not in issues
        issues.add(canonical(issue))
    counts = report["counts"]
    if report["availability"] == "available":
        assert counts["excluded"] == len(decisions), "Excluded decision count mismatch"
        assert counts["current"] + counts["excluded"] == counts["retained_total"], (
            "Current/retained union count mismatch"
        )
    return decisions


def check(origin, expected=None, *, verify_archive=False):
    origin = origin.rstrip("/") + "/"
    with urlopen(origin, timeout=20) as response:
        assert response.status == 200, "Dashboard unavailable"
    checked_bytes = 0

    def read(path, budget, *, archive=False):
        nonlocal checked_bytes
        # Bound the actual read by both limits, including the one-byte overflow sentinel.
        limit = budget if archive else min(budget, 20_000_000 - checked_bytes)
        with urlopen(origin + path, timeout=30) as response:
            raw = response.read(limit + 1)
        if not archive:
            checked_bytes += len(raw)
            assert checked_bytes <= 20_000_000, "Default publication exceeds monitor budget"
        assert len(raw) <= budget, (
            "Publication manifest exceeds monitor budget"
            if path == "manifest.json"
            else "Publication part exceeds monitor budget"
        )
        return raw

    manifest = json.loads(read("manifest.json", 2_000_000))

    def verified(path, budget, *, archive=False):
        raw = read(path, budget, archive=archive)
        assert hashlib.sha256(raw).hexdigest() == manifest["sha256"][path], "Fingerprint mismatch"
        return raw

    marker_verified = False
    if ".nojekyll" in manifest["sha256"]:
        verified(".nojekyll", 1024)
        marker_verified = True

    try:
        index = json.loads(verified("data/index.json", 2_000_000))
    except HTTPError as error:
        if error.code != 404 or "data/index.json" in manifest["sha256"]:
            raise
        index = None
    checked_parts = 0
    if index is None:
        raw = verified("snapshot.json", 30_000_000)
        data = json.loads(raw)
    else:
        assert index["schema_version"] == 1, "Unsupported static index"
        assert index["publication"]["id"] == manifest["generation"], "Mixed publication index"

        def part(descriptor):
            nonlocal checked_parts
            path = descriptor["path"]
            assert re.fullmatch(r"data/[a-f0-9]{64}\.json", path), "Invalid part path"
            assert path == "data/" + descriptor["sha256"] + ".json", "Non-addressed part"
            assert 0 < descriptor["bytes"] <= 8_000_000, "Oversized part"
            raw = verified(path, descriptor["bytes"])
            assert len(raw) == descriptor["bytes"], "Part size mismatch"
            assert hashlib.sha256(raw).hexdigest() == descriptor["sha256"], "Part hash mismatch"
            checked_parts += 1
            value = json.loads(raw)
            assert (
                value["schema_version"] == 1
                and value["publication"] == index["publication"]
                and value["generated_at"] == index["generated_at"]
            ), "Mixed evidence generations"
            return value["data"]

        data = part(index["bootstrap"])
        descriptors = {
            d["path"]: d for cid in data["benchmark_cohort"] for d in index["cohorts"].get(cid, [])
        }
        rows = [r for descriptor in descriptors.values() for r in part(descriptor)]
        data["records"] = [r["record"] for r in rows if r["kind"] == "record"]
    assert data["publication"]["id"] == manifest["generation"], "Mixed publication manifest"
    current_availability = "unavailable"
    current_counts = dict(current=None, excluded=None, retained_total=None)
    capability = index.get("current_evidence") if index is not None else None
    marker = data.get("current_evidence_version")
    if capability is not None or marker is not None:
        assert (
            index is not None and capability is not None and type(marker) is int and marker == 1
        ), "Missing current-evidence capability"
        assert type(capability["schema_version"]) is int and capability["schema_version"] == 1
        schemas = {}
        for name in ("current-evidence-v1.json", "kev-v1.json"):
            schemas[name] = json.loads(verified("schemas/" + name, 500_000))
        report = part(capability["report"])
        decisions = validate_current_evidence(
            report, data["publication"], data["generated_at"], schemas
        )
        root_report = json.loads(verified("current-evidence.json", 2_000_000))
        assert root_report == report, "Current-evidence root differs from index"
        retained = []
        membership = []
        assert len(capability["retained"]) <= 1000, "Oversized retained index"
        for fragment in capability["retained"]:
            wrappers = part(fragment["part"])
            assert isinstance(wrappers, list), "Malformed retained fragment"
            assert [w["decision_id"] for w in wrappers] == fragment["decision_ids"], (
                "Retained decision membership mismatch"
            )
            assert (
                sorted({cid for w in wrappers for cid in w["record"]["cves"]})
                == fragment["cve_ids"]
            )
            for wrapper in wrappers:
                assert set(wrapper) == {"record", "decision_id", "record_scope", "target_key"}
                assert wrapper["record_scope"] == "retained_latest_excluded"
                decision = decisions.get(wrapper["decision_id"])
                assert decision and wrapper["target_key"] == decision["target_key"]
                record = wrapper["record"]
                identity = {k: record[k] for k in decision["target"]}
                # Literal JSON scalar types matter (in particular integer revisions).
                assert json.dumps(identity, sort_keys=True) == json.dumps(
                    decision["target"], sort_keys=True
                )
                assert not record.get("notes"), "Private retained projection failed"
                validate_public_metrics(record)
                retained.append(record)
                membership.append(wrapper["decision_id"])
        assert len(membership) == len(set(membership)) and set(membership) == set(decisions), (
            "Incomplete retained decision membership"
        )
        current_availability = report["availability"]
        current_counts = report["counts"]
        if current_availability == "available":
            assert data["counts"]["advisories"] == current_counts["current"]
            assert len(retained) == current_counts["excluded"]
        if "retained_advisories" in data:
            assert data["retained_advisories"] == [] or data["retained_advisories"] == retained
        excluded_targets = {json.dumps(d["target"], sort_keys=True) for d in decisions.values()}
        for record in data["records"]:
            identity = {
                k: record[k]
                for k in ("vendor", "advisory_id", "revision_id", "source_url", "sha256")
            }
            assert json.dumps(identity, sort_keys=True) not in excluded_targets, (
                "Excluded record is current"
            )
        assert {row["decision_id"] for row in data["retained_index"]} == set(decisions)
    elif "current_evidence" in data:
        schemas = {
            name: json.loads(verified("schemas/" + name, 500_000))
            for name in ("current-evidence-v1.json", "kev-v1.json")
        }
        report = data["current_evidence"]
        validate_current_evidence(report, data["publication"], data["generated_at"], schemas)
        assert index is None or report["availability"] == "unavailable", (
            "Missing current-evidence capability"
        )
        if report["availability"] == "available":
            assert report == json.loads(verified("current-evidence.json", 2_000_000))
            wrappers = data["retained_advisories"]
            assert len(wrappers) == report["counts"]["excluded"]
            assert len(data["records"]) == report["counts"]["current"]
            decisions = {d["decision_id"]: d for d in report["decisions"]}
            assert {w["decision_id"] for w in wrappers} == set(decisions)
            for wrapper in wrappers:
                decision = decisions[wrapper["decision_id"]]
                assert set(wrapper) == {"record", "decision_id", "record_scope", "target_key"}
                assert wrapper["record_scope"] == "retained_latest_excluded"
                assert wrapper["target_key"] == decision["target_key"]
                assert not wrapper["record"].get("notes"), "Private retained projection failed"
                validate_public_metrics(wrapper["record"])
                identity = {k: wrapper["record"][k] for k in decision["target"]}
                assert json.dumps(identity, sort_keys=True) == json.dumps(
                    decision["target"], sort_keys=True
                )
            fields = ("vendor", "advisory_id", "revision_id", "source_url", "sha256")
            identities = [
                json.dumps({k: r[k] for k in fields}, sort_keys=True) for r in data["records"]
            ]
            targets = {json.dumps(d["target"], sort_keys=True) for d in decisions.values()}
            assert len(identities) == len(set(identities)), "Duplicate current identity"
            assert not set(identities) & targets, "Excluded record is current"
            current_availability, current_counts = report["availability"], report["counts"]
    switching_availability = "unavailable"
    if index is not None and "switching" in index:
        switching = index["switching"]
        assert isinstance(switching, dict), "Malformed switching index"
        report = part(switching["summary"])
        schemas = {}
        for name in SCHEMAS:
            raw = verified("schemas/" + name, 500_000)
            schemas[name] = json.loads(raw)
        validate_schema(index, "static-index-v1.json", schemas)

        def descriptors(value):
            if isinstance(value, dict):
                if set(value) == {"path", "sha256", "bytes"}:
                    assert value["path"] == "data/" + value["sha256"] + ".json", (
                        "Non-addressed study part"
                    )
                    assert manifest["sha256"].get(value["path"]) == value["sha256"], (
                        "Study part absent from manifest"
                    )
                else:
                    for item in value.values():
                        descriptors(item)
            elif isinstance(value, list):
                for item in value:
                    descriptors(item)

        descriptors(switching)
        validate_switching_report(report, data["publication"], data["generated_at"], schemas)
        switching_availability = report["availability"]
    published = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
    age_seconds = (datetime.now(timezone.utc) - published).total_seconds()
    assert age_seconds >= -300, "Publication timestamp exceeds five-minute clock tolerance"
    assert age_seconds < 36 * 3600, "Publication is stale"
    assert not expected or data["publication"]["id"] == expected, "Old deployment still served"
    assert data["records"], "Empty public dataset"
    kev_availability = None
    if "kev" in data or "kev.json" in manifest["sha256"]:
        report = json.loads(verified("kev.json", 8_000_000))
        scope = set(data.get("all_cves", [])) | set(data.get("benchmark_cohort", {}))
        validate_kev_report(report, data["publication"], data["generated_at"], scope)
        assert report == data.get("kev"), "KEV report differs from bootstrap"
        kev_availability = report["source"]["availability"]
    if "research_dossiers" in data:
        validate_dossier_limits(data["research_dossiers"])
        report = json.loads(verified("research-dossiers.json", 15_000_000))
        validate_dossier_limits(report)
        assert report.get("publication") == data["publication"], "Mixed report generations"
        assert report.get("generated_at") == data["generated_at"], "Mixed report dates"
    eligibility_verification = "unavailable"
    if "comparison-eligibility-summary.json" in manifest["sha256"]:
        report = json.loads(verified("comparison-eligibility-summary.json", 100_000))
        validate_eligibility_summary(
            report,
            data["publication"],
            data["generated_at"],
            data["vendors"],
            manifest["sha256"].get("comparison-eligibility.json"),
        )
        assert report["publication"]["id"] == manifest["generation"], "Mixed summary manifest"
        eligibility_verification = "compact_summary"
    if data.get("product_groups"):
        report_keys = (
            "product_groups",
            "extraction_validation",
            "review_packet",
            "publisher_history",
            "comparison_eligibility",
        )
        for key in report_keys + tuple(
            k
            for k in (
                "vendor_gaps",
                "family_completeness",
                "comparison_readiness",
                "fix_leads",
                "component_studies",
                "product_cohorts",
                "disclosure_review",
            )
            if data.get(k)
        ):
            if key == "comparison_eligibility" and eligibility_verification == "compact_summary":
                continue
            filename = key.replace("_", "-") + ".json"
            report_raw = verified(filename, 15_000_000)
            report = json.loads(report_raw)
            assert report["publication"] == data["publication"], "Mixed report generations"
            assert report["generated_at"] == data["generated_at"], "Mixed report dates"
            if key in ("comparison_eligibility", "product_cohorts", "disclosure_review"):
                data[key] = report
        assert data["extraction_validation"]["independent_human_review_completed"] is False
        # This monitor is deliberately runnable with standard-library Python,
        # outside an installed application. The writer validates full schemas;
        # check generation hashes and the published safety gates here.
        if data.get("product_cohorts"):
            cohorts = data["product_cohorts"]
            assert cohorts["ranking_supported"] is False
            assert cohorts["independent_human_review_completed"] is False
            if cohorts.get("build_pilot"):
                pilot = cohorts["build_pilot"]
                assert pilot["independent_human_review_completed"] is False
                assert pilot["build_denominator"] is None and pilot["rate_comparison"] is None
                assert all(t["verified_inventory"] is False for t in pilot["targets"])
                for target in pilot["targets"]:
                    proposal = target.get("inventory_proposal_template")
                    if proposal is not None:
                        assert proposal["artifacts"] == [], (
                            "Public inventory template contains artifacts"
                        )
                        assert all(
                            c["state"] == "unknown" and c["value"] is None and c["evidence"] == []
                            for c in proposal["claims"]
                        ), "Public inventory template contains private claims"
            assert all(
                c["state"] == "blocked"
                and c["confirmed_build_denominator"] is None
                and all(
                    u["state"] == "blocked"
                    and u["comparison_rate"] is None
                    and u["build_inventory_denominator"] is None
                    for u in c["units"]
                )
                for c in cohorts["cohorts"]
            ), "Product cohort comparison gates changed"
        if data.get("disclosure_review"):
            review = data["disclosure_review"]
            assert review["independent_human_review_completed"] is False
            assert all(
                c["concealment"] == "not_established"
                and c["state"] == "review_required"
                and all(g["state"] == "not_established" for g in c["checklist"])
                for c in review["cases"]
            ), "Disclosure investigation gates changed"
        if eligibility_verification != "compact_summary":
            assert all(
                v["eligibility"]["rate_comparison"] == "suppressed"
                for v in data["comparison_eligibility"]["vendors"]
            )
            eligibility_verification = "legacy_full_report"
    for record in data["records"]:
        assert not record.get("notes"), "Private projection failed"
        validate_public_metrics(record)
    compressed_bytes = 0
    compressed_verified = False
    if (index is None or verify_archive) and "snapshot.json.gz" in manifest["sha256"]:
        compressed = verified("snapshot.json.gz", 8_000_000, archive=verify_archive)
        compressed_bytes = len(compressed)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as archive:
            expanded = archive.read(128_000_001)
        assert len(expanded) <= 128_000_000, "Expanded archive exceeds monitor budget"
        assert hashlib.sha256(expanded).hexdigest() == manifest["sha256"]["snapshot.json"], (
            "Compressed archive differs from full JSON"
        )
        compressed_verified = True
    return {
        "status": "fresh",
        "kev_availability": kev_availability,
        "switching_availability": switching_availability,
        "current_evidence_availability": current_availability,
        "current_evidence_counts": current_counts,
        "static_marker_verified": marker_verified,
        "publication": data["publication"]["id"],
        "generated_at": data["generated_at"],
        "advisories": data.get("counts", {}).get("advisories", len(data["records"])),
        "delivery": "cohort_parts_v1" if index else "legacy_snapshot",
        "checked_default_bytes": checked_bytes,
        "comparison_eligibility_verification": eligibility_verification,
        "checked_parts": checked_parts,
        "full_archive_download_verified": index is None,
        "compressed_archive_verified": compressed_verified,
        "checked_compressed_archive_bytes": compressed_bytes,
        "source_failures": (data.get("collector", {}).get("last_run") or {}).get("failures"),
        "benchmark_passed": data.get("benchmark", {}).get("passed"),
        "benchmark_total": data.get("benchmark", {}).get("total"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin")
    parser.add_argument("--generation")
    parser.add_argument(
        "--verify-archive",
        action="store_true",
        help="Explicitly verify the separate compressed full archive",
    )
    args = parser.parse_args()
    print(json.dumps(check(args.origin, args.generation, verify_archive=args.verify_archive)))


if __name__ == "__main__":
    main()
