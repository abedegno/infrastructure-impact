"""Monitor a static public publication without access to its private evidence vault."""

import argparse
import gzip
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.request import urlopen


def check(origin, expected=None):
    origin = origin.rstrip("/") + "/"
    with urlopen(origin, timeout=20) as response:
        assert response.status == 200, "Dashboard unavailable"
    with urlopen(origin + "manifest.json", timeout=20) as response:
        manifest = json.load(response)

    def verified(path, budget):
        with urlopen(origin + path, timeout=30) as response:
            raw = response.read(budget + 1)
        assert len(raw) <= budget, "Publication part exceeds monitor budget"
        assert hashlib.sha256(raw).hexdigest() == manifest["sha256"][path], "Fingerprint mismatch"
        return raw

    marker_verified = False
    if ".nojekyll" in manifest["sha256"]:
        verified(".nojekyll", 1024)
        marker_verified = True

    try:
        index = json.loads(verified("data/index.json", 2_000_000))
    except HTTPError as error:
        if error.code != 404:
            raise
        index = None
    checked_bytes = 0
    checked_parts = 0
    if index is None:
        raw = verified("snapshot.json", 30_000_000)
        data = json.loads(raw)
        checked_bytes = len(raw)
    else:
        assert index["schema_version"] == 1, "Unsupported static index"
        assert index["publication"]["id"] == manifest["generation"], "Mixed publication index"

        def part(descriptor):
            nonlocal checked_bytes, checked_parts
            path = descriptor["path"]
            assert re.fullmatch(r"data/[a-f0-9]{64}\.json", path), "Invalid part path"
            assert path == "data/" + descriptor["sha256"] + ".json", "Non-addressed part"
            assert 0 < descriptor["bytes"] <= 8_000_000, "Oversized part"
            raw = verified(path, descriptor["bytes"])
            assert len(raw) == descriptor["bytes"], "Part size mismatch"
            assert hashlib.sha256(raw).hexdigest() == descriptor["sha256"], "Part hash mismatch"
            checked_bytes += len(raw)
            checked_parts += 1
            assert checked_bytes <= 20_000_000, "Default cohort exceeds monitor budget"
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
    published = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - published).total_seconds() < 36 * 3600, (
        "Publication is stale"
    )
    assert not expected or data["publication"]["id"] == expected, "Old deployment still served"
    assert data["records"], "Empty public dataset"
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
            filename = key.replace("_", "-") + ".json"
            with urlopen(origin + filename, timeout=20) as response:
                report_raw = response.read(15_000_001)
            assert len(report_raw) <= 15_000_000, "Evidence-quality report exceeds monitor budget"
            assert hashlib.sha256(report_raw).hexdigest() == manifest["sha256"][filename], (
                "Evidence-quality report fingerprint mismatch"
            )
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
        assert all(
            v["eligibility"]["rate_comparison"] == "suppressed"
            for v in data["comparison_eligibility"]["vendors"]
        )
    assert all(not r.get("notes") and not r.get("metrics") for r in data["records"]), (
        "Private projection failed"
    )
    compressed_bytes = 0
    compressed_verified = False
    if "snapshot.json.gz" in manifest["sha256"]:
        compressed = verified("snapshot.json.gz", 8_000_000)
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
        "static_marker_verified": marker_verified,
        "publication": data["publication"]["id"],
        "generated_at": data["generated_at"],
        "advisories": data.get("counts", {}).get("advisories", len(data["records"])),
        "delivery": "cohort_parts_v1" if index else "legacy_snapshot",
        "checked_default_bytes": checked_bytes,
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
    args = parser.parse_args()
    print(json.dumps(check(args.origin, args.generation)))


if __name__ == "__main__":
    main()
