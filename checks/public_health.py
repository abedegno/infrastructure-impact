"""Monitor a static public publication without access to its private evidence vault."""

import argparse
import hashlib
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
        for key in (
            "product_groups",
            "extraction_validation",
            "review_packet",
            "publisher_history",
            "comparison_eligibility",
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
            if key == "comparison_eligibility":
                data[key] = report
        assert data["extraction_validation"]["independent_human_review_completed"] is False
        assert all(
            v["eligibility"]["rate_comparison"] == "suppressed"
            for v in data["comparison_eligibility"]["vendors"]
        )
    assert all(not r.get("notes") and not r.get("metrics") for r in data["records"]), (
        "Private projection failed"
    )
    return {
        "status": "fresh",
        "publication": data["publication"]["id"],
        "generated_at": data["generated_at"],
        "advisories": data.get("counts", {}).get("advisories", len(data["records"])),
        "delivery": "cohort_parts_v1" if index else "legacy_snapshot",
        "checked_default_bytes": checked_bytes,
        "checked_parts": checked_parts,
        "full_archive_download_verified": index is None,
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
