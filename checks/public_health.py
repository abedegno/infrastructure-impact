"""Monitor a static public publication without access to its private evidence vault."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from urllib.request import urlopen


def check(origin, expected=None):
    origin = origin.rstrip("/") + "/"
    with urlopen(origin, timeout=20) as response:
        assert response.status == 200, "Dashboard unavailable"
    with urlopen(origin + "snapshot.json", timeout=30) as response:
        raw = response.read(30_000_001)
    assert len(raw) <= 30_000_000, "Publication exceeds monitor budget"
    data = json.loads(raw)
    published = datetime.fromisoformat(data["generated_at"].replace("Z", "+00:00"))
    assert (datetime.now(timezone.utc) - published).total_seconds() < 36 * 3600, (
        "Publication is stale"
    )
    assert not expected or data["publication"]["id"] == expected, "Old deployment still served"
    with urlopen(origin + "manifest.json", timeout=20) as response:
        manifest = json.load(response)
    assert hashlib.sha256(raw).hexdigest() == manifest["sha256"]["snapshot.json"], (
        "Fingerprint mismatch"
    )
    assert data["records"], "Empty public dataset"
    assert all(not r.get("notes") and not r.get("metrics") for r in data["records"]), (
        "Private projection failed"
    )
    return {
        "status": "fresh",
        "publication": data["publication"]["id"],
        "generated_at": data["generated_at"],
        "advisories": len(data["records"]),
        "source_failures": data.get("collector", {}).get("last_run", {}).get("failures"),
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
