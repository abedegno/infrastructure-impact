"""Exercise the deployed reader over HTTP, without access to its vault."""

import argparse
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("origin")
    args = parser.parse_args()
    origin = args.origin.rstrip("/")

    def request(path, method="GET"):
        try:
            with urlopen(Request(origin + path, method=method), timeout=10) as response:
                return response.status, response.read(), response.headers
        except HTTPError as error:
            return error.code, error.read(), error.headers

    status, body, _ = request("/health/ready")
    assert status == 200, body
    health = json.loads(body)
    status, body, headers = request("/api/v1/advisories?limit=1")
    data = json.loads(body)
    assert status == 200 and len(data["items"]) == 1 and data["total"] > 0
    assert headers["X-Content-Type-Options"] == "nosniff"
    record = data["items"][0]
    assert not record["notes"] and not record["metrics"]
    assert request("/api/v1/advisories?limit=0")[0] == 400
    assert request("/api/state", "POST")[0] == 405
    assert request("/snapshot.json", "HEAD")[1] == b""
    assert request("/data/intel.sqlite3")[0] == 404
    assert request("/api/raw/1")[0] == 404
    assert request("/schemas/advisory-v2.json")[0] == 200
    assert request("/openapi.json")[0] == 200
    print(
        json.dumps(
            {
                "http_reader": True,
                "readiness": True,
                "pagination": True,
                "private_routes_denied": True,
                "schema_and_openapi": True,
                "generation": health["publication"]["id"],
            }
        )
    )


if __name__ == "__main__":
    main()
