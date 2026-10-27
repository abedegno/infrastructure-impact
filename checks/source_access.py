"""Probe reviewed public source alternatives without retaining response bodies.

Run on the collector's network as well as locally. Success is access evidence,
not parser validation, a historical availability date or proof of affectedness.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from infrastructure_impact.collection.errors import check_access_response
from infrastructure_impact.source_policy import allowed

SOURCES = (
    (
        "cisco",
        "ucs-rack-html",
        "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/b_release-notes-for-cisco-ucs-rack-server-software-release-4_2_3.html",
    ),
    (
        "cisco",
        "ucs-rack-pdf",
        "https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/b_release-notes-for-cisco-ucs-rack-server-software-release-4_2_3.pdf",
    ),
    (
        "cisco",
        "nxos-html",
        "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/release-notes/cisco-nexus-9000-nxos-release-notes-1042.html",
    ),
    (
        "aruba",
        "orchestrator-remediation",
        "https://arubanetworking.hpe.com/techdocs/sdwan-PDFs/docs/advisories/orch_resolution_to_cve-2024-6387_latest.pdf",
    ),
)
MAX_BYTES = 3_000_000


def probe(vendor, identity, url):
    if (vendor, identity, url) not in SOURCES or not allowed(url, vendor):
        raise ValueError("Only reviewed exact public probe routes are permitted")

    class Redirects(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            if not allowed(newurl, vendor):
                raise ValueError("Redirect outside vendor HTTPS policy")
            return super().redirect_request(req, fp, code, msg, hdrs, newurl)

    result = dict(
        id=identity,
        vendor=vendor,
        source_url=url,
        checked_at=datetime.now(timezone.utc).isoformat(),
        outcome="unavailable",
    )
    try:
        request = Request(
            url, headers={"User-Agent": "VendorImpact/0.2 (public advisory research)"}
        )
        with build_opener(Redirects()).open(request, timeout=25) as response:
            raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                result["reason"] = "response_budget_exceeded"
                return result
            check_access_response(raw)
            result.update(
                outcome="retrieved_requires_content_review",
                http_status=response.status,
                bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
    except HTTPError as error:
        result.update(reason="http_error", http_status=error.code)
        error.close()
    except (OSError, URLError, TimeoutError):
        result["reason"] = "transport_error"
    except ValueError:
        result["reason"] = "access_or_redirect_policy_rejected"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = dict(
        schema_version=1,
        observations=[probe(*s) for s in SOURCES],
        method="Ordinary anonymous GET from this runner, bounded to 3 MB; no credentials, challenge bypass, user-agent rotation or response-body retention. HTTP success still requires source and parser review. Failures do not establish vendor intent or universal inaccessibility.",
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
