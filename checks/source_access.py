"""Probe reviewed public source alternatives without retaining response bodies.

Run on the collector's network as well as locally. Success is access evidence,
not parser validation, a historical availability date or proof of affectedness.
"""

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from infrastructure_impact.collection.errors import check_access_response
from infrastructure_impact.source_policy import allowed

SOURCES = (
    (
        "f5",
        "php-advisory-pdf",
        "https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000163821",
    ),
    (
        "f5",
        "openssh-advisory-pdf",
        "https://my.f5.com/manage/MyF5_KnowledgeArticlePDF?article=K000140222",
    ),
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
    ("cisco", "csaf-provider", "https://www.cisco.com/.well-known/csaf/provider-metadata.json"),
    ("cisco", "csaf-index", "https://www.cisco.com/.well-known/csaf/index.txt"),
    ("aruba", "csaf-index", "https://csaf.arubanetworking.hpe.com/index.txt"),
    (
        "cisco",
        "sbom-instructions",
        "https://sec.cloudapps.cisco.com/security/center/resources/sbom-form-instructions",
    ),
    (
        "hpe",
        "hfp-release-listing",
        "https://support.hpe.com/connect/s/softwaredetails?collectionId=MTX-575acc2c0e334c3a&language=fr&softwareId=MTX_c65e615117944819bcdc6219e0",
    ),
)
MAX_BYTES = 3_000_000


def probe(vendor, identity, url, *, verify_f5=False):
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
            if verify_f5 and vendor == "f5":
                from infrastructure_impact.plugins.registry import default_registry

                try:
                    document = default_registry().normalize(raw, url, vendor)
                except (ValueError, subprocess.SubprocessError):
                    result["normalization"] = {"status": "rejected_requires_review"}
                else:
                    result["normalization"] = dict(
                        status="passed",
                        schema_version=document["schema_version"],
                        adapter_version=document["adapter_version"],
                        cves=len(document["cves"]),
                        assessments=len(document["assessments"]),
                        affected=sum(a["status"] == "affected" for a in document["assessments"]),
                        unaffected=sum(
                            a["status"] == "unaffected" for a in document["assessments"]
                        ),
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
    parser.add_argument(
        "--verify-f5",
        action="store_true",
        help="Also normalize the two reviewed F5 PDFs and retain counts only; no vault",
    )
    args = parser.parse_args()
    report = dict(
        schema_version=1,
        observations=[probe(*s, verify_f5=args.verify_f5) for s in SOURCES],
        f5_normalization_requested=args.verify_f5,
        method="Ordinary anonymous GET from this runner, bounded to 3 MB; no credentials, challenge bypass, user-agent rotation or response-body retention. Optional F5 PDF normalization retains counts and a parser fingerprint only, without a vault or publication. HTTP success alone still requires source and parser review. Failures do not establish vendor intent or universal inaccessibility.",
    )
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if args.verify_f5 and any(
        observation.get("normalization", {}).get("status") != "passed"
        for observation in report["observations"]
        if observation["vendor"] == "f5"
    ):
        raise SystemExit("Reviewed F5 PDF normalization did not pass; inspect retained metadata")


if __name__ == "__main__":
    main()
