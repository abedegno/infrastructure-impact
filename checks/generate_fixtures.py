"""Generate small synthetic parser inputs; these are never vendor evidence.

Literal layout markers exercise the reviewed adapters. Product/CVE identifiers
are test values and must not be interpreted as current publisher assertions.
"""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "tests/fixtures"


def put(name, value):
    if isinstance(value, dict) or isinstance(value, list):
        value = json.dumps(value, indent=2) + "\n"
    ROOT.joinpath(name).write_text(value)


def html(name, content):
    put(
        name,
        "<!doctype html><html><head><title>Synthetic parser fixture</title></head>"
        "<body><!-- Synthetic input, not a captured vendor document. -->"
        + content
        + "</body></html>\n",
    )


def csaf(identity, title="Synthetic advisory", status="final"):
    return {
        "document": {
            "title": title,
            "tracking": {
                "id": identity,
                "status": status,
                "initial_release_date": "2025-01-01T00:00:00Z",
            },
        },
        "vulnerabilities": [],
    }


def article(name, identity, solution):
    data = {
        "props": {
            "pageProps": {
                "data": {
                    "id": identity,
                    "title": "Synthetic article",
                    "lastModified": "2025-01-01",
                    "solution": solution,
                }
            }
        }
    }
    html(
        name, '<script id="__NEXT_DATA__" type="application/json">' + json.dumps(data) + "</script>"
    )


def pdf(lines):
    # A tiny original PDF avoids retaining a publisher attachment or adding a PDF
    # authoring dependency just to rebuild fixtures.
    escaped = [s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for s in lines]
    stream = (
        "BT /F1 12 Tf 40 780 Td 16 TL " + " Tj T* ".join("(" + s + ")" for s in escaped) + " Tj ET"
    ).encode()
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = b"%PDF-1.4\n"
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output += f"{index} 0 obj\n".encode() + obj + b"\nendobj\n"
    start = len(output)
    output += b"xref\n0 6\n0000000000 65535 f \n"
    output += b"".join(f"{offset:010} 00000 n \n".encode() for offset in offsets[1:])
    output += f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode()
    ROOT.joinpath("juniper-ssr.pdf").write_bytes(output)


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    html(
        "cisco-php.html",
        """<h1>Synthetic PHP scope test</h1><h2>Summary</h2>
<p>CVE-2026-109618 CVE-2026-109619</p><p>First Published: 2026 October 21 19:12</p>
<h2>Affected Products</h2><h3>Products Under Investigation</h3><ul><li>Catalyst Center</li></ul>
<h3>Vulnerable Products</h3><table><tr><td>Ultra-Reliable Wireless Backhaul</td><td>27.1.1 (TBD)</td></tr></table>
<h3>Products Confirmed Not Vulnerable</h3><ul><li>IOS XE Software</li></ul>""",
    )
    html(
        "cisco-curl.html",
        """<h1>Synthetic curl scope test</h1><h2>Summary</h2>
<p>This advisory covers CVE-2023-38545 only. Background: CVE-2023-38546.</p>
<h2>Affected Products</h2><h3>Vulnerable Products</h3><ul><li>Example Cisco appliance</li></ul>""",
    )
    html(
        "arista-log4shell.html",
        """<h1>Security Advisory synthetic Log4Shell case</h1>
<p>Date: May 20, 2022</p><h2>Vulnerability Assessment</h2>
<p>The following products are affected by CVE-2021-44228.</p><ul>
<li>CloudVision Portal<ul><li>2019.1.0 to 2021.2.1</li></ul></li></ul>
<p>The following products are affected by CVE-2021-4104.</p><ul><li>Example logging product</li></ul>
<p>These products are NOT affected.</p><ul><li>Arista EOS-based products</li></ul>
<h2>Revision history</h2><table><tr><td>1.0</td><td>December 12, 2021</td><td>Initial test revision</td></tr></table>""",
    )
    d = csaf("synthetic-arista-120", status="draft")
    d["product_tree"] = {
        "branches": [
            {
                "category": "product_family",
                "name": "Example platform",
                "branches": [
                    {
                        "category": "product_name",
                        "name": "Example router",
                        "product": {"name": "Example router 1", "product_id": "p1"},
                    }
                ],
            }
        ],
        "full_product_names": [
            {"product_id": "p2", "name": "Example switch 2"},
            {"product_id": "p3", "name": "Example router 3"},
        ],
    }
    d["vulnerabilities"] = [
        {"cve": "CVE-2025-12345", "product_status": {"known_affected": ["p1", "p2", "p3"]}}
    ]
    put("arista120.json", d)
    d = csaf("synthetic-aruba")
    d["product_tree"] = {
        "full_product_names": [{"product_id": "CPPM-6.14.1", "name": "Synthetic ClearPass case"}]
    }
    d["vulnerabilities"] = [
        {
            "cve": "CVE-2026-109618",
            "product_status": {"fixed": ["CPPM-6.14.1"]},
            "remediations": [
                {"category": "vendor_fix", "details": "Partial mitigation; full fix planned."}
            ],
        }
    ]
    put("aruba.json", d)
    put(
        "checkpoint-advisories.json",
        [
            {
                "id": 1,
                "skId": "sk182459",
                "summary": "Synthetic regreSSHion index",
                "cveId": "CVE-2024-6387",
                "products": [
                    {"name": "Example appliance", "version": "1.0", "affected": "Details in SK"},
                    {"name": "Example OS", "version": "2.0", "affected": "None"},
                ],
            }
        ],
    )
    put(
        "fortinet-php.json",
        csaf("synthetic-fortinet", "Synthetic CVE-2026-109618 CVE-2026-109619 discovery"),
    )
    html(
        "hpe-cray.html",
        "<h1>HPESBCR04733 Synthetic firmware timing case</h1><p>Release Date: 2024-11-06</p>"
        "<p>CVE-2024-6387</p><h2>SUPPORTED SOFTWARE VERSIONS*</h2>"
        + "".join(f"<p>Example compute product {i} - Prior to 1.9.5-39</p>" for i in range(7))
        + "<h2>BACKGROUND</h2><p>Synthetic background.</p><h2>RESOLUTION</h2><p>Upgrade test firmware (08/28/2024).</p><h2>HISTORY</h2>",
    )
    html(
        "hpe-document.raw",
        """<h1>HPESBNS04567 Synthetic curl case</h1><p>CVE-2023-38545 CVE-2023-38546</p>
<h2>SUPPORTED SOFTWARE VERSIONS*</h2><p>Example NonStop product - Prior to T1204L01^AAI</p>
<h2>BACKGROUND</h2><p>Synthetic background.</p><h2>RESOLUTION</h2><p>Apply the test update.</p><h2>HISTORY</h2>""",
    )
    html(
        "fortinac-release.html",
        """<h1>Synthetic release</h1><p>Applies to the FortiNAC-F product only</p>
<table><tr><td>1</td><td>FortiNAC F 7.4.1 is no longer vulnerable to CVE-2024-6387.</td></tr>
<tr><td>2</td><td>Other product CVE-2025-32728</td></tr></table>""",
    )
    pdf(
        [
            "Synthetic parser fixture",
            "Session Smart Router JSA103137",
            "C V E - 2023 -",
            "48795",
            "Product Status",
            "All versions before 6.2.10-lts and before 6.3.6-sts",
        ]
    )
    html(
        "arista-openssl.html",
        "<h1>Security Advisory synthetic OpenSSL case</h1><p>CVE-2022-3602 CVE-2022-3786</p>"
        "<h2>Vulnerability Assessment</h2><h4>Products NOT affected</h4><ul>"
        + "".join(f"<li>Example network product {i}</li>" for i in range(11))
        + "</ul>",
    )
    html(
        "arista-openssh.html",
        """<h1>Security Advisory synthetic OpenSSH case</h1>
<h2>Vulnerability Assessment</h2><p>The following products are affected by CVE-2024-6387.</p><ul>
<li>Example EOS<ul><li>4.30.0F</li></ul></li><li>Example agent</li><li>Example manager</li></ul>
<p>The following products are affected by CVE-2025-12345.</p><ul><li>Example EOS new branch<ul><li>4.34.0F</li></ul></li></ul>
<p>Products NOT affected</p><ul><li>Example legacy product</li></ul>""",
    )
    html(
        "pan-oss.html",
        """<h1>OSS CVEs Fixed in PAN-OS</h1><table>
<tr><td>CVE-2024-1086</td><td>fixed in PAN-OS 10.2.11</td></tr>
<tr><td>CVE-2023-38546</td><td>fixed in PAN-OS 11.1.1</td></tr></table>""",
    )
    for name, product, version in [
        ("fortiproxy-728.html", "FortiProxy", "7.2.8"),
        ("fortios-727.html", "FortiOS", "7.2.7"),
    ]:
        html(
            name,
            f"<h1>Synthetic release</h1><h2>Common Vulnerabilities and Exposures</h2><p>{product} {version} is no longer vulnerable</p>"
            "<table><tr><td>1</td><td>CVE-2023-38545</td></tr><tr><td>2</td><td>CVE-2023-38546</td></tr></table>",
        )
    html(
        "pan-impact-2024.html",
        """<h1>Impact of OSS CVEs in PAN-OS</h1>
<p>PAN-OS does not offer any scenarios required for an attacker to successfully exploit these vulnerabilities and is not impacted.</p>
<table><tr><td>CVE-2022-0847</td><td>Test restriction: shell access is disabled.</td></tr></table>""",
    )
    article(
        "checkpoint-regresshion.html",
        "sk182459",
        """<p>Quantum Spark appliances that run the R81.10.x versions are vulnerable to CVE-2024-6387.</p>
<p>Quantum Spark appliances that run the versions R80.20.x or lower are not vulnerable to CVE-2024-6387.</p>
<p>Gaia OS versions (on all Check Point appliances and servers other than Quantum Spark) are not vulnerable to CVE-2024-6387.</p>
<p>R81.10.10 Build 996002993</p><p>14 July 2024 First release of this article</p><p>Background CVE-2006-5051 CVE-2024-24919</p>""",
    )
    article(
        "checkpoint-terrapin.html",
        "sk181833",
        "<p>This problem was fixed. The fix is included starting from: Check Point R82</p>",
    )
    html(
        "arista-0200.html",
        """<h1>Security Advisory synthetic service case</h1><p>CVE-2026-109618 CVE-2026-109619</p>
<h2>Affected Software</h2><p>No Arista software products are presently impacted by these vulnerabilities.</p>
<p>CloudVision CUE cloud service delivery and Arista Edge Threat Management were impacted but have already been upgraded to unaffected PHP versions with correct patches.</p>
<h2>History</h2><table><tr><td>1.0</td><td>October 23, 2026</td><td>Initial test revision</td></tr></table>""",
    )
    html(
        "arista-0201.html",
        """<h1>Security Advisory synthetic heading case</h1><p>The CVE-ID tracking this issue: CVE-2026-111943</p>
<h2>Affected Software</h2><div>EOS Versions:</div><ul><li>4.36.3M</li></ul>
<div>Streaming Telemetry Agent Versions:</div><ul><li>v1.46.2</li></ul><h2>History</h2>""",
    )
    put(
        "pan-cna.json",
        {
            "cveMetadata": {"cveId": "CVE-2026-109618"},
            "containers": {
                "cna": {
                    "title": "Synthetic version and score scenarios",
                    "affected": [
                        {
                            "vendor": "Example",
                            "product": "Example default",
                            "versions": [{"version": "1", "status": "unaffected"}],
                        },
                        {
                            "vendor": "Example",
                            "product": "PAN-OS",
                            "versions": [
                                {"version": "12.2.0", "lessThan": "12.2.4-h1", "status": "affected"}
                            ],
                        },
                        {
                            "vendor": "Example",
                            "product": "Panorama",
                            "defaultStatus": "unaffected",
                            "versions": [{"version": "1", "status": "affected"}],
                        },
                    ],
                    "metrics": [
                        {
                            "cvssV3_1": {"baseScore": score},
                            "scenarios": [{"lang": "en", "value": f"Synthetic scenario {i}"}],
                        }
                        for i, score in enumerate([8.7, 7.1, 9.2])
                    ],
                }
            },
        },
    )
    # Original-capture manifests are retained privately, not carried into releases.
    for name in [
        "expanded-manifest.json",
        "backfill-manifest.json",
        "arista-current-manifest.json",
    ]:
        ROOT.joinpath(name).unlink(missing_ok=True)
    put(
        "manifest.json",
        [
            {
                "file": p.name,
                "kind": "synthetic",
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }
            for p in sorted(ROOT.iterdir())
            if p.name not in ("manifest.json", "README.md") and p.is_file()
        ],
    )


if __name__ == "__main__":
    main()
