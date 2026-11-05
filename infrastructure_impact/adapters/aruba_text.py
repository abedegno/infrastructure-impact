"""Reviewed 2021 Aruba signed-text layouts; framing is not signature verification.

All three public entry points re-read source bytes. Literal family/platform prose
does not identify exact study models or publisher product IDs.
"""

import re
from datetime import datetime
from hashlib import sha256

from .common import assessment, base, cves

DIRECTORY = "https://csaf.arubanetworking.hpe.com/2021/"
FORMAT = "Aruba reviewed 2021 signed text"
SECTIONS = (
    "Title",
    "Overview",
    "Affected Products",
    "Unaffected Products",
    "Details",
    "Resolution",
    "Workaround",
    "Exploitation and Public Discussion",
    "Revision History",
    "Aruba SIRT Security Procedures",
)


def _flat(text):
    return " ".join(text.split())


def _date(text):
    for fmt in ("%Y-%B-%d", "%Y-%b-%d"):
        try:
            return datetime.strptime(text or "", fmt).date().isoformat()
        except ValueError:
            pass
    return None


def _read(raw, url, vendor):
    route = re.fullmatch(re.escape(DIRECTORY) + r"hpe_aruba_networking_-_(2021-\d{3})\.txt", url)
    if vendor != "aruba" or not route:
        raise ValueError("Unreviewed Aruba text route")
    text = raw.decode("utf-8").replace("\r\n", "\n")
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"):
        raise ValueError("Expected Aruba signed-message framing")
    if text.count("-----BEGIN PGP SIGNATURE-----") != 1 or not text.rstrip().endswith(
        "-----END PGP SIGNATURE-----"
    ):
        raise ValueError("Incomplete Aruba signature framing")
    text = text.split("-----BEGIN PGP SIGNATURE-----")[0]
    # RFC 4880 cleartext dash escaping is removed for interpretation only.
    text = re.sub(r"(?m)^- ", "", text)
    headings = list(re.finditer(r"(?m)^([A-Za-z][A-Za-z ]+?)\s*\n={3,}\s*\n", text))
    names = [m[1].strip() for m in headings]
    expected = ["Aruba Product Security Advisory", *SECTIONS]
    if names != expected and names != [n for n in expected if n != "Workaround"]:
        raise ValueError("Unreviewed Aruba text sections")
    sections = {
        m[1].strip(): text[
            m.end() : headings[i + 1].start() if i + 1 < len(headings) else len(text)
        ].strip()
        for i, m in enumerate(headings)
    }
    header = sections.pop("Aruba Product Security Advisory")
    fields = {}
    key = None
    for line in header.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([A-Za-z ]+):\s*(.*)", line)
        if match:
            key = match[1]
            if key in fields:
                raise ValueError("Duplicate Aruba header")
            fields[key] = match[2]
        elif key == "CVE" and line[:1].isspace():
            fields[key] += " " + line.strip()
        else:
            raise ValueError("Unrecognized Aruba header continuation")
    if set(fields) - {
        "Advisory ID",
        "CVE",
        "Publication Date",
        "Last Update",
        "Status",
        "Severity",
        "Revision",
    }:
        raise ValueError("Unreviewed Aruba header")
    if fields.get("Advisory ID") != "ARUBA-PSA-" + route[1]:
        raise ValueError("Aruba source identity disagrees with route")
    ids = cves(fields.get("CVE", ""))
    if not ids or not re.fullmatch(
        r"CVE-\d{4}-\d{4,}(?:,\s*CVE-\d{4}-\d{4,})*", fields.get("CVE", "")
    ):
        raise ValueError("Aruba header CVE scope missing or ambiguous")
    if fields.get("Status") != "Confirmed" or not re.fullmatch(r"\d+", fields.get("Revision", "")):
        raise ValueError("Unreviewed Aruba revision/status")
    details = sections["Details"]
    starts = list(re.finditer(r"(?m)^[ \t]*[^\n]+\((CVE-\d{4}-\d{4,})\)\s*\n  -{4,}\s*\n", details))
    per_cve = {}
    for i, match in enumerate(starts):
        if match[1] in per_cve or match[1] not in ids:
            raise ValueError("Ambiguous Aruba CVE sections")
        per_cve[match[1]] = details[
            match.end() : starts[i + 1].start() if i + 1 < len(starts) else len(details)
        ].strip()
    if starts and set(per_cve) != set(ids):
        raise ValueError("Aruba CVE sections do not account for header scope")
    return fields, ids, sections, per_cve


def _interpret(raw, url, vendor):
    from .switching import _availability

    fields, ids, sections, per_cve = _read(raw, url, vendor)
    doc = base(
        vendor,
        url,
        fields["Advisory ID"],
        _flat(sections["Title"]),
        _date(fields.get("Publication Date")),
        _date(fields.get("Last Update")),
    )
    doc["source_format"] = FORMAT
    doc["document_status"] = "published"
    doc["cves"] = ids
    doc["warnings"].append("Signed-message framing retained; cryptographic signature not verified.")
    for field, value in (
        ("Publication Date", doc["published_at"]),
        ("Last Update", doc["updated_at"]),
    ):
        if not value:
            doc["warnings"].append(f"Publisher {field} unknown or absent.")
    for name in SECTIONS:
        if name in sections:
            doc["notes"].append(
                dict(category=name, text=sections[name], source_locator="text/" + name)
            )
    affected = sections["Affected Products"]
    family = re.fullmatch(
        r"(Aruba [0-9A-Za-z/]+ switch series and Aruba [0-9A-Za-z/]+ switch\s+series) "
        r"running the following version of the AOS-CX firmware:\s*\n(.+)",
        affected,
        re.S,
    )
    if family and per_cve:
        resolution = sections["Resolution"]
        if not (
            "that address multiple security vulnerabilities." in _flat(sections["Overview"])
            and "to address all of the vulnerabilities." in _flat(resolution)
            and resolution.startswith(
                "Upgrade AOS-CX devices to the following version based on your current version:"
            )
        ):
            raise ValueError("Aruba shared vulnerability scope not explicit")
        versions = [line.strip() for line in family[2].splitlines() if line.strip()]
        if not all(
            re.fullmatch(r"\d+\.\d+\.xxxx - versions prior to \d+\.\d+\.\d+", v) for v in versions
        ):
            raise ValueError("Unreviewed Aruba affected version layout")
        product = _flat(family[1])
        for cid in ids:
            rem = dict(
                category="vendor_fix",
                details=resolution,
                source_locator="text/Overview; text/Resolution",
                published_availability=sections["Overview"] + "\n" + resolution,
                availability=_availability(
                    sections["Overview"] + "\n" + resolution,
                    "vendor_fix",
                    None,
                    as_of=doc["updated_at"] or doc["published_at"],
                ),
            )
            # Upgrade guidance supplies fixed versions, not a public release date.
            a = assessment(
                cid,
                product,
                "affected",
                "text/Affected Products; text/Details/" + cid,
                versions=[dict(expression=v, status="affected") for v in versions],
                remediations=[rem],
                scope="bulletin_shared",
            )
            a["product_family"] = "AOS-CX"
            a["exposure"] = [dict(details=per_cve[cid], source_locator="text/Details/" + cid)]
            workaround = sections.get("Workaround", "")
            if workaround.startswith("For " + cid + ",") and cves(workaround) == [cid]:
                a["remediations"].append(
                    dict(
                        category="workaround",
                        details=workaround,
                        availability="not_a_fix",
                        source_locator="text/Workaround",
                    )
                )
            doc["assessments"].append(a)
    elif (
        not per_cve
        and "The conclusion of the investigation is that the products listed above under the Unaffected Products section are not vulnerable to these vulnerabilities."
        in _flat(sections["Details"])
    ):
        # Only the explicitly enumerated unaffected products are shared across
        # the header CVEs. Affected-product scope and generic others stay notes.
        blocks = re.split(r"\n[ \t]*\n", sections["Unaffected Products"])
        lines = blocks[0].splitlines()
        if not all(re.fullmatch(r"[ \t]*-- [^\n]+", line) for line in lines):
            raise ValueError("Unreviewed Aruba unaffected product continuation")
        rows = [line.strip()[3:] for line in lines]
        if not rows or "ArubaOS-CX Switches" not in rows:
            raise ValueError("Unreviewed Aruba unaffected product list")
        for row in rows:
            # Catch-all prose is retained in the section note, even when the
            # publisher formats it as a bullet beside literal product names.
            if re.search(r"\b(?:other|all|any|every)\b|\bnot listed\b", row, re.I):
                continue
            for cid in ids:
                a = assessment(
                    cid,
                    row,
                    "unaffected",
                    "text/Unaffected Products/" + row,
                    scope="bulletin_shared",
                )
                if row == "ArubaOS-CX Switches":
                    a["product_family"] = "AOS-CX"
                doc["assessments"].append(a)
    else:
        raise ValueError("Unreviewed Aruba product attribution layout")
    return doc, fields, sections, per_cve


def parse(raw: bytes, url: str, vendor: str) -> dict:
    return _interpret(raw, url, vendor)[0]


def research_evidence(raw: bytes, url: str, vendor: str, document: dict) -> dict:
    from .switching import _claim, _source

    parsed, fields, _, _ = _interpret(raw, url, vendor)
    if parsed["advisory_id"] != document.get("advisory_id"):
        raise ValueError("Aruba research identity changed")
    digest = sha256(raw).hexdigest()
    publisher = dict(
        id=fields["Advisory ID"],
        sequence=fields["Revision"],
        status=fields["Status"],
        source=_source(url, digest, "text/header"),
    )
    claims = []
    for a in parsed["assessments"]:
        claim = _claim(
            vendor,
            parsed,
            _source(url, digest, a["evidence_locator"]),
            publisher.copy(),
            parsed["published_at"],
            parsed["updated_at"],
        )
        claim.update(
            cve_id=a["cve_id"],
            product=a["product"],
            status=a["status"],
            scope=a["scope"],
            family="aruba-aoscx" if a.get("product_family") == "AOS-CX" else None,
            version_expressions=[v["expression"] for v in a["versions"]],
            conditions=[e["details"] for e in a["exposure"]],
        )
        for rem in a["remediations"]:
            claim["remediations"].append(
                dict(
                    publisher_id=None,
                    category=rem["category"],
                    details=rem["details"],
                    product_ids=[],
                    version_expressions=[],
                    published_availability=rem.get("published_availability", rem["details"]),
                    availability=rem["availability"],
                    availability_date=None,
                    source=_source(url, digest, rem["source_locator"]),
                )
            )
        claims.append(claim)
    return dict(schema_version=1, claims=claims, bundles=[], issues=[])


def metric_inputs(raw: bytes, url: str, vendor: str, document: dict) -> dict:
    parsed, fields, _, per_cve = _interpret(raw, url, vendor)
    if parsed["advisory_id"] != document.get("advisory_id"):
        raise ValueError("Aruba metric identity changed")
    result = dict(metrics=[], severity=[], issues=[])
    if fields.get("Severity"):
        result["severity"].append(
            dict(
                rating=fields["Severity"],
                source_locator="text/header/Severity",
                scheme=None,
                namespace=None,
            )
        )
    for cid, text in per_cve.items():
        scores = re.findall(r"(?m)^\s*CVSSv(\S+) Overall Score:\s*([^\n]+)", text)
        vectors = re.findall(r"(?m)^\s*CVSS Vector:\s*([^\n]+)", text)
        if not scores and not vectors:
            continue
        locator = "text/Details/" + cid + "/CVSS"
        if len(scores) > 1 or len(vectors) > 1:
            result["issues"].append(
                dict(
                    code="score_format_unsupported",
                    source_url=url,
                    source_locator=locator,
                    cve_id=cid,
                )
            )
            continue
        score = scores[0][1].strip() if scores else None
        try:
            score = float(score) if score is not None else None
        except ValueError:
            pass
        vector = vectors[0].strip() if vectors else None
        version = re.match(r"CVSS:(\d+\.\d+)/", vector or "")
        result["metrics"].append(
            dict(
                metric=dict(
                    version=version[1] if version else None, baseScore=score, vectorString=vector
                ),
                cve_id=cid,
                source_locator=locator,
                form="cvss_v3" if scores and scores[0][0] == "3" else "unsupported",
                context=[text],
            )
        )
    return result
