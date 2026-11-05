"""Allowlisted, attributed reported CVSS; structural checks are not rescoring.

Rules: FIRST CVSS v2/v3.0/v3.1 JSON schemas and v4 specification Table 23.
Reported base/vector numerical consistency remains explicitly unverified.
"""

import json
import math
import re
from hashlib import sha256
from urllib.parse import urlsplit

from ..source_policy import allowed

CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")
V2 = {
    "AV": "NAL",
    "AC": "HML",
    "Au": "MSN",
    "C": "NPC",
    "I": "NPC",
    "A": "NPC",
    "E": ("ND", "U", "POC", "F", "H"),
    "RL": ("ND", "OF", "TF", "W", "U"),
    "RC": ("ND", "UC", "UR", "C"),
    "CDP": ("ND", "N", "L", "LM", "MH", "H"),
    "TD": ("ND", "N", "L", "M", "H"),
    "CR": ("ND", "L", "M", "H"),
    "IR": ("ND", "L", "M", "H"),
    "AR": ("ND", "L", "M", "H"),
}
V3 = {
    "AV": "NALP",
    "AC": "LH",
    "PR": "NLH",
    "UI": "NR",
    "S": "UC",
    "C": "NLH",
    "I": "NLH",
    "A": "NLH",
    "E": "XUPFH",
    "RL": "XOTWU",
    "RC": "XURC",
    "CR": "XHML",
    "IR": "XHML",
    "AR": "XHML",
    "MAV": "XNALP",
    "MAC": "XLH",
    "MPR": "XNLH",
    "MUI": "XNR",
    "MS": "XUC",
    "MC": "XNLH",
    "MI": "XNLH",
    "MA": "XNLH",
}
V4 = {
    "AV": "NALP",
    "AC": "LH",
    "AT": "NP",
    "PR": "NLH",
    "UI": "NPA",
    "VC": "HLN",
    "VI": "HLN",
    "VA": "HLN",
    "SC": "HLN",
    "SI": "HLN",
    "SA": "HLN",
    "E": "XAPU",
    "CR": "XHML",
    "IR": "XHML",
    "AR": "XHML",
    "MAV": "XNALP",
    "MAC": "XLH",
    "MAT": "XNP",
    "MPR": "XNLH",
    "MUI": "XNPA",
    "MVC": "XNLH",
    "MVI": "XNLH",
    "MVA": "XNLH",
    "MSC": "XNLH",
    "MSI": "XNLHS",
    "MSA": "XNLHS",
    "S": "XNP",
    "AU": "XNY",
    "R": "XAUI",
    "V": "XDC",
    "RE": "XLMH",
    "U": ("X", "Clear", "Green", "Amber", "Red"),
}
FIELDS = {
    "AV": ("attackVector", "accessVector"),
    "AC": ("attackComplexity", "accessComplexity"),
    "Au": ("authentication",),
    "PR": ("privilegesRequired",),
    "UI": ("userInteraction",),
    "S": ("scope",),
    "C": ("confidentialityImpact",),
    "I": ("integrityImpact",),
    "A": ("availabilityImpact",),
    "AT": ("attackRequirements",),
    "VC": ("vulnConfidentialityImpact",),
    "VI": ("vulnIntegrityImpact",),
    "VA": ("vulnAvailabilityImpact",),
    "SC": ("subConfidentialityImpact",),
    "SI": ("subIntegrityImpact",),
    "SA": ("subAvailabilityImpact",),
}
NAMES = {
    "NETWORK": "N",
    "ADJACENT_NETWORK": "A",
    "ADJACENT": "A",
    "LOCAL": "L",
    "PHYSICAL": "P",
    "LOW": "L",
    "MEDIUM": "M",
    "HIGH": "H",
    "NONE": "N",
    "REQUIRED": "R",
    "PASSIVE": "P",
    "ACTIVE": "A",
    "PRESENT": "P",
    "UNCHANGED": "U",
    "CHANGED": "C",
    "PARTIAL": "P",
    "COMPLETE": "C",
    "SINGLE": "S",
    "MULTIPLE": "M",
}
PRIORITY = {"vendor_advisory": 0, "cve_record": 1, "nvd": 2}


OPTIONAL_FIELDS = {
    "E": ("exploitability", "exploitCodeMaturity", "exploitMaturity"),
    "RL": ("remediationLevel",),
    "RC": ("reportConfidence",),
    "CDP": ("collateralDamagePotential",),
    "TD": ("targetDistribution",),
    "CR": ("confidentialityRequirement",),
    "IR": ("integrityRequirement",),
    "AR": ("availabilityRequirement",),
    "AU": ("automatable",),
    "R": ("recovery",),
    "V": ("valueDensity",),
    "RE": ("vulnerabilityResponseEffort",),
    "U": ("providerUrgency",),
}
for _key, _fields in tuple(FIELDS.items()):
    OPTIONAL_FIELDS["M" + _key] = tuple(
        "modified" + field[0].upper() + field[1:] for field in _fields
    )
NAMES.update(
    {
        "NEGLIGIBLE": "N",
        "NOT_DEFINED": "X",
        "UNPROVEN": "U",
        "PROOF_OF_CONCEPT": "P",
        "FUNCTIONAL": "F",
        "OFFICIAL_FIX": "O",
        "TEMPORARY_FIX": "T",
        "WORKAROUND": "W",
        "UNAVAILABLE": "U",
        "UNKNOWN": "U",
        "REASONABLE": "R",
        "CONFIRMED": "C",
        "ATTACKED": "A",
        "UNREPORTED": "U",
        "SAFETY": "S",
        "NO": "N",
        "YES": "Y",
        "AUTOMATIC": "A",
        "USER": "U",
        "IRRECOVERABLE": "I",
        "DIFFUSE": "D",
        "CONCENTRATED": "C",
        "MODERATE": "M",
        "CLEAR": "Clear",
        "GREEN": "Green",
        "AMBER": "Amber",
        "RED": "Red",
    }
)


def _structured_value(value, version):
    if not isinstance(value, str):
        return None
    if version == "2.0":
        return {
            "NOT_DEFINED": "ND",
            "PROOF_OF_CONCEPT": "POC",
            "OFFICIAL_FIX": "OF",
            "TEMPORARY_FIX": "TF",
            "UNCONFIRMED": "UC",
            "UNCORROBORATED": "UR",
            "LOW_MEDIUM": "LM",
            "MEDIUM_HIGH": "MH",
        }.get(value, NAMES.get(value))
    return NAMES.get(value)


def _objects(value):
    return (
        [(i, item) for i, item in enumerate(value) if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _text(value):
    return value if type(value) is str and value.strip() and len(value) <= 4000 else None


def _strings(values):
    return list(dict.fromkeys(v for v in values if _text(v))) if isinstance(values, list) else []


def official_route(url, origin, cid):
    if not isinstance(url, str) or not CVE.fullmatch(cid or ""):
        return False
    expected = (
        "https://cveawg.mitre.org/api/cve/" + cid
        if origin == "cve_record"
        else "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cid
    )
    return origin in ("cve_record", "nvd") and url == expected


def _validate(metric):
    version, value, vector = (
        metric.get("version"),
        metric.get("baseScore"),
        metric.get("vectorString"),
    )
    issues = []
    if version not in ("2.0", "3.0", "3.1", "4.0"):
        issues.append("version_invalid")
    if value is None:
        issues.append("base_missing")
    elif (
        type(value) not in (int, float)
        or not 0 <= value <= 10
        or not math.isfinite(value)
        or round(value, 1) != value
    ):
        issues.append("base_invalid")
    if vector is None:
        issues.append("vector_missing")
    elif not isinstance(vector, str) or len(vector) > 2000:
        issues.append("vector_invalid")
    elif version in ("2.0", "3.0", "3.1", "4.0"):
        prefix = "" if version == "2.0" else "CVSS:" + version + "/"
        if prefix and not vector.startswith(prefix):
            issues.append("vector_version_disagreement")
        else:
            parts = vector[len(prefix) :].split("/")
            pairs = [p.split(":") for p in parts]
            rules = V2 if version == "2.0" else V4 if version == "4.0" else V3
            mandatory = list(rules)[: 6 if version == "2.0" else 11 if version == "4.0" else 8]
            if any(
                len(p) != 2 or p[0] not in rules or p[1] not in tuple(rules[p[0]]) for p in pairs
            ):
                issues.append("vector_invalid")
            else:
                keys = [p[0] for p in pairs]
                if len(keys) != len(set(keys)):
                    issues.append("vector_duplicate_metric")
                if not set(mandatory) <= set(keys):
                    issues.append("vector_base_metrics_missing")
                if version == "4.0" and keys != sorted(keys, key=list(rules).index):
                    issues.append("vector_order_invalid")
                structured = {**FIELDS, **OPTIONAL_FIELDS}
                if version == "4.0":
                    structured["S"] = ("safety",)
                supplied = dict(pairs)
                for key, fields in structured.items():
                    if key not in rules:
                        continue
                    literal = supplied.get(key, "ND" if version == "2.0" else "X")
                    for field in fields:
                        if field in metric and _structured_value(metric[field], version) != literal:
                            issues.append("structured_metric_disagreement")
    if (
        type(value) in (int, float)
        and 0 <= value <= 10
        and math.isfinite(value)
        and "baseSeverity" in metric
        and metric["baseSeverity"] != _band(version, value).upper()
    ):
        issues.append("base_severity_disagreement")

    state = (
        "invalid"
        if any(i not in ("base_missing", "vector_missing") for i in issues)
        else "incomplete"
        if issues
        else "valid"
    )
    if state == "valid":
        issues.append("consistency_not_verified")
    return state, sorted(set(issues))


def _band(version, value):
    if value is None:
        return None
    if version == "2.0":
        return "Low" if value < 4 else "Medium" if value < 7 else "High"
    return (
        "None"
        if value == 0
        else "Low"
        if value < 4
        else "Medium"
        if value < 7
        else "High"
        if value < 9
        else "Critical"
    )


def _vector_group(version, vector):
    if version != "4.0":
        return "reported_base_with_optional_context"
    pairs = dict(part.split(":", 1) for part in vector.split("/")[1:])
    threat = pairs.get("E", "X") != "X"
    environmental_keys = (
        "CR",
        "IR",
        "AR",
        "MAV",
        "MAC",
        "MAT",
        "MPR",
        "MUI",
        "MVC",
        "MVI",
        "MVA",
        "MSC",
        "MSI",
        "MSA",
    )
    environment = any(pairs.get(key, "X") != "X" for key in environmental_keys)
    return "CVSS-B" + ("T" if threat else "") + ("E" if environment else "")


def _form_versions(form):
    return {
        "cvss_v2": ("2.0",),
        "cvss_v3": ("3.0", "3.1"),
        "cvss_v4": ("4.0",),
        "cvssV2_0": ("2.0",),
        "cvssV3_0": ("3.0",),
        "cvssV3_1": ("3.1",),
        "cvssV4_0": ("4.0",),
        "cvssMetricV2": ("2.0",),
        "cvssMetricV30": ("3.0",),
        "cvssMetricV31": ("3.1",),
        "cvssMetricV40": ("4.0",),
    }[form]


def extract(raw: bytes, url: str, vendor: str, document: dict) -> dict:
    """Extract only source-structured metrics; never read normalized raw metrics."""
    result = {"claims": [], "issues": [], "vendor_severity": []}
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        result["issues"].append({"code": "score_format_unsupported", "source_url": url})
        return result
    if not isinstance(data, dict):
        return result
    digest = sha256(raw).hexdigest()
    product_context = {}

    def rating(value, locator, *, scheme=None, namespace=None):
        if not _text(value) or not _text(document.get("advisory_id")):
            return
        issues = []
        if not _text(scheme):
            issues.append("vendor_severity_scheme_missing")
        if not _text(namespace):
            issues.append("vendor_severity_namespace_missing")
        result["vendor_severity"].append(
            dict(
                vendor=vendor,
                advisory_id=document["advisory_id"],
                rating=value,
                scheme=_text(scheme),
                namespace=_text(namespace),
                scope="advisory",
                cve_id=None,
                product_ids=[],
                source=dict(
                    source_url=url, source_sha256=digest, retrieved_at=None, source_locator=locator
                ),
                revision=None,
                issues=issues,
            )
        )

    def add(metric, cid, products, provider, origin, locator, context=(), *, form):
        if not isinstance(metric, dict) or not CVE.fullmatch(cid or ""):
            return
        if origin == "vendor_advisory":
            if not allowed(url, vendor):
                return
        elif not official_route(url, origin, cid):
            return
        state, issues = _validate(metric)
        if metric.get("version") not in _form_versions(form):
            state = "invalid"
            issues.append("score_form_version_disagreement")
        value = metric.get("baseScore")
        if type(value) not in (int, float) or not 0 <= value <= 10 or not math.isfinite(value):
            value = None
        claim = dict(
            system="CVSS",
            version=_text(metric.get("version")),
            value=value,
            vector=_text(metric.get("vectorString")),
            severity=_band(metric.get("version"), value),
            cve_id=cid,
            product_ids=_strings(products),
            scope="cve_specific",
            source=dict(
                source_url=url, source_sha256=digest, retrieved_at=None, source_locator=locator
            ),
            provider=_text(provider),
            origin=origin,
            applicability="source_product"
            if origin == "vendor_advisory" and _strings(products)
            else "cve_level",
            revision=None,
            validation=state,
            issues=issues,
            context=_strings(list(context)),
            product_context=[
                product_context[p] for p in _strings(products) if p in product_context
            ],
        )
        result["claims"].append(claim)
        result["issues"].extend(
            {"code": i, "source_url": url, "source_locator": locator, "cve_id": cid} for i in issues
        )

    if "document" in data and isinstance(data.get("vulnerabilities"), list):
        from .standards import csaf_products

        aggregate = data["document"].get("aggregate_severity")
        if (
            isinstance(aggregate, dict)
            and data["document"].get("tracking", {}).get("id") == document.get("advisory_id")
            and allowed(url, vendor)
        ):
            rating(
                aggregate.get("text"),
                "/document/aggregate_severity",
                scheme=aggregate.get("scheme"),
                namespace=aggregate.get("namespace"),
            )
        products = csaf_products(data.get("product_tree", {}))
        for pid, p in products.items():
            product_context[pid] = dict(
                product_id=pid,
                product=_text(p["name"]),
                source_locator=p["locator"],
                version_expressions=_strings(
                    [
                        name
                        for category, name, *_ in p["ancestry"]
                        if category
                        in (
                            "product_version",
                            "product_version_range",
                            "service_pack",
                            "patch_level",
                        )
                    ]
                ),
                issues=_strings(p["issues"]),
            )
        provider = data["document"].get("publisher", {}).get("name") or vendor
        for i, v in _objects(data["vulnerabilities"]):
            for j, score in _objects(v.get("scores", [])):
                for key in ("cvss_v2", "cvss_v3", "cvss_v4"):
                    if key in score:
                        add(
                            score[key],
                            v.get("cve"),
                            score.get("products", []),
                            provider,
                            "vendor_advisory",
                            f"/vulnerabilities/{i}/scores/{j}/{key}",
                            [n.get("text") for n in v.get("notes", []) if isinstance(n, dict)],
                            form=key,
                        )
    elif (
        vendor == "cisco"
        and urlsplit(url).netloc == "apix.cisco.com"
        and urlsplit(url).scheme == "https"
        and urlsplit(url).path.startswith("/security/advisories/v2/")
        and not urlsplit(url).fragment
    ):
        rows = _objects(data.get("advisories")) if "advisories" in data else [(None, data)]
        for i, row in rows:
            if row.get("advisoryId") == document.get("advisory_id"):
                rating(
                    row.get("sir"),
                    "/sir" if i is None else f"/advisories/{i}/sir",
                    scheme="Cisco SIR",
                )
    elif (
        data.get("dataType") == "CVE_RECORD"
        and data.get("cveMetadata", {}).get("state") == "PUBLISHED"
    ):
        cid = data["cveMetadata"].get("cveId")
        containers = data.get("containers", {})
        for locator, container in [("/containers/cna", containers.get("cna", {}))] + [
            (f"/containers/adp/{i}", c) for i, c in enumerate(containers.get("adp", []))
        ]:
            provider = container.get("providerMetadata", {})
            for i, metric in _objects(container.get("metrics", [])):
                for key in ("cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0"):
                    if key in metric:
                        add(
                            metric[key],
                            cid,
                            [],
                            provider.get("shortName") or provider.get("orgId"),
                            "cve_record",
                            f"{locator}/metrics/{i}/{key}",
                            [
                                s.get("value")
                                for s in metric.get("scenarios", [])
                                if isinstance(s, dict)
                            ],
                            form=key,
                        )
    elif isinstance(data.get("vulnerabilities"), list):
        for i, item in _objects(data["vulnerabilities"]):
            c = item.get("cve", {})
            if c.get("vulnStatus") == "Rejected":
                continue
            for key in ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"):
                for j, metric in _objects(c.get("metrics", {}).get(key, [])):
                    add(
                        metric.get("cvssData"),
                        c.get("id"),
                        [],
                        metric.get("source"),
                        "nvd",
                        f"/vulnerabilities/{i}/cve/metrics/{key}/{j}/cvssData",
                        form=key,
                    )
    else:
        result["issues"].append({"code": "score_format_unsupported", "source_url": url})
    return result


def public_metrics(claims: list[dict]) -> list[dict]:
    """Revalidate and reconstruct typed fields; conflicts stay separate, never max()."""
    result = []
    for c in claims:
        if not isinstance(c, dict) or c.get("system") != "CVSS" or c.get("validation") != "valid":
            continue
        state, _ = _validate(
            {
                "version": c.get("version"),
                "baseScore": c.get("value"),
                "vectorString": c.get("vector"),
            }
        )
        source = c.get("source", {})
        origin = c.get("origin")
        if state != "valid" or origin not in PRIORITY or not CVE.fullmatch(c.get("cve_id") or ""):
            continue
        if not re.fullmatch("[a-f0-9]{64}", source.get("source_sha256", "")) or not _text(
            source.get("source_locator")
        ):
            continue
        url = source.get("source_url", "")
        u = urlsplit(url)
        if u.scheme != "https" or u.username or u.password or u.fragment:
            continue
        if origin != "vendor_advisory" and not official_route(url, origin, c["cve_id"]):
            continue
        if origin == "vendor_advisory":
            from ..plugins.registry import default_registry

            if not any(allowed(url, vendor) for vendor in default_registry().names()):
                continue
        product_ids = _strings(c.get("product_ids", []))
        product_ids_set = set(product_ids)
        result.append(
            dict(
                system="CVSS",
                version=c["version"],
                value=c["value"],
                vector=c["vector"],
                severity=_band(c["version"], c["value"]),
                cve_id=c["cve_id"],
                product_ids=product_ids,
                scope="cve_specific",
                source={
                    k: _text(source.get(k))
                    for k in ("source_url", "source_sha256", "retrieved_at", "source_locator")
                },
                provider=_text(c.get("provider")),
                origin=origin,
                applicability="source_product"
                if origin == "vendor_advisory" and product_ids
                else "cve_level",
                revision=_text(c.get("revision")),
                validation="valid",
                vector_group=_vector_group(c["version"], c["vector"]),
                issues=["consistency_not_verified"],
                context=_strings(c.get("context", [])),
                product_context=[
                    dict(
                        product_id=p["product_id"],
                        product=_text(p.get("product")),
                        source_locator=_text(p.get("source_locator")),
                        version_expressions=_strings(p.get("version_expressions", [])),
                        issues=_strings(p.get("issues", [])),
                    )
                    for p in c.get("product_context", [])
                    if isinstance(p, dict)
                    and isinstance(p.get("product_id"), str)
                    and p["product_id"] in product_ids_set
                ],
            )
        )

    def priority(claim):
        return (
            3
            if claim["origin"] == "vendor_advisory" and not claim["product_ids"]
            else PRIORITY[claim["origin"]]
        )

    for c in result:
        c["preferred"] = priority(c) == min(
            priority(d) for d in result if d["cve_id"] == c["cve_id"]
        )
    return list({json.dumps(c, sort_keys=True): c for c in result}.values())
