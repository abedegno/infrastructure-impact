"""Pure disclosure-era counts over native selected affected ownership evidence.

Neither row CVE/advisory set intersections nor release-event dates prove an
advisory/CVE publication pair. Claim IDs resolve against the same generation.
"""

import json
from collections import Counter
from copy import deepcopy

from jsonschema import Draft202012Validator, FormatChecker

from ..adapters.cisco_disclosure import initial_day
from ..domain import validate_advisory
from ..settings import PACKAGE
from . import switching_comparison as comparison
from . import switching_evidence as contracts

VERSION = "selected-owned-disclosure-v1"
POLICY_URL = "https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure"
LIMITATIONS = [
    "Counts describe disclosure and scrutiny, not security quality or underlying bug counts.",
    "July date eras are independent of the unchanged 7 April study windows.",
    "Dates and advisory types do not attribute an individual CVE to AI or a disclosure programme.",
    "Unknown method, missing metadata and unavailable bundle proof are not negative findings.",
    "Source-specific severity facets are nonadditive and retain publisher score provenance.",
    "Human extraction review remains pending.",
    "Method counts use source-owned advisory/CVE pairs; shared CVEs make era and year totals nonadditive.",
]


def _period(literal):
    day = comparison.day(literal)
    return "unknown" if day is None else "pre_july" if day < "2026-07-01" else "from_july"


def _key(c):
    return (
        c["vendor"],
        c["family"],
        c["advisory_id"],
        c["cve_id"],
        c["source"]["source_url"],
        c["source"]["source_sha256"],
    )


def _source_key(r):
    return (r["vendor"], r["advisory_id"], r["source_url"], r["sha256"])


def _summary(pairs):
    advisory_ids = sorted({(p["vendor"], p["advisory_id"]) for p in pairs})
    cves = sorted({p["cve_id"] for p in pairs})
    umbrella = sorted({p["cve_id"] for p in pairs if p["umbrella"] is not None})
    methods = Counter(p["method"]["classification"] or "unknown" for p in pairs)
    facets = {}
    for p in pairs:
        for s in p["severity"] or [
            dict(version=None, provider=None, origin=None, preferred=None, band="Unknown")
        ]:
            k = (s["version"], s["provider"], s["origin"], s["preferred"], s["band"])
            facets.setdefault(k, set()).add(p["cve_id"])
    return dict(
        counts=dict(
            advisories=len(advisory_ids),
            cves=len(cves),
            owned_pairs=len({(p["vendor"], p["advisory_id"], p["cve_id"]) for p in pairs}),
            umbrella_cves=len(umbrella),
        ),
        advisory_ids=[dict(vendor=v, advisory_id=a) for v, a in advisory_ids],
        cve_ids=cves,
        umbrella_cve_ids=umbrella,
        method_counts=dict(sorted(methods.items())),
        severity=[
            dict(
                version=k[0],
                provider=k[1],
                origin=k[2],
                preferred=k[3],
                band=k[4],
                cve_ids=sorted(v),
                count=len(v),
            )
            for k, v in sorted(facets.items(), key=lambda item: contracts._json(list(item[0])))
        ],
    )


def _year_periods(pairs):
    years = sorted(
        {
            comparison.day(p["initial_published_at"])[:4]
            for p in pairs
            if comparison.day(p["initial_published_at"])
        }
    )
    return {
        year: {
            period: _summary(
                [
                    p
                    for p in pairs
                    if (comparison.day(p["initial_published_at"]) or "")[:4] == year
                    and p["date_period"] == period
                ]
            )
            for period in ("pre_july", "from_july", "unknown")
        }
        for year in years
    }


def severity_facets(claims):
    """Source-owned facets shared with compact delivery; no cross-claim score join."""
    severity = {}
    for v in claims:
        for s in v["scores"]:
            if s["scope"] == "cve_specific" and s["cve_id"] == v["cve_id"]:
                facet = dict(
                    version=s.get("version"),
                    provider=s.get("provider"),
                    origin=s.get("origin"),
                    preferred=s.get("preferred"),
                    band=comparison.severity_band(
                        s.get("version"),
                        s.get("value") if s.get("validation") != "incomplete" else None,
                    ),
                )
                severity[contracts._json(facet)] = facet
    return [severity[k] for k in sorted(severity)]


def build_report(
    records,
    study_selection,
    *,
    evidence,
    publication,
    generated_at,
    policy_source=None,
    bundle_history=None,
):
    return _build_report(
        records,
        study_selection,
        evidence=evidence,
        publication=publication,
        generated_at=generated_at,
        policy_source=policy_source,
        bundle_history=bundle_history,
    )


def _build_report(
    records,
    study_selection,
    *,
    evidence,
    publication,
    generated_at,
    policy_source=None,
    bundle_history=None,
    evidence_proof=None,
):
    """Consume normalized *current* records plus full native selected comparison.

    ``evidence`` must equal the selection's retained same-generation envelope.
    Optional ``bundle_history`` is a validated native release-history envelope;
    its upstream lineage is retained separately and never relabelled as this
    generation or as freshly captured vendor bytes. It cannot add affectedness.
    ``policy_source`` is a caller-verified {url, sha256, retrieved_at} receipt.
    """
    contracts._require_evidence(
        evidence, publication=publication, generated_at=generated_at, evidence_proof=evidence_proof
    )
    validate = (
        contracts.validate_comparison if evidence_proof is None else contracts._validate_comparison
    )
    proof_args = {} if evidence_proof is None else dict(evidence_proof=evidence_proof)
    validate(study_selection, publication=publication, generated_at=generated_at, **proof_args)
    if (
        study_selection["inputs"] is None
        or study_selection["inputs"]["evidence"] != evidence
        or evidence["definition_sha256"] != study_selection["selection"]["definition_sha256"]
    ):
        raise ValueError("Disclosure selection evidence identity mismatch")
    if policy_source is not None:
        import re
        from datetime import datetime

        if (
            set(policy_source) != {"url", "sha256", "retrieved_at"}
            or policy_source["url"] != POLICY_URL
            or not re.fullmatch("[0-9a-f]{64}", policy_source["sha256"])
            or not datetime.fromisoformat(
                policy_source["retrieved_at"].replace("Z", "+00:00")
            ).tzinfo
        ):
            raise ValueError("Disclosure policy receipt invalid")
    record_index = {}
    for r in records:
        validate_advisory(r)
        k = _source_key(r)
        if k in record_index and record_index[k] != r:
            raise ValueError("Conflicting disclosure records for exact source")
        record_index[k] = r
    selected_ids = {cid for row in study_selection["rows"] for cid in row["claim_ids"]}
    selected = [
        c
        for c in evidence["claims"]
        if c["claim_id"] in selected_ids
        and comparison._explicit(c)
        and (c["publisher"]["status"] or "").lower() != "draft"
    ]
    groups = {}
    for c in selected:
        groups.setdefault(_key(c), []).append(c)
    facts, pairs, bundles = {}, [], []
    for key, claims in sorted(groups.items()):
        c = claims[0]
        dates = {v["initial_published_at"] for v in claims}
        if len(dates) != 1:
            raise ValueError("Disclosure source-owned initial dates conflict")
        literal = c["initial_published_at"]
        r = record_index.get((key[0], key[2], key[4], key[5]))
        meta, fact_id = None, None
        missing = []
        if r is None:
            missing.append("current_record_unavailable")
        else:
            if c["cve_id"] not in r["cves"] or literal != r["published_at"]:
                raise ValueError("Disclosure claim record ownership mismatch")
            meta = r.get("disclosure_metadata")
            if meta:
                fact_id = contracts.definition_sha256(
                    dict(vendor=key[0], advisory_id=key[2], source_url=key[4], source_sha256=key[5])
                )
                facts[fact_id] = dict(
                    id=fact_id,
                    vendor=r["vendor"],
                    advisory_id=r["advisory_id"],
                    source=dict(
                        source_url=r["source_url"],
                        source_sha256=r["sha256"],
                        retrieved_at=r["source_observed_at"],
                        source_locator="advisory",
                    ),
                    metadata=deepcopy(meta),
                )
            else:
                missing.append("disclosure_metadata_unavailable")
        umbrella = (
            next((deepcopy(u) for u in meta["umbrella_cves"] if u["cve_id"] == c["cve_id"]), None)
            if meta
            else None
        )
        method = (
            deepcopy(meta["method"])
            if meta
            else dict(classification=None, basis="unknown", locator=None)
        )
        severity = severity_facets(claims)
        if not initial_day(literal):
            missing.append("publisher_initial_date_unavailable")
        if not meta or meta["bundle"] is None:
            missing.append("explicit_bundle_unavailable")
        pairs.append(
            dict(
                vendor=c["vendor"],
                family=c["family"],
                advisory_id=c["advisory_id"],
                cve_id=c["cve_id"],
                initial_published_at=literal,
                original_published_at=(
                    r.get("publisher_chronology", {}).get("original_published_at", literal)
                    if r
                    else c.get("initial_date_provenance", {}).get("original_published_at", literal)
                ),
                date_period=_period(literal),
                date_precision=(
                    meta["date_precision"]
                    if meta
                    else "day"
                    if literal and len(literal) == 10
                    else "timestamp"
                    if initial_day(literal)
                    else "unknown"
                ),
                method=method,
                umbrella=umbrella,
                fact_id=fact_id,
                claim_ids=sorted(v["claim_id"] for v in claims),
                product_ids=sorted(
                    {v["product_id"] for v in claims if v["product_id"] is not None}
                ),
                models=sorted(
                    {
                        b["model"]
                        for v in claims
                        for b in v["platform_bindings"]
                        if b["model"] is not None
                    }
                ),
                source=deepcopy(c["source"]),
                severity=severity,
                missing=missing,
            )
        )
    for f in facts.values():
        b = f["metadata"]["bundle"]
        if b:
            members = [p for p in pairs if p["fact_id"] == f["id"] and p["cve_id"] in b["cve_ids"]]
            bundles.append(
                dict(
                    kind="security_hardening",
                    vendor=f["vendor"],
                    family=members[0]["family"],
                    publisher_id=b["id"],
                    initial_published_at=b["initial_published_at"],
                    date_period=_period(b["initial_published_at"]),
                    member_advisory_ids=b["advisory_ids"],
                    member_cve_ids=b["cve_ids"],
                    selected_advisory_ids=sorted({p["advisory_id"] for p in members}),
                    selected_cve_ids=sorted({p["cve_id"] for p in members}),
                    source=deepcopy(f["source"]),
                    upstream=None,
                )
            )
    for c in selected:
        b = c["bundle"]
        if b is None:
            continue
        members = [
            p
            for p in pairs
            if p["vendor"] == c["vendor"]
            and p["family"] == c["family"]
            and p["advisory_id"] in b["member_advisory_ids"]
        ]
        value = dict(
            kind="explicit_publisher_bundle",
            vendor=c["vendor"],
            family=c["family"],
            publisher_id=b["publisher_id"],
            initial_published_at=b["published_at"],
            date_period=_period(b["published_at"]),
            member_advisory_ids=deepcopy(b["member_advisory_ids"]),
            member_cve_ids=[],
            selected_advisory_ids=sorted({p["advisory_id"] for p in members}),
            selected_cve_ids=sorted({p["cve_id"] for p in members}),
            source=deepcopy(b["source"]),
            upstream=None,
        )
        if value not in bundles:
            bundles.append(value)
    if bundle_history is not None:
        from .switching_releases import validate_report as validate_history

        validate_history(bundle_history)
        for b in bundle_history["bundles"]:
            members = [
                p
                for p in pairs
                if p["vendor"] == b["vendor"]
                and p["family"] == b["family"]
                and p["advisory_id"] in b["member_advisory_ids"]
            ]
            if not members:
                continue
            bundles.append(
                dict(
                    kind="explicit_publisher_bundle",
                    vendor=b["vendor"],
                    family=b["family"],
                    publisher_id=b["publisher_id"],
                    initial_published_at=b["initial_published_at"],
                    date_period=_period(b["initial_published_at"]),
                    member_advisory_ids=deepcopy(b["member_advisory_ids"]),
                    member_cve_ids=[],
                    selected_advisory_ids=sorted({p["advisory_id"] for p in members}),
                    selected_cve_ids=sorted({p["cve_id"] for p in members}),
                    source=deepcopy(b["source"]),
                    upstream=dict(
                        publication=deepcopy(bundle_history["publication"]),
                        generated_at=bundle_history["generated_at"],
                        definition_sha256=bundle_history["definition_sha256"],
                    ),
                )
            )
    # Bundle proof may come from the accepted native claim parser or a retained
    # primary-source history, independently of document disclosure metadata.
    for p in pairs:
        if any(
            p["vendor"] == b["vendor"]
            and p["family"] == b["family"]
            and p["advisory_id"] in b["selected_advisory_ids"]
            and p["cve_id"] in b["selected_cve_ids"]
            for b in bundles
        ):
            p["missing"] = [m for m in p["missing"] if m != "explicit_bundle_unavailable"]
    unique = {}
    for b in bundles:
        key = contracts._json({k: v for k, v in b.items() if k != "upstream"})
        if key not in unique or b["upstream"] is not None:
            unique[key] = b
    bundles = list(unique.values())
    result = dict(
        schema_version=1,
        method_version=VERSION,
        publication=deepcopy(publication),
        generated_at=generated_at,
        definition_sha256=evidence["definition_sha256"],
        selection=deepcopy(study_selection["selection"]),
        observation_end=study_selection["observation_end"],
        policy_source=deepcopy(policy_source),
        pairs=pairs,
        advisory_facts=list(facts.values()),
        bundles=bundles,
        periods={
            period: _summary([p for p in pairs if p["date_period"] == period])
            for period in ("pre_july", "from_july", "unknown")
        },
        years={
            year: _summary(
                [
                    p
                    for p in pairs
                    if (comparison.day(p["initial_published_at"]) or "unknown")[:4] == year
                ]
            )
            for year in sorted(
                {
                    comparison.day(p["initial_published_at"])[:4]
                    for p in pairs
                    if comparison.day(p["initial_published_at"])
                }
            )
        },
        year_periods=_year_periods(pairs),
        coverage=dict(
            selected_affected_claims=len(selected),
            owned_source_pairs=len(pairs),
            metadata_advisories=len(facts),
            missing_counts=dict(sorted(Counter(m for p in pairs for m in p["missing"]).items())),
            unsupported_advisory_types=sorted(
                {
                    f["metadata"]["advisory_type"]
                    for f in facts.values()
                    if f["metadata"]["advisory_type"] == "unknown"
                }
            ),
        ),
        limitations=LIMITATIONS.copy(),
    )

    validate_report(result)
    return result


_SCHEMA = json.loads((PACKAGE / "schemas/switching-disclosure-v1.json").read_text())
_VALIDATOR = Draft202012Validator(_SCHEMA, format_checker=FormatChecker())


def validate_report(report):
    """Closed DTO plus recomputable era, identity and distinct-count invariants."""
    contracts._json(report)
    _VALIDATOR.validate(report)
    if report["selection"]["definition_sha256"] != report["definition_sha256"]:
        raise ValueError("Disclosure definition identity mismatch")
    facts = {f["id"]: f for f in report["advisory_facts"]}
    if len(facts) != len(report["advisory_facts"]):
        raise ValueError("Duplicate disclosure facts")
    seen = set()
    claim_ids = set()
    for p in report["pairs"]:
        k = _key(p)
        if k in seen or p["date_period"] != _period(p["initial_published_at"]):
            raise ValueError("Disclosure pair identity or era mismatch")
        seen.add(k)
        if not p["claim_ids"] or claim_ids.intersection(p["claim_ids"]):
            raise ValueError("Disclosure claim identity mismatch")
        claim_ids.update(p["claim_ids"])
        f = facts.get(p["fact_id"])
        if p["fact_id"] is not None:
            if (
                f is None
                or f["vendor"] != p["vendor"]
                or f["advisory_id"] != p["advisory_id"]
                or any(f["source"][k] != p["source"][k] for k in ("source_url", "source_sha256"))
                or f["metadata"]["initial_published_at"] != p["initial_published_at"]
                or f["metadata"]["method"] != p["method"]
            ):
                raise ValueError("Disclosure fact ownership mismatch")
        owned = (
            next((u for u in f["metadata"]["umbrella_cves"] if u["cve_id"] == p["cve_id"]), None)
            if f
            else None
        )
        if owned != p["umbrella"]:
            raise ValueError("Disclosure umbrella ownership mismatch")
    expected_periods = {
        period: _summary([p for p in report["pairs"] if p["date_period"] == period])
        for period in ("pre_july", "from_july", "unknown")
    }
    expected_years = {
        year: _summary(
            [
                p
                for p in report["pairs"]
                if (comparison.day(p["initial_published_at"]) or "unknown")[:4] == year
            ]
        )
        for year in sorted(
            {
                comparison.day(p["initial_published_at"])[:4]
                for p in report["pairs"]
                if comparison.day(p["initial_published_at"])
            }
        )
    }
    if (
        report["periods"] != expected_periods
        or report["years"] != expected_years
        or report["year_periods"] != _year_periods(report["pairs"])
    ):
        raise ValueError("Disclosure distinct counts mismatch")
    if (
        report["coverage"]["selected_affected_claims"] != len(claim_ids)
        or report["coverage"]["owned_source_pairs"] != len(seen)
        or report["coverage"]["metadata_advisories"] != len(facts)
        or report["coverage"]["missing_counts"]
        != dict(sorted(Counter(m for p in report["pairs"] for m in p["missing"]).items()))
    ):
        raise ValueError("Disclosure coverage mismatch")
    for b in report["bundles"]:
        members = [
            p
            for p in report["pairs"]
            if p["vendor"] == b["vendor"]
            and p["family"] == b["family"]
            and p["advisory_id"] in b["member_advisory_ids"]
        ]
        if b["selected_advisory_ids"] != sorted({p["advisory_id"] for p in members}) or b[
            "selected_cve_ids"
        ] != sorted({p["cve_id"] for p in members}):
            raise ValueError("Disclosure selected bundle members mismatch")
        if b["kind"] == "security_hardening":
            owners = [
                f
                for f in facts.values()
                if f["vendor"] == b["vendor"]
                and f["advisory_id"] == b["publisher_id"]
                and f["source"] == b["source"]
            ]
            if (
                len(owners) != 1
                or owners[0]["metadata"]["bundle"] is None
                or b["initial_published_at"]
                != owners[0]["metadata"]["bundle"]["initial_published_at"]
                or b["member_advisory_ids"] != owners[0]["metadata"]["bundle"]["advisory_ids"]
                or b["member_cve_ids"] != owners[0]["metadata"]["bundle"]["cve_ids"]
            ):
                raise ValueError("Disclosure hardening bundle ownership mismatch")
        if b["date_period"] != _period(b["initial_published_at"]) or not set(
            b["selected_advisory_ids"]
        ).issubset(b["member_advisory_ids"]):
            raise ValueError("Disclosure bundle membership or date mismatch")
