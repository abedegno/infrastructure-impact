"""Dated publisher releases and explicit actions; no rates or automatic review."""

import json
import re
from collections import defaultdict
from datetime import date, datetime
from functools import cache
from itertools import pairwise
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..settings import PACKAGE

CAVEAT = (
    "Counts describe disclosure and collection, not vendor quality. "
    "Missing evidence is unknown, never zero. Independent human review pending."
)
_HOSTS = {
    "cisco": {"www.cisco.com", "cisco.com"},
    "aruba": {
        "arubanetworking.hpe.com",
        "www.hpe.com",
        "hpe.com",
        "arubanetworks.com",
        "www.arubanetworks.com",
        "support.hpe.com",
    },
    "arista": {"www.arista.com", "arista.com"},
}


def _version_key(vendor, literal):
    patterns = {
        "cisco": r"([0-9]+)\.([0-9]+)\.([0-9]+)([a-z]?)",
        "aruba": r"([0-9]+)\.([0-9]+)\.([0-9]{4})",
        "arista": r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.([0-9]+))?([FM])",
    }
    match = re.fullmatch(patterns[vendor], literal)
    if not match:
        raise ValueError("Unsupported release identity or special train")
    if vendor == "cisco":
        return (*map(int, match.group(1, 2, 3)), ord(match[4]) - 96 if match[4] else 0)
    if vendor == "arista":
        return (*map(int, match.group(1, 2, 3)), int(match[4] or 0))
    return tuple(map(int, match.groups()))


@cache
def _validator():
    schema = json.loads((PACKAGE / "schemas/release-catalogue-v1.json").read_text())
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _official_url(url, vendor):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in _HOSTS[vendor]
        or parsed.netloc != parsed.hostname
        or parsed.fragment
        or "\\" in url
        or any(c.isspace() or ord(c) < 32 for c in url)
    ):
        raise ValueError("Catalogue requires an anonymous official HTTPS source URL")


def validate_catalogue(value):
    """Fail closed on missing provenance, inconsistent identities and future facts."""
    try:
        _validator().validate(value)
    except ValidationError as error:
        raise ValueError("Invalid release catalogue: " + error.message) from error
    generated = datetime.fromisoformat(value["generated_at"].upper())
    if generated.tzinfo is None:
        raise ValueError("Catalogue timestamp requires timezone")
    sources = {}
    for source in value["sources"]:
        key = source["source_id"]
        if key in sources:
            raise ValueError("Duplicate source identity")
        _official_url(source["source_url"], source["vendor"])
        literal = source["retrieved_at"]
        retrieved = datetime.fromisoformat(literal.upper()) if len(literal) != 10 else None
        if (
            retrieved is not None and (retrieved.tzinfo is None or retrieved > generated)
        ) or literal[:10] > generated.date().isoformat():
            raise ValueError("Invalid source receipt time")
        original = source["capture_kind"] == "original_document"
        if original != bool(source["original_sha256"]) or (
            not original and not source["excerpt_sha256"]
        ):
            raise ValueError("Capture kind conflicts with original/excerpt fingerprint")
        sources[key] = source
    dates = {}
    for section in ("releases", "notices", "statements"):
        for fact in value[section]:
            receipts = []
            for reference in fact["evidence"]:
                source = sources.get(reference["source_id"])
                if source is None or source["vendor"] != fact["vendor"]:
                    raise ValueError("Missing or cross-vendor source receipt")
                receipts.append(source["retrieved_at"][:10])
            for field in (
                "release_date",
                "announcement_date",
                "notice_date",
                "action_date",
                "revision_date",
            ):
                if fact.get(field) and fact[field] > min(receipts):
                    raise ValueError("Fact date is later than its source receipt")
            versions = [fact["version"]] if "version" in fact else fact["affected_releases"]
            for version in versions:
                parts = _version_key(fact["vendor"], version)
                if f"{parts[0]}.{parts[1]}" != fact["train"]:
                    raise ValueError("Release identity conflicts with declared train")
            for fixed in fact.get("fixed_releases", []):
                if not set(fixed["platforms_stated"]) <= set(fact["platforms_stated"]):
                    raise ValueError("Fixed-release scope exceeds stated notice models")
                parts = _version_key(fact["vendor"], fixed["version"])
                if f"{parts[0]}.{parts[1]}" != fact["train"]:
                    raise ValueError("Fixed release conflicts with declared train")
            if section == "releases":
                if (fact["date_status"] == "stated") != bool(fact["release_date"]):
                    raise ValueError("Release date status conflicts with release date")
                if fact["release_date"]:
                    for platform in fact["platforms_stated"] or [None]:
                        key = (fact["vendor"], fact["train"], fact["version"], platform)
                        previous = dates.setdefault(key, fact["release_date"])
                        if previous != fact["release_date"]:
                            raise ValueError("Conflicting release dates for stated platform")
            if section == "statements" and fact["status"] == "corrective_respin":
                if not fact["related_release"] or fact["related_release"] == fact["version"]:
                    raise ValueError("Corrective respin requires a distinct related release")
    coverage_ids = set()
    for row in value["coverage"]:
        key = (row["vendor"], row["train"], row["year"])
        if key in coverage_ids:
            raise ValueError("Duplicate coverage judgement")
        coverage_ids.add(key)
        if any(
            k not in sources or sources[k]["vendor"] != row["vendor"] for k in row["source_ids"]
        ):
            raise ValueError("Coverage source missing or cross-vendor")
    return value


def validate_config(config):
    if set(config) != {"schema_version", "start", "end", "trains"} or config["schema_version"] != 1:
        raise ValueError("Invalid catalogue configuration")
    start, end = date.fromisoformat(config["start"]), date.fromisoformat(config["end"])
    if start > end or end.year - start.year > 20 or not isinstance(config["trains"], list):
        raise ValueError("Invalid catalogue period")
    seen = set()
    for row in config["trains"]:
        if set(row) != {
            "vendor",
            "family",
            "train",
            "platforms",
            "base_pattern",
            "base_replacement",
        }:
            raise ValueError("Invalid configured train")
        key = (row["vendor"], row["train"])
        if row["vendor"] not in _HOSTS or key in seen or not row["platforms"]:
            raise ValueError("Invalid or duplicate configured train")
        seen.add(key)
        re.compile(row["base_pattern"])
    return config


def _original(fact, sources):
    return all(
        sources[r["source_id"]]["capture_kind"] == "original_document" for r in fact["evidence"]
    )


def _scope(fact, train):
    return set(fact["platforms_stated"]) & set(train["platforms"])


def _releases(value, train):
    return [
        r
        for r in value["releases"]
        if (r["vendor"], r["family"], r["train"])
        == (train["vendor"], train["family"], train["train"])
    ]


def catalogue_summary(value, config):
    """Observed counts have explicit eligibility; a missing denominator stays null."""
    validate_catalogue(value)
    validate_config(config)
    sources = {s["source_id"]: s for s in value["sources"]}
    coverage = {(c["vendor"], c["train"], c["year"]): c for c in value["coverage"]}
    annual, undated = [], []
    as_of = value["generated_at"][:10]
    for train in config["trains"]:
        releases = _releases(value, train)
        undated.append(
            {
                "vendor": train["vendor"],
                "train": train["train"],
                "versions": sorted({r["version"] for r in releases if not r["release_date"]}),
                "model_unresolved_versions": sorted(
                    {r["version"] for r in releases if not _scope(r, train)}
                ),
            }
        )
        for year in range(int(config["start"][:4]), int(config["end"][:4]) + 1):
            start = max(config["start"], f"{year}-01-01")
            end = min(config["end"], f"{year}-12-31", as_of)
            judgement = coverage.get((train["vendor"], train["train"], year))
            status = judgement["status"] if judgement and start <= end else "unknown"
            dated = [r for r in releases if r["release_date"] and start <= r["release_date"] <= end]
            eligible = {r["version"] for r in dated if _original(r, sources) and _scope(r, train)}
            research = {r["version"] for r in dated if not _original(r, sources)}
            denominator = None
            if status == "complete":
                if (
                    start > end
                    or not judgement["enumeration_complete"]
                    or not judgement["date_coverage_complete"]
                    or not set(train["platforms"]) <= set(judgement["platforms"])
                    or not judgement["source_ids"]
                    or any(
                        sources[k]["capture_kind"] != "original_document"
                        for k in judgement["source_ids"]
                    )
                    or any(
                        not r["release_date"]
                        or (
                            start <= r["release_date"] <= end
                            and (not _original(r, sources) or not _scope(r, train))
                        )
                        for r in releases
                    )
                ):
                    raise ValueError("Cannot establish complete dated original release coverage")
                denominator = len(eligible)
            annual.append(
                {
                    "vendor": train["vendor"],
                    "train": train["train"],
                    "year": year,
                    "period_start": start,
                    "period_end": end if start <= end else None,
                    "year_to_date": end < f"{year}-12-31",
                    "observed_dated_releases": len(eligible)
                    if eligible
                    else (0 if status == "complete" else None),
                    "research_dated_releases": len(research) if research else None,
                    "denominator": denominator,
                    "coverage": status,
                    "coverage_reason": judgement["reason"]
                    if judgement
                    else "No reviewed enumeration and date coverage judgement",
                }
            )
    return {
        "schema_version": 1,
        "generated_at": value["generated_at"],
        "caveat": CAVEAT,
        "review_status": value["review_status"],
        "annual": annual,
        "undated": undated,
    }


def find_respins(value, config):
    """Nearest same-base predecessor per stated model, bounded to 90 release-date days."""
    validate_catalogue(value)
    validate_config(config)
    sources = {s["source_id"]: s for s in value["sources"]}
    result = {}
    for train in config["trains"]:
        groups = defaultdict(dict)
        for row in _releases(value, train):
            match = re.fullmatch(train["base_pattern"], row["version"])
            if not match or not row["release_date"]:
                continue
            base = match.expand(train["base_replacement"])
            for platform in sorted(_scope(row, train)):
                key = (base, platform)
                # Duplicate source rows do not create extra releases.
                existing = groups[key].get(row["version"])
                if existing is None or (
                    _original(row, sources) and not _original(existing, sources)
                ):
                    groups[key][row["version"]] = row
        for (base, platform), versions in groups.items():
            ordered = sorted(
                versions.values(),
                key=lambda r: (r["release_date"], _version_key(train["vendor"], r["version"])),
            )
            for previous, current in pairwise(ordered):
                if (
                    not config["start"]
                    <= current["release_date"]
                    <= min(config["end"], value["generated_at"][:10])
                ):
                    continue
                days = (
                    date.fromisoformat(current["release_date"])
                    - date.fromisoformat(previous["release_date"])
                ).days
                if _version_key(train["vendor"], current["version"]) <= _version_key(
                    train["vendor"], previous["version"]
                ):
                    raise ValueError("Release dates are not monotonic within a maintenance line")
                if not 0 <= days <= 90:
                    continue
                identity = (
                    train["vendor"],
                    train["train"],
                    previous["version"],
                    current["version"],
                )
                evidence = [*previous["evidence"], *current["evidence"]]
                explicit = [
                    s
                    for s in value["statements"]
                    if s["status"] == "corrective_respin"
                    and s["family"] == train["family"]
                    and (s["vendor"], s["train"], s["version"], s["related_release"]) == identity
                    and platform in s["platforms_stated"]
                ]
                classification = "corrective_respin" if explicit else "possible_respin"
                if explicit:
                    evidence.extend(e for s in explicit for e in s["evidence"])
                row = result.setdefault(
                    (*identity, platform),
                    {
                        "vendor": train["vendor"],
                        "train": train["train"],
                        "base_version": base,
                        "previous_release": previous["version"],
                        "followup_release": current["version"],
                        "previous_release_date": previous["release_date"],
                        "followup_release_date": current["release_date"],
                        "days": days,
                        "within_30_days": days <= 30,
                        "within_90_days": True,
                        "classification": classification,
                        "reason": explicit[0]["evidence"][0]["quote"] if explicit else None,
                        "platforms_stated": [],
                        "production_eligible": _original(previous, sources)
                        and _original(current, sources)
                        and all(_original(s, sources) for s in explicit),
                        "evidence": evidence,
                    },
                )
                row["platforms_stated"].append(platform)
    return list(result.values())
