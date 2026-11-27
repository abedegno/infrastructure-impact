"""Dated publisher releases and explicit actions; no rates or automatic review."""

import json
import re
from collections import defaultdict
from copy import deepcopy
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
        "csaf.arubanetworking.hpe.com",
    },
    "arista": {"www.arista.com", "arista.com"},
}
RESPIN_RULES = {"cisco": "letter_suffix", "aruba": "non_decadal_build", "arista": "subrelease"}
RESPIN_IDENTITY = "vendor_train_previous_followup"


def _reason(proofs):
    kinds = {p["reason"] for p in proofs}
    return "both" if len(kinds) == 2 else next(iter(kinds), "unknown")


def _union(values):
    result = []
    for value in values:
        if value not in result:
            result.append(deepcopy(value))
    return result


def _literal_named(version, evidence):
    return any(
        version in re.findall(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*", e["quote"]) for e in evidence
    )


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
    identities = set()
    flattened = []
    for row in value["releases"]:
        key = (row["vendor"], row["train"], row["version"])
        if value.get("release_identity") and key in identities:
            raise ValueError("Duplicate release identity")
        identities.add(key)
        observations = row.get("observations")
        if observations:
            if any((o["vendor"], o["train"], o["version"]) != key for o in observations):
                raise ValueError("Release observation identity differs")
            if _merge_release(observations) != row:
                raise ValueError("Release observation union differs")
            flattened.extend(observations)
        else:
            flattened.append(row)
    if any("observations" in row for row in value["releases"]):
        legacy = {**value, "releases": flattened}
        legacy.pop("release_identity", None)
        validate_catalogue(legacy)
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
                proofs = fact.get("build_reason_evidence", [])
                if ("build_reason" in fact or proofs) and fact.get("build_reason") != _reason(
                    proofs
                ):
                    raise ValueError("Build reason differs from its source proofs")
                for proof in proofs:
                    if not all(
                        e["source_id"] in sources
                        and sources[e["source_id"]]["vendor"] == fact["vendor"]
                        for e in proof["evidence"]
                    ):
                        raise ValueError("Build reason source missing or cross-vendor")
                    if not _literal_named(fact["version"], proof["evidence"]):
                        raise ValueError("Build reason does not name the literal release")
                    if proof["reason"] == "security_fix" and not proof["advisory_id"]:
                        raise ValueError("Security build reason requires an advisory identifier")
                    if proof["reason"] == "defect_fix":
                        predecessor = proof["predecessor"]
                        if (
                            not predecessor
                            or predecessor == fact["version"]
                            or _version_key(fact["vendor"], predecessor)[:2]
                            != _version_key(fact["vendor"], fact["version"])[:2]
                            or _version_key(fact["vendor"], predecessor)
                            >= _version_key(fact["vendor"], fact["version"])
                            or not _literal_named(predecessor, proof["evidence"])
                        ):
                            raise ValueError("Defect build reason requires its stated predecessor")
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


def _merge_release(rows):
    """Union identity records without transferring dates or eligibility across scopes."""
    observations = []
    for row in rows:
        for observation in row.get("observations", [row]):
            if observation not in observations:
                observations.append(deepcopy(observation))
    merged = deepcopy(observations[0])
    if any(row["family"] != merged["family"] for row in observations):
        raise ValueError("Conflicting release family")
    merged["platforms_stated"] = sorted(
        {p for row in observations for p in row["platforms_stated"]}
    )
    merged["evidence"] = []
    for row in observations:
        for reference in row["evidence"]:
            if reference not in merged["evidence"]:
                merged["evidence"].append(deepcopy(reference))
    for field in ("release_date", "announcement_date"):
        dates = {row[field] for row in observations}
        merged[field] = dates.pop() if len(dates) == 1 else None
    merged["date_status"] = "stated" if merged["release_date"] else "unknown"
    if len({row.get("observation_basis") for row in observations}) > 1:
        merged.pop("observation_basis", None)
    if any("build_reason" in row for row in observations):
        merged["build_reason_evidence"] = _union(
            p for row in observations for p in row.get("build_reason_evidence", [])
        )
        merged["build_reason"] = _reason(merged["build_reason_evidence"])
    if len(observations) > 1:
        merged["observations"] = observations
    return merged


def deduplicate_releases(value):
    """Return one record per vendor/train/version; preserve the input and all observations."""
    legacy = deepcopy(value)
    legacy.pop("release_identity", None)
    validate_catalogue(legacy)
    groups = defaultdict(list)
    for row in legacy["releases"]:
        groups[row["vendor"], row["train"], row["version"]].append(row)
    result = {
        **legacy,
        "release_identity": "vendor_train_version",
        "releases": [_merge_release(rows) for rows in groups.values()],
    }
    return validate_catalogue(result)


def validate_config(config):
    if set(config) != {"schema_version", "start", "end", "trains"} or config["schema_version"] != 1:
        raise ValueError("Invalid catalogue configuration")
    start, end = date.fromisoformat(config["start"]), date.fromisoformat(config["end"])
    if start > end or end.year - start.year > 20 or not isinstance(config["trains"], list):
        raise ValueError("Invalid catalogue period")
    seen = set()
    for row in config["trains"]:
        if set(row) - {"respin_rule"} != {
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
        if "respin_rule" in row and row["respin_rule"] != RESPIN_RULES[row["vendor"]]:
            raise ValueError("Invalid vendor respin rule")
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
        for record in value["releases"]
        for r in record.get("observations", [record])
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


def _regular(vendor, version):
    parts = _version_key(vendor, version)
    if vendor == "aruba":
        return parts[2] % 10 == 0
    return parts[3] == 0


def find_respins(value, config):
    """Configured rebuilds use a regular predecessor; legacy reports remain readable.

    Missing or undated anchors remain explicit candidates with unknown intervals.
    They never enter 30/90-day numerators or establish withdrawal evidence.
    """
    validate_catalogue(value)
    validate_config(config)
    sources = {s["source_id"]: s for s in value["sources"]}
    result = {}
    for train in config["trains"]:
        corrected = "respin_rule" in train
        groups = defaultdict(dict)
        captures = defaultdict(list)
        for row in _releases(value, train):
            match = re.fullmatch(train["base_pattern"], row["version"])
            if not match or (not corrected and not row["release_date"]):
                continue
            base = match.expand(train["base_replacement"])
            for platform in sorted(_scope(row, train)):
                key = (base, platform)
                captures[key].append(row)
                # Duplicate source rows do not create extra releases.
                existing = groups[key].get(row["version"])
                if (
                    existing is None
                    or (
                        corrected
                        and (bool(row["release_date"]), _original(row, sources))
                        > (bool(existing["release_date"]), _original(existing, sources))
                    )
                    or (
                        not corrected
                        and _original(row, sources)
                        and not _original(existing, sources)
                    )
                ):
                    groups[key][row["version"]] = row
        for (base, platform), versions in groups.items():
            ordered = sorted(
                (r for r in versions.values() if r["release_date"]),
                key=lambda r: (r["release_date"], _version_key(train["vendor"], r["version"])),
            )
            # Ordering is validated independently of candidate selection and interval.
            for previous, current in pairwise(ordered):
                if corrected and _version_key(train["vendor"], current["version"]) <= _version_key(
                    train["vendor"], previous["version"]
                ):
                    raise ValueError("Release dates are not monotonic within a maintenance line")
            candidates = list(pairwise(ordered))
            if corrected:
                candidates = []
                by_version = sorted(
                    versions.values(), key=lambda r: _version_key(train["vendor"], r["version"])
                )
                for current in by_version:
                    if _regular(train["vendor"], current["version"]):
                        continue
                    preceding = [
                        r
                        for r in by_version
                        if _regular(train["vendor"], r["version"])
                        and _version_key(train["vendor"], r["version"])
                        < _version_key(train["vendor"], current["version"])
                    ]
                    candidates.append((preceding[-1] if preceding else None, current))
            for previous, current in candidates:
                if current["release_date"] is not None and not config["start"] <= current[
                    "release_date"
                ] <= min(config["end"], value["generated_at"][:10]):
                    continue
                if not corrected and _version_key(
                    train["vendor"], current["version"]
                ) <= _version_key(train["vendor"], previous["version"]):
                    raise ValueError("Release dates are not monotonic within a maintenance line")
                days = (
                    (
                        date.fromisoformat(current["release_date"])
                        - date.fromisoformat(previous["release_date"])
                    ).days
                    if previous and previous["release_date"] and current["release_date"]
                    else None
                )
                if days is not None and not 0 <= days <= 90:
                    continue
                identity = (
                    train["vendor"],
                    train["train"],
                    previous["version"] if previous else None,
                    current["version"],
                )
                evidence = [*(previous["evidence"] if previous else []), *current["evidence"]]
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
                        "previous_release": previous["version"] if previous else None,
                        "followup_release": current["version"],
                        "previous_release_date": previous["release_date"] if previous else None,
                        "followup_release_date": current["release_date"],
                        "days": days,
                        "within_30_days": days <= 30 if days is not None else None,
                        "within_90_days": True if days is not None else None,
                        "classification": classification,
                        "reason": explicit[0]["evidence"][0]["quote"] if explicit else None,
                        "platforms_stated": [],
                        "production_eligible": previous is not None
                        and days is not None
                        and _original(previous, sources)
                        and _original(current, sources)
                        and all(_original(s, sources) for s in explicit),
                        "evidence": evidence,
                    },
                )
                if value.get("respin_identity"):
                    row["timing_evidence"] = deepcopy(row["evidence"])
                    row["release_observations"] = _union(
                        r
                        for r in captures[base, platform]
                        if r["version"]
                        in {previous["version"] if previous else None, current["version"]}
                    )
                    row["evidence"] = _union(
                        [
                            *row["evidence"],
                            *(e for r in row["release_observations"] for e in r["evidence"]),
                        ]
                    )
                if corrected:
                    row["respin_rule"] = train["respin_rule"]
                    if train["vendor"] == "aruba":
                        build = _version_key("aruba", current["version"])[2]
                        expected = f"{train['train']}.{build - build % 10:04d}"
                        row["expected_regular_build"] = expected
                        row["expected_regular_build_absent"] = expected not in versions
                row["platforms_stated"].append(platform)
    rows = list(result.values())
    return (
        _deduplicate_respins(rows, value)
        if value.get("respin_identity") == RESPIN_IDENTITY
        else rows
    )


def _deduplicate_respins(rows, catalogue):
    """Unique public pairs preserve every scoped observation and unresolved anchor."""
    groups = defaultdict(list)
    for row in rows:
        groups[row["vendor"], row["train"], row["followup_release"]].append(row)
    release_groups = defaultdict(list)
    for r in catalogue["releases"]:
        release_groups[r["vendor"], r["train"], r["version"]].append(r)
    releases = {key: _merge_release(facts) for key, facts in release_groups.items()}
    result = []
    for identity, observations in groups.items():
        predecessors = list(dict.fromkeys(o["previous_release"] for o in observations))
        resolved = [p for p in predecessors if p is not None]
        for predecessor in resolved or [None]:
            scoped = _union(o for o in observations if o["previous_release"] in {predecessor, None})
            anchors = [o for o in scoped if o["previous_release"] == predecessor]
            row = deepcopy(anchors[0])
            row["platforms_stated"] = sorted({p for o in scoped for p in o["platforms_stated"]})
            row["evidence"] = _union(e for o in scoped for e in o["evidence"])
            for key in ("timing_evidence", "release_observations"):
                row[key] = _union(item for o in scoped for item in o.get(key, []))
            for field in (
                "previous_release_date",
                "followup_release_date",
                "days",
                "within_30_days",
                "within_90_days",
                "reason",
            ):
                values = {o[field] for o in scoped}
                row[field] = values.pop() if len(values) == 1 else None
            row["classification"] = (
                "corrective_respin"
                if all(o["classification"] == "corrective_respin" for o in scoped)
                else "possible_respin"
            )
            row["production_eligible"] = all(o["production_eligible"] for o in scoped)
            if "expected_regular_build_absent" in row:
                row["expected_regular_build_absent"] = any(
                    o["expected_regular_build_absent"] for o in scoped
                )
            release = releases[identity]
            row["build_reason"] = release.get("build_reason", "unknown")
            row["build_reason_evidence"] = deepcopy(release.get("build_reason_evidence", []))
            row["observations"] = scoped
            result.append(row)
    return result
