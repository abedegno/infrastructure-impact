"""Prepare a separate catalogue candidate and pending-review report from cached evidence."""

from collections import defaultdict
from copy import deepcopy
from datetime import UTC, datetime

from ..collection.reliability_refresh import SOURCES
from ..release_catalogue_cli import read_json
from ..settings import PACKAGE
from .release_catalogue import catalogue_summary, validate_catalogue
from .release_reliability import build_report


def _receipt(source_id, digest, capture):
    source = SOURCES[source_id]
    return {
        "source_id": f"{source_id}-{digest}",
        "vendor": source["vendor"],
        "source_url": source["url"],
        "retrieved_at": capture["retrieved_at"],
        "capture_kind": "original_document",
        "original_sha256": digest,
        "excerpt_sha256": None,
    }


def _fact(observation, receipt):
    cisco = receipt["vendor"] == "cisco"
    return {
        "vendor": receipt["vendor"],
        "family": "IOS XE" if cisco else "EOS",
        "train": "17.12" if cisco else "4.33",
        "version": observation.version,
        "observation_basis": "version_table" if cisco else "availability_announcement",
        "release_date": None,
        "date_status": "unknown",
        "announcement_date": observation.announcement_date,
        "platforms_stated": list(observation.models),
        "evidence": [
            {
                "source_id": receipt["source_id"],
                "locator": observation.locator,
                "quote": observation.quote,
            }
        ],
    }


def _identity(fact):
    return fact["vendor"], fact["family"], fact["train"], fact["version"]


def _fact_fields(fact):
    return fact["release_date"], fact["announcement_date"], tuple(sorted(fact["platforms_stated"]))


def _independent_cisco_models(previous, fact, source_url, sources):
    """Each exact Cisco chapter contributes its own documented family scope."""
    if fact["vendor"] != "cisco":
        return False
    scopes = {tuple(previous["platforms_stated"]), tuple(fact["platforms_stated"])}
    return scopes == {("Catalyst 9200",), ("Catalyst 9300",)} and all(
        sources[evidence["source_id"]]["source_url"] != source_url
        for evidence in previous["evidence"]
    )


def _differences(previous, fact):
    fields = []
    if set(previous["platforms_stated"]) != set(fact["platforms_stated"]):
        fields.append("platforms_stated")
    for name in ("announcement_date", "release_date"):
        if previous[name] and fact[name] and previous[name] != fact[name]:
            fields.append(name)
    return fields


def _already_stated(previous, fact):
    return set(previous["platforms_stated"]) == set(fact["platforms_stated"]) and all(
        value is None or previous[field] == value
        for field, value in (
            ("announcement_date", fact["announcement_date"]),
            ("release_date", fact["release_date"]),
        )
    )


def _remember_source(candidate, sources, receipt):
    key = receipt["source_id"]
    if key in sources:
        if sources[key] != receipt:
            raise ValueError("Candidate source ID collides with another source receipt")
        return
    sources[key] = receipt
    candidate["sources"].append(receipt)
    retrieved = datetime.fromisoformat(receipt["retrieved_at"])
    generated = datetime.fromisoformat(candidate["generated_at"].upper())
    if retrieved > generated or retrieved.date().isoformat() > candidate["generated_at"][:10]:
        candidate["generated_at"] = max(retrieved, generated).astimezone(UTC).isoformat()


def _record_conflict(review, receipt, proposed, previous, fields, sources):
    receipts = {
        evidence["source_id"]: sources[evidence["source_id"]] for evidence in previous["evidence"]
    }
    review["conflicts"].append(
        {
            "status": "pending",
            "fields": fields,
            "prior": previous,
            "prior_receipts": list(receipts.values()),
            "proposed": proposed,
            "proposed_receipt": receipt,
        }
    )


def _merge_capture(candidate, review, sources, versions, receipt, observations):
    by_version = defaultdict(dict)
    for observation in observations:
        fact = _fact(observation, receipt)
        by_version[_identity(fact)].setdefault(_fact_fields(fact), fact)

    for identity, facts in by_version.items():
        facts = list(facts.values())
        if len(facts) > 1:
            # A single revision offers inconsistent statements for one identity.
            # No row gets priority based on its document position.
            capture_sources = sources | {receipt["source_id"]: receipt}
            for index, proposed in enumerate(facts):
                alternative = facts[0 if index else 1]
                _record_conflict(
                    review,
                    receipt,
                    proposed,
                    alternative,
                    _differences(alternative, proposed),
                    capture_sources,
                )
            continue
        fact = facts[0]
        existing = [
            previous
            for previous in versions[identity]
            if not _independent_cisco_models(previous, fact, receipt["source_url"], sources)
        ]
        differences = [(previous, _differences(previous, fact)) for previous in existing]
        conflicts = [(previous, fields) for previous, fields in differences if fields]
        if conflicts:
            for previous, fields in conflicts:
                _record_conflict(review, receipt, fact, previous, fields, sources)
            continue
        if any(_already_stated(previous, fact) for previous in existing):
            continue
        _remember_source(candidate, sources, receipt)
        candidate["releases"].append(fact)
        versions[identity].append(fact)


def prepare(cache, baseline):
    """Return validated data and a separate report. Replays never write the baseline."""
    candidate = deepcopy(validate_catalogue(baseline))
    sources = {source["source_id"]: source for source in candidate["sources"]}
    versions = defaultdict(list)
    for fact in candidate["releases"]:
        versions[_identity(fact)].append(fact)
    review = {
        "schema_version": 1,
        "review_status": candidate["review_status"],
        "sources": {},
        "observations": {},
        "conflicts": [],
    }
    for source_id, (state, captures) in cache.observations().items():
        review["sources"][source_id] = {
            key: value for key, value in state.items() if key != "validators"
        }
        review["observations"][source_id] = []
        processed = set()
        previous = set()
        for revision in state["revisions"]:
            digest = revision["sha256"]
            observations = captures[digest]
            current = {observation.version for observation in observations}
            review["observations"][source_id].append(
                {
                    "sha256": digest,
                    "added_versions": sorted(current - previous),
                    "omitted_versions": sorted(previous - current),
                    "pub_dates": [
                        {
                            "version": item.version,
                            "locator": item.locator,
                            "pub_date": item.pub_date,
                        }
                        for item in observations
                        if item.pub_date is not None
                    ],
                }
            )
            previous = current
            if digest not in processed:
                receipt = _receipt(source_id, digest, state["captures"][digest])
                _merge_capture(candidate, review, sources, versions, receipt, observations)
                processed.add(digest)

    config = read_json(PACKAGE / "resources/release-catalogue-trains.json")
    review["summary"] = catalogue_summary(candidate, config)
    preview = build_report(
        catalogue=candidate, config=config, publication=None, generated_at=candidate["generated_at"]
    )
    review["candidate_sha256"] = preview["catalogue_sha256"]
    review["respins"] = preview["respins"]
    return candidate, review
