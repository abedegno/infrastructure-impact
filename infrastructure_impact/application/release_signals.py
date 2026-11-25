"""Release-signal observations with source receipts and conservative chronology."""

import csv
import json
from collections import defaultdict
from copy import deepcopy
from datetime import date, datetime
from functools import cache
from hashlib import sha256
from io import StringIO
from itertools import pairwise
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..collection.release_signals import ARISTA_URL
from ..settings import PACKAGE
from .software_versions import compare_releases, release_train, version_key

_HOSTS = {
    "cisco.com": "cisco",
    "www.cisco.com": "cisco",
    "arubanetworking.hpe.com": "aruba",
    "hpe.com": "aruba",
    "www.hpe.com": "aruba",
    "arubanetworks.com": "aruba",
    "www.arubanetworks.com": "aruba",
    "arista.com": "arista",
    "www.arista.com": "arista",
}
_MAX_CAPTURE_BYTES = 8 * 1024 * 1024
_MAX_DATASET_EVENTS = 20000
_MAX_WINDOW_YEARS = 100
_MAX_UPGRADE_BYTES = 32 * 1024 * 1024
_STUDY_TRAINS = {("cisco", "17.12"), ("aruba", "10.13"), ("arista", "4.33")}
_COUNT_FIELDS = {
    "release": "observed_releases",
    "withdrawn": "explicit_withdrawals",
    "deferred": "explicit_deferred",
    "corrective_respin": "confirmed_corrective_respins",
    "field_notice": "field_notices",
    "recommended": "recommendations",
}
_ANNUAL_IDENTITIES = {"release", "withdrawn", "deferred", "corrective_respin"}
_RELEASE_REQUIRED = {
    "release",
    "withdrawn",
    "deferred",
    "corrective_respin",
    "recommended",
    "bug_list",
}


@cache
def _validator(contract):
    path = PACKAGE / "schemas" / f"release-signals-{contract}-v1.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_shape(contract, value):
    try:
        _validator(contract).validate(value)
    except ValidationError as error:
        path = "/".join(map(str, error.absolute_path)) or "(root)"
        raise ValueError(f"Invalid release-signals {contract} field {path}") from error


def _digest(value):
    digest = sha256()
    encoder = json.JSONEncoder(
        ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    size = 0
    for chunk in encoder.iterencode(value):
        payload = chunk.encode("ascii")
        size += len(payload)
        if size > _MAX_UPGRADE_BYTES:
            raise ValueError("Release-signals JSON input exceeds digest size limit")
        digest.update(payload)
    return digest.hexdigest()


def _timestamp(value):
    return datetime.fromisoformat(value)


def _source_vendor(url):
    if "\\" in url or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("Release signals require an official HTTPS source URL")
    parsed = urlsplit(url)
    vendor = _HOSTS.get(parsed.hostname)
    if (
        parsed.scheme != "https"
        or vendor is None
        or parsed.netloc.lower() != parsed.hostname
        or parsed.fragment
    ):
        raise ValueError("Release signals require an official HTTPS source URL")
    return vendor


def _validate_event(event, vendor, retrieved):
    if event["vendor"] != vendor:
        raise ValueError("Release signal vendor differs from source vendor")
    if event["date"] is not None and date.fromisoformat(event["date"]) > retrieved.date():
        raise ValueError("Release signal date is later than its receipt")
    release, related = event["release"], event["related_release"]
    if event["kind"] in _RELEASE_REQUIRED and release is None:
        raise ValueError("Release signal requires a release identity")
    for literal in (release, related):
        actual_train = release_train(vendor, literal)
        if actual_train is not None and actual_train != event["train"]:
            raise ValueError("Release signal train conflicts with its release identity")
    if event["kind"] == "corrective_respin" and (related is None or related == release):
        raise ValueError("Corrective respin requires a distinct related release")
    if event["kind"] == "bug_list" and not event["bug_ids"]:
        raise ValueError("Bug disclosure requires a published bug ID")


def _check_coverage(rows):
    for coverage in rows:
        if coverage["start"] > coverage["end"]:
            raise ValueError("Invalid release-signals coverage interval")


def new_dataset(generated_at):
    return validate_dataset(
        dict(schema_version=1, generated_at=generated_at, documents=[], coverage=[])
    )


def _latest_documents(documents):
    return {document["source_url"]: document for document in documents}


def validate_dataset(dataset):
    _validate_shape("dataset", dataset)
    if sum(len(doc["events"]) for doc in dataset["documents"]) > _MAX_DATASET_EVENTS:
        raise ValueError("Too many release-signals dataset events")
    _check_coverage(dataset["coverage"])
    generated = _timestamp(dataset["generated_at"])
    latest = {}
    ids = set()
    for document in dataset["documents"]:
        revision = document["revision_id"]
        source = document["source_url"]
        vendor = _source_vendor(source)
        retrieved = _timestamp(document["retrieved_at"])
        previous = latest.get(source)
        if retrieved > generated:
            raise ValueError("Source receipt postdates dataset generation")
        if document["previous_revision_id"] != (previous["revision_id"] if previous else None):
            raise ValueError("Invalid release-signals revision chain")
        if previous and (
            retrieved < _timestamp(previous["retrieved_at"])
            or document["source_sha256"] == previous["source_sha256"]
        ):
            raise ValueError("Invalid release-signals revision ordering or duplicate bytes")
        if revision in ids or revision != _digest(
            {key: value for key, value in document.items() if key != "revision_id"}
        ):
            raise ValueError("Invalid release-signals revision digest")
        for event in document["events"]:
            _validate_event(event, vendor, retrieved)
        latest[source] = document
        ids.add(revision)
    return dataset


def add_document(dataset, raw, source_url, retrieved_at, events, *, capture_method="http_response"):
    """Append a validated receipt, returning its revision ID. Equal latest bytes reuse it."""
    validate_dataset(dataset)
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_CAPTURE_BYTES:
        raise ValueError("Release-signals source must be nonempty bounded bytes")
    if not isinstance(source_url, str) or not isinstance(retrieved_at, str):
        raise ValueError("Release-signals source URL and receipt timestamp must be strings")
    _source_vendor(source_url)
    try:
        _validator("dataset").evolve(
            schema=_validator("dataset").schema["$defs"]["timestamp"]
        ).validate(retrieved_at)
    except ValidationError as error:
        raise ValueError("Invalid release-signals retrieval timestamp") from error
    retrieved = _timestamp(retrieved_at)
    source_sha256 = sha256(raw).hexdigest()
    previous = _latest_documents(dataset["documents"]).get(source_url)
    if previous and retrieved < _timestamp(previous["retrieved_at"]):
        raise ValueError("Source receipt predates latest revision")
    document = dict(
        previous_revision_id=previous["revision_id"] if previous else None,
        source_url=source_url,
        source_sha256=source_sha256,
        retrieved_at=retrieved_at,
        capture_method=capture_method,
        events=events,
    )
    document["revision_id"] = _digest(document)
    updated = {
        **dataset,
        "generated_at": max(retrieved_at, dataset["generated_at"], key=_timestamp),
        "documents": [*dataset["documents"], document],
    }
    if previous and previous["source_sha256"] == source_sha256:
        dataset["generated_at"] = updated["generated_at"]
        return previous["revision_id"]
    validate_dataset(updated)
    dataset.update(
        generated_at=updated["generated_at"], documents=[*dataset["documents"], deepcopy(document)]
    )
    return document["revision_id"]


def _window(start, end):
    if not isinstance(start, str) or not isinstance(end, str):
        raise ValueError("Release-signals window needs ISO dates")
    try:
        first, last = date.fromisoformat(start), date.fromisoformat(end)
    except ValueError as error:
        raise ValueError("Release-signals window needs ISO dates") from error
    if (
        (first.isoformat(), last.isoformat()) != (start, end)
        or first > last
        or last.year - first.year >= _MAX_WINDOW_YEARS
    ):
        raise ValueError("Invalid release-signals report window")
    return first, last


def _is_rolling_announcement(source_url, event):
    return source_url == ARISTA_URL and event["kind"] == "release"


def _announcement_key(event):
    return (*_fact_key(event), tuple(sorted(event["platforms"])))


def _current_events(dataset):
    output = {}
    rolling = {}
    latest = _latest_documents(dataset["documents"])
    for document in dataset["documents"]:
        url = document["source_url"]
        receipt = {key: value for key, value in document.items() if key != "events"}
        announcements = defaultdict(dict)
        for event in document["events"]:
            announcement = _is_rolling_announcement(url, event)
            if not announcement and document is not latest[url]:
                continue
            source = {**receipt, "source_locator": event["source_locator"]}
            normalized = {**event, "source": source}
            event_id = _digest(normalized)
            retained = {**normalized, "event_id": event_id}
            if announcement:
                announcements[_announcement_key(event)][event_id] = retained
            else:
                output[event_id] = retained
        rolling.update(announcements)
    for events in rolling.values():
        output.update(events)
    return sorted(
        output.values(),
        key=lambda event: (
            event["vendor"],
            event["train"],
            event["date"] or "",
            event["kind"],
            event["release"] or "",
            event["event_id"],
        ),
    )


def _fact_key(event):
    kind = event["kind"]
    key = (event["vendor"], event["train"], event["release"], kind)
    if kind != "release":
        key += (event["related_release"], tuple(sorted(event["platforms"])))
    if kind == "field_notice":
        key += (" ".join(event["statement"].split()),)
    return key


def _fact_dates(events):
    result = defaultdict(set)
    for event in events:
        if event["date"]:
            result[_fact_key(event)].add(event["date"])
    return result


def _targets(event):
    if event["kind"] == "corrective_respin":
        return (event["release"], event["related_release"])
    return (event["release"],)


def _candidate_order(vendor, earlier, later):
    a, b = version_key(vendor, earlier), version_key(vendor, later)
    if a is None or b is None:
        return False
    if vendor == "arista":
        if a[-1] != b[-1]:
            return False
        # An explicitly numbered EOS follow-up can extend the exact preceding release literal.
        if len(a) == 4 and len(b) == 5:
            return a[:3] == b[:3] and b[3] > 0
    return compare_releases(vendor, earlier, later) == -1


def _candidates(events, fact_dates):
    announcements = defaultdict(dict)
    for event in events:
        if event["kind"] == "release" and event["date"]:
            cohort = (event["vendor"], event["train"])
            identity = (event["date"], event["release"], tuple(sorted(event["platforms"])))
            announcements[cohort].setdefault(identity, event)
    result = []
    for (vendor, train), entries in sorted(announcements.items()):
        dates = defaultdict(list)
        for (day, _, _), event in entries.items():
            dates[day].append(event)
        for earlier_day, later_day in pairwise(sorted(dates)):
            # Multiple distinct releases or scopes on a date obscure adjacency.
            if len(dates[earlier_day]) != 1 or len(dates[later_day]) != 1:
                continue
            earlier, later = dates[earlier_day][0], dates[later_day][0]
            a, b = earlier["release"], later["release"]
            days = (date.fromisoformat(later_day) - date.fromisoformat(earlier_day)).days
            if (
                days <= 30
                and set(earlier["platforms"]) == set(later["platforms"])
                and len(fact_dates[_fact_key(earlier)]) == len(fact_dates[_fact_key(later)]) == 1
                and _candidate_order(vendor, a, b)
            ):
                result.append(
                    dict(
                        vendor=vendor,
                        train=train,
                        earlier_release=a,
                        later_release=b,
                        earlier_date=earlier_day,
                        later_date=later_day,
                        calendar_days=days,
                        within_14_days=days <= 14,
                        within_30_days=True,
                        corrective_respin_confirmed=False,
                        event_ids=[earlier["event_id"], later["event_id"]],
                    )
                )
    return result


def _metrics(events, coverage, first, last, as_of, fact_dates):
    groups = defaultdict(list)
    for row in coverage:
        lower = max(first.year, int(row["start"][:4]))
        upper = min(last.year, int(row["end"][:4]))
        for year in range(lower, upper + 1):
            groups[row["vendor"], row["train"], year]
    # Conflicting dates within a year still support one annual observation.
    cross_year = {
        identity
        for identity, days in fact_dates.items()
        if identity[3] in _ANNUAL_IDENTITIES and len({day[:4] for day in days}) > 1
    }
    for event in events:
        if event["date"] is None or _fact_key(event) in cross_year:
            continue
        year = int(event["date"][:4])
        groups[event["vendor"], event["train"], year].append(event)
    result = []
    for (vendor, train, year), facts in sorted(groups.items()):
        counts = defaultdict(set)
        for event in facts:
            kind = event["kind"]
            if kind in _COUNT_FIELDS:
                identity = _fact_key(event)
                if kind not in _ANNUAL_IDENTITIES:
                    identity += (event["date"],)
                counts[_COUNT_FIELDS[kind]].add(identity)
            counts["published_bug_ids"].update(event["bug_ids"])
        result.append(
            dict(
                vendor=vendor,
                train=train,
                year=year,
                partial_year=first > date(year, 1, 1) or min(last, as_of) < date(year, 12, 31),
                **{
                    key: len(counts[key])
                    for key in (*_COUNT_FIELDS.values(), "published_bug_ids", "undated_events")
                },
                withdrawal_rate=None,
                coverage="not_established",
            )
        )
    return result


def _chronology(step_date, signal_date):
    if step_date is None or signal_date is None:
        return "unknown"
    return "later" if signal_date > step_date else "not_later"


def _upgrade_links(upgrades, events, candidates, start, end, fact_dates, cohorts):
    if upgrades is None:
        return []
    if (
        not isinstance(upgrades, dict)
        or not isinstance(upgrades.get("rows"), list)
        or len(upgrades["rows"]) > 20000
    ):
        raise ValueError("Release-signals upgrades must contain native rows")
    index = defaultdict(list)
    for event in events:
        vendor, train = event["vendor"], event["train"]
        day = event["date"] if len(fact_dates[_fact_key(event)]) == 1 else None
        for release in _targets(event):
            if release_train(vendor, release) == train:
                index[vendor, train, release].append((event["kind"], day, event["event_id"]))
    for pair in candidates:
        key = (pair["vendor"], pair["train"], pair["earlier_release"])
        index[key].append(("candidate_follow_up", pair["later_date"], pair["event_ids"][1]))

    links = []
    try:
        for row in upgrades["rows"]:
            vendor, train = row["vendor"], row["train"]
            if not isinstance(vendor, str) or not isinstance(train, str):
                raise ValueError("Invalid native upgrade vendor or train")
            if (vendor, train) not in cohorts:
                continue
            steps = row["events"]
            if not isinstance(steps, list) or len(steps) > 4096:
                raise ValueError("Invalid native upgrade event collection")
            for step in steps:
                target, day = step["target"], step["date"]
                if day is not None:
                    _window(day, day)
                    if not start <= day <= end:
                        continue
                if release_train(vendor, target) != train:
                    raise ValueError("Native upgrade target does not match its train")
                claim_ids = step["claim_ids"]
                if not isinstance(claim_ids, list):
                    raise ValueError("Native upgrade event must contain claim IDs")
                common = dict(
                    vendor=vendor,
                    train=train,
                    year=row["year"],
                    scenario=row["scenario"],
                    policy=row["policy"],
                    date=day,
                    target=target,
                    claim_ids=claim_ids,
                    relation="model_unresolved",
                    model_applicability="unresolved",
                )
                matches = index.get((vendor, train, target), [("unknown", None, None)])
                for signal, signal_date, event_id in matches:
                    links.append(
                        dict(
                            **common,
                            event_id=event_id,
                            signal=signal,
                            chronology=_chronology(day, signal_date),
                            reason="The upgrade row lacks an explicit device model."
                            if event_id
                            else "no_retained_release_signal",
                        )
                    )
                    if len(links) > 20000:
                        raise ValueError("Too many release-signals upgrade links")
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("Invalid native upgrade row or event") from error
    return links


def build_report(dataset, *, start, end, upgrades=None):
    validate_dataset(dataset)
    first, last = _window(start, end)
    as_of = _timestamp(dataset["generated_at"]).date()
    all_events = _current_events(dataset)
    events = [
        event for event in all_events if event["date"] is None or start <= event["date"] <= end
    ]
    dates = _fact_dates(all_events)
    retained_dates = _fact_dates(events)
    date_conflict_evidence = [
        event
        for event in all_events
        if event["date"]
        and not start <= event["date"] <= end
        and retained_dates.get(_fact_key(event))
    ]
    candidates = _candidates(events, dates)
    coverage = sorted(
        [row for row in dataset["coverage"] if row["start"] <= end and row["end"] >= start],
        key=lambda row: (row["vendor"], row["train"], row["start"], row["end"], row["status"]),
    )
    report = dict(
        schema_version=1,
        generated_at=dataset["generated_at"],
        window=dict(start=start, end=end),
        dataset_sha256=_digest(dataset),
        upgrades_sha256=_digest(upgrades) if upgrades is not None else None,
        events=events,
        date_conflict_evidence=date_conflict_evidence,
        metrics=_metrics(events, coverage, first, last, as_of, dates),
        candidate_pairs=candidates,
        upgrade_links=_upgrade_links(
            upgrades,
            events,
            candidates,
            start,
            min(end, as_of.isoformat()),
            dates,
            _STUDY_TRAINS | {(item["vendor"], item["train"]) for item in [*coverage, *events]},
        ),
        coverage=coverage,
        caveats=[
            "Counts describe observed publisher disclosures. Coverage is unestablished and vendor withdrawal rates are unavailable.",
            "Close release pairs report calendar proximity only. Their model applicability and cause remain unknown.",
            "Undated facts remain in the evidence list and are excluded from annual counts.",
            "Upgrade rows are supplied retrospective scenario evidence. Annotations leave device applicability unresolved.",
            "Bug ID counts describe dated public disclosures, including any cumulative lists.",
            "Release, withdrawal, deferment and corrective respin observations with conflicting years are excluded from annual counts.",
        ],
        review_status="independent_human_review_pending",
    )
    return validate_report(report)


def validate_report(report):
    _validate_shape("report", report)
    start, end = report["window"]["start"], report["window"]["end"]
    first, last = _window(start, end)
    generated = _timestamp(report["generated_at"])
    _check_coverage(report["coverage"])
    events = {}
    receipts = {}
    source_revisions = {}
    if any(not (row["start"] <= end and row["end"] >= start) for row in report["coverage"]):
        raise ValueError("Release-signals coverage outside report window")
    if len(report["events"]) + len(report["date_conflict_evidence"]) > _MAX_DATASET_EVENTS:
        raise ValueError("Too many release-signals report events")
    for event in [*report["events"], *report["date_conflict_evidence"]]:
        source = event["source"]
        retrieved = _timestamp(source["retrieved_at"])
        if retrieved > generated or source["source_locator"] != event["source_locator"]:
            raise ValueError("Invalid release-signals report receipt")
        vendor = _source_vendor(source["source_url"])
        _validate_event(event, vendor, retrieved)
        receipt = {key: value for key, value in source.items() if key != "source_locator"}
        if receipts.setdefault(source["revision_id"], receipt) != receipt:
            raise ValueError("Inconsistent source receipt in release-signals report")
        url = source["source_url"]
        identity = (url, _announcement_key(event)) if _is_rolling_announcement(url, event) else url
        if source_revisions.setdefault(identity, source["revision_id"]) != source["revision_id"]:
            raise ValueError("Mixed source revisions in release-signals report")
        event_id = event["event_id"]
        if event_id in events or event_id != _digest(
            {key: value for key, value in event.items() if key != "event_id"}
        ):
            raise ValueError("Invalid release-signals event ID")
        events[event_id] = event
    retained_dates = _fact_dates(report["events"])
    for event in report["events"]:
        if event["date"] is not None and not start <= event["date"] <= end:
            raise ValueError("Release signal date outside report window")
    for event in report["date_conflict_evidence"]:
        if (
            event["date"] is None
            or start <= event["date"] <= end
            or not retained_dates.get(_fact_key(event))
        ):
            raise ValueError("Invalid release-signals date conflict evidence")
        retained_dates[_fact_key(event)].add(event["date"])
    dates = retained_dates
    evidence = {event["event_id"]: event for event in report["events"]}
    possible = {tuple(pair["event_ids"]): pair for pair in _candidates(report["events"], dates)}
    pairs = {}
    for pair in report["candidate_pairs"]:
        ids = tuple(pair["event_ids"])
        if ids in pairs or possible.get(ids) != pair:
            raise ValueError("Invalid release-signals candidate pair")
        pairs[ids] = pair
    follow_ups = {(pair["event_ids"][1], pair["earlier_release"]): pair for pair in pairs.values()}
    expected_metrics = _metrics(
        report["events"], report["coverage"], first, last, generated.date(), dates
    )
    if (
        sorted(report["metrics"], key=lambda row: (row["vendor"], row["train"], row["year"]))
        != expected_metrics
    ):
        raise ValueError("Invalid release-signals metrics")
    if report["upgrade_links"] and report["upgrades_sha256"] is None:
        raise ValueError("Release-signals upgrade links require an input fingerprint")
    for link in report["upgrade_links"]:
        if release_train(link["vendor"], link["target"]) != link["train"]:
            raise ValueError("Native upgrade target does not match its train")
        if link["date"] and (
            not start <= link["date"] <= min(end, generated.date().isoformat())
            or int(link["date"][:4]) != link["year"]
        ):
            raise ValueError("Invalid release-signals upgrade date")
        event = evidence.get(link["event_id"])
        if link["signal"] == "unknown":
            if (
                link["event_id"] is not None
                or link["chronology"] != "unknown"
                or link["reason"] != "no_retained_release_signal"
            ):
                raise ValueError("Invalid unmatched release-signals upgrade link")
            continue
        if event is None or (link["vendor"], link["train"]) != (event["vendor"], event["train"]):
            raise ValueError("Invalid release-signals upgrade event reference")
        signal_date = event["date"]
        if link["signal"] == "candidate_follow_up":
            follow_up = follow_ups.get((link["event_id"], link["target"]))
            if follow_up is None:
                raise ValueError("Invalid release-signals upgrade candidate reference")
        elif link["signal"] != event["kind"] or link["target"] not in _targets(event):
            raise ValueError("Upgrade signal must match exact target release")
        if len(dates[_fact_key(event)]) > 1:
            signal_date = None
        expected = _chronology(link["date"], signal_date)
        if link["chronology"] not in {expected, "unknown"}:
            raise ValueError("Invalid release-signals upgrade chronology")
    return report


def to_csv(report):
    """Export report records under one header, with formula-safe spreadsheet cells."""
    validate_report(report)
    sections = (
        "metrics",
        "candidate_pairs",
        "upgrade_links",
        "coverage",
        "events",
        "date_conflict_evidence",
    )
    schema = _validator("report").schema["$defs"]
    fields = dict.fromkeys(
        field
        for kind in ("metrics", "candidate", "upgrade", "coverage", "event")
        for field in schema[kind]["properties"]
    )
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=["section", *fields])
    writer.writeheader()
    for section in sections:
        for row in report[section]:
            record = {"section": section}
            for field, value in row.items():
                if isinstance(value, (dict, list, bool)):
                    value = json.dumps(value, ensure_ascii=True, sort_keys=True)
                if isinstance(value, str) and (
                    value.startswith(("\t", "\r", "\n"))
                    or value.lstrip().startswith(("=", "+", "-", "@"))
                ):
                    value = "'" + value
                record[field] = value
            writer.writerow(record)
    return output.getvalue()
