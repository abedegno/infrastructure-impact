"""Generation-bound release evidence; disclosure counts never imply vendor quality."""

import copy
import hashlib
import json
from datetime import date, datetime, timedelta
from functools import cache

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

from ..exports import csv_table
from ..settings import PACKAGE
from . import release_catalogue as catalogue_tools

METRICS = (
    "releases_shipped",
    "deferred_or_withdrawn",
    "possible_respin_30",
    "possible_respin_90",
    "corrective_respin_30",
    "corrective_respin_90",
    "software_defect_notices",
    "deferral_notices",
)
ACTIONS = {"deferred", "withdrawn", "removed_from_download", "no_longer_available"}
PENDING = "independent_human_review_pending"
_UNSET = object()
LIMITATIONS = [
    catalogue_tools.CAVEAT,
    "Research excerpts are observed context, not production-eligible original evidence.",
    "Notice dates, action dates and software release dates retain separate meanings.",
    "A model-unresolved upgrade match is context, never proven applicability.",
    "Rates require complete original release and signal coverage; respins use the follow-up release cohort.",
]
METHOD = {
    "release_cohort": "software release date",
    "notice_cohort": "notice date",
    "withdrawal_cohort": "affected shipped release date",
    "respin_cohort": "follow-up software release date",
    "respin_denominator": "releases shipped in follow-up cohort year",
    "rate_support": "complete dated original release enumeration and explicit complete signal coverage; 30/90 day prior original release history for respins",
    "review_status": PENDING,
}


def _timestamp(literal):
    value = datetime.fromisoformat(literal.upper())
    if value.tzinfo is None:
        raise ValueError("Generation timestamp requires timezone")
    return value


def _hash(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()


def _eligible(fact, sources, train):
    return catalogue_tools._original(fact, sources) and bool(catalogue_tools._scope(fact, train))


def _annual(catalogue, config, respins):
    summary = catalogue_tools.catalogue_summary(catalogue, config)
    sources = {s["source_id"]: s for s in catalogue["sources"]}
    coverages = {(c["vendor"], c["train"], c["year"]): c for c in catalogue["coverage"]}
    result = []
    for item in summary["annual"]:
        train = next(
            t
            for t in config["trains"]
            if (t["vendor"], t["train"]) == (item["vendor"], item["train"])
        )
        start, end = item["period_start"], item["period_end"]

        def during(day):
            return day is not None and end is not None and start <= day <= end

        def same(fact):
            return (fact["vendor"], fact["train"], fact.get("family", train["family"])) == (
                train["vendor"],
                train["train"],
                train["family"],
            )

        releases = catalogue_tools._releases(catalogue, train)
        train_notices = [r for r in catalogue["notices"] if same(r)]
        notices = [r for r in train_notices if during(r["notice_date"])]
        statements = [r for r in catalogue["statements"] if same(r) and r["status"] in ACTIONS]
        statements += [
            {**notice, "version": version}
            for notice in catalogue["notices"]
            if same(notice)
            and notice["classification"] in {"release_deferral", "release_withdrawal"}
            for version in notice["affected_releases"] or [None]
        ]
        judgement = coverages.get((item["vendor"], item["train"], item["year"]), {})
        action_model_blockers, action_cohort_blockers = set(), set()
        if end is not None:
            for statement in statements:
                models = catalogue_tools._scope(statement, train)
                if statement["platforms_stated"] and not models:
                    continue
                version = statement["version"]
                blocker_id = version if version is not None else "notice:" + statement["notice_id"]
                matching = [r for r in releases if r["version"] == version]
                if not statement["platforms_stated"]:
                    # A version identity cannot supply an unstated action model binding.
                    action_model_blockers.add(blocker_id)
                    action_cohort_blockers.add(blocker_id)
                    continue
                for model in models:
                    scoped = [r for r in matching if model in r["platforms_stated"]]
                    if not scoped or any(r["release_date"] is None for r in scoped):
                        action_cohort_blockers.add(blocker_id)
                    if not scoped and any(not r["platforms_stated"] for r in matching):
                        action_model_blockers.add(blocker_id)
        metrics = {}
        for metric in METRICS:
            if metric == "releases_shipped":
                facts = [r for r in releases if during(r["release_date"])]

                def key(r):
                    return r["version"]
            elif metric == "deferred_or_withdrawn":
                facts = []
                for statement in statements:
                    for release in releases:
                        if (
                            release["version"] == statement["version"]
                            and during(release["release_date"])
                            and set(release["platforms_stated"])
                            & set(statement["platforms_stated"])
                        ):
                            facts.append(
                                {
                                    **statement,
                                    "evidence": [*statement["evidence"], *release["evidence"]],
                                    "platforms_stated": sorted(
                                        set(statement["platforms_stated"])
                                        & set(release["platforms_stated"])
                                    ),
                                }
                            )

                def key(r):
                    return r["version"]
            elif "respin" in metric:
                corrective = metric.startswith("corrective")
                interval = int(metric.rsplit("_", 1)[1])
                facts = [
                    r
                    for r in respins
                    if same(r)
                    and during(r["followup_release_date"])
                    and r["days"] is not None
                    and r["days"] <= interval
                    and (not corrective or r["classification"] == "corrective_respin")
                ]

                def key(r):
                    return r["followup_release"]
            else:
                kinds = (
                    {"software_defect"}
                    if metric == "software_defect_notices"
                    else {"release_deferral", "release_withdrawal"}
                )
                facts = [r for r in notices if r["classification"] in kinds]

                def key(r):
                    return r["notice_id"]

            observed = {key(r) for r in facts}
            eligible = {
                key(r) for r in facts if r.get("production_eligible", _eligible(r, sources, train))
            }
            research = {key(r) for r in facts if not catalogue_tools._original(r, sources)}
            research -= eligible
            unresolved = {key(r) for r in facts if not catalogue_tools._scope(r, train)}
            if metric == "deferred_or_withdrawn":
                unresolved |= action_model_blockers
            signal_complete = (
                end is not None
                and judgement.get("signal_coverage", {}).get(metric) == "complete"
                and bool(judgement.get("source_ids"))
                and set(train["platforms"]) <= set(judgement.get("platforms", []))
                and all(
                    sources[s]["capture_kind"] == "original_document"
                    for s in judgement["source_ids"]
                )
            )
            if "respin" in metric:
                signal_complete = signal_complete and not any(
                    same(r)
                    and r["days"] is None
                    and (r["followup_release_date"] is None or during(r["followup_release_date"]))
                    for r in respins
                )
            if metric in {"software_defect_notices", "deferral_notices"}:
                potential_notices = [
                    notice
                    for notice in train_notices
                    if notice["classification"] in kinds
                    and (notice["notice_date"] is None or during(notice["notice_date"]))
                    and (not notice["platforms_stated"] or catalogue_tools._scope(notice, train))
                ]
                signal_complete = signal_complete and all(
                    notice["notice_date"] is not None and _eligible(notice, sources, train)
                    for notice in potential_notices
                )
            else:
                signal_complete = signal_complete and not research and not unresolved
                if metric == "deferred_or_withdrawn":
                    signal_complete = signal_complete and not action_cohort_blockers
            supported = item["denominator"] is not None and signal_complete
            if supported:
                supported = bool(judgement.get("source_ids")) and all(
                    sources[s]["capture_kind"] == "original_document"
                    for s in judgement["source_ids"]
                )
                supported = supported and not research and not unresolved
                if "respin" in metric:
                    lookback = (
                        date.fromisoformat(start) - timedelta(days=int(metric.rsplit("_", 1)[1]))
                    ).isoformat()
                    history_start = judgement.get("prior_release_history_start")
                    supported = (
                        supported and history_start is not None and history_start <= lookback
                    )
                    supported = supported and all(
                        r["release_date"] and _eligible(r, sources, train)
                        for r in releases
                        if r["release_date"] is None or history_start <= r["release_date"] < start
                    )
            count_complete = (
                item["denominator"] is not None
                if metric == "releases_shipped"
                else signal_complete
                if metric in {"software_defect_notices", "deferral_notices"}
                else supported
            )
            count = len(observed) if observed or count_complete else None
            numerator = len(eligible) if eligible or count_complete else None
            denominator = item["denominator"] if supported else None
            rate = numerator / denominator if denominator and numerator is not None else None
            if metric in {"releases_shipped", "software_defect_notices", "deferral_notices"}:
                denominator = item["denominator"] if metric == "releases_shipped" else None
                rate = None
            metrics[metric] = dict(
                observed_count=count,
                numerator=numerator,
                denominator=denominator,
                rate=rate,
                coverage="complete" if count_complete else "partial" if observed else "unknown",
                evidence_class="mixed"
                if research and eligible
                else "research_only"
                if research
                else "original_document"
                if eligible or supported
                else "unknown",
                model_unresolved_count=len(unresolved),
                research_only_count=len(research) if research else None,
                reason="Complete dated original release and signal coverage"
                if supported
                else "Rate unavailable: complete dated original release denominator and signal coverage not established. "
                + item["coverage_reason"],
            )
            if metric == "deferred_or_withdrawn" and (
                action_model_blockers or action_cohort_blockers
            ):
                metrics[metric]["reason"] += (
                    f" Unresolved action inputs: {len(action_model_blockers | action_cohort_blockers)}"
                    f" (model scope: {len(action_model_blockers)}; release cohort: {len(action_cohort_blockers)})."
                )
        result.append(
            {
                k: item[k]
                for k in ("vendor", "train", "year", "period_start", "period_end", "year_to_date")
            }
            | {"metrics": metrics}
        )
    return result


def _review(catalogue, respins=()):
    notices = [
        dict(
            type=kind,
            index=index,
            vendor=fact["vendor"],
            train=fact["train"],
            classification=fact.get("classification", fact.get("status")),
            notice_date=fact["notice_date"],
            action_date=fact["action_date"],
            platforms_stated=fact["platforms_stated"],
            evidence=fact["evidence"],
            review_status=PENDING,
            fact=copy.deepcopy(fact),
        )
        for section, kind in (("notices", "notice"), ("statements", "statement"))
        for index, fact in enumerate(catalogue[section])
    ]
    return notices + [
        dict(
            type="respin",
            index=index,
            vendor=fact["vendor"],
            train=fact["train"],
            classification=fact["classification"],
            notice_date=None,
            action_date=None,
            platforms_stated=fact["platforms_stated"],
            evidence=fact["evidence"],
            review_status=PENDING,
            fact=copy.deepcopy(fact),
        )
        for index, fact in enumerate(respins)
        if "respin_rule" in fact
    ]


def build_report(
    catalogue=None, config=None, *, publication, generated_at, staircase_join_version=None
):
    """Build from packaged public facts without selecting or hydrating study claims."""
    catalogue = copy.deepcopy(
        catalogue
        if catalogue is not None
        else json.loads((PACKAGE / "resources/release-catalogue.json").read_text())
    )
    config = copy.deepcopy(
        config
        if config is not None
        else json.loads((PACKAGE / "resources/release-catalogue-trains.json").read_text())
    )
    catalogue_tools.validate_catalogue(catalogue)
    catalogue_tools.validate_config(config)
    if any("respin_rule" in train for train in config["trains"]):
        catalogue = catalogue_tools.deduplicate_releases(catalogue)
    available = _timestamp(catalogue["generated_at"]) <= _timestamp(generated_at)
    if not available:
        return unavailable_report(publication=publication, generated_at=generated_at)
    report = dict(
        schema_version=1,
        publication=copy.deepcopy(publication),
        generated_at=generated_at,
        availability="available" if available else "unavailable",
        dataset_observed_at=catalogue["generated_at"] if available else None,
        catalogue_sha256=_hash(catalogue) if available else None,
        catalogue=catalogue if available else None,
        config=config,
        annual=[],
        respins=[],
        upgrade_annotations=[],
        upgrade_selection=None,
        review_packet=[],
        validation=dict(
            status="passed" if available else "unavailable",
            checks=[
                "catalogue_schema",
                "source_provenance",
                "date_separation",
                "model_scope",
                "same_base_chronology",
                *(["unique_release_identity"] if catalogue.get("release_identity") else []),
            ],
            review_status=PENDING,
        ),
        limitations=copy.deepcopy(LIMITATIONS),
        method=copy.deepcopy(METHOD),
    )
    if staircase_join_version is not None:
        if type(staircase_join_version) is not int or staircase_join_version != 1:
            raise ValueError("Unsupported staircase join version")
        report["staircase_join_version"] = staircase_join_version
    if available:
        report["respins"] = catalogue_tools.find_respins(catalogue, config)
        report["annual"] = _annual(catalogue, config, report["respins"])
        report["review_packet"] = _review(catalogue, report["respins"])
    return validate_report(report, publication=publication, generated_at=generated_at)


@cache
def _validator():
    return Draft202012Validator(
        json.loads((PACKAGE / "schemas/release-reliability-v1.json").read_text()),
        format_checker=FormatChecker(),
    )


def validate_report(report, *, publication=_UNSET, generated_at=None):
    """Reject malformed, future, mixed-generation and fabricated derived metrics."""
    try:
        _validator().validate(report)
    except ValidationError as error:
        raise ValueError("Invalid release reliability report: " + error.message) from error
    if publication is not _UNSET and report["publication"] != publication:
        raise ValueError("Release reliability publication identity differs")
    if generated_at is not None and report["generated_at"] != generated_at:
        raise ValueError("Release reliability generation time differs")
    _timestamp(report["generated_at"])
    catalogue_tools.validate_config(report["config"])
    if "published_staircase_version" in report:
        _validate_published_selection(report)
    if report["availability"] == "unavailable":
        if any(
            report[k]
            for k in (
                "catalogue",
                "dataset_observed_at",
                "catalogue_sha256",
                "annual",
                "respins",
                "review_packet",
                "upgrade_annotations",
            )
        ):
            raise ValueError("Unavailable report contains evidence")
    else:
        cat = report["catalogue"]
        if cat is None:
            raise ValueError("Available report requires catalogue")
        catalogue_tools.validate_catalogue(cat)
        if _timestamp(cat["generated_at"]) > _timestamp(report["generated_at"]):
            raise ValueError("Future catalogue capture")
        if report["dataset_observed_at"] != cat["generated_at"] or report[
            "catalogue_sha256"
        ] != _hash(cat):
            raise ValueError("Catalogue identity differs")
        pairs = catalogue_tools.find_respins(cat, report["config"])
        if (
            report["respins"] != pairs
            or report["annual"] != _annual(cat, report["config"], pairs)
            or report["review_packet"] != _review(cat, pairs)
        ):
            raise ValueError("Release reliability derived facts differ")
    if report["upgrade_annotations"]:
        if report["upgrade_selection"] is None:
            raise ValueError("Upgrade annotations require selected analysis context")
        reconstructed = []
        for annotation in report["upgrade_annotations"]:
            if annotation["date"] > report["generated_at"][:10]:
                raise ValueError("Upgrade annotation step is later than generation")
            for reference in annotation["references"]:
                reconstructed.append(
                    dict(
                        vendor=annotation["vendor"],
                        train=annotation["train"],
                        **reference,
                        events=[
                            dict(
                                date=annotation["date"],
                                target=annotation["target"],
                                models=annotation["models"],
                            )
                        ],
                    )
                )
        if _annotations(report, {"rows": reconstructed}) != report["upgrade_annotations"]:
            raise ValueError("Upgrade annotation facts differ from source evidence")
    return report


def _published_selection(report, study):
    return dict(
        kind="configured_staircases",
        start=report["config"]["start"],
        end=report["config"]["end"],
        trains=[{k: t[k] for k in ("vendor", "train")} for t in report["config"]["trains"]],
        study=copy.deepcopy(study),
    )


def _validate_published_selection(report):
    selected = report["upgrade_selection"]
    study = selected.get("study") if isinstance(selected, dict) else None
    if (
        report.get("staircase_join_version") != 1
        or not isinstance(study, dict)
        or selected != _published_selection(report, study)
        or study.get("requested_vendor") is not None
        or study.get("requested_cve_ids") is not None
        or study.get("requested_window") != "all"
        or study.get("scope_level") != "os_family"
        or set(study)
        != {
            "requested_vendor",
            "effective_vendors",
            "scope_level",
            "requested_window",
            "effective_windows",
            "requested_cve_ids",
            "effective_cve_ids",
            "definition_sha256",
        }
        or study.get("effective_vendors") != ["cisco", "aruba", "arista"]
        or study.get("effective_windows")
        != [f"{v}:os_family:all" for v in ("cisco", "aruba", "arista")]
    ):
        raise ValueError("Invalid published staircase selection")


def validate_published_report(report, **identity):
    """Only the writer's bounded default context may accompany a published root."""
    validate_report(report, **identity)
    if (
        report["upgrade_selection"] is not None or report["upgrade_annotations"]
    ) and not report.get("published_staircase_version"):
        raise ValueError("Published reliability report contains selected analysis")
    return report


def _with_published_analysis(report, compiled, study):
    """Writer-only join from its already validated complete compiled source frame.

    Expand only configured train constraints, retain pre-period walk state, and
    never materialize another complete selected report or change upgrade counts.
    """
    if report["availability"] != "available":
        return report
    from . import switching_analysis as analysis
    from . import switching_upgrades as upgrades

    for source in (compiled, study):
        if any(source[k] != report[k] for k in ("publication", "generated_at")):
            raise ValueError("Published staircase source identity differs")
    selection = _published_selection(report, study["selection"])
    _validate_published_selection(
        dict(report, upgrade_selection=selection, published_staircase_version=1)
    )
    if compiled["definition_sha256"] != study["selection"]["definition_sha256"]:
        raise ValueError("Published staircase definition differs")
    targets = {(t["vendor"], t["train"]) for t in report["config"]["trains"]}
    source = compiled["requirements"]
    constraints = []
    for req in source["requirements"]:
        member = source["members"][req["claim_id"]]
        if (member["vendor"], req["train"]) in targets and (
            member["date"] is None
            or study["definition"]["start_date"] <= member["date"] <= compiled["observation_end"]
        ):
            constraints.append(analysis._expand(source, req))
    rows = upgrades._rows(
        constraints,
        end=compiled["observation_end"],
        vendors=study["selection"]["effective_vendors"],
    )
    selected = {k: report[k] for k in ("publication", "generated_at")}
    selected.update(selection=selection, rows=rows)
    result = with_upgrades(report, selected)
    result["published_staircase_version"] = 1
    return validate_published_report(result)


def _catalogue_match(report, group):
    candidates = [
        r
        for r in report["catalogue"]["releases"]
        if (r["vendor"], r["train"]) == (group["vendor"], group["train"])
    ]
    exact = [r for r in candidates if r["version"] == group["target"]]
    variants = []
    if not exact and group["vendor"] == "cisco":
        try:
            key = catalogue_tools._version_key("cisco", group["target"])[:3]
            variants = [
                r
                for r in candidates
                if catalogue_tools._version_key("cisco", r["version"])[:3] == key
            ]
        except ValueError:
            pass
    found = exact or variants
    observations = [o for r in found for o in r.get("observations", [r])]
    evidence = []
    for o in observations:
        for e in o["evidence"]:
            if e not in evidence:
                evidence.append(copy.deepcopy(e))
    scope = {p for o in observations for p in o["platforms_stated"]}
    return dict(
        present=bool(exact),
        match_type="exact" if exact else "suffix_variant" if variants else "not_found",
        versions=sorted({r["version"] for r in found}),
        scope_status="matched"
        if exact and group["models"] and set(group["models"]) <= scope
        else "model_unresolved",
        evidence=evidence,
        release_observations=[
            {k: o[k] for k in ("version", "release_date", "platforms_stated", "evidence")}
            for o in observations
        ],
    )


def _annotations(report, selected):
    groups = {}
    for row in selected["rows"]:
        for event in row["events"]:
            if report.get("staircase_join_version") == 1 and (
                not any(
                    (row["vendor"], row["train"]) == (t["vendor"], t["train"])
                    for t in report["config"]["trains"]
                )
                or not report["config"]["start"] <= event["date"] <= report["config"]["end"]
            ):
                continue
            key = (row["vendor"], row["train"], event["date"], event["target"])
            group = groups.setdefault(
                key,
                dict(
                    vendor=key[0],
                    train=key[1],
                    date=key[2],
                    target=key[3],
                    references=[],
                    models=[],
                    matches=[],
                    caveats=[],
                ),
            )
            reference = {k: row[k] for k in ("scenario", "policy")}
            if reference not in group["references"]:
                group["references"].append(reference)
            # Every contributing event must supply models to establish applicability.
            models = event.get("models", row.get("models", []))
            group.setdefault("_model_sets", []).append(set(models))
    catalogue = report["catalogue"]
    sources = {s["source_id"]: s for s in catalogue["sources"]} if catalogue else {}
    for group in groups.values():
        model_sets = group.pop("_model_sets")
        group["models"] = sorted(set.union(*model_sets)) if all(model_sets) else []
        models = set(group["models"])
        group["references"].sort(key=lambda r: (r["scenario"], r["policy"]))
        if not models:
            group["caveats"].append(
                "Upgrade rows do not establish exact models; matches are model-unresolved context."
            )
        if not catalogue:
            continue
        if report.get("staircase_join_version") == 1:
            group["target_catalogue"] = _catalogue_match(report, group)
        for section, kind in (
            ("notices", "notice"),
            ("statements", "statement"),
            ("respins", "respin"),
        ):
            for fact in report["respins"] if section == "respins" else catalogue[section]:
                if (fact["vendor"], fact["train"]) != (group["vendor"], group["train"]):
                    continue
                versions = (
                    fact["affected_releases"]
                    if kind == "notice"
                    else [fact["version"]]
                    if kind == "statement"
                    else [fact["previous_release"]]
                )
                if group["target"] not in versions:
                    continue
                scope = set(fact["platforms_stated"])
                if models and scope and not models & scope:
                    continue
                if models and scope and not models <= scope:
                    caveat = "Source scope covers only some selected models; applicability remains model-unresolved."
                    if caveat not in group["caveats"]:
                        group["caveats"].append(caveat)
                day = fact["followup_release_date"] if kind == "respin" else fact["action_date"]
                group["matches"].append(
                    dict(
                        type=kind,
                        classification=fact.get("classification", fact.get("status")),
                        notice_id=fact.get("notice_id"),
                        notice_date=fact.get("notice_date"),
                        action_date=fact.get("action_date"),
                        release_date=fact.get("followup_release_date"),
                        previous_release_date=fact.get("previous_release_date"),
                        days=fact.get("days"),
                        chronology="unknown"
                        if day is None
                        else "after_step"
                        if day > group["date"]
                        else "on_or_before_step",
                        scope_status="matched"
                        if models and models <= scope
                        else "model_unresolved",
                        platforms_stated=fact["platforms_stated"],
                        production_eligible=fact.get(
                            "production_eligible", catalogue_tools._original(fact, sources)
                        ),
                        evidence=fact["evidence"],
                    )
                )
                if report.get("staircase_join_version") == 1:
                    group["matches"][-1].update(
                        related_release=fact.get("followup_release")
                        if kind == "respin"
                        else fact.get("replacement_release", fact.get("related_release")),
                        days_after_step=(
                            date.fromisoformat(day) - date.fromisoformat(group["date"])
                        ).days
                        if day
                        else None,
                    )
    return [groups[k] for k in sorted(groups)]


def with_upgrades(report, selected_upgrades):
    """Add separately selected step context, deduplicating scenario and policy rows."""
    validate_report(report)
    if (
        selected_upgrades.get("publication") != report["publication"]
        or selected_upgrades.get("generated_at") != report["generated_at"]
    ):
        raise ValueError("Selected upgrades publication identity differs")
    result = copy.deepcopy(report)
    result.pop("published_staircase_version", None)
    result["upgrade_selection"] = copy.deepcopy(selected_upgrades["selection"])
    if result["availability"] == "available":
        result["upgrade_annotations"] = _annotations(report, selected_upgrades)
    return validate_report(result)


CSV_FIELDS = [
    "row_type",
    "publication_id",
    "generated_at",
    "dataset_observed_at",
    "catalogue_sha256",
    "vendor",
    "train",
    "year",
    "period_start",
    "period_end",
    "year_to_date",
    "metric",
    "observed_count",
    "numerator",
    "denominator",
    "rate",
    "coverage",
    "evidence_class",
    "model_unresolved_count",
    "research_only_count",
    "reason",
    "date",
    "target",
    "references",
    "models",
    "matches",
    "upgrade_selection",
    "limitation",
    "payload",
]


def csv_export(report, *, max_bytes=None):
    """Export the accepted report with spreadsheet-safe cells and generation identity."""
    validate_report(report)
    identity = dict(
        publication_id=(report["publication"] or {}).get("id"),
        generated_at=report["generated_at"],
        dataset_observed_at=report["dataset_observed_at"],
        catalogue_sha256=report["catalogue_sha256"],
    )

    def rows():
        for annual in report["annual"]:
            for name, metric in annual["metrics"].items():
                yield (
                    identity
                    | {k: v for k, v in annual.items() if k != "metrics"}
                    | metric
                    | dict(row_type="annual", metric=name)
                )
        for annotation in report["upgrade_annotations"]:
            yield (
                identity
                | annotation
                | dict(
                    row_type="upgrade_annotation",
                    references=json.dumps(
                        annotation["references"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    models=json.dumps(
                        annotation["models"], separators=(",", ":"), ensure_ascii=False
                    ),
                    matches=json.dumps(
                        annotation["matches"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    upgrade_selection=json.dumps(
                        report["upgrade_selection"],
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ),
                    payload=json.dumps(
                        annotation, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    )
                    if report.get("staircase_join_version") == 1
                    else None,
                )
            )
        catalogue = report["catalogue"] or {}
        sections = (
            ("catalogue_source", catalogue.get("sources", [])),
            ("coverage", catalogue.get("coverage", [])),
            ("release", catalogue.get("releases", [])),
            ("notice", catalogue.get("notices", [])),
            ("statement", catalogue.get("statements", [])),
            ("respin", report["respins"]),
            ("review_item", report["review_packet"]),
            ("validation", [report["validation"]]),
            (
                "report_context",
                [
                    {
                        key: report[key]
                        for key in ("availability", "config", "method", "upgrade_selection")
                    }
                ],
            ),
        )
        for kind, facts in sections:
            for fact in facts:
                yield identity | dict(
                    row_type=kind,
                    vendor=fact.get("vendor"),
                    train=fact.get("train"),
                    year=fact.get("year"),
                    payload=json.dumps(
                        fact, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    ),
                )
        for limitation in report["limitations"]:
            yield identity | dict(row_type="limitation", limitation=limitation)

    return csv_table(CSV_FIELDS, rows, max_bytes=max_bytes)


def unavailable_report(*, publication, generated_at, reason="Release reliability root unavailable"):
    """Represent legacy missing roots without borrowing evidence from another generation."""
    config = json.loads((PACKAGE / "resources/release-catalogue-trains.json").read_text())
    return validate_report(
        dict(
            schema_version=1,
            publication=copy.deepcopy(publication),
            generated_at=generated_at,
            availability="unavailable",
            dataset_observed_at=None,
            catalogue_sha256=None,
            catalogue=None,
            config=config,
            annual=[],
            respins=[],
            upgrade_annotations=[],
            upgrade_selection=None,
            review_packet=[],
            validation=dict(status="unavailable", checks=[], review_status=PENDING),
            limitations=[reason, *LIMITATIONS],
            method=copy.deepcopy(METHOD),
        ),
        publication=publication,
        generated_at=generated_at,
    )
