"""Selected evidence coverage, without exposure or upgrade inference.

Counts across models overlap. A zero is lack of owned evidence, never evidence
of unaffectedness. Input envelopes must be validated and own the same generation.
"""

from copy import deepcopy

from . import switching_evidence as contracts


def _counts(claims):
    return dict(
        claims=len({c["claim_id"] for c in claims}),
        advisories=len({(c["vendor"], c["advisory_id"]) for c in claims}),
        cves=len({c["cve_id"] for c in claims if c["cve_id"] is not None}),
    )


def _sources(claims, model=None):
    values = {}
    for c in claims:
        for source in [c["source"]] + [
            b["source"]
            for b in c["platform_bindings"]
            if b["source"] is not None and (model is None or b["model"] == model)
        ]:
            values[tuple(source[k] for k in contracts._SOURCE_FIELDS)] = source
    return [deepcopy(v) for _, v in sorted(values.items())]


def _by_status(claims):
    return {
        status: _counts([c for c in claims if c["status"] == status])
        for status in sorted({c["status"] for c in claims})
    }


def _by_source(claims, model):
    groups = {}
    for c in claims:
        for b in c["platform_bindings"]:
            if b["model"] != model or b["basis"] == "unresolved" or b["source"] is None:
                continue
            key = tuple(b["source"][k] for k in contracts._SOURCE_FIELDS)
            source, owned = groups.setdefault(key, (b["source"], {}))
            owned[c["claim_id"]] = c
    return [
        dict(
            source=deepcopy(source),
            counts=_counts(list(owned.values())),
            by_status=_by_status(list(owned.values())),
            claim_ids=sorted(owned),
        )
        for _, (source, owned) in sorted(groups.items())
    ]


def build_report(evidence, study_selection, *, publication, generated_at):
    """Return a fresh model coverage DTO for actual selected row claim IDs.

    No independent vendor/CVE/model set cross-products are used. Definition,
    window and cohort semantics are owned by the validated native comparison.
    Sources retain exact URL, hash, retrieval and locator ownership.
    """
    contracts.validate_evidence(evidence, publication=publication, generated_at=generated_at)
    contracts.validate_comparison(
        study_selection, publication=publication, generated_at=generated_at
    )
    if (
        study_selection["inputs"] is None
        or study_selection["inputs"]["evidence"] != evidence
        or evidence["definition_sha256"] != study_selection["selection"]["definition_sha256"]
    ):
        raise ValueError("Model coverage selection evidence identity mismatch")
    ids = {cid for row in study_selection["rows"] for cid in row["claim_ids"]}
    selected = [c for c in evidence["claims"] if c["claim_id"] in ids]
    return from_selected(
        selected, study_selection, publication=publication, generated_at=generated_at
    )


def from_selected(selected, study_selection, *, publication, generated_at):
    """Internal delivery seam; caller authenticates compact claim ownership first."""
    ids = {c["claim_id"] for c in selected}
    models = []
    for target in study_selection["definition"]["targets"]:
        if target["vendor"] not in study_selection["selection"]["effective_vendors"]:
            continue
        for model in target["models"]:
            claims = [
                c
                for c in selected
                if c["vendor"] == target["vendor"]
                and c["family"] == target["family"]
                and any(
                    b["model"] == model and b["basis"] != "unresolved"
                    for b in c["platform_bindings"]
                )
            ]
            models.append(
                dict(
                    vendor=target["vendor"],
                    family=target["family"],
                    model=model,
                    counts=_counts(claims),
                    by_status=_by_status(claims),
                    by_source=_by_source(claims, model),
                    claim_ids=sorted(c["claim_id"] for c in claims),
                    advisory_ids=sorted({c["advisory_id"] for c in claims}),
                    cve_ids=sorted({c["cve_id"] for c in claims if c["cve_id"] is not None}),
                    sources=_sources(claims, model),
                )
            )
    unresolved = {}
    for c in selected:
        if any(
            b["model"] is not None and b["basis"] != "unresolved" for b in c["platform_bindings"]
        ):
            continue
        reasons = [i for i in c["issues"] if i.startswith("cisco_model_")]
        for reason in reasons or ["model_binding_unresolved"]:
            unresolved.setdefault(reason, []).append(c)
    bound_ids = {cid for row in models for cid in row["claim_ids"]}
    totals = _counts(selected)
    totals.update(bound_claims=len(bound_ids), unresolved_claims=len(ids - bound_ids))
    return dict(
        schema_version=1,
        publication=publication,
        generated_at=generated_at,
        definition_sha256=study_selection["selection"]["definition_sha256"],
        observation_end=study_selection["observation_end"],
        selection=deepcopy(study_selection["selection"]),
        nonadditive=True,
        interpretation="Missing model evidence does not establish unaffectedness or an upgrade.",
        totals=totals,
        models=models,
        unresolved=[
            dict(
                reason=reason,
                counts=_counts(claims),
                claim_ids=sorted(c["claim_id"] for c in claims),
                sources=_sources(claims),
            )
            for reason, claims in sorted(unresolved.items())
        ],
    )
