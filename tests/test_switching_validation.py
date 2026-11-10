"""Synthetic validation-engine tests; actual source replays stay private."""

from infrastructure_impact.application import switching_validation as validation


def test_separate_definition_packet_and_missing_sources():
    d = validation.definition()
    assert {c["vendor"] for c in d["cases"]} == {"arista", "aruba", "cisco"}
    result = validation.report([], [])
    assert result["independent_human_review_completed"] is False
    assert all(v["full_byte_matches"] == 0 and v["failures"] for v in result["vendor_results"])
    packet = validation.packet([])
    assert packet["review_status"] == "awaiting_independent_reviewer"
    assert "expected_status" not in str(packet)
    assert packet["study"] == "campus-branch-switching"


def synthetic_review():
    """Invented engine inputs with their own real hashes; never primary evidence."""
    import hashlib

    review = dict(
        schema_version=1,
        reviewed_at="2026-11-04",
        review_method="Synthetic engine unit test, not source adjudication",
        sample_strategy="Project-authored synthetic assertions",
        cases=[],
    )
    records = []
    bodies = {}
    for index, vendor in enumerate(("cisco", "aruba", "arista")):
        url = {
            "cisco": "https://sec.cloudapps.cisco.com/synthetic-unit-test",
            "aruba": "https://support.hpe.com/synthetic-unit-test",
            "arista": "https://www.arista.com/synthetic-unit-test",
        }[vendor]
        raw = (
            "<html><body><div class='item-page'>Synthetic " + vendor + " scope</div></body></html>"
        ).encode()
        digest = hashlib.sha256(raw).hexdigest()
        cid = "CVE-2025-" + str(10001 + index)
        case = dict(
            id="synthetic-" + vendor,
            vendor=vendor,
            source_url=url,
            source_sha256=digest,
            cve_id=cid,
            product_pattern="^Synthetic product$",
            expected_status="affected",
            source_locator="Synthetic local scope",
            rationale="Invented unit-test assertion; no vendor exposure claim",
        )
        if vendor == "arista":
            from infrastructure_impact.application.source_scope import scope_sha256

            case["reviewed_scope"] = dict(
                scheme="arista_advisory_body_v1",
                sha256=scope_sha256(raw, "arista_advisory_body_v1"),
            )
        review["cases"].append(case)
        records.append(
            dict(
                vendor=vendor,
                source_url=url,
                sha256=digest,
                document_status="published",
                assessments=[
                    dict(
                        cve_id=cid,
                        product="Synthetic product",
                        status="affected",
                        scope="cve_specific",
                        versions=[],
                        remediations=[],
                    )
                ],
            )
        )
        bodies[url] = raw
    return review, records, bodies


def test_synthetic_engine_separates_full_byte_and_scoped_matches(monkeypatch):
    import copy
    import hashlib

    from infrastructure_impact.application.source_scope import scope_sha256

    review, records, bodies = synthetic_review()
    monkeypatch.setattr(validation, "definition", lambda: copy.deepcopy(review))
    result = validation.report(records, [])
    assert result["passed"] == 3 and result["scope_matches"] == 0
    assert all(
        not v["validation_complete"] and not v["sample_requirement_met"]
        for v in result["vendor_results"]
    )
    changed = copy.deepcopy(records)
    record = changed[-1]
    raw = bodies[record["source_url"]].replace(
        b"<body>", b"<body><p>Synthetic navigation changed</p>"
    )
    record["sha256"] = hashlib.sha256(raw).hexdigest()
    scopes = [
        dict(
            source_url=record["source_url"],
            source_sha256=record["sha256"],
            scheme="arista_advisory_body_v1",
            scope_sha256=scope_sha256(raw, "arista_advisory_body_v1"),
        )
    ]
    result = validation.report(changed, scopes)
    assert result["passed"] == 2 and result["scope_matches"] == 1
    assert validation.report(changed, [])["passed"] == 2
    packet = validation.packet(records)
    assert "expected_status" not in str(packet)
    assert packet["study"] == "campus-branch-switching"


def test_synthetic_engine_reports_disagreements_by_vendor(monkeypatch):
    review, records, _ = synthetic_review()
    monkeypatch.setattr(validation, "definition", lambda: review)
    records[1]["assessments"][0]["status"] = "unaffected"
    result = validation.report(records, [])
    aruba = next(v for v in result["vendor_results"] if v["vendor"] == "aruba")
    assert aruba["failures"] == [dict(id="synthetic-aruba", outcome="disagreement")]
    assert aruba["full_byte_matches"] == 0


def test_real_review_metadata_does_not_turn_synthetic_inputs_into_evidence():
    import hashlib
    from pathlib import Path

    definition = validation.definition()
    assert all(
        sum(c["vendor"] == vendor for c in definition["cases"]) >= 5
        for vendor in ("cisco", "aruba", "arista")
    )
    real_hashes = {c["source_sha256"] for c in definition["cases"]}
    _, records, bodies = synthetic_review()
    assert all(r["sha256"] not in real_hashes for r in records)
    assert all(hashlib.sha256(raw).hexdigest() not in real_hashes for raw in bodies.values())
    fixtures = Path(__file__).parent / "fixtures"
    assert not list(fixtures.rglob("*.capture"))
    assert not (fixtures / "switching-sources").exists()
    assert validation.report(records, [])["passed"] == 0


def test_switching_validation_cli_uses_separate_packet(monkeypatch, tmp_path, capsys):
    import json

    from infrastructure_impact.cli import main
    from infrastructure_impact.storage import repository

    path = tmp_path / "test.sqlite"
    repository.connect(path).close()
    connect = repository.connect
    monkeypatch.setattr(repository, "connect", lambda **kwargs: connect(path, **kwargs))
    main(["switching-validation", "--packet"])
    packet = json.loads(capsys.readouterr().out)
    assert packet["study"] == "campus-branch-switching"
    assert "switching-validation.json" in packet["instructions"]
    from infrastructure_impact.storage import source_selections

    selected_record, choice = alternate_inputs(monkeypatch)
    original_report = validation.report
    captured = []

    def reporting(records, scopes, **kwargs):
        captured.append(kwargs["source_selections"])
        return original_report([selected_record], scopes, **kwargs)

    monkeypatch.setattr(source_selections, "latest", lambda db: [choice])
    monkeypatch.setattr(validation, "report", reporting)
    main(["switching-validation"])
    result = json.loads(capsys.readouterr().out)
    assert captured == [[choice]]
    assert result["cases"][0]["source_context"]["state"] == ("retained_unselected_representation")


def test_excluded_changed_bytes_keep_reviewed_scope_outcome_and_provenance(monkeypatch):
    import copy

    from infrastructure_impact.application.extraction_validation import validation_report

    review, records, _ = synthetic_review()
    changed = copy.deepcopy(records[-1])
    changed["sha256"] = "b" * 64
    case = review["cases"][-1]
    case["claim_context"] = [["feature", "management"]]
    changed["assessments"][0]["product_context"] = [["feature", "management"]]
    scopes = [
        {
            "source_url": changed["source_url"],
            "source_sha256": changed["sha256"],
            "scheme": case["reviewed_scope"]["scheme"],
            "scope_sha256": case["reviewed_scope"]["sha256"],
        }
    ]
    retained = [
        {"record": changed, "decision_id": "d" * 64, "record_scope": "retained_latest_excluded"}
    ]
    monkeypatch.setattr(validation, "definition", lambda: review)
    historical = validation_report([changed], review, scopes)["cases"][-1]
    assert historical["outcome"] == "reviewed_scope_match_source_changed"
    for report in (
        validation_report([], review, scopes, retained_advisories=retained),
        validation.report([], scopes, retained_advisories=retained),
    ):
        result = report["cases"][-1]
        assert result["outcome"] == "current_scope_excluded"
        assert result["historical_outcome"] == "reviewed_scope_match_source_changed"
        assert result["historical_result"] == historical
        assert result["decision_ids"] == ["d" * 64]
        assert report["passed"] == report["scope_matches"] == 0
    # Same source proof without the reviewed claim context cannot support this case.
    changed["assessments"][0]["product_context"] = []
    result = validation.report([], scopes, retained_advisories=retained)["cases"][-1]
    assert result["outcome"] == "source_missing"
    assert "decision_ids" not in result


def test_excluded_pinned_source_requires_actual_nondraft_claim_support(monkeypatch):
    import copy

    review, records, _ = synthetic_review()
    monkeypatch.setattr(validation, "definition", lambda: review)
    for mismatch in ("cve", "product", "context", "draft"):
        record = copy.deepcopy(records[0])
        case = review["cases"][0]
        case["claim_context"] = [["role", "reviewed"]]
        record["assessments"][0]["product_context"] = [["role", "reviewed"]]
        if mismatch == "cve":
            record["assessments"][0]["cve_id"] = "CVE-2025-99999"
        elif mismatch == "product":
            record["assessments"][0]["product"] = "Unrelated product"
        elif mismatch == "context":
            record["assessments"][0]["product_context"] = []
        else:
            record["document_status"] = "draft"
        report = validation.report(
            [],
            [],
            retained_advisories=[
                {
                    "record": record,
                    "decision_id": "d" * 64,
                    "record_scope": "retained_latest_excluded",
                }
            ],
        )
        assert report["cases"][0]["outcome"] == "source_missing", mismatch
        assert "decision_ids" not in report["cases"][0], mismatch


def alternate_inputs(monkeypatch):
    import copy

    review, records, _ = synthetic_review()
    selected = copy.deepcopy(records[0])
    selected["source_url"] += "/selected"
    selected["sha256"] = "a" * 64
    monkeypatch.setattr(validation, "definition", lambda: copy.deepcopy(review))

    def view(url, digest, selected):
        return dict(
            source_url=url,
            source_sha256=digest,
            selected=selected,
            source_observed_at="2026-11-10T00:00:00Z",
            source_format="synthetic",
            adapter_version="synthetic-v1",
            normalized_statements=1,
            private_note="PRIVATE_SENTINEL",
        )

    choice = dict(
        vendor="cisco",
        requested_url=selected["source_url"],
        selected_at="2026-11-10T00:00:00Z",
        reason="Synthetic",
        meaning="Synthetic",
        views=[
            view(selected["source_url"], selected["sha256"], True),
            view(records[0]["source_url"], records[0]["sha256"], False),
        ],
        unavailable=[],
        private_note="PRIVATE_SENTINEL",
    )
    return selected, choice


def test_retained_alternate_context_is_metadata_only(monkeypatch):
    import copy

    record, choice = alternate_inputs(monkeypatch)
    baseline = validation.report([record], [])
    result = validation.report([record], [], source_selections=[choice])
    context = result["cases"][0].pop("source_context")
    assert context == dict(
        state="retained_unselected_representation",
        source_url=choice["views"][1]["source_url"],
        source_sha256=choice["views"][1]["source_sha256"],
        selected_source_url=record["source_url"],
        selected_source_sha256=record["sha256"],
    )
    assert result == baseline
    assert result["cases"][0]["outcome"] == "source_missing"
    assert result["independent_human_review_completed"] is False
    assert "PRIVATE_SENTINEL" not in str(context)
    assert "source_context" not in str(validation.packet([record]))
    for mismatch in ("hash", "url", "vendor", "unavailable", "anchor", "selected"):
        changed = copy.deepcopy(choice)
        if mismatch == "hash":
            changed["views"][1]["source_sha256"] = "b" * 64
        elif mismatch == "url":
            changed["views"][1]["source_url"] += "/wrong"
        elif mismatch == "vendor":
            changed["vendor"] = "arista"
        elif mismatch == "unavailable":
            changed["unavailable"] = [
                dict(source_url=changed["views"][1]["source_url"], error_code="fetch_failed")
            ]
        elif mismatch == "anchor":
            changed["views"][0]["source_sha256"] = "c" * 64
        else:
            changed["views"][1]["selected"] = True
        assert validation.report([record], [], source_selections=[changed]) == baseline, mismatch


def test_malformed_optional_selection_fails_closed(monkeypatch):
    import copy

    record, choice = alternate_inputs(monkeypatch)
    baseline = validation.report([record], [])
    malformed = [
        None,
        3,
        {},
        dict(choice, views=None),
        dict(choice, unavailable=None),
        dict(choice, views=[None]),
        dict(choice, reason=3),
    ]
    missing = copy.deepcopy(choice)
    del missing["views"][1]["adapter_version"]
    malformed.append(missing)
    for value in malformed:
        assert validation.report([record], [], source_selections=[value]) == baseline, value
    assert validation.report([record], [], source_selections=None) == baseline
