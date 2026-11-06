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
    main(["switching-validation"])
    assert json.loads(capsys.readouterr().out)["total"] == 16
