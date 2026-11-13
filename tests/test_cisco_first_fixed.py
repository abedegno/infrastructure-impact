"""Authored reductions of the public CSAF note shape, never vendor captures."""

import copy
import hashlib
import json

import pytest

from infrastructure_impact.adapters.standards import csaf
from infrastructure_impact.application.publication import public_projection
from infrastructure_impact.application.query import state
from infrastructure_impact.domain import NormalizationError, validate_advisory
from infrastructure_impact.storage.repository import connect, ingest, latest

URL = "https://sec.cloudapps.cisco.com/synthetic-first-fixed.json"
CVE_IDS = ["CVE-2099-12345", "CVE-2099-12346"]
INTRO = (
    "In the following table, the left column lists Cisco software releases. "
    "The right column indicates whether a release is affected by the vulnerabilities "
    "that are described in this advisory and the first release that includes the fix "
    "for these vulnerabilities."
)
HEADER = "Cisco IOS XE Software Release  First Fixed Release"
END = (
    "The Cisco Product Security Incident Response Team (PSIRT) validates only "
    "the affected and fixed release information that is documented in this advisory."
)
BODY = (
    "17.8 and earlier  Migrate to a fixed release.      17.9  17.9.10      "
    "17.12  17.12.8      17.15  17.15.6      "
    "17.18  17.18.4, 17.18.4a      26.1  26.1.2"
)


def source():
    return {
        "document": {
            "title": "Synthetic Cisco IOS XE advisory",
            "tracking": {
                "id": "synthetic-iosxe",
                "status": "final",
                "version": "1.1.0",
                "initial_release_date": "2026-08-05T16:00:00Z",
                "current_release_date": "2026-10-02T19:21:28Z",
                "revision_history": [
                    {
                        "number": "1.1.0",
                        "date": "2026-10-02T19:21:28Z",
                        "summary": "Fixed information",
                    }
                ],
            },
            "notes": [
                {"title": "Summary", "category": "summary", "text": "Synthetic"},
                {
                    "title": "Fixed Software",
                    "category": "general",
                    "text": f"Fixed Releases\r\n{INTRO}\r\n  {HEADER}    {BODY}\r\n{END}",
                },
            ],
        },
        "product_tree": {
            "branches": [
                {
                    "category": "product_family",
                    "name": "Cisco IOS XE Software",
                    "branches": [
                        {
                            "category": "product_version",
                            "name": "17.9.9",
                            "product": {"name": "17.9.9", "product_id": "p1"},
                        }
                    ],
                }
            ]
        },
        "vulnerabilities": [
            {
                "cve": cid,
                "product_status": {"known_affected": ["p1"]},
                "notes": [{"category": "description", "text": "Retain me"}],
                "remediations": [{"category": "vendor_fix", "details": "Upgrade"}],
            }
            for cid in CVE_IDS
        ],
    }


def normalized(data=None, vendor="cisco"):
    return csaf(json.dumps(source() if data is None else data).encode(), URL, vendor)


def test_csaf_retains_shared_table_once_without_changing_original_claims():
    record = normalized()
    facts = record.get("first_fixed", [])
    assert len(facts) == 6
    assert [f["train"] for f in facts] == [None, "17.9", "17.12", "17.15", "17.18", "26.1"]
    assert facts[0]["train_expression"] == "17.8 and earlier"
    assert facts[0]["disposition"] == "migrate"
    assert facts[0]["fixed_versions"] == []
    assert facts[4]["fixed_versions"] == ["17.18.4", "17.18.4a"]
    assert (
        facts[4]["source_locator"] == "/document/notes/1/text / Fixed Releases / row[train=17.18]"
    )
    assert all(f["scope"] == "bulletin_shared" and f["cve_ids"] == CVE_IDS for f in facts)
    assert all(f["product_ids"] is None and f["product"] is None for f in facts)
    assert all(
        f["family"] == "cisco-iosxe"
        and f["method"] == "stated_table"
        and f["evidence_state"] == "publisher_stated"
        for f in facts
    )
    original = source()
    original["document"]["notes"] = []
    before = normalized(original)
    for field in ["assessments", "cves", "notes", "timeline", "published_at", "updated_at"]:
        assert record[field] == before[field]
    assert len(record["assessments"]) == 2
    assert not any("first_fixed" in a for a in record["assessments"])
    validate_advisory(record)


@pytest.mark.parametrize(
    "mutation",
    [
        "header",
        "end",
        "heading",
        "ownership",
        "duplicate_note",
        "duplicate_section",
        "duplicate_row",
        "malformed_row",
        "mixed_product",
        "unresolved_product",
        "missing_cve",
    ],
)
def test_ownership_or_structure_drift_is_visible_and_never_guessed(mutation):
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    note = data["document"]["notes"][1]
    if mutation == "duplicate_note":
        data["document"]["notes"].append(copy.deepcopy(note))
    elif mutation == "duplicate_section":
        note["text"] += "\n" + note["text"]
    elif mutation == "mixed_product":
        data["product_tree"]["branches"].append(
            {
                "category": "product_family",
                "name": "Cisco NX-OS Software",
                "product": {"name": "NX-OS", "product_id": "p2"},
            }
        )
        data["vulnerabilities"][1]["product_status"] = {"known_affected": ["p2"]}
    elif mutation == "unresolved_product":
        data["vulnerabilities"][1]["product_status"] = {"known_affected": ["missing"]}
    elif mutation == "missing_cve":
        data["vulnerabilities"][1].pop("cve")
    else:
        old, new = {
            "header": (HEADER, "Cisco IOS Software Release  First Fixed Release"),
            "end": (END, "Other legal prose 17.9.11"),
            "heading": ("Fixed Releases", "Other Releases"),
            "ownership": (INTRO, "This table concerns only CVE-2099-12345."),
            "duplicate_row": ("26.1  26.1.2", "17.9  17.9.11"),
            "malformed_row": ("26.1  26.1.2", "26.1"),
        }[mutation]
        note["text"] = note["text"].replace(old, new)
    result = extract_cisco_first_fixed(data)
    assert result["first_fixed"] == []
    assert result["issues"]
    record = normalized(data)
    assert not record.get("first_fixed")
    assert record["warnings"]


def test_missing_table_is_not_migration_and_non_cisco_csaf_is_unchanged():
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    data["document"]["notes"] = []
    result = extract_cisco_first_fixed(data)
    assert result["first_fixed"] == []
    assert result["issues"]
    assert "first_fixed" not in normalized(data)
    assert "first_fixed" not in normalized(vendor="aruba")


def test_unsupported_source_literals_survive_without_becoming_orderable():
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
        "17.9.10", "17.9.10w"
    )
    result = extract_cisco_first_fixed(data)
    assert result["first_fixed"][1]["fixed_versions"] == ["17.9.10w"]
    assert result["issues"]


@pytest.mark.parametrize(
    "change",
    [
        {"method": "inferred_next_release"},
        {"evidence_state": "inferred_candidate"},
        {"cve_ids": ["CVE-2099-99999"]},
        {"scope": "cve_specific"},
        {"scope": "unresolved"},
        {"disposition": "migrate"},
        {"source_locator": ""},
        {"private_payload": {"secret": "DO-NOT-PUBLISH"}},
    ],
)
def test_closed_fact_contract_rejects_forged_scope_method_and_payload(change):
    record = normalized()
    assert record.get("first_fixed"), "adapter must retain typed facts"
    record["first_fixed"][1].update(change)
    with pytest.raises(NormalizationError):
        validate_advisory(record)


def test_ingest_revision_and_public_projection_retain_typed_facts_and_provenance():
    data = source()
    raw = json.dumps(data).encode()
    with connect(":memory:") as db:
        assert ingest(db, raw, URL, csaf, "cisco")
        record = latest(db)[0]
        assert record.get("first_fixed"), "ingest must retain typed facts"
        assert record["sha256"] == hashlib.sha256(raw).hexdigest()
        assert record["source_observed_at"] and record["revision_id"]
        view = state(db, CVE_IDS)
        assert not ingest(db, raw, URL, csaf, "cisco")
        data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
            "17.9.10", "17.9.11"
        )
        assert ingest(db, json.dumps(data).encode(), URL, csaf, "cisco")
        rows = [
            json.loads(r[0]) for r in db.execute("SELECT normalized FROM revisions ORDER BY id")
        ]
        assert rows[0]["first_fixed"][1]["fixed_versions"] == ["17.9.10"]
        assert rows[1]["first_fixed"][1]["fixed_versions"] == ["17.9.11"]
    view["records"][0]["extensions"] = {"secret": "DO-NOT-PUBLISH"}
    projected = public_projection(view)
    output = next(r for r in projected["records"] if r["vendor"] == "cisco")
    assert output["first_fixed"] == record["first_fixed"]
    for key in ["source_url", "sha256", "source_observed_at", "revision_id"]:
        assert output[key] == record[key]
    assert output["notes"] == []
    assert "DO-NOT-PUBLISH" not in json.dumps(projected)


def test_absent_optional_field_keeps_old_schema_and_public_projection_compatible():
    data = source()
    data["document"]["notes"] = []
    record = normalized(data)
    assert "first_fixed" not in record
    validate_advisory(record)


@pytest.mark.parametrize("literal", ["17.9.10w", "17.9.10.1", "17.9.10(ED)", "１７.9.10"])
def test_unsupported_atomic_version_spellings_are_retained_with_diagnostics(literal):
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
        "17.9.10", literal
    )
    result = extract_cisco_first_fixed(data)
    assert len(result["first_fixed"]) == 6
    assert result["first_fixed"][1]["fixed_versions"] == [literal]
    assert result["issues"]


@pytest.mark.parametrize(
    "mutation",
    [
        "notes_not_array",
        "vulnerabilities_not_array",
        "vulnerability_not_object",
        "statuses_not_object",
        "status_not_array",
        "branch_not_object",
        "branches_not_array",
        "note_too_large",
        "too_many_rows",
        "wrong_train",
        "duplicate_alternative",
    ],
)
def test_malformed_or_unbounded_inputs_are_diagnostics_instead_of_exceptions(mutation):
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    if mutation == "notes_not_array":
        data["document"]["notes"] = None
    elif mutation == "vulnerabilities_not_array":
        data["vulnerabilities"] = None
    elif mutation == "vulnerability_not_object":
        data["vulnerabilities"][0] = None
    elif mutation == "statuses_not_object":
        data["vulnerabilities"][0]["product_status"] = None
    elif mutation == "status_not_array":
        data["vulnerabilities"][0]["product_status"] = {"known_affected": "p1"}
    elif mutation == "branch_not_object":
        data["product_tree"]["branches"] = [None]
    elif mutation == "branches_not_array":
        data["product_tree"]["branches"] = None
    elif mutation == "note_too_large":
        data["document"]["notes"][1]["text"] += "x" * 131072
    else:
        old, new = {
            "too_many_rows": (BODY, "      ".join(f"17.{i}  17.{i}.1" for i in range(101))),
            "wrong_train": ("17.9.10", "17.12.10"),
            "duplicate_alternative": ("17.18.4, 17.18.4a", "17.18.4, 17.18.4"),
        }[mutation]
        data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
            old, new
        )
    result = extract_cisco_first_fixed(data)
    assert result["first_fixed"] == []
    assert result["issues"]


def test_prose_in_fixed_release_cell_is_not_a_version_literal():
    from infrastructure_impact.adapters.cisco_first_fixed import extract_cisco_first_fixed

    data = source()
    data["document"]["notes"][1]["text"] = data["document"]["notes"][1]["text"].replace(
        "26.1.2", "Unavailable."
    )
    result = extract_cisco_first_fixed(data)
    assert result["first_fixed"] == []
    assert result["issues"]


@pytest.mark.parametrize(
    "change",
    [
        {"method": "inferred_next_release", "evidence_state": "inferred_candidate"},
        {"fixed_versions": []},
        {"cve_ids": None},
        {"cve_ids": []},
        {"scope": "unresolved", "cve_ids": None},
        {"disposition": "unknown"},
    ],
)
def test_source_facts_cannot_forge_candidates_or_incomplete_owned_fixes(change):
    record = normalized()
    record["first_fixed"][1].update(change)
    with pytest.raises(NormalizationError):
        validate_advisory(record)


def test_unresolved_unknown_fact_keeps_ownership_explicitly_unknown():
    record = normalized()
    record["first_fixed"] = [
        dict(
            record["first_fixed"][1],
            scope="unresolved",
            cve_ids=None,
            disposition="unknown",
            fixed_versions=[],
        )
    ]
    validate_advisory(record)


def test_old_record_without_facts_survives_actual_public_projection():
    data = source()
    data["document"]["notes"] = []
    with connect(":memory:") as db:
        ingest(db, json.dumps(data).encode(), URL, csaf, "cisco")
        view = state(db, CVE_IDS)
    output = public_projection(view)
    assert len(output["records"]) == 1
    assert "first_fixed" not in output["records"][0]
