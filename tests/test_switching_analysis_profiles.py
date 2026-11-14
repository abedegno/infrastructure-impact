"""Closed installed profile behavior; rejection inputs are authored, not captures."""

import importlib
import json
from hashlib import sha256

import pytest

PROFILE = "campus-switching-openvuln-2026-11-14-v1"
DIGEST = "e8cc5e131c3c2bd835185795357044f427ec9c796f708a98eb652f9831289356"


def module():
    return importlib.import_module("infrastructure_impact.application.switching_analysis_profiles")


def authored():
    return {
        "policy_source": {
            "url": "https://sec.cloudapps.cisco.com/security/center/resources/risk-based-disclosure",
            "sha256": "a" * 64,
            "retrieved_at": "2026-11-14T10:00:00+00:00",
        },
        "api_results": [
            {
                "source": {
                    "url": f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version=17.12.{i}",
                    "sha256": "b" * 64,
                    "retrieved_at": "2026-11-14T10:00:00+00:00",
                },
                "query_release": f"17.12.{i}",
                "parser_revision": "cisco-first-fixed-api-2",
                "first_fixed": [],
                "advisory_context": [
                    {
                        "advisory_id": "cisco-sa-synthetic-test",
                        "source_locator": "/advisories/0/firstFixed",
                        "source_first_fixed": [],
                        "first_fixed_state": "empty",
                        "cve_refs": ["CVE-2026-12345"],
                        "ownership_state": "ownership_unresolved",
                    }
                ],
                "issues": ["ownership_unresolved", "empty_first_fixed"],
            }
            for i in range(59)
        ],
        "calibration_records": [],
    }


def decode(value):
    raw = json.dumps(value).encode()
    return module()._decode(raw, expected_sha256=sha256(raw).hexdigest())


def test_default_does_not_read_resource(monkeypatch):
    def forbidden(*args):
        raise AssertionError("default read resource")

    monkeypatch.setattr(module(), "files", forbidden)
    assert module().build_options() == {}
    assert module().build_options("") == {}


def test_installed_identity_and_fresh_options():
    selected = module().profile(PROFILE)
    assert selected.identity() == {"profile_id": PROFILE, "input_sha256": DIGEST, "api_frames": 59}
    options = selected.build_options()
    assert set(options) == {"include_switching_analysis", "switching_analysis_input"}
    assert options["include_switching_analysis"] is True
    frame = options["switching_analysis_input"]
    assert set(frame) == {"policy_source", "api_results", "calibration_records"}
    assert len(frame["api_results"]) == 59
    assert sum(len(f["advisory_context"]) for f in frame["api_results"]) == 1800
    assert all(set(f["source"]) == {"url", "sha256", "retrieved_at"} for f in frame["api_results"])
    frame["api_results"].clear()
    assert len(selected.build_options()["switching_analysis_input"]["api_results"]) == 59
    assert module().build_options(PROFILE) == selected.build_options()
    selected.identity().clear()
    assert selected.identity()["api_frames"] == 59


@pytest.mark.parametrize(
    "selector",
    ["", "unknown", "../profile", "/tmp/input.json", "https://apix.cisco.com/", None, True, {}],
)
def test_unknown_selectors_fail(selector):
    with pytest.raises(ValueError):
        module().profile(selector)
    if selector != "":
        with pytest.raises(ValueError):
            module().build_options(selector)


def test_authored_public_frame_accepted():
    assert decode(authored()) == authored()


@pytest.mark.parametrize(
    "change",
    [
        "extra",
        "calibration",
        "frame_extra",
        "evidence_id",
        "source_extra",
        "private_url",
        "credential_url",
        "query",
        "fragment",
        "receipt",
        "time",
        "parser",
        "query_release",
        "count",
        "duplicate",
        "context_extra",
        "ownership",
        "state",
        "locator",
        "cve",
        "fixed",
        "issues",
        "first_fixed",
        "huge_context",
        "policy",
        "bool",
        "text",
    ],
)
def test_rejects_unreviewed_or_inconsistent_fields(change):
    value = authored()
    frame = value["api_results"][0]
    context = frame["advisory_context"][0]
    if change == "extra":
        value["path"] = "/private/local"
    elif change == "calibration":
        value["calibration_records"] = [{}]
    elif change == "frame_extra":
        frame["token"] = "private"
    elif change == "evidence_id":
        frame["source"]["evidence_id"] = 1
    elif change == "source_extra":
        frame["source"]["headers"] = {}
    elif change == "private_url":
        frame["source"]["url"] = "http://localhost/private"
    elif change == "credential_url":
        frame["source"]["url"] = frame["source"]["url"].replace("https://", "https://x:y@")
    elif change == "query":
        frame["source"]["url"] += "&token=x"
    elif change == "fragment":
        frame["source"]["url"] += "#private"
    elif change == "receipt":
        frame["source"]["sha256"] = "A" * 64
    elif change == "time":
        frame["source"]["retrieved_at"] = "2026-11-14T10:00:00"
    elif change == "parser":
        frame["parser_revision"] = "cisco-first-fixed-api-1"
    elif change == "query_release":
        frame["query_release"] = "17.15.1"
    elif change == "count":
        value["api_results"].pop()
    elif change == "duplicate":
        value["api_results"][1] = frame
    elif change == "context_extra":
        context["local_path"] = "/private"
    elif change == "ownership":
        context["ownership_state"] = "owned"
    elif change == "state":
        context["first_fixed_state"] = "present"
    elif change == "locator":
        context["source_locator"] = "/private/path"
    elif change == "cve":
        context["cve_refs"] = ["token"]
    elif change == "fixed":
        context["source_first_fixed"] = ["https://private/"]
    elif change == "issues":
        frame["issues"] = ["private token"]
    elif change == "first_fixed":
        frame["first_fixed"] = [{}]
    elif change == "huge_context":
        frame["advisory_context"] *= 2001
    elif change == "policy":
        value["policy_source"]["url"] += "?secret=x"
    elif change == "bool":
        frame["query_release"] = True
    elif change == "text":
        context["advisory_id"] = "cisco-sa-" + "x" * 500
    with pytest.raises(ValueError):
        decode(value)


@pytest.mark.parametrize(
    "raw",
    [b'{"a":1,"a":2}', b"NaN", b"1e999", b"\xff", b"{", b"[]", b'"' + b"x" * 1_000_000 + b'"'],
)
def test_strict_bounded_json(raw):
    with pytest.raises(ValueError):
        module()._decode(raw, expected_sha256=sha256(raw).hexdigest())


def test_tampered_resource_rejected(monkeypatch, tmp_path):
    package = tmp_path / "resources" / "switching-analysis"
    package.mkdir(parents=True)
    (package / (PROFILE + ".json")).write_text(json.dumps(authored()))
    monkeypatch.setattr(module(), "files", lambda _: tmp_path)
    with pytest.raises(ValueError, match="digest"):
        module().profile(PROFILE)


def test_installed_package_probe_checks_profile():
    from pathlib import Path

    from checks.package_probe import check_switching_analysis_profile

    check_switching_analysis_profile(Path(__file__).resolve().parents[1] / "infrastructure_impact")
