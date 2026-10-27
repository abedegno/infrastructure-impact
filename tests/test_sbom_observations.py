"""Private SBOM subset observations cannot certify firmware, patches or exposure."""

import json
import os
from copy import deepcopy
from hashlib import sha256
from unittest.mock import patch

import pytest

from infrastructure_impact.application import sbom
from infrastructure_impact.research_cli import main


def cdx(version="1.7"):
    return dict(
        bomFormat="CycloneDX",
        specVersion=version,
        metadata=dict(
            timestamp="2026-10-27T00:00:00Z",
            component=dict(
                type="firmware", name="Example firmware", version="1.0", **{"bom-ref": "image"}
            ),
            authors=[dict(name="PRIVATE_SENTINEL")],
        ),
        components=[
            dict(
                type="library",
                name="openssh",
                version="9.7p1-2.vendor",
                scope="excluded",
                **{"bom-ref": "ssh-old"},
                components=[
                    dict(
                        type="library",
                        name="openssh",
                        version="9.8p1-4.vendor",
                        **{"bom-ref": "ssh-new"},
                    )
                ],
            ),
            dict(type="library", name="OpenSSH", version="1.0", **{"bom-ref": "different-case"}),
        ],
        vulnerabilities=[dict(id="CVE-2099-99999", analysis=dict(state="not_affected"))],
        externalReferences=[dict(type="bom", url="https://private.example/PRIVATE_SENTINEL")],
    )


def spdx():
    return dict(
        spdxVersion="SPDX-2.3",
        SPDXID="SPDXRef-DOCUMENT",
        documentDescribes=["SPDXRef-Image"],
        creationInfo=dict(created="2026-10-27T00:00:00Z", creators=["Person: PRIVATE_SENTINEL"]),
        packages=[
            dict(
                SPDXID="SPDXRef-Image",
                name="Example firmware",
                versionInfo="1.0",
                primaryPackagePurpose="FIRMWARE",
            ),
            dict(
                SPDXID="SPDXRef-SSH",
                name="openssh",
                versionInfo="9.7p1-2.vendor",
                externalRefs=[
                    dict(
                        referenceCategory="PACKAGE-MANAGER",
                        referenceType="purl",
                        referenceLocator="pkg:rpm/vendor/openssh@9.7p1-2.vendor",
                    ),
                    dict(
                        referenceCategory="SECURITY",
                        referenceType="cpe23Type",
                        referenceLocator="cpe:2.3:a:example:openssh:9.7:*:*:*:*:*:*:*",
                    ),
                ],
                checksums=[
                    dict(algorithm="SHA256", checksumValue="A" * 64),
                    dict(algorithm="SHA1", checksumValue="b" * 40),
                ],
            ),
        ],
        externalDocumentRefs=[dict(spdxDocument="https://private.example/PRIVATE_SENTINEL")],
    )


def inspect(value, **kwargs):
    raw = json.dumps(value).encode()
    result = sbom.inspect(raw, **kwargs)
    assert result["source_sha256"] == sha256(raw).hexdigest()
    assert result["source_bytes"] == len(raw)
    assert (
        result["inventory_verified"]
        is result["cve_assessments_created"]
        is result["metric_eligibility_changed"]
        is result["evidence_published"]
        is False
    )
    assert not result["full_standards_validation_performed"]
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    assert "CVE-2099-99999" not in json.dumps(result)
    return result


@pytest.mark.parametrize("version", ["1.5", "1.6", "1.7"])
def test_cyclonedx_preserves_multiple_instances_exact_names_and_parent_scope(version):
    result = inspect(cdx(version), component="openssh")
    assert result["observed_components"] == 4 and result["returned_components"] == 2
    a, b = result["components"]
    assert a["literal_version"] == "9.7p1-2.vendor" and a["declared_scope"] == "excluded"
    assert b["literal_version"] == "9.8p1-4.vendor" and b["parent_locator"] == a["locator"]
    assert b["declared_scope"] is None  # No inherited runtime conclusion.
    assert inspect(cdx(version), component="libopenssh")["returned_components"] == 0
    assert inspect(cdx(version), component="OpenSSH")["returned_components"] == 1


@pytest.mark.parametrize("version", ["SPDX-2.2", "SPDX-2.3"])
def test_spdx_subject_package_version_and_hashes_are_literal_observations(version):
    value = spdx()
    value["spdxVersion"] = version
    result = inspect(value)
    subject, package = result["components"]
    assert subject["role"] == "declared_document_subject"
    assert package["role"] == "listed_component"
    assert package["literal_version"] == "9.7p1-2.vendor"
    assert package["purls"] == ["pkg:rpm/vendor/openssh@9.7p1-2.vendor"]
    assert package["cpes"][0].startswith("cpe:2.3:")
    assert package["package_hashes"] == [
        dict(algorithm="sha256", value="a" * 64, locator="$.packages[1].checksums[0]")
    ]
    assert package["hash_algorithms_not_normalized"] == 1


def test_external_version_range_is_not_a_bundled_literal_version():
    value = cdx()
    value["components"] = [
        dict(type="library", name="openssl", isExternal=True, versionRange="vers:generic/>=3.0.0")
    ]
    entry = inspect(value, component="openssl")["components"][0]
    assert entry["literal_version"] is None and entry["declared_is_external"] is True
    assert entry["declared_version_range"] == "vers:generic/>=3.0.0"
    for mutate in [
        lambda d: d.update(specVersion="1.6"),
        lambda d: d["components"][0].update(isExternal=False),
        lambda d: d["components"][0].update(version="3.0.0"),
    ]:
        altered = deepcopy(value)
        mutate(altered)
        with pytest.raises(ValueError):
            inspect(altered)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(specVersion="1.99"),
        lambda d: d.update(spdxVersion="SPDX-2.3"),
        lambda d: d["components"][0].update(version=3),
        lambda d: d["components"][0].update(name=[]),
        lambda d: d["components"][0].update(**{"bom-ref": "image"}),
        lambda d: d["components"][0].update(isExternal="yes"),
        lambda d: d["metadata"]["component"].update(isExternal=True),
        lambda d: d["components"][0].update(purl="https://example.com/package"),
        lambda d: d["components"][0].update(hashes=[dict(alg="SHA-256", content="invalid")]),
        lambda d: d["components"][0].update(components={}),
    ],
)
def test_selected_component_structure_cannot_be_ambiguous_or_malformed(mutate):
    value = cdx()
    mutate(value)
    with pytest.raises(ValueError):
        inspect(value)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(spdxVersion="SPDX-3.0"),
        lambda d: d.update(SPDXID="SPDXRef-Other"),
        lambda d: d["packages"][1].update(SPDXID="SPDXRef-Image"),
        lambda d: d["packages"][1].update(SPDXID=[]),
        lambda d: d["packages"][1]["externalRefs"][1].update(referenceType=[]),
        lambda d: d["packages"][1].update(versionInfo={}),
    ],
)
def test_spdx_package_identifiers_and_selected_fields_require_unambiguous_types(mutate):
    value = spdx()
    mutate(value)
    with pytest.raises(ValueError):
        inspect(value)


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}',
        b'{"x":NaN}',
        b'{"x":1e999}',
        b"\xff",
        b"<" * 10,
    ],
)
def test_invalid_nonfinite_or_ambiguous_json_is_rejected(raw):
    with pytest.raises(ValueError):
        sbom.inspect(raw)


def test_missing_versions_stay_null_and_dont_derive_from_package_urls():
    value = spdx()
    del value["packages"][1]["versionInfo"]
    row = inspect(value, component="openssh")["components"][0]
    assert row["literal_version"] is None and "9.7p1" in row["purls"][0]


def test_global_item_and_nested_component_budgets_apply_before_filtering(monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(sbom, "MAX_COMPONENTS", 1)
        with pytest.raises(ValueError):
            inspect(cdx(), component="not present")
    value = cdx()
    node = value["components"][0]
    for _ in range(sbom.MAX_DEPTH + 1):
        child = dict(name="nested")
        node["components"] = [child]
        node = child
    with pytest.raises(ValueError, match="nesting"):
        inspect(value)
    with monkeypatch.context() as context:
        context.setattr(sbom, "MAX_BYTES", 10)
        with pytest.raises(ValueError, match="budget"):
            inspect(cdx())


def test_cli_reads_no_vault_or_external_documents_and_summary_omits_values(tmp_path, capsys):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(cdx()))
    with (
        patch(
            "infrastructure_impact.research_cli.connect",
            side_effect=AssertionError("Vault forbidden"),
        ),
        patch("urllib.request.urlopen", side_effect=AssertionError("Network forbidden")),
    ):
        main(["sbom-inspect", str(path), "--component", "openssh", "--summary"])
    result = json.loads(capsys.readouterr().out)
    assert result["returned_components"] == 2 and "components" not in result
    assert "selected_component_name" not in result
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    path.write_text('{"PRIVATE_SENTINEL":1}')
    with pytest.raises(SystemExit):
        main(["sbom-inspect", str(path)])
    assert "PRIVATE_SENTINEL" not in capsys.readouterr().err


def test_regular_file_reader_rejects_links_directories_and_nonblocking_fifo(tmp_path):
    p = tmp_path / "bom.json"
    p.write_text(json.dumps(cdx()))
    assert sbom.read_local(p) == p.read_bytes()
    link = tmp_path / "link.json"
    link.symlink_to(p)
    with pytest.raises(OSError):
        sbom.read_local(link)
    with pytest.raises((OSError, ValueError)):
        sbom.read_local(tmp_path)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        sbom.read_local(fifo)


def test_summary_has_its_own_contract_kind_and_never_copies_private_values():
    report = inspect(cdx(), component="openssh")
    report["method"] = "PRIVATE_SENTINEL"
    result = sbom.summary(report)
    sbom.validator().validate(result)
    assert result["kind"] == "private_sbom_summary"
    assert "components" not in result and "selected_component_name" not in result
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    assert sbom.summary(result) == result
    modified = deepcopy(result)
    modified["kind"] = "private_sbom_observations"
    assert list(sbom.validator().iter_errors(modified))
    modified = deepcopy(result)
    modified["components"] = []
    assert list(sbom.validator().iter_errors(modified))


def test_nonbyte_sbom_input_cannot_claim_original_artifact_provenance():
    with pytest.raises(ValueError, match="original JSON file bytes"):
        sbom.inspect(json.dumps(cdx()))


def test_strict_text_json_budget_counts_encoded_bytes():
    from infrastructure_impact.application.strict_json import loads

    with pytest.raises(ValueError, match="budget"):
        loads('"éé"', budget=5)
