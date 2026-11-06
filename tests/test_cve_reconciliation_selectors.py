"""Authored synthetic records; no source captures or operational receipts."""

import hashlib
import importlib
import json
from copy import deepcopy
from pathlib import Path

import pytest

from infrastructure_impact.reconciliation.snapshot import Entry, Snapshot

CISCO = "d1c1063e-7a18-46af-9102-31f8928bc633"
HPE = "eb103674-0d28-4225-80f8-39fb86215de0"
ARISTA = "c8b34d1a-69ae-45c3-88fe-f3b3d44f39b7"
OTHER = "11111111-1111-4111-8111-111111111111"


def api():
    return importlib.import_module("infrastructure_impact.reconciliation.selectors")


def product(name="Cisco IOS XE Software", vendor="Cisco", status="affected", **extra):
    return dict(vendor=vendor, product=name, versions=[dict(version="1.2", status=status)], **extra)


def container(products=(), provider=CISCO, references=(), **extra):
    return dict(
        providerMetadata=dict(orgId=provider, shortName="synthetic"),
        affected=list(products),
        references=list(references),
        **extra,
    )


def record(cna=None, adp=(), **meta):
    return dict(
        dataType="CVE_RECORD",
        dataVersion="5.1",
        cveMetadata=dict(
            cveId="CVE-1999-1234",
            state="PUBLISHED",
            assignerOrgId=CISCO,
            datePublished="2026-03-02T23:15:00Z",
            **meta,
        ),
        containers=dict(cna=cna if cna is not None else container([product()]), adp=list(adp)),
    )


def select(value, *, path="cves/1999/1xxx/CVE-1999-1234.json", **options):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    entry = Entry(path, "CVE-1999-1234", "a" * 40, len(raw))
    snap = Snapshot("b" * 40, "c" * 40, "d" * 64, 1, 100, Path("unused"), (entry,))
    return api().select_record(
        raw,
        entry=entry,
        snapshot=snap,
        rules=api().load_selectors(),
        start_date="2026-01-01",
        end_date="2026-12-31",
        **options,
    )


# Catches merged CNA/ADP products, references, or provider identities.
def test_cna_adp_and_copied_refs_remain_separate():
    ref = dict(url="https://security.example.test/advisory", tags=["x_transferred"])
    value = record(
        container([product()], references=[ref]),
        [container([product(status="unaffected")], OTHER, [ref])],
    )
    result = select(value)
    assert result["outcome"] == "parsed"
    rows = result["findings"]
    assert [
        (
            r["container_type"],
            r["container_index"],
            r["provider_identity"]["orgId"],
            r["trusted_vendor_cna"],
        )
        for r in rows
    ] == [("cna", 0, CISCO, True), ("adp", 0, OTHER, False)]
    assert [r["references"][0]["locator"] for r in rows] == [
        "/containers/cna/references/0",
        "/containers/adp/0/references/0",
    ]
    assert all(r["references"][0]["row"] == ref for r in rows)
    assert rows[0]["product"]["versions"][0]["status"] == "affected"
    assert rows[1]["product"]["versions"][0]["status"] == "unaffected"
    assert result["source_sha256"] == hashlib.sha256(json.dumps(value).encode()).hexdigest()
    assert result["source_url"] == (
        "https://raw.githubusercontent.com/CVEProject/cvelistV5/"
        + "b" * 40
        + "/cves/1999/1xxx/CVE-1999-1234.json"
    )
    assert rows[0]["matching_rules"][0]["locator"] == "/containers/cna/affected/0/product"


# Catches filtering away unaffected/unknown rows or flattening version changes/platforms.
def test_family_rows_include_unknown_and_unaffected_branches():
    branches = [
        product(status=s, platforms=["synthetic switch"], defaultStatus="unknown")
        for s in ["affected", "unaffected", "unknown"]
    ]
    branches[0]["versions"][0].update(
        lessThan="9", versionType="custom", changes=[dict(at="5", status="unaffected")]
    )
    result = select(record(container(branches)))
    assert len(result["findings"]) == 3
    assert [r["product"] for r in result["findings"]] == branches
    assert {r["discovery_class"] for r in result["findings"]} == {"explicit_family_row"}
    assert {r["family"] for r in result["findings"]} == {"cisco-iosxe"}
    assert result["discovery_class"] == "explicit_family_row"
    assert not any(k in result for k in ["assessments", "impact", "affected", "advisory"])


# Catches substring/brand/component matching, IOS/XR and ArubaOS conflation, bare EOS trust.
@pytest.mark.parametrize(
    "name,vendor,family,classification",
    [
        ("Cisco IOS XE Software", "Cisco", "cisco-iosxe", "explicit_family_row"),
        ("IOS XE", "Cisco", "cisco-iosxe", "explicit_family_row"),
        ("IOS", "Cisco", None, "non_target"),
        ("Cisco IOS XR Software", "Cisco", None, "non_target"),
        ("Cisco IOS XE Software helper", "Acme", None, "non_target"),
        ("AOS-CX", "Hewlett Packard Enterprise (HPE)", "aruba-aoscx", "explicit_family_row"),
        ("ArubaOS", "Hewlett Packard Enterprise (HPE)", None, "non_target"),
        ("EOS", "Arista Networks", "arista-eos", "explicit_family_row"),
        ("EOS", "n/a", "arista-eos", "ambiguous_family_lead"),
        ("EOS", "Canon", None, "non_target"),
        ("OpenSSL", "Cisco", None, "non_target"),
        ("OpenSSH", "Arista Networks", None, "non_target"),
        ("Linux", "HPE", None, "non_target"),
    ],
)
def test_lookalikes_components_and_vendor_domain_do_not_prove_family(
    name,
    vendor,
    family,
    classification,
):
    result = select(record(container([product(name, vendor)], OTHER)))
    assert result["discovery_class"] == classification
    assert [r["family"] for r in result["findings"]] == ([family] if family else [])


# Catches provider gating and status-conflict resolution instead of preserving assertions.
def test_unknown_provider_and_conflicts_remain_visible():
    rows = [product(status="affected"), product(status="unaffected")]
    c = container(rows, OTHER)
    del c["providerMetadata"]["orgId"]
    result = select(record(c, [container([product("AOS-CX", "n/a")], HPE)]))
    assert len(result["findings"]) == 3
    assert not any(r["trusted_vendor_cna"] for r in result["findings"])
    assert "unknown_provider" in result["diagnostic_codes"]
    assert result["findings"][0]["provider_identity"] == {"shortName": "synthetic"}
    assert [r["product"]["versions"][0]["status"] for r in result["findings"][:2]] == [
        "affected",
        "unaffected",
    ]
    # A reference-only vendor route is a lead, even when the actual product is upstream.
    ref = dict(url="https://support.hpe.com/advisory/synthetic")
    result = select(record(container([product("OpenSSH", "upstream")], OTHER, [ref])))
    assert result["discovery_class"] == "reference_only_lead"
    assert result["findings"][0]["product"] is None
    assert result["findings"][0]["family"] == "aruba-aoscx"
    result = select(
        record(
            container(
                [],
                OTHER,
                descriptions=[
                    dict(lang="en", value="A synthetically authored Cisco IOS XE Software mention.")
                ],
            )
        )
    )
    assert result["discovery_class"] == "ambiguous_family_lead"
    assert result["findings"][0]["product"] is None


# Catches CVE-year filtering, dateUpdated fallback, and invalid/date-only timestamp guessing.
@pytest.mark.parametrize(
    "published,want",
    [
        ("2026-01-01T00:00:00Z", "inside"),
        ("2026-12-31T23:59:59.999Z", "inside"),
        ("2025-12-31T23:59:59Z", "outside"),
        (None, "unknown"),
        ("not-a-date", "unknown"),
        ("2026-02-30T00:00:00Z", "unknown"),
        ("2026-03-02", "unknown"),
    ],
)
def test_old_id_recent_publication_and_unknown_dates(published, want):
    value = record()
    value["cveMetadata"].update(datePublished=published, dateUpdated="2026-04-01T00:00:00Z")
    result = select(value)
    assert result["cve_id"] == "CVE-1999-1234"
    assert result["date_window_state"] == want
    assert result["dates"]["datePublished"] == published
    assert result["dates"]["dateUpdated"] == "2026-04-01T00:00:00Z"
    assert len(result["findings"]) == 1


# Catches accepting bad identities, future schema versions, invalid shapes, or rejected targets.
@pytest.mark.parametrize(
    "mutation,outcome,code",
    [
        ("id", "invalid", "record_id_mismatch"),
        ("path", "invalid", "record_path_mismatch"),
        ("future", "unsupported_version", "unsupported_data_version"),
        ("missing_version", "invalid", "invalid_record_structure"),
        ("missing_cna", "invalid", "invalid_record_structure"),
        ("bad_products", "invalid", "invalid_record_structure"),
        ("bad_adp", "invalid", "invalid_record_structure"),
        ("reserved", "invalid", "unsupported_record_state"),
        ("rejected", "rejected_record", "record_rejected"),
    ],
)
def test_path_id_and_data_version_are_validated(mutation, outcome, code):
    value, options = record(), {}
    if mutation == "id":
        value["cveMetadata"]["cveId"] = "CVE-2026-5555"
    if mutation == "path":
        options["path"] = "cves/2026/1xxx/CVE-1999-1234.json"
    if mutation == "future":
        value["dataVersion"] = "5.99"
    if mutation == "missing_version":
        del value["dataVersion"]
    if mutation == "missing_cna":
        del value["containers"]["cna"]
    if mutation == "bad_products":
        value["containers"]["cna"]["affected"] = ["bad"]
    if mutation == "bad_adp":
        value["containers"]["adp"] = [False]
    if mutation == "reserved":
        value["cveMetadata"]["state"] = "RESERVED"
    if mutation == "rejected":
        value["cveMetadata"]["state"] = "REJECTED"
    result = select(value, **options)
    assert result["outcome"] == outcome
    assert result["findings"] == []
    assert code in result["diagnostic_codes"]
    assert result["discovery_class"] == (
        "rejected_record" if mutation == "rejected" else "unprocessed"
    )
    for version in ["5.1", "5.2"]:
        supported = record()
        supported["dataVersion"] = version
        assert select(supported)["outcome"] == "parsed"


# Catches leaking source strings/parser exceptions/credentialed URLs into safe diagnostics.
def test_source_text_and_url_credentials_are_not_diagnostics():
    secret = "SYNTHETIC_PRIVATE_TOKEN"
    result = select(b'{"' + secret.encode() + b'":')
    assert result["diagnostic_codes"] == ["invalid_json"]
    assert secret not in json.dumps(result)
    ref = dict(url=f"https://user:{secret}@www.arista.com/advisory", name=secret)
    value = record(container([product("OpenSSL", "unknown")], OTHER, [ref]))
    result = select(value)
    assert result["discovery_class"] == "non_target"
    assert secret not in json.dumps(result["diagnostic_codes"])
    result = select(record(container([product()], references=[ref])))
    assert result["findings"][0]["references"][0]["row"] == ref
    assert secret not in json.dumps(result["diagnostic_codes"])
    assert select(b'{"dataVersion":"5.1","dataVersion":"5.2"}')["outcome"] == "invalid"
    assert select(b'{"x":NaN}')["outcome"] == "invalid"
    assert select(b"[]")["outcome"] == "invalid"


# Catches rules hash dependence on key insertion order and accidental shared mutable rules.
def test_selector_hash_is_canonical_and_rules_are_fresh():
    rules = api().load_selectors()
    original = deepcopy(rules)
    reordered = dict(reversed(list(rules.items())))
    assert api().selector_hash(rules) == api().selector_hash(reordered)
    assert len(api().selector_hash(rules)) == 64
    rules["families"].clear()
    assert api().load_selectors() == original
    assert api().selector_hash(rules) != api().selector_hash(original)


# Catches promoting unreviewed CPE bindings into family claims or losing literal CPE context.
def test_cpe_context_is_retained_without_a_family_binding():
    cpe = "cpe:2.3:o:synthetic:unreviewed_os:*:*:*:*:*:*:*:*"
    context = [dict(nodes=[dict(cpeMatch=[dict(criteria=cpe, vulnerable=False)])])]
    row = product(cpes=[cpe])
    result = select(record(container([row], cpeApplicability=context)))
    assert result["findings"][0]["product"]["cpes"] == [cpe]
    assert result["findings"][0]["container_cpe_applicability"] == context
    value = record(
        container([dict(vendor="n/a", product="n/a", cpes=[cpe])], cpeApplicability=context)
    )
    assert select(value)["discovery_class"] == "non_target"


# Catches hiding an assigner/provider disagreement behind a false trusted flag.
def test_assigner_provider_conflict_remains_explicit():
    result = select(record(container([product()], OTHER)))
    assert result["assigner_org_id"] == CISCO
    assert result["findings"][0]["provider_identity"]["orgId"] == OTHER
    assert result["findings"][0]["trusted_vendor_cna"] is False
    assert "cna_assigner_mismatch" in result["diagnostic_codes"]
