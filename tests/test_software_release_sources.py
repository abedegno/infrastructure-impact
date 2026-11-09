"""Synthetic reviewed release evidence; raw publisher captures stay outside Git."""

from copy import deepcopy
from importlib import import_module
from unittest.mock import patch

import pytest

from infrastructure_impact.collection.config import validate_config
from infrastructure_impact.collection.service import run
from infrastructure_impact.references.registry import SOURCES, source
from infrastructure_impact.references.storage import ingest
from infrastructure_impact.storage.repository import collection_result, connect

ARUBA = "aruba-aos-cx-6300-6400-10-14-history"
ARUBA16 = "aruba-aos-cx-6300-6400-10-16-history"
MODELS = "aruba-aos-cx-6300-6400-10-14-models"
CISCO = "cisco-iosxe-17-12-1-release"
ARISTA = "arista-eos-advisory-bundle-0148"
IDS = [ARUBA, ARUBA16, MODELS, CISCO, ARISTA]


def api():
    return import_module("infrastructure_impact.references.software_releases")


def table(headers, rows):
    return (
        "<table><tr>"
        + "".join(f"<th>{h}</th>" for h in headers)
        + "</tr>"
        + "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
        + "</table>"
    )


def history(branch="10.14", rows=None):
    return (
        "<title>Version history</title><h1>Version history</h1>"
        + table(
            ["Version number", "Release date", "Remarks"],
            rows
            if rows is not None
            else [
                [
                    branch + ".0007",
                    "12 July 2024",
                    "Released, fully supported, and posted on the Web.",
                ],
                [branch + ".0001", "29 May 2024", "Initial release."],
            ],
        )
        + "<footer>Published October 2026</footer>"
    ).encode()


def models():
    return (
        "<title>Products Supported</title><h1>Products Supported</h1>"
        + table(
            ["Product Number", "Product Name", "Minimum Software Version"],
            [
                ["R8S89A", "HPE Aruba Networking CX 6300M Switch", "10.10.0002"],
                ["R0X27A", "Aruba 6410 Switch", "10.05.0001"],
                ["SYN01A", "HPE Aruba Networking 6300M Switch", "10.16.1006"],
            ],
        )
    ).encode()


def cisco():
    return b"<title>Cisco IOS XE Dublin 17.12.1 - Cisco</title><h1>Cisco IOS XE Dublin 17.12.1</h1><section><h2>Cisco IOS XE Dublin 17.12.1</h2><dl><dt>Release Date</dt><dd>31-Jul-2023</dd></dl></section><h2>Documentation</h2><p>Updated November 9, 2026</p>"


def bundle():
    # Synthetic filler rows exercise complete table ownership, not real URL discovery.
    filler = [
        [
            f'<a href="/en/support/advisories-notices/security-advisory/90000-security-advisory-{identity:04}">{identity}</a>',
            "EOS (Synthetic component)"
            if identity < 179
            else "VeloCloud Edge (Synthetic component)",
            "CVE-2026-12347",
            "Medium",
            "5.0",
        ]
        for identity in range(150, 183)
        if identity != 179
    ]
    return (
        "<h2>Security Advisory 0148 PDF</h2><p>September 2, 2026</p>"
        + table(
            ["Revision", "Date", "Changes"],
            [
                ["1.0", "September 02, 2026", "Initial release"],
                ["1.1", "September 09, 2026", "Updated Information"],
            ],
        )
        + "<p>On September 09, 2026 Arista published multiple Security Advisories. This update serves as a summary of those security advisories.</p>"
        + table(
            ["Security Advisory #", "Product (Component)", "CVE ID", "Severity", "CVSS 3.1 Score"],
            [
                [
                    '<a href="/en/support/advisories-notices/security-advisory/24705-security-advisory-0149">149</a>',
                    "EOS (802.1X)",
                    "CVE-2026-12345",
                    "Medium",
                    "5.9",
                ],
                [
                    '<a href="/en/support/advisories-notices/security-advisory/24735-security-advisory-0179">179</a>',
                    "VeloCloud Edge (HA)",
                    "CVE-2026-12346",
                    "Critical",
                    "9.6",
                ],
            ]
            + filler,
        )
    ).encode()


def test_reviewed_routes_only_and_missing_sources_remain_visible():
    assert all(key in SOURCES for key in IDS), "Release sources must be explicitly registered"
    import sqlite3

    with sqlite3.connect(":memory:") as db:
        values = api().inputs(db, {"vendors": []})
    assert [v["source_id"] for v in values] == IDS
    assert all(not v["configured"] and not v["enabled"] and v["retained"] is None for v in values)
    for key in IDS:
        spec = source(key)
        assert spec.purpose == "release_history"
        config = {"vendors": [], "reference_sources": [{"source_id": key, "url": spec.url}]}
        assert validate_config(config) == config
        for url in [
            spec.url + "?other=1",
            spec.url.replace("https:", "http:"),
            spec.url.replace("6300-6400", "4100i"),
        ]:
            if url == spec.url:
                continue
            bad = deepcopy(config)
            bad["reference_sources"][0]["url"] = url
            with pytest.raises(ValueError):
                validate_config(bad)


def test_aruba_explicit_dates_and_unknown_posting_are_not_footer_dates():
    doc = api().parse_aruba_10_14(history())
    assert (doc["vendor"], doc["family"], doc["product"]) == ("aruba", "aruba-aoscx", "AOS-CX")
    assert doc["platforms"] == ["6300 Switch Series", "6300L Switch Series", "6400 Switch Series"]
    first, initial = doc["releases"]
    assert first["version"] == "10.14.0007"
    assert first["reported_release_date"] == "2024-07-12"
    assert first["publisher_reports_posted"] is True
    assert initial["reported_release_date"] == "2024-05-29"
    assert initial["publisher_reports_posted"] is None
    assert first["date_basis"] == "publisher_release_history"
    assert not doc["bundles"] and not doc["platform_support"]
    assert api().parse_aruba_10_16(history("10.16"))["releases"][0]["branch"] == "10.16"


@pytest.mark.parametrize(
    "old,new",
    [
        (b"<h1>Version history", b"<h1>Other history"),
        (b"<title>Version history", b"<title>Other history"),
        (b"Release date</th>", b"Published</th>"),
        (b"10.14.0007", b"10.16.0007"),
        (b"12 July 2024", b"12/07/2024"),
        (b"12 July 2024", b"31 February 2024"),
        (b"Initial release.", b"Expected release."),
        (b"10.14.0007", b"<script>10.14.0007</script>"),
        (b"12 July 2024", b"<span hidden>12 July 2024</span>"),
        (b"10.14.0007", b'<img onerror="alert(1)">10.14.0007'),
    ],
)
def test_aruba_fails_closed_for_layout_branch_dates_remarks_and_active_html(old, new):
    with pytest.raises(ValueError):
        api().parse_aruba_10_14(history().replace(old, new))


@pytest.mark.parametrize(
    "raw",
    [
        history(rows=[]),
        history(rows=[["10.14.0007", "12 July 2024"]]),
        history(rows=[["10.14.0007", "12 July 2024", "Initial release."]] * 2),
        history() + history(),
    ],
)
def test_missing_duplicate_or_conflicting_release_rows_are_errors(raw):
    with pytest.raises(ValueError):
        api().parse_aruba_10_14(raw)


def test_support_preserves_literal_sku_context_and_later_minima():
    doc = api().parse_aruba_support_10_14(models())
    assert not doc["releases"]
    assert [(r["sku"], r["minimum_version"]) for r in doc["platform_support"]] == [
        ("R8S89A", "10.10.0002"),
        ("R0X27A", "10.05.0001"),
        ("SYN01A", "10.16.1006"),
    ]
    assert doc["platform_support"][1]["model_literal"] == "Aruba 6410 Switch"
    for old, new in [
        (b"Aruba 6410", b"Aruba 4100i"),
        (b"Minimum Software Version", b"Current Version"),
        (b"R0X27A", b"R8S89A"),
        (b"10.05.0001", b"unknown"),
    ]:
        with pytest.raises(ValueError):
            api().parse_aruba_support_10_14(models().replace(old, new))


def test_bundle_initial_and_member_dates_preserve_eos_table_ownership_and_hrefs():
    doc = api().parse_arista_0148(bundle())
    row = doc["bundles"][0]
    assert doc["family"] == "arista-eos" and not doc["releases"]
    assert row["initial_published_at"] == "2026-09-02"
    assert row["member_publication_date"] == "2026-09-09"
    assert row["member_advisory_ids"] == [str(identity) for identity in range(149, 179)]
    assert "/24705-security-advisory-0149" in row["source_locator"]
    assert any("179" in issue and "VeloCloud Edge" in issue for issue in doc["issues"])
    assert row["publisher_id"] == "0148"


@pytest.mark.parametrize(
    "old,new",
    [
        (b"0148 PDF", b"0149 PDF"),
        (b"Product (Component)", b"Product"),
        (b"EOS (802.1X)", b"CloudVision"),
        (b"September 02, 2026", b"October 2026"),
        (b"24705-security-advisory-0149", b"24705-security-advisory-0150"),
        (
            b"/en/support/advisories-notices/security-advisory/24705-security-advisory-0149",
            b"javascript:alert(1)",
        ),
        (b"149</a>", b"150</a>"),
    ],
)
def test_bundle_rejects_wrong_identity_ownership_dates_or_links(old, new):
    with pytest.raises(ValueError):
        api().parse_arista_0148(bundle().replace(old, new))


def test_bundle_does_not_take_an_unrelated_link_or_duplicate_table():
    raw = bundle().replace(
        b'<a href="/en/support/advisories-notices/security-advisory/24705-security-advisory-0149">149</a>',
        b"149",
    )
    raw += b'<a href="/en/support/advisories-notices/security-advisory/24705-security-advisory-0149">149</a>'
    for bad in [raw, bundle() + bundle()]:
        with pytest.raises(ValueError):
            api().parse_arista_0148(bad)


def test_cisco_release_date_is_scoped_to_the_named_software_version():
    doc = api().parse_cisco_17_12_1(cisco())
    row = doc["releases"][0]
    assert doc["family"] == "cisco-iosxe"
    assert row["version"] == "17.12.1" and row["branch"] == "17.12"
    assert row["reported_release_date"] == "2023-07-31"
    assert row["publisher_reports_posted"] is None
    assert row["date_basis"] == "publisher_release_date"
    for old, new in [
        (b"<h1>Cisco IOS XE Dublin 17.12.1", b"<h1>Cisco Catalyst 9300 Series"),
        (b"17.12.1", b"17.12.2"),
        (b"Release Date", b"Documentation Updated"),
        (b"31-Jul-2023", b"July 2023"),
    ]:
        with pytest.raises(ValueError):
            api().parse_cisco_17_12_1(cisco().replace(old, new))
    with pytest.raises(ValueError):
        api().parse_cisco_17_12_1(
            cisco().replace(b"</dl>", b"<dt>Release Date</dt><dd>01-Aug-2023</dd></dl>")
        )


def test_closed_schema_rejects_inferred_or_unbounded_fields():
    doc = api().parse_aruba_10_14(history())
    assert api().validate_document(doc) == doc
    mutations = [
        lambda d: d.update(affected=True),
        lambda d: d["releases"][0].update(available=True),
        lambda d: d["platforms"].append("x" * 501),
        lambda d: d["releases"][0].update(reported_release_date="2024-02-30"),
        lambda d: d["releases"][0].update(publisher_reports_posted="yes"),
        lambda d: d.update(releases=d["releases"] * 1001),
        lambda d: d.update(source_url="https://evil.example/history"),
    ]
    for mutate in mutations:
        bad = deepcopy(doc)
        mutate(bad)
        with pytest.raises(ValueError):
            api().validate_document(bad)
    with pytest.raises(ValueError):
        api().parse_aruba_10_14(b"x" * 2_000_001)


def test_inputs_retained_content_and_sanitized_attempt_remain_distinct(tmp_path):
    config = {
        "vendors": [],
        "reference_sources": [{"source_id": ARUBA, "url": source(ARUBA).url, "enabled": False}],
    }
    with connect(tmp_path / "release.sqlite") as db:
        assert ingest(db, history(), ARUBA)
        assert not ingest(db, history(), ARUBA)
        collection_result(db, "upstream", source(ARUBA).url, "ok", "collected")
        collection_result(
            db, "upstream", source(ARUBA).url, "error", "private-secret", "access_denied"
        )
        value = api().inputs(db, config)[0]
        assert value["configured"] and not value["enabled"]
        assert value["latest_attempt"]["error_code"] == "access_denied"
        assert "private-secret" not in str(value)
        retained = value["retained"]
        assert retained["document"]["releases"][0]["version"] == "10.14.0007"
        assert len(retained["sha256"]) == len(retained["normalized_sha256"]) == 64
        assert retained["parser_fingerprint"] == retained["document"]["parser_fingerprint"]
        assert retained["source_observed_at"] and retained["parsed_at"] and value["checked_at"]
        assert not db.execute("SELECT 1 FROM browser_captures").fetchone()
        assert not db.execute("SELECT 1 FROM documents").fetchone()


def test_release_collection_bound_and_disabled_cisco(tmp_path):
    config = {
        "vendors": [],
        "reference_sources": [
            {"source_id": ARUBA, "url": source(ARUBA).url},
            {"source_id": CISCO, "url": source(CISCO).url, "enabled": False},
        ],
    }
    with patch("infrastructure_impact.collection.service.fetch", return_value=history()) as fetch:
        assert run(config, db_path=tmp_path / "release.sqlite") == (0, 0)
    fetch.assert_called_once()
    assert fetch.call_args.kwargs == {"max_bytes": 2_000_000}


def test_reviewed_real_layout_details_are_accepted_without_relaxing_active_content():
    supported = models().replace(b"CX 6300M Switch", b"CX 6300F Switch")
    assert (
        api()
        .parse_aruba_support_10_14(supported)["platform_support"][0]["model_literal"]
        .endswith("6300F Switch")
    )
    raw = bundle().replace(
        b"0148 PDF</h2>",
        b'0148 <a onclick="" href="/en/support/advisories-notices/security-advisory/24535-security-advisory-0148?tmpl=component&amp;format=pdf">PDF</a></h2>',
    )
    assert api().parse_arista_0148(raw)["bundles"][0]["publisher_id"] == "0148"
    with pytest.raises(ValueError):
        api().parse_arista_0148(raw.replace(b'onclick=""', b'onclick="alert(1)"'))


@pytest.mark.parametrize("tag", ["b", "em", "section"])
def test_concealed_content_is_rejected_on_every_element(tag):
    with pytest.raises(ValueError):
        api().parse_aruba_10_14(
            history().replace(b"12 July 2024", f"<{tag} hidden>12 July 2024</{tag}>".encode())
        )


def test_unknown_error_code_is_not_exported(tmp_path):
    with connect(tmp_path / "release.sqlite") as db:
        collection_result(
            db,
            "upstream",
            source(ARUBA).url,
            "error",
            "private-secret",
            "<script>private-secret</script>",
        )
        value = api().inputs(db, {"vendors": []})[0]
        assert value["latest_attempt"]["error_code"] is None
        assert "private-secret" not in str(value)


def test_normalized_document_is_bound_to_its_reviewed_source_and_product():
    doc = api().parse_aruba_10_14(history())
    assert api().validate_document(doc, source_id=ARUBA) == doc
    for source_id in [ARUBA16, MODELS, CISCO, ARISTA, "unreviewed"]:
        with pytest.raises(ValueError):
            api().validate_document(doc, source_id=source_id)
    mutations = [
        lambda d: d.update(family="arista-eos"),
        lambda d: d.update(vendor="cisco"),
        lambda d: d.update(product="4100i"),
        lambda d: d.update(platforms=["4100i Switch Series"]),
        lambda d: d["releases"][0].update(branch="10.16"),
        lambda d: d["releases"][0].update(version="10.16.0007"),
        lambda d: d.update(releases=[]),
        lambda d: d["releases"].append(deepcopy(d["releases"][0])),
    ]
    for mutate in mutations:
        bad = deepcopy(doc)
        mutate(bad)
        with pytest.raises(ValueError):
            api().validate_document(bad)


def test_duplicate_conflicting_member_and_support_rows_are_rejected():
    for raw, parse in [
        (
            bundle().replace(b"179</a>", b"149</a>"),
            api().parse_arista_0148,
        ),
        (models() + models(), api().parse_aruba_support_10_14),
    ]:
        with pytest.raises(ValueError):
            parse(raw)


def test_real_http_bound_rejects_oversize_release_body_before_retaining(tmp_path):
    from io import BytesIO

    class Response(BytesIO):
        headers = {}
        status = 200

    class Opener:
        def open(self, request, timeout):
            return Response(b"x" * 2_000_001)

    path = tmp_path / "oversize.sqlite"
    config = {"vendors": [], "reference_sources": [{"source_id": ARUBA, "url": source(ARUBA).url}]}
    with patch("infrastructure_impact.collection.transport.build_opener", return_value=Opener()):
        assert run(config, db_path=path) == (0, 1)
    with connect(path) as db:
        assert not db.execute("SELECT 1 FROM evidence").fetchone()
        value = api().inputs(db, config)[0]
        assert value["retained"] is None
        assert value["latest_attempt"]["outcome"] == "error"


@pytest.mark.parametrize(
    "wrapper",
    ["<div hidden>{}</div>", '<div style="display: none">{}</div>', "<template>{}</template>"],
)
def test_evidence_under_concealed_or_inert_ancestors_is_rejected(wrapper):
    with pytest.raises(ValueError):
        api().parse_aruba_10_14(wrapper.format(history().decode()).encode())


def test_active_link_in_reviewed_heading_is_rejected():
    with pytest.raises(ValueError):
        api().parse_arista_0148(
            bundle().replace(b"0148 PDF</h2>", b'0148 <a href="javascript:alert(1)">PDF</a></h2>')
        )


def test_truncated_bundle_with_missing_linked_member_row_is_an_error():
    raw = bundle()
    start = raw.index(
        b'<tr><td><a href="/en/support/advisories-notices/security-advisory/90000-security-advisory-0150"'
    )
    end = raw.index(b"</tr>", start) + len(b"</tr>")
    with pytest.raises(ValueError):
        api().parse_arista_0148(raw[:start] + raw[end:])


def test_bundle_reviewed_product_split_cannot_be_reassigned():
    for old, new in [
        (b"EOS (802.1X)", b"VeloCloud Edge (HA)"),
        (b"VeloCloud Edge (HA)", b"EOS (SNMPv3)"),
    ]:
        with pytest.raises(ValueError):
            api().parse_arista_0148(bundle().replace(old, new))


@pytest.mark.parametrize(
    "body",
    [
        b"<section><h2>Cisco Catalyst 9300 Series</h2><dl><dt>Release Date</dt><dd>01-Jan-2010</dd></dl></section>",
        b'<section><h2>Documentation</h2><a href="https://www.cisco.com/document">Configuration Guide</a><dl><dt>Release Date</dt><dd>01-Jan-2026</dd></dl></section>',
        b"<dl><dt>Release Date</dt><dd>31-Jul-2023</dd></dl>",
    ],
)
def test_cisco_unrelated_or_unowned_release_date_is_not_software_metadata(body):
    prefix = (
        b"<title>Cisco IOS XE Dublin 17.12.1 - Cisco</title><h1>Cisco IOS XE Dublin 17.12.1</h1>"
    )
    with pytest.raises(ValueError):
        api().parse_cisco_17_12_1(prefix + body)


def test_cisco_explicit_software_metadata_ignores_other_owned_section_dates():
    raw = (
        cisco()
        + b"<section><h2>Cisco Catalyst 9300 Series</h2><dl><dt>Release Date</dt><dd>01-Jan-2010</dd></dl></section><section><h2>Documentation</h2><dl><dt>Release Date</dt><dd>01-Jan-2026</dd></dl></section>"
    )
    row = api().parse_cisco_17_12_1(raw)["releases"][0]
    assert row["reported_release_date"] == "2023-07-31"
    assert row["source_locator"] == "section[h2=Cisco IOS XE Dublin 17.12.1] / dl / Release Date"


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: raw.replace(
            b"<h2>Cisco IOS XE Dublin 17.12.1", b"<h2>Cisco IOS XE Dublin 17.12.2"
        ),
        lambda raw: raw.replace(
            b"<h2>Cisco IOS XE Dublin 17.12.1", b"<h2>Cisco Catalyst 9300 Series"
        ),
        lambda raw: raw.replace(
            b"<dl>", b"<section><h3>Cisco Catalyst 9300 Series</h3><dl>"
        ).replace(b"</dl>", b"</dl></section>"),
        lambda raw: raw.replace(b"<dl>", b"<h3>Documentation</h3><dl>"),
        lambda raw: raw.replace(b"<dl>", b"<div><dl>").replace(b"</dl>", b"</dl></div>"),
        lambda raw: raw.replace(
            b"</section>", b"<dl><dt>Release Date</dt><dd>01-Aug-2023</dd></dl></section>"
        ),
        lambda raw: raw.replace(b"</dl>", b"<dt>Documentation</dt><dd>01-Jan-2026</dd></dl>"),
        lambda raw: (
            raw
            + b"<section><h2>Cisco IOS XE Dublin 17.12.1</h2><dl><dt>Release Date</dt><dd>01-Aug-2023</dd></dl></section>"
        ),
        lambda raw: (
            raw + b"<section><h2>Cisco IOS XE Dublin 17.12.1</h2><p>No model metadata</p></section>"
        ),
    ],
)
def test_cisco_changed_nested_or_ambiguous_model_metadata_is_rejected(change):
    with pytest.raises(ValueError):
        api().parse_cisco_17_12_1(change(cisco()))
