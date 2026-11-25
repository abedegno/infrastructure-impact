"""Offline integration tests for the fixed release-reliability preparation CLI."""

import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta

import pytest

from infrastructure_impact.application.release_reliability import build_report
from infrastructure_impact.release_catalogue_cli import read_json
from infrastructure_impact.settings import PACKAGE

C9200 = "cisco-c9200-rommon"
C9300 = "cisco-c9300-rommon"
ARISTA = "arista-eos-rss"
ROBOTS = "https://www.cisco.com/robots.txt"
CISCO_URL = (
    "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9200/software/release/"
    "17-12/release_notes/ol-17-12-9200/rommon_versions.html"
)
ARISTA_URL = "https://www.arista.com/en/support/release-notes"
CURRENT = datetime(2026, 11, 26, tzinfo=UTC)
CAPTURED = "2026-11-25T17:00:00+00:00"
BASELINE = PACKAGE / "resources/release-catalogue.json"
ROBOT_ALLOW = b"User-agent: *\nDisallow: /private\nCrawl-delay: 2\n"


@pytest.fixture
def refresh():
    try:
        from infrastructure_impact import reliability_refresh_cli as cli
        from infrastructure_impact.application import reliability_refresh as app
        from infrastructure_impact.collection import reliability_refresh as collection
    except ImportError:
        pytest.fail("The reliability refresh entry point and implementation are missing")
    return cli, app, collection


def cisco(*versions, model="9200"):
    series = f"Cisco Catalyst {model} Series Switches"
    title = f"Release Notes for {series}, Cisco IOS XE Dublin 17.12.x"
    heading = "Boot Loader Versions" if model == "9200" else "ROMMON Versions"
    columns = (
        ["ROMMON Version"]
        if model == "9200"
        else [
            f"ROMMON Version ({name} Models)" for name in ("C9300", "C9300L", "C9300X", "C9300LM")
        ]
    )
    headers = "".join(f"<th>{column}</th>" for column in ["Release", *columns])
    values = "<td>17.8.1r</td>" * len(columns)
    rows = "".join(f"<tr><td>Dublin {version}</td>{values}</tr>" for version in versions)
    return (
        f"<html><head><title>{title} - {heading} [{series}] - Cisco</title></head><body>"
        f"<h1>{title}</h1><h1>{heading}</h1><h2>{heading}</h2>"
        f"<table><tr>{headers}</tr>{rows}</table></body></html>"
    ).encode()


def rss(*items):
    return (
        '<rss version="2.0"><channel><title>Arista Networks :: Software Release</title>'
        "<link>https://www.arista.com/support/release-notes</link>"
        + "".join(
            f"<item><title>EOS-{version} is now available for download.</title>"
            f"<pubDate>{date}</pubDate></item>"
            for version, date in items
        )
        + "</channel></rss>"
    ).encode()


def policy(path, *, sources=(C9200,), reviewed="2026-11-25T00:00:00Z"):
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "allowed_source_ids": list(sources),
                "reviewed_at": reviewed,
                "terms_url": "https://www.cisco.com/c/en/us/about/legal/terms-conditions.html",
                "terms_locator": "Reviewed public terms",
                "terms_sha256": "a" * 64,
            }
        )
    )
    return path


def transport(collection, *responses, start=CURRENT):
    """Use real refresh logic with a deterministic substitute for the upstream HTTP server."""
    clock = [start]
    calls = []
    pending = iter(responses)

    def request(url, headers):
        calls.append((url, dict(headers), clock[0]))
        response = next(pending)
        status, media, raw, *validators = response
        metadata = {"Content-Type": media, **(validators[0] if validators else {})}
        return collection.Response(status, metadata, raw)

    def sleep(seconds):
        clock[0] += timedelta(seconds=seconds)

    return {"request": request, "now": lambda: clock[0], "sleep": sleep}, calls


def collect(collection, cache, receipt, *responses, source=C9200):
    args, calls = transport(collection, *responses)
    return collection.collect(cache, source, receipt, **args), calls


def test_conditional_checks_and_restored_digest_preserve_first_capture(refresh, tmp_path):
    _, app, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    receipt = policy(tmp_path / "policy.json")
    old, new = cisco("17.12.9"), cisco("17.12.9", "17.12.10")
    robot = (200, "text/plain", ROBOT_ALLOW)
    response = (
        200,
        "text/html",
        old,
        {"ETag": '"first"', "Last-Modified": "Wed, 25 Nov 2026 12:00:00 GMT"},
    )
    args, calls = transport(
        collection,
        robot,
        response,
        robot,
        (304, "", b"", {"ETag": '"first"'}),
        robot,
        (200, "text/html", new, {"ETag": '"first"'}),
        robot,
        response,
        robot,
        response,
    )
    assert collection.collect(cache, C9200, receipt, **args) == "captured"
    baseline = read_json(BASELINE)
    before_check, _ = app.prepare(cache, baseline)
    assert collection.collect(cache, C9200, receipt, **args) == "not_modified"
    after_check, _ = app.prepare(cache, baseline)
    assert before_check == after_check
    outcomes = [collection.collect(cache, C9200, receipt, **args) for _ in range(3)]
    assert outcomes == ["changed", "restored", "unchanged"]
    assert calls[0][0] == ROBOTS and calls[1][0] == CISCO_URL and calls[1][1] == {}
    assert calls[3][1] == {
        "If-None-Match": '"first"',
        "If-Modified-Since": "Wed, 25 Nov 2026 12:00:00 GMT",
    }
    assert all(right[2] - left[2] >= timedelta(seconds=2) for left, right in zip(calls, calls[1:]))
    state = cache.snapshot()[C9200]
    old_hash, new_hash = (hashlib.sha256(raw).hexdigest() for raw in (old, new))
    assert [entry["sha256"] for entry in state["revisions"]] == [old_hash, new_hash, old_hash]
    assert [entry["predecessor_sha256"] for entry in state["revisions"]] == [
        None,
        old_hash,
        new_hash,
    ]
    assert state["latest_sha256"] == old_hash
    assert state["captures"][old_hash]["retrieved_at"] == calls[1][2].isoformat()
    assert state["captures"][old_hash]["origin"] == "network"


@pytest.mark.parametrize("damaged", [None, b"wrong body"])
def test_304_refuses_missing_or_corrupt_cached_bytes(refresh, tmp_path, damaged):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    receipt = policy(tmp_path / "policy.json")
    robot = (200, "text/plain", ROBOT_ALLOW)
    response = (200, "text/html", cisco("17.12.9"), {"ETag": '"one"'})
    outcome, _ = collect(collection, cache, receipt, robot, response)
    assert outcome == "captured"
    digest = cache.snapshot()[C9200]["latest_sha256"]
    path = cache.directory / "bodies" / digest
    if damaged is None:
        path.unlink()
    else:
        path.write_bytes(damaged)
    outcome, _ = collect(collection, cache, receipt, robot, (304, "", b""))
    assert outcome == "cache_body_invalid"
    assert cache.snapshot()[C9200]["latest_sha256"] == digest


@pytest.mark.parametrize(
    ("source", "reviewed", "sources", "expected"),
    [
        (ARISTA, "2026-11-25T00:00:00Z", (C9200,), "network_disabled"),
        (C9200, "2026-10-26T23:59:59Z", (C9200,), "policy_review_required"),
        (C9200, "2026-11-26T00:00:01Z", (C9200,), "policy_review_required"),
        (C9200, "2026-11-25T00:00:00Z", (C9300,), "policy_review_required"),
    ],
)
def test_policy_requires_current_route_specific_review(
    refresh, tmp_path, source, reviewed, sources, expected
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    receipt = policy(tmp_path / "policy.json", reviewed=reviewed, sources=sources)
    outcome, calls = collect(collection, cache, receipt, source=source)
    assert outcome == expected
    assert calls == []
    assert cache.snapshot()[source]["last_check"]["status"] == expected


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            (200, "text/plain", b"User-agent: *\nDisallow: /c/en/*rommon_versions.html$"),
            "robots_denied",
        ),
        ((200, "text/html", b"<html><title>Client Challenge</title></html>"), "robots_unavailable"),
        (
            (200, "text/plain", b"User-agent: *\nDisallow: /\nUser-agent: AnotherBot\nAllow: /"),
            "robots_denied",
        ),
        ((403, "", b""), "robots_unavailable"),
        ((302, "", b""), "robots_unavailable"),
    ],
)
def test_robots_can_prevent_route_request(refresh, tmp_path, response, expected):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    outcome, calls = collect(collection, cache, policy(tmp_path / "policy.json"), response)
    assert outcome == expected
    assert [call[0] for call in calls] == [ROBOTS]
    assert cache.snapshot()[C9200]["latest_sha256"] is None


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ((302, "", b""), "redirect_rejected"),
        ((401, "", b""), "access_denied"),
        ((403, "", b""), "access_denied"),
        ((429, "", b""), "rate_limited"),
        (
            (200, "text/html", b"<html><title>Client Challenge</title></html>"),
            "access_verification_required",
        ),
        ((200, "text/html", b"<html><h1>Sign in</h1></html>"), "access_verification_required"),
        ((200, "text/html", cisco("17.12.9", model="9300")), "unsupported_or_invalid_document"),
        (
            (200, "text/html", cisco("17.12.9").replace(b"<th>Release</th>", b"<th>Version</th>")),
            "unsupported_or_invalid_document",
        ),
    ],
)
def test_bad_live_response_preserves_good_pointer_without_retry(
    refresh, tmp_path, response, expected
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    cache.import_capture(C9200, cisco("17.12.9"), CAPTURED)
    old = cache.snapshot()[C9200]
    robots = (
        200,
        "text/plain",
        f"User-agent: *\nDisallow: /\nAllow: {CISCO_URL.removeprefix('https://www.cisco.com')}$".encode(),
    )
    outcome, calls = collect(collection, cache, policy(tmp_path / "policy.json"), robots, response)
    assert outcome == expected
    assert [call[0] for call in calls] == [ROBOTS, CISCO_URL]
    state = cache.snapshot()[C9200]
    assert state["latest_sha256"] == old["latest_sha256"]
    assert state["revisions"] == old["revisions"]
    assert state["last_check"]["status"] == expected


@pytest.mark.parametrize(
    "raw",
    [
        b"<rss><channel>",
        rss(("4.33.99M", "2026-11-25 17:00:01 +0000")),
        rss(("4.33.99M", "2026-11-24 12:00:00 +0000")).replace(
            b"Software Release", b"Field Notice"
        ),
    ],
)
def test_offline_import_rejects_malformed_wrong_channel_and_future_announcements(
    refresh, tmp_path, raw
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    assert cache.import_capture(ARISTA, raw, CAPTURED) == "unsupported_or_invalid_document"
    assert cache.snapshot()[ARISTA]["captures"] == {}


def test_failed_metadata_write_does_not_replace_good_pointer(refresh, tmp_path, monkeypatch):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    cache.import_capture(C9200, cisco("17.12.9"), CAPTURED)
    old = cache.snapshot()[C9200]
    original_replace = collection.Path.replace

    def replace(path, target):
        if target.name == f"{C9200}.json":
            raise OSError("simulated failure during metadata commit")
        return original_replace(path, target)

    monkeypatch.setattr(collection.Path, "replace", replace)
    with pytest.raises(OSError, match="simulated failure"):
        cache.import_capture(C9200, cisco("17.12.10"), CAPTURED)
    assert cache.snapshot()[C9200] == old
    monkeypatch.undo()
    assert cache.import_capture(C9200, cisco("17.12.10"), CAPTURED) == "changed"


def test_cache_refuses_checkout_ancestor_and_symlinks(refresh, tmp_path):
    _, _, collection = refresh
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    (checkout / ".git").write_text("gitdir: /other/worktree")
    with pytest.raises(ValueError, match="outside Git"):
        collection.RefreshCache(checkout / "raw")
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        collection.RefreshCache(link / "raw")
    cache = collection.RefreshCache(tmp_path / "raw")
    cache.import_capture(C9200, cisco("17.12.9"), CAPTURED)
    body = cache.directory / "bodies" / cache.snapshot()[C9200]["latest_sha256"]
    body.unlink()
    original = tmp_path / "capture"
    original.write_bytes(cisco("17.12.9"))
    body.symlink_to(original)
    with pytest.raises(ValueError, match="cache body"):
        cache.observations()


def test_cli_rolling_replay_preserves_announcements_coverage_and_packaged_defaults(
    refresh, tmp_path
):
    cli, _, _ = refresh
    baseline_bytes = BASELINE.read_bytes()
    baseline = read_json(BASELINE)
    cache = tmp_path / "cache"
    raw = tmp_path / "incoming"
    cutoff = "2026-11-26T00:00:00Z"
    initial = (
        (ARISTA, rss(("4.33.99M", "2026-11-24 23:30:00 -0100")), "2026-11-25T16:00:00Z"),
        (ARISTA, rss(("4.33.100M", "2026-11-25 16:15:00 +0000")), CAPTURED),
        (C9200, cisco("17.12.99", "17.12.99", model="9200"), CAPTURED),
        (C9300, cisco("17.12.99", model="9300"), CAPTURED),
    )
    for source, document, stamp in initial:
        raw.write_bytes(document)
        assert (
            cli.main(
                [
                    "import-capture",
                    "--source",
                    source,
                    "--input",
                    str(raw),
                    "--retrieved-at",
                    stamp,
                    "--cache-dir",
                    str(cache),
                ]
            )
            == 0
        )
    outputs = [tmp_path / name for name in ("candidate.json", "review.json")]
    args = [
        "prepare",
        "--cache-dir",
        str(cache),
        "--output",
        str(outputs[0]),
        "--report",
        str(outputs[1]),
    ]
    assert cli.main(args) == 0
    candidate, review = map(read_json, outputs)
    assert candidate["coverage"] == baseline["coverage"]
    assert candidate["review_status"] == baseline["review_status"]
    assert candidate["releases"][: len(baseline["releases"])] == baseline["releases"]
    added = candidate["releases"][len(baseline["releases"]) :]
    assert len(added) == 4
    arista = next(fact for fact in added if fact["version"] == "4.33.99M")
    assert arista["release_date"] is None
    assert arista["announcement_date"] == "2026-11-25"
    assert arista["platforms_stated"] == []
    assert arista["evidence"][0]["quote"] == "EOS-4.33.99M is now available for download."
    assert arista["evidence"][0]["locator"] == "RSS channel/item[1] / title and pubDate"
    assert review["observations"][ARISTA][0]["pub_dates"] == [
        {
            "version": "4.33.99M",
            "locator": "RSS channel/item[1] / title and pubDate",
            "pub_date": "2026-11-24 23:30:00 -0100",
        }
    ]
    assert review["observations"][ARISTA][1]["omitted_versions"] == ["4.33.99M"]
    cisco_releases = [fact for fact in added if fact["vendor"] == "cisco"]
    assert {tuple(fact["platforms_stated"]) for fact in cisco_releases} == {
        ("Catalyst 9200",),
        ("Catalyst 9300",),
    }
    assert all(
        fact["release_date"] is None and fact["announcement_date"] is None
        for fact in cisco_releases
    )
    assert all(fact["evidence"][0]["quote"] == "Dublin 17.12.99" for fact in cisco_releases)
    assert all(row["denominator"] is None for row in review["summary"]["annual"])
    expected = [path.read_bytes() for path in outputs]
    assert cli.main(args) == 0
    assert [path.read_bytes() for path in outputs] == expected
    assert (
        cli.main([*args, "--catalogue", str(outputs[0]), "--output", str(tmp_path / "replay.json")])
        == 0
    )
    assert read_json(tmp_path / "replay.json") == candidate
    assert BASELINE.read_bytes() == baseline_bytes
    assert build_report(publication=None, generated_at=cutoff)["catalogue"] == baseline


def test_conflicting_dates_and_unrelated_model_scope_stay_pending(refresh, tmp_path):
    _, app, collection = refresh
    baseline = read_json(BASELINE)
    cache = collection.RefreshCache(tmp_path / "cache")
    cache.import_capture(ARISTA, rss(("4.33.99M", "2026-11-24 12:00:00 +0000")), CAPTURED)
    accepted, _ = app.prepare(cache, baseline)
    cache.import_capture(ARISTA, rss(("4.33.99M", "2026-11-25 12:00:00 +0000")), CAPTURED)
    candidate, review = app.prepare(cache, accepted)
    assert candidate == accepted
    assert review["conflicts"][0]["fields"] == ["announcement_date"]
    assert review["conflicts"][0]["proposed"]["announcement_date"] == "2026-11-25"
    accepted["releases"][-1]["platforms_stated"] = ["720XP"]
    candidate, review = app.prepare(cache, accepted)
    assert candidate == accepted
    assert any("platforms_stated" in conflict["fields"] for conflict in review["conflicts"])


def test_simultaneous_conflicting_announcements_are_not_selected_implicitly(refresh, tmp_path):
    _, app, collection = refresh
    baseline = read_json(BASELINE)
    cache = collection.RefreshCache(tmp_path / "cache")
    cache.import_capture(
        ARISTA,
        rss(
            ("4.33.99M", "2026-11-24 12:00:00 +0000"),
            ("4.33.99M", "2026-11-25 12:00:00 +0000"),
        ),
        CAPTURED,
    )
    candidate, review = app.prepare(cache, baseline)
    assert candidate == baseline
    assert sorted(
        conflict["proposed"]["announcement_date"] for conflict in review["conflicts"]
    ) == ["2026-11-24", "2026-11-25"]


def test_cli_refuses_conflicting_output_paths_before_any_write(refresh, tmp_path):
    cli, _, _ = refresh
    baseline = tmp_path / "baseline.json"
    baseline.write_bytes(BASELINE.read_bytes())
    args = ["prepare", "--cache-dir", str(tmp_path / "cache"), "--catalogue", str(baseline)]
    target = tmp_path / "candidate.json"
    with pytest.raises(SystemExit) as error:
        cli.main([*args, "--output", str(target), "--report", str(baseline)])
    assert error.value.code == 1
    assert not target.exists()
    assert baseline.read_bytes() == BASELINE.read_bytes()


@pytest.mark.parametrize("existing", [False, True])
def test_cli_restores_previous_pair_if_second_replace_fails(
    refresh, tmp_path, monkeypatch, existing
):
    cli, _, collection = refresh
    candidate = tmp_path / "candidate.json"
    report = tmp_path / "review.json"
    if existing:
        candidate.write_bytes(b"previous candidate")
        report.write_bytes(b"previous review")
    original_replace = collection.Path.replace

    def replace(path, target):
        if target == candidate:
            raise OSError("simulated candidate rename failure")
        return original_replace(path, target)

    monkeypatch.setattr(collection.Path, "replace", replace)
    with pytest.raises(SystemExit) as error:
        cli.main(
            [
                "prepare",
                "--cache-dir",
                str(tmp_path / "cache"),
                "--output",
                str(candidate),
                "--report",
                str(report),
            ]
        )
    assert error.value.code == 1
    if existing:
        assert candidate.read_bytes() == b"previous candidate"
        assert report.read_bytes() == b"previous review"
    else:
        assert not candidate.exists() and not report.exists()


@pytest.mark.parametrize(("source", "model", "columns"), [(C9200, "9200", 1), (C9300, "9300", 4)])
def test_cisco_rommon_tables_include_out_of_scope_history(
    refresh, tmp_path, source, model, columns
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    raw = cisco("17.12.7a", model=model)
    historical_rows = b"".join(
        b"<tr><td>" + release + b"</td>" + b"<td>17.8.1r</td>" * columns + b"</tr>"
        for release in (
            b"Dublin 17.11.1",
            b"Cupertino 17.9.10",
            b"Bengaluru 17.6.8",
            b"Amsterdam 17.3.8a",
        )
    )
    raw = raw.replace(b"</table>", historical_rows + b"</table>")
    assert cache.import_capture(source, raw, CAPTURED) == "captured"
    _, observations = cache.observations()[source]
    [observation] = next(iter(observations.values()))
    assert observation.version == "17.12.7a"
    assert observation.models == (f"Catalyst {model}",)
    assert observation.locator.endswith("table body row 1 / Release")


@pytest.mark.parametrize(
    ("release_cell", "other_versions"),
    [
        (b"Dublin 17.12.invalid", ("17.12.8",)),
        (b"Cupertino 17.12.9", ("17.12.8",)),
        (b"Dublin 17.11.1", ()),
    ],
)
def test_cisco_rejects_malformed_rows_and_requires_a_target_train_release(
    refresh, tmp_path, release_cell, other_versions
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    raw = cisco("17.12.9", *other_versions).replace(b"Dublin 17.12.9", release_cell)
    assert cache.import_capture(C9200, raw, CAPTURED) == "unsupported_or_invalid_document"
    assert cache.snapshot()[C9200]["latest_sha256"] is None


def _prepare_args(cache, output, report, baseline=BASELINE):
    return [
        "prepare",
        "--cache-dir",
        str(cache),
        "--catalogue",
        str(baseline),
        "--output",
        str(output),
        "--report",
        str(report),
    ]


def test_cli_refuses_an_existing_baseline_under_an_equivalent_unicode_name(refresh, tmp_path):
    cli, _, _ = refresh
    baseline = tmp_path / "café.json"
    alias = tmp_path / "cafe\u0301.json"
    baseline.write_bytes(BASELINE.read_bytes())
    report = tmp_path / "review.json"
    args = _prepare_args(tmp_path / "cache", alias, report, baseline)
    if alias.exists():
        with pytest.raises(SystemExit) as error:
            cli.main(args)
        assert error.value.code == 1
        assert not report.exists()
    else:
        assert cli.main(args) == 0
        assert alias.exists() and report.exists()
    assert baseline.read_bytes() == BASELINE.read_bytes()


def test_cli_refuses_existing_hardlink_alias_to_baseline(refresh, tmp_path):
    cli, _, _ = refresh
    baseline = tmp_path / "baseline.json"
    alias = tmp_path / "candidate.json"
    report = tmp_path / "review.json"
    baseline.write_bytes(BASELINE.read_bytes())
    alias.hardlink_to(baseline)
    with pytest.raises(SystemExit) as error:
        cli.main(_prepare_args(tmp_path / "cache", alias, report, baseline))
    assert error.value.code == 1
    assert baseline.read_bytes() == alias.read_bytes() == BASELINE.read_bytes()
    assert not report.exists()


def test_cli_compares_prospective_unicode_output_names_as_the_volume_does(refresh, tmp_path):
    cli, _, _ = refresh
    candidate = tmp_path / "café.json"
    report = tmp_path / "cafe\u0301.json"
    candidate.touch()
    aliases = report.exists()
    candidate.unlink()
    args = _prepare_args(tmp_path / "cache", candidate, report)
    if aliases:
        with pytest.raises(SystemExit) as error:
            cli.main(args)
        assert error.value.code == 1
        assert not candidate.exists() and not report.exists()
    else:
        assert cli.main(args) == 0
        assert "releases" in read_json(candidate)
        assert "conflicts" in read_json(report)


def test_cli_locks_an_aliased_output_parent_once(refresh, tmp_path, monkeypatch):
    cli, _, _ = refresh
    directory = tmp_path / "Outputs"
    alternate = tmp_path / "outputs"
    directory.mkdir()
    if not alternate.exists():
        pytest.skip("output filesystem distinguishes the two directory spellings")
    original_lock = cli._dataset_lock
    acquired = []

    @contextmanager
    def track_lock(path):
        info = path.parent.stat()
        identity = (info.st_dev, info.st_ino)
        assert identity not in acquired, "Second exclusive lock would block on the same directory"
        acquired.append(identity)
        with original_lock(path):
            yield

    monkeypatch.setattr(cli, "_dataset_lock", track_lock)
    candidate, report = directory / "candidate.json", alternate / "review.json"
    assert cli.main(_prepare_args(tmp_path / "cache", candidate, report)) == 0
    assert len(acquired) == 1
    assert "releases" in read_json(candidate)
    assert "conflicts" in read_json(report)


def test_conflicting_entity_tag_on_304_preserves_the_verified_body_and_validators(
    refresh, tmp_path
):
    _, _, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    receipt = policy(tmp_path / "policy.json")
    robot = (200, "text/plain", ROBOT_ALLOW)
    old_body = cisco("17.12.9")
    old_date = "Wed, 25 Nov 2026 12:00:00 GMT"
    args, calls = transport(
        collection,
        robot,
        (200, "text/html", old_body, {"ETag": '"first"', "Last-Modified": old_date}),
        robot,
        (304, "", b"", {"ETag": '"second"', "Last-Modified": "Wed, 25 Nov 2026 13:00:00 GMT"}),
        robot,
        (304, "", b"", {"ETag": '"first"'}),
    )
    assert collection.collect(cache, C9200, receipt, **args) == "captured"
    previous = cache.snapshot()[C9200]
    assert collection.collect(cache, C9200, receipt, **args) == "unsupported_response"
    current = cache.snapshot()[C9200]
    assert current["last_check"]["status"] == "unsupported_response"
    assert {k: v for k, v in current.items() if k != "last_check"} == {
        k: v for k, v in previous.items() if k != "last_check"
    }
    assert (cache.directory / "bodies" / current["latest_sha256"]).read_bytes() == old_body
    assert collection.collect(cache, C9200, receipt, **args) == "not_modified"
    assert calls[5][1] == {"If-None-Match": '"first"', "If-Modified-Since": old_date}


@pytest.mark.parametrize("version", ["4.33.\u0669M", "4.33." + "1" * 123 + "M"])
def test_unsupported_arista_version_leaves_prior_revision_replayable(refresh, tmp_path, version):
    _, app, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    baseline = read_json(BASELINE)
    date = "2026-11-24 12:00:00 +0000"
    assert cache.import_capture(ARISTA, rss(("4.33.99M", date)), CAPTURED) == "captured"
    before, _ = app.prepare(cache, baseline)
    state = cache.snapshot()[ARISTA]
    assert (
        cache.import_capture(ARISTA, rss((version, date)), CAPTURED)
        == "unsupported_or_invalid_document"
    )
    updated = cache.snapshot()[ARISTA]
    assert updated["last_check"]["status"] == "unsupported_or_invalid_document"
    assert updated["latest_sha256"] == state["latest_sha256"]
    assert updated["revisions"] == state["revisions"]
    assert updated["captures"] == state["captures"]
    after, _ = app.prepare(cache, baseline)
    assert before == after


def test_matching_baseline_observation_does_not_hide_other_conflicting_receipts(refresh, tmp_path):
    cli, app, collection = refresh
    cache = collection.RefreshCache(tmp_path / "cache")
    original = rss(("4.33.99M", "2026-11-24 12:00:00 +0000"))
    assert cache.import_capture(ARISTA, original, CAPTURED) == "captured"
    baseline, _ = app.prepare(cache, read_json(BASELINE))
    matching_fact = baseline["releases"][-1]
    for date, label in [("2026-11-22", "second"), ("2026-11-23", "third")]:
        receipt = {
            **baseline["sources"][-1],
            "source_id": label,
            "original_sha256": hashlib.sha256(label.encode()).hexdigest(),
        }
        baseline["sources"].append(receipt)
        baseline["releases"].append(
            {
                **matching_fact,
                "announcement_date": date,
                "evidence": [{**matching_fact["evidence"][0], "source_id": label}],
            }
        )

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline, indent=2, ensure_ascii=False) + "\n")
    candidate, review = tmp_path / "candidate.json", tmp_path / "review.json"
    assert cli.main(_prepare_args(cache.directory, candidate, review, baseline_path)) == 0
    assert candidate.read_bytes() == baseline_path.read_bytes()
    conflicts = read_json(review)["conflicts"]
    assert [conflict["prior"]["announcement_date"] for conflict in conflicts] == [
        "2026-11-22",
        "2026-11-23",
    ]
    assert [conflict["prior_receipts"][0]["source_id"] for conflict in conflicts] == [
        "second",
        "third",
    ]
    for conflict in conflicts:
        assert conflict["fields"] == ["announcement_date"]
        assert conflict["proposed"]["announcement_date"] == "2026-11-24"
        assert (
            conflict["proposed_receipt"]["original_sha256"] == hashlib.sha256(original).hexdigest()
        )


@pytest.mark.parametrize(
    ("generated", "retained", "captured", "expected_instant"),
    [
        (
            "2026-11-26T02:00:00+09:00",
            "2026-11-26T01:55:00+09:00",
            "2026-11-25T17:30:00+00:00",
            "2026-11-25T17:30:00+00:00",
        ),
        (
            "2026-11-25T17:00:00+00:00",
            "2026-11-25T16:55:00+00:00",
            "2026-11-26T06:55:00+14:00",
            "2026-11-25T17:00:00+00:00",
        ),
    ],
)
def test_external_catalogue_receipt_calendar_cutoffs(
    refresh, tmp_path, generated, retained, captured, expected_instant
):
    cli, _, collection = refresh
    baseline = read_json(BASELINE)
    baseline["generated_at"] = generated
    baseline["sources"][0]["retrieved_at"] = retained
    baseline_file = tmp_path / "external.json"
    baseline_file.write_text(json.dumps(baseline))
    cache = collection.RefreshCache(tmp_path / "cache")
    args, _ = transport(
        collection,
        (200, "text/plain", ROBOT_ALLOW),
        (200, "text/html", cisco("17.12.99")),
        start=datetime.fromisoformat(captured) - timedelta(seconds=2),
    )
    receipt = policy(tmp_path / "policy.json")
    assert collection.collect(cache, C9200, receipt, **args) == "captured"
    output, report = tmp_path / "candidate.json", tmp_path / "report.json"
    assert cli.main(_prepare_args(cache.directory, output, report, baseline_file)) == 0
    candidate = read_json(output)
    assert datetime.fromisoformat(candidate["generated_at"]) == datetime.fromisoformat(
        expected_instant
    )
    assert candidate["generated_at"][:10] >= max(generated[:10], captured[:10])
    assert candidate["sources"][:-1] == baseline["sources"]
    assert candidate["sources"][-1]["retrieved_at"] == captured
    assert candidate["releases"][:-1] == baseline["releases"]
    assert candidate["releases"][-1]["version"] == "17.12.99"
    replay = tmp_path / "replay.json"
    assert cli.main(_prepare_args(cache.directory, replay, report, output)) == 0
    assert replay.read_bytes() == output.read_bytes()


def test_long_robots_cooldown_survives_reopening_the_cache(refresh, tmp_path):
    _, _, collection = refresh
    directory = tmp_path / "cache"
    receipt = policy(tmp_path / "policy.json")
    args, calls = transport(
        collection,
        (200, "text/plain", b"User-agent: *\nAllow: /\nCrawl-delay: 120"),
        (200, "text/plain", ROBOT_ALLOW),
        (200, "text/html", cisco("17.12.99")),
    )

    def run():
        return collection.collect(collection.RefreshCache(directory), C9200, receipt, **args)

    assert run() == "robots_unavailable"
    assert run() == "robots_unavailable"
    assert [(url, time) for url, _, time in calls] == [(ROBOTS, CURRENT)]
    assert args["now"]() == CURRENT
    args["sleep"](121)
    assert run() == "captured"
    assert [(url, (time - CURRENT).total_seconds()) for url, _, time in calls] == [
        (ROBOTS, 0),
        (ROBOTS, 121),
        (CISCO_URL, 123),
    ]
