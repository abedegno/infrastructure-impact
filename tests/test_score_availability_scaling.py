"""Bound diagnostic work to the input size while retaining matching semantics."""

from infrastructure_impact.application.publication import switching_score_availability


class CountedList(list):
    """Count records visited by the real projection, without timing thresholds."""

    def __init__(self, values):
        super().__init__(values)
        self.visits = 0

    def __add__(self, other):
        return list(self) + other

    def __radd__(self, other):
        return other + list(self)

    def __iter__(self):
        for value in super().__iter__():
            self.visits += 1
            yield value


def entry(advisory="a", url="https://example.test/a", **extra):
    return dict(dict(vendor="cisco", advisory_id=advisory, source_url=url), **extra)


def claim(cid="CVE-1", product="p", **extra):
    return dict(
        vendor="cisco",
        advisory_id="a",
        source={"source_url": "https://example.test/a"},
        cve_id=cid,
        product_id=product,
        **extra,
    )


def score(cid="CVE-1", **extra):
    return dict(dict(cve_id=cid, scope="cve_specific", validation="valid"), **extra)


def test_diagnostic_inputs_are_scanned_once_instead_of_per_advisory_or_context():
    # Reintroducing the advisory-by-claim or context-by-attempt scan exceeds these bounds.
    claims = CountedList(
        [
            dict(
                claim(f"CVE-{i}-{j}"),
                advisory_id=f"a-{i}",
                source={"source_url": f"https://example.test/{i}"},
            )
            for i in range(12)
            for j in range(8)
        ]
    )
    attempts = CountedList(
        [dict(cve_id=f"CVE-{i}-{j}", source="nvd", state="ok") for i in range(12) for j in range(8)]
    )
    fallback = CountedList([score(f"CVE-{i}-{j}") for i in range(12) for j in range(8)])
    entry_scores = [CountedList([score(f"CVE-{i}-{j}") for j in range(8)]) for i in range(12)]
    advisories = [
        entry(f"a-{i}", f"https://example.test/{i}", claims=entry_scores[i]) for i in range(12)
    ]

    rows = switching_score_availability(
        {"advisories": advisories, "fallback": {"claims": fallback, "attempts": attempts}},
        {"claims": claims},
        [],
    )

    assert len(rows) == 96
    assert {row["state"] for row in rows} == {"available"}
    assert claims.visits <= len(claims)
    assert attempts.visits <= len(attempts)
    assert fallback.visits <= len(fallback)
    assert all(scores.visits <= len(scores) for scores in entry_scores)


def test_source_and_product_matching_preserve_sorted_unique_contexts_and_issue_priority():
    claims = [
        claim(product="z"),
        claim(product="a"),
        claim(product="a"),
        claim(product="x"),
        claim(cid=None),
    ]
    claims += [
        dict(claim("CVE-foreign"), vendor="aruba"),
        dict(claim("CVE-foreign"), advisory_id="other"),
        dict(claim("CVE-foreign"), source={"source_url": "https://other.test"}),
    ]
    scores = [
        score(product_ids=["a"], validation="incomplete", issues=["base_missing"]),
        score(product_ids=["z"], validation="invalid", issues=["vector_invalid"]),
        score(product_ids=["unused"]),
        score(product_ids=["x"], validation="invalid", issues=["vector_missing"]),
        score(scope="advisory", issues=["base_invalid"]),
        score(origin="vendor_advisory", source={"source_url": "https://other.test"}),
        score(cid=None),
    ]
    rows = switching_score_availability(
        {
            "advisories": [
                entry(
                    claims=scores,
                    issues=[{"code": "score_invalid"}, {"code": "private"}, "base_invalid"],
                )
            ],
            "fallback": {"claims": [score(product_ids=["z"], issues=["consistency_not_verified"])]},
        },
        {"claims": claims},
        [],
    )
    assert [
        (r["cve_id"], r["product_id"], r["context"], r["state"], r["issues"]) for r in rows
    ] == [
        (None, "p", "study_claim", "unavailable", ["score_invalid", "score_unavailable"]),
        ("CVE-1", "a", "study_claim", "incomplete", ["base_missing", "score_invalid"]),
        ("CVE-1", "x", "study_claim", "invalid", ["score_invalid", "vector_missing"]),
        (
            "CVE-1",
            "z",
            "study_claim",
            "available",
            ["consistency_not_verified", "score_invalid", "vector_invalid"],
        ),
    ]


def test_source_only_fallback_uses_vendor_advisory_records_and_filters_attempts():
    source = dict(
        source_url="https://example.test/a",
        source_sha256="abc",
        retrieved_at="today",
        source_locator="document",
        private="hidden",
    )
    attempts = [
        dict(
            cve_id="CVE-1", source="nvd", state="rate_limited", checked_at="first", retry_at="later"
        ),
        dict(cve_id="CVE-1", source="other", state="ok"),
        dict(cve_id="CVE-1", source="nvd", state="private"),
        dict(cve_id="CVE-1", source="cve_record", state="ok", checked_at="second"),
        dict(cve_id=None, source="nvd", state="unknown"),
    ]
    records = [
        dict(vendor="cisco", advisory_id="a", cves=["CVE-1", None, "CVE-1"]),
        dict(vendor="aruba", advisory_id="a", cves=["CVE-foreign"]),
        dict(vendor="cisco", advisory_id="other", cves=["CVE-foreign"]),
    ]
    rows = switching_score_availability(
        {
            "advisories": [entry(source=source), entry(source=source), entry(vendor="aruba")],
            "fallback": {
                "claims": [score(product_ids=["p"]), score(cid=None)],
                "attempts": attempts,
            },
        },
        {"claims": []},
        records,
    )
    assert [(r["cve_id"], r["context"], r["state"]) for r in rows] == [
        (None, "source_only_unclassified", "unavailable"),
        ("CVE-1", "source_only_unclassified", "unavailable"),
        (None, "source_only_unclassified", "unavailable"),
        ("CVE-1", "source_only_unclassified", "unavailable"),
        ("CVE-foreign", "source_only_unclassified", "unavailable"),
    ]
    assert rows[1]["attempts"] == [
        dict(
            source="nvd", cve_id="CVE-1", state="rate_limited", checked_at="first", retry_at="later"
        ),
        dict(source="cve_record", cve_id="CVE-1", state="ok", checked_at="second", retry_at=None),
    ]
    assert rows[0]["attempts"] == [
        dict(source="nvd", cve_id=None, state="unknown", checked_at=None, retry_at=None),
    ]
    assert rows[1]["source"] == dict(
        source_url="https://example.test/a",
        source_sha256="abc",
        retrieved_at="today",
        source_locator="document",
    )
    assert rows[1]["attempts"][0] is not rows[3]["attempts"][0]
    assert rows[1]["source"] is not rows[3]["source"]


def test_source_only_record_contexts_are_indexed_once_and_unsupported_vendors_are_skipped():
    records = CountedList(
        [dict(vendor="cisco", advisory_id=f"a-{i}", cves=[f"CVE-{i}"]) for i in range(12)]
    )
    rows = switching_score_availability(
        {"advisories": [entry(f"a-{i}") for i in range(12)] + [entry(vendor="other")]},
        {},
        records,
    )
    assert len(rows) == 12
    assert rows[0] == dict(
        vendor="cisco",
        advisory_id="a-0",
        source_url="https://example.test/a",
        cve_id="CVE-0",
        product_id=None,
        context="source_only_unclassified",
        source=None,
        state="unavailable",
        issues=["score_unavailable"],
        attempts=[],
    )
    assert records.visits <= len(records)
