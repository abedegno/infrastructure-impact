"""Explicit paired-source chronology repair; no collection or implicit activation.

Receipt keys deliberately describe a separate capture (url/sha256/retrieved_at),
not the study's primary claim source. They must never be restamped at ingestion.
"""

import json
import re
from copy import deepcopy
from datetime import date, datetime
from email.utils import parsedate_to_datetime
from hashlib import sha256
from urllib.parse import urljoin
from xml.etree import ElementTree

from .common import HTML, cves, iso_date

HTML_URL = r"https://www\.arista\.com/en/support/advisories-notices/security-advisory/\d+-security-advisory-0*(\d+)"
CSAF_URL = "https://www.arista.com/assets/data/SecurityAdvisories/CSAF/arista_networks_security_advisory_{}_CSAF.json"
RSS_URL = "https://www.arista.com/en/support/advisories-notices/security-advisory-rss"
METHOD = "arista_owned_html_initial_v1"


def _bytes(raw):
    return raw.encode() if isinstance(raw, str) else raw


def _receipt(raw, source):
    if not isinstance(source, dict) or set(source) != {"url", "sha256", "retrieved_at"}:
        raise ValueError("capture_receipt_invalid")
    if sha256(_bytes(raw)).hexdigest() != source["sha256"]:
        raise ValueError("capture_hash_mismatch")
    at = datetime.fromisoformat(source["retrieved_at"].replace("Z", "+00:00"))
    if not at.tzinfo:
        raise ValueError("capture_time_invalid")
    return deepcopy(source)


def _day(literal):
    value = iso_date(literal)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("html_date_not_day_precision")
    return date.fromisoformat(value).isoformat()


def _observation(event, literal, value, source, locator, revision=None, summary=None):
    return dict(
        event=event,
        literal=literal,
        value=value,
        source=source,
        locator=locator,
        revision=revision,
        summary=summary,
    )


def reconcile(record, *, html_raw, html_source, csaf_raw, rss_raw=None, rss_source=None):
    """Return an isolated copy, correcting only an exactly paired HTML initial day.

    Optional record.source_observed_at is the caller-owned CSAF capture time;
    absence remains null. Local ingestion time must not masquerade as that time.
    """
    unchanged = dict(
        status="unchanged", corrected_record=deepcopy(record), chronology=None, issues=[]
    )
    try:
        if any(key in record for key in ("revision_id", "evidence_id", "observed_at")):
            raise ValueError("materialized_revision_requires_fresh_normalization")
        html_source = _receipt(html_raw, html_source)
        match = re.fullmatch(HTML_URL, html_source["url"])
        if not match:
            raise ValueError("html_identity_invalid")
        number = int(match[1])
        url = CSAF_URL.format(number)
        data = json.loads(csaf_raw)
        doc = data["document"]
        tracking = doc["tracking"]
        digest = sha256(_bytes(csaf_raw)).hexdigest()
        identity = f"Arista Networks Security Advisory {number}"
        ids = sorted({v["cve"] for v in data["vulnerabilities"]})
        if (
            record.get("vendor") != "arista"
            or record.get("source_url") != url
            or record.get("advisory_id") != identity
            or tracking["id"] != identity
            or doc["title"] != f"Security Advisory {number}"
            or sorted(record["cves"]) != ids
            or not ids
            or record.get("sha256", digest) != digest
        ):
            raise ValueError("csaf_record_identity_mismatch")
        if [r["url"] for r in doc.get("references", []) if r.get("category") == "self"] != [
            html_source["url"]
        ]:
            raise ValueError("csaf_self_reference_mismatch")
        tree = HTML(html_raw).root
        articles = [
            n for n in tree.find({"div"}) if "item-page" in n.attrs.get("class", "").split()
        ]
        if len(articles) != 1:
            raise ValueError("article_boundary_ambiguous")
        article = articles[0]
        headings = [
            n for n in article.find({"h2"}) if "pageTitle" in n.attrs.get("class", "").split()
        ]
        if len(headings) != 1 or not re.match(
            rf"^Security Advisory 0*{number}\b", headings[0].text()
        ):
            raise ValueError("html_heading_mismatch")
        links = [
            urljoin(html_source["url"], n.attrs.get("href", ""))
            for n in headings[0].find({"a"})
            if n.attrs.get("title") == "Download CSAF"
        ]
        if links != [url]:
            raise ValueError("article_csaf_link_mismatch")
        # Only the introductory tracking paragraphs or Description CVE headings
        # own advisory membership. Later affected/resolution/footer text cannot.
        intro_ids = []
        description = False
        for node in article.find({"h2", "h4", "p"}):
            text = node.text()
            if node.tag == "h2":
                if text == "Description":
                    description = True
                elif text == "Vulnerability Assessment":
                    break
            if node.tag == "p" and text.startswith("The CVE-ID tracking this issue:"):
                intro_ids.extend(cves(text))
            elif description and node.tag == "h4" and re.fullmatch(r"CVE-\d{4}-\d{4,}", text):
                intro_ids.append(text)
        if sorted(set(intro_ids)) != ids:
            raise ValueError("html_cve_scope_mismatch")
        tables = [
            t
            for t in article.find({"table"})
            if any(
                [c.text() for c in row.find({"th"})] == ["Revision", "Date", "Changes"]
                for row in t.find({"tr"})
            )
        ]
        if len(tables) != 1:
            raise ValueError("revision_table_ambiguous")
        rows = [
            [c.text() for c in row.find({"td"})]
            for row in tables[0].find({"tr"})
            if list(row.find({"td"}))
        ]
        if not rows or any(len(row) != 3 for row in rows):
            raise ValueError("revision_row_invalid")
        initial = [r for r in rows if r[0] == "1.0"]
        if len(initial) != 1 or initial[0][2].lower() != "initial release":
            raise ValueError("initial_revision_ambiguous")
        effective = _day(initial[0][1])
        dates = [_day(row[1]) for row in rows]
        if (
            len({r[0] for r in rows}) != len(rows)
            or dates != sorted(dates)
            or rows[0] != initial[0]
        ):
            raise ValueError("html_revision_conflict")
        headers = [
            n.text().removeprefix("Date:").strip()
            for n in article.find({"p"})
            if n.text().startswith("Date:")
        ]
        if len(headers) != 1 or _day(headers[0]) != effective:
            raise ValueError("html_initial_date_conflict")
        if record.get("publisher_chronology"):
            raise ValueError("already_reconciled_use_original_record")
        if record.get("published_at") != tracking.get("initial_release_date") or record.get(
            "updated_at"
        ) != tracking.get("current_release_date"):
            raise ValueError("original_csaf_dates_mismatch")
        observations = [
            _observation(
                "html_revision", r[1], day, "html", f"item-page/revision-table/row/{i}", r[0], r[2]
            )
            for i, (r, day) in enumerate(zip(rows, dates, strict=True))
        ]
        for field, event in [
            ("initial_release_date", "csaf_initial"),
            ("current_release_date", "csaf_current"),
        ]:
            value = tracking.get(field)
            if not value or not datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo:
                raise ValueError("csaf_date_invalid")
            observations.append(
                _observation(event, value, value, "csaf", "/document/tracking/" + field)
            )
        issues = []
        revisions = tracking.get("revision_history", [])
        for i, r in enumerate(revisions):
            datetime.fromisoformat(r["date"].replace("Z", "+00:00"))
            observations.append(
                _observation(
                    "csaf_revision",
                    r["date"],
                    r["date"],
                    "csaf",
                    f"/document/tracking/revision_history/{i}",
                    r["number"],
                    r["summary"],
                )
            )
        if revisions and (
            revisions[-1]["date"] != tracking["current_release_date"]
            or revisions[-1]["number"] != tracking["version"]
        ):
            issues.append("csaf_current_revision_conflict")
        # A CSAF current/history conflict does not contradict the owned HTML
        # initial event. It remains explicit, and current/updated is untouched.
        rss = None
        if rss_raw is not None:
            rss = _receipt(rss_raw, rss_source)
            if rss["url"] != RSS_URL:
                raise ValueError("rss_source_invalid")
            items = [
                i
                for i in ElementTree.fromstring(rss_raw).findall("./channel/item")
                if i.findtext("link") == html_source["url"]
            ]
            if len(items) > 1:
                raise ValueError("rss_item_ambiguous")
            if items:
                literal = items[0].findtext("pubDate")
                value = parsedate_to_datetime(literal).isoformat()
                observations.append(
                    _observation(
                        "rss_publication",
                        literal,
                        value,
                        "rss",
                        "channel/item/link=" + html_source["url"],
                    )
                )
            else:
                issues.append("rss_item_not_observed")
        else:
            issues.append("rss_not_supplied")
        meta = dict(
            method=METHOD,
            advisory_id=identity,
            cve_ids=ids,
            effective_initial=effective,
            original_published_at=record["published_at"],
            original_updated_at=record["updated_at"],
            html_source=html_source,
            csaf_source=dict(url=url, sha256=digest, retrieved_at=record.get("source_observed_at")),
            rss_source=rss,
            observations=observations,
            issues=issues,
        )
        corrected = deepcopy(record)
        corrected["published_at"] = effective
        corrected["publisher_chronology"] = meta
        from ..domain import validate_advisory

        validate_advisory(corrected)
        return dict(
            status="corrected", corrected_record=corrected, chronology=deepcopy(meta), issues=issues
        )
    except (ValueError, TypeError, KeyError, ElementTree.ParseError) as error:
        # Do not echo source bytes, paths, or arbitrary exception values publicly.
        code = str(error) if re.fullmatch("[a-z_]+", str(error)) else "invalid_chronology_input"
        unchanged["issues"] = [code]
        return unchanged


def validate_chronology_binding(
    meta, *, vendor, advisory_id, cve_ids, source_url, source_sha256=None, initial, updated
):
    """Cross-field guards shared by normalized records and study claim copies."""
    if (
        meta["method"] != METHOD
        or vendor != "arista"
        or meta["advisory_id"] != advisory_id
        or not set(cve_ids).issubset(meta["cve_ids"])
        or not cve_ids
        or meta["csaf_source"]["url"] != source_url
        or (source_sha256 is not None and meta["csaf_source"]["sha256"] != source_sha256)
        or meta["effective_initial"] != initial
        or meta["original_updated_at"] != updated
    ):
        raise ValueError("chronology_binding_mismatch")
    match = re.fullmatch(HTML_URL, meta["html_source"]["url"])
    if (
        not match
        or meta["csaf_source"]["url"] != CSAF_URL.format(int(match[1]))
        or advisory_id != f"Arista Networks Security Advisory {int(match[1])}"
        or meta["html_source"]["retrieved_at"] is None
        or (meta["rss_source"] is not None and meta["rss_source"]["url"] != RSS_URL)
    ):
        raise ValueError("chronology_pair_identity_mismatch")
    initials = [
        o for o in meta["observations"] if o["event"] == "html_revision" and o["revision"] == "1.0"
    ]
    csaf = [o for o in meta["observations"] if o["event"] == "csaf_initial"]
    if (
        len(initials) != 1
        or initials[0]["value"] != initial
        or initials[0]["source"] != "html"
        or len(csaf) != 1
        or csaf[0]["value"] != meta["original_published_at"]
        or csaf[0]["source"] != "csaf"
    ):
        raise ValueError("chronology_event_mismatch")


def apply_claim_chronology(extracted, record, raw):
    """Correct claim templates before finalization; never mutate accepted claims."""
    result = deepcopy(extracted)
    meta = record.get("publisher_chronology")
    if meta is None:
        return result
    from ..domain import validate_advisory

    validate_advisory(record)
    if sha256(_bytes(raw)).hexdigest() != meta["csaf_source"]["sha256"]:
        raise ValueError("chronology_capture_mismatch")
    for claim in result.get("claims", []):
        if "claim_id" in claim:
            raise ValueError("chronology refuses finalized claims")
        if claim["initial_published_at"] != meta["original_published_at"]:
            raise ValueError("chronology_original_date_mismatch")
        validate_chronology_binding(
            meta,
            vendor=claim["vendor"],
            advisory_id=claim["advisory_id"],
            cve_ids=[claim["cve_id"]],
            source_url=claim["source"]["source_url"],
            source_sha256=claim["source"]["source_sha256"],
            initial=meta["effective_initial"],
            updated=claim["updated_at"],
        )
        claim["initial_published_at"] = meta["effective_initial"]
        claim["initial_date_provenance"] = deepcopy(meta)
    return result


def retained_chronology(raw, document, previous, lookup):
    """Recompute accepted enrichment from exact local receipts, or fail closed."""
    meta = previous.get("publisher_chronology")
    if meta is None:
        return document
    try:
        if (
            document["source_url"] != meta["csaf_source"]["url"]
            or sha256(_bytes(raw)).hexdigest() != meta["csaf_source"]["sha256"]
            or document["advisory_id"] != meta["advisory_id"]
            or sorted(document["cves"]) != sorted(meta["cve_ids"])
        ):
            raise ValueError("chronology_source_changed_requires_review")
        fresh = deepcopy(document)
        if meta["csaf_source"]["retrieved_at"] is not None:
            fresh["source_observed_at"] = meta["csaf_source"]["retrieved_at"]
        html = lookup(meta["html_source"])
        rss = lookup(meta["rss_source"]) if meta["rss_source"] else None
        result = reconcile(
            fresh,
            html_raw=html,
            html_source=meta["html_source"],
            csaf_raw=raw,
            rss_raw=rss,
            rss_source=meta["rss_source"],
        )
        if result["chronology"] != meta:
            raise ValueError("chronology_proof_invalid_requires_review")
        fixed = result["corrected_record"]
        if "source_observed_at" not in document:
            fixed.pop("source_observed_at", None)
        return fixed
    except (KeyError, TypeError, ValueError):
        raise ValueError("chronology_unresolved_requires_review") from None
