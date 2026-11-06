"""Read-only operator inventory; queue state and parser previews are separate facts."""

import hashlib
import json
from collections import Counter
from urllib.parse import urlsplit, urlunsplit

from jsonschema import Draft202012Validator

from ..collection.config import validate_config
from ..collection.discovery import inventory
from ..collection.errors import CiscoAccessError, SourceNotRetained, failure_code
from ..collection.retained import retained_fetch
from ..collection.service import resolve_document
from ..plugins.contracts import SourceNotApplicable
from ..plugins.registry import default_registry
from ..settings import PACKAGE
from ..storage.repository import now
from .comparison import parse_date

ERRORS = CiscoAccessError.CODES | {
    "publisher_scope_unavailable",
    "retained_source_missing",
    "access_verification_required",
    "source_missing",
    "redirect_target_missing",
    "edge_access_denied",
    "unsupported_or_invalid_document",
    "collection_error",
}
RETRIEVAL_ERRORS = {
    "network_error",
    "source_missing",
    "redirect_target_missing",
    "http_error",
    "access_denied",
    "edge_access_denied",
    "rate_limited",
    "access_verification_required",
    "auth_not_configured",
    "auth_rejected",
    "service_unavailable",
    "request_state_unresolved",
}
OUTCOMES = (
    "parsed_preview",
    "recognized_notice",
    "retained_unlinked_notice",
    "other_not_applicable",
    "not_retained",
    "error",
)
REPLAYS = ("recovered", "not_applicable", "still_unsupported", "not_retained")
DIAGNOSTICS = {
    "listing_duplicate_links",
    "overlapping_pages",
    "missing_document_link",
    "publisher_total_missing",
    "publisher_total_changed",
    "publisher_total_mismatch",
    "publisher_page_limit",
    "entries_without_links",
    "pagination_cycle",
    "pre_2022_history_not_enumerated",
}


def _code(value):
    return value if value in ERRORS else "collection_error" if value else None


def _url(value, vendor):
    """Only official route identities; query/fragment values are never exported."""
    if not isinstance(value, str):
        return None
    try:
        u = urlsplit(value)
        plugin = default_registry().get(vendor)
        official = any(
            u.hostname == d or (u.hostname or "").endswith("." + d) for d in plugin.domains
        )
        api = (
            vendor == "cisco"
            and u.hostname == "apix.cisco.com"
            and u.path.startswith("/security/advisories/v2/")
        )
        if (
            u.scheme != "https"
            or u.username
            or u.password
            or u.port not in (None, 443)
            or not (official or api)
        ):
            return None
        if not api and not plugin.url_filter(value):
            return None
        return urlunsplit(("https", u.netloc, u.path, "", ""))
    except ValueError:
        return None


def _evidence(db, url):
    return db.execute(
        "SELECT e.* FROM evidence e WHERE e.id=coalesce((SELECT evidence_id FROM http_cache WHERE url=?),(SELECT max(id) FROM evidence WHERE source_url=?))",
        (url, url),
    ).fetchone()


def _window(db, url, vendor, kind):
    e = _evidence(db, url)
    if e is None or kind not in ("rss", "index", "listing"):
        return None, []
    try:
        if kind == "listing":
            listing = default_registry().get(vendor).parse_archive(e["raw"], url, vendor)
            found = dict(
                entry_count=listing.entry_count,
                urls=listing.urls,
                entries_without_links=listing.entries_without_links,
            )
        else:
            found = inventory(e["raw"], url, kind)
        return dict(
            observed_at=e["observed_at"],
            entries=found["entry_count"],
            unique_links=len(found["urls"]),
            entries_without_links=found["entries_without_links"],
            historical_availability="unknown",
        ), list(found["urls"])
    except Exception:
        return None, []


def _preview(db, vendor, url):
    resolved = None
    result = dict(
        vendor=vendor,
        source_url=_url(url, vendor),
        resolved_url=None,
        source_sha256=None,
        outcome="not_retained",
        error_code=None,
        cves=None,
        assessments=None,
    )
    try:
        resolved, raw = resolve_document(db, url, vendor, fetcher=retained_fetch)
        result.update(
            resolved_url=_url(resolved, vendor), source_sha256=hashlib.sha256(raw).hexdigest()
        )
        registry = default_registry()
        normalized = registry.normalize(raw, resolved, vendor)
        plugin = registry.get(vendor)
        if not normalized["cves"]:
            if plugin.non_cve_notice(normalized):
                outcome = "recognized_notice"
            elif plugin.retain_unlinked_notice(normalized):
                outcome = "retained_unlinked_notice"
            else:
                raise ValueError("No retained identity")
        else:
            outcome = "parsed_preview"
        result.update(
            outcome=outcome,
            cves=len(normalized["cves"]),
            assessments=len(normalized["assessments"]),
        )
    except SourceNotApplicable:
        result["outcome"] = "other_not_applicable"
    except SourceNotRetained:
        pass
    except Exception as error:
        result.update(outcome="error", error_code=_code(failure_code(error)))
    # Keep the exact route internal: public URLs omit query strings/fragments.
    return result, resolved


def report(db, config: dict, *, vendor: str | None = None, limit: int = 32) -> dict:
    """Inspect an explicit vault/config without ingestion, retrieval or credential access.

    Trusted installed plugins may normalize a globally bounded retained sample.
    Those previews neither certify current ingestion nor human review.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("Coverage sample limit must be an integer from 1 to 200")
    registry = default_registry()
    if vendor is not None:
        registry.get(vendor)
    validate_config(config)
    names = registry.names()
    selected = {vendor} if vendor else set(names)
    sources = {}

    def add(name, url, kind, section=None, archive_id=None, invocation=None):
        if name not in selected:
            return
        key = (name, url, kind, invocation["run_id"] if invocation else None)
        row = sources.setdefault(
            key,
            dict(
                vendor=name,
                source_url=_url(url, name),
                kind=kind,
                configured=False,
                configuration_sections=[],
                archive_id=archive_id,
                invocation=invocation,
                budgets=dict(feed_limit=None, page_limit=None, document_limit=None),
            ),
        )
        if section:
            row["configured"] = True
            if section not in row["configuration_sections"]:
                row["configuration_sections"].append(section)
        if archive_id is not None:
            row["archive_id"] = archive_id

    for section in ("vendors", "pinned", "release_documents", "archives", "switching_sources"):
        for entry in config.get(section, []):
            add(
                entry["vendor"],
                entry["url"],
                entry.get("kind", "document" if section == "pinned" else "release_notes"),
                section,
            )
            key = (
                entry["vendor"],
                entry["url"],
                entry.get("kind", "document" if section == "pinned" else "release_notes"),
                None,
            )
            if key in sources:
                if section == "vendors":
                    sources[key]["budgets"]["feed_limit"] = entry.get("limit", 4)
                elif section == "archives":
                    sources[key]["budgets"].update(
                        page_limit=entry.get("page_limit", 2),
                        document_limit=entry.get("document_limit", 8),
                    )
    for r in db.execute("SELECT * FROM archive_sources ORDER BY id"):
        add(r["vendor"], r["source_url"], r["kind"], archive_id=r["id"])
    for r in db.execute("SELECT * FROM switching_backfills ORDER BY started_at,id"):
        invocation = dict(
            run_id=r["id"],
            study_id=r["study_id"],
            requested_window=dict(start_date=r["start_date"], end_date=r["end_date"]),
            started_at=r["started_at"],
            checked_at=r["checked_at"],
            enumeration_state="unstable"
            if r["unstable"]
            else "blocked"
            if r["error_code"]
            else "enumerated"
            if r["enumerated"]
            else "partial",
            error_code=_code(r["error_code"]),
            enumerated_identities=db.execute(
                "SELECT count(*) FROM switching_backfill_entries WHERE run_id=?", (r["id"],)
            ).fetchone()[0],
            duplicate_entries=r["duplicate_entries"],
            expected_total=r["expected_total"],
        )
        invocation["diagnostics"] = [
            issue[0]
            for issue in db.execute(
                "SELECT code FROM switching_backfill_issues WHERE run_id=? ORDER BY code",
                (r["id"],),
            )
            if issue[0] in DIAGNOSTICS
        ]
        if r["source_id"] is None:
            invocation["enumeration_state"] = "not_configured"
        add(
            r["vendor"],
            r["source_url"],
            r["kind"] or "unknown",
            archive_id=r["source_id"],
            invocation=invocation,
        )
        base = sources.get((r["vendor"], r["source_url"], r["kind"], None))
        current = sources.get((r["vendor"], r["source_url"], r["kind"] or "unknown", r["id"]))
        if base and current:
            current.update(
                configured=base["configured"],
                configuration_sections=list(base["configuration_sections"]),
                budgets=dict(base["budgets"]),
            )
    # Preserve observed unconfigured standalone sources, without allocating them to feeds.
    for r in db.execute(
        "SELECT vendor,source_url FROM collection_runs UNION SELECT vendor,source_url FROM revisions ORDER BY vendor,source_url"
    ):
        covered = any(key[0] == r["vendor"] and key[1] == r["source_url"] for key in sources)
        queued = db.execute(
            "SELECT 1 FROM archive_items i JOIN archive_sources s ON s.id=i.source_id WHERE s.vendor=? AND (i.url=? OR i.resolved_url=?)",
            (r["vendor"], r["source_url"], r["source_url"]),
        ).fetchone()
        if not covered and not queued:
            add(r["vendor"], r["source_url"], "document")
    # One preview per vendor/request URL globally, including not_applicable rows.
    targets = list(
        db.execute(
            "SELECT s.vendor,i.url,min(i.id) AS item_id,min(CASE i.state WHEN 'error' THEN 0 WHEN 'not_applicable' THEN 1 WHEN 'pending' THEN 2 ELSE 3 END) AS priority FROM archive_items i JOIN archive_sources s ON s.id=i.source_id WHERE i.kind='document' GROUP BY s.vendor,i.url ORDER BY priority,item_id"
        )
    )
    targets = [r for r in targets if r["vendor"] in selected]
    windows = {}
    for key in sources:
        name, url, kind, _ = key
        if (name, url, kind) not in windows:
            windows[(name, url, kind)] = _window(db, url, name, kind)
    seen = {(target["vendor"], target["url"]) for target in targets}
    for (name, url, kind, _), row in sources.items():
        candidates = windows[(name, url, kind)][1]
        root = _evidence(db, url)
        if (
            root is not None
            and db.execute(
                "SELECT 1 FROM revisions WHERE vendor=? AND evidence_id=? LIMIT 1",
                (name, root["id"]),
            ).fetchone()
        ):
            candidates = candidates + [url]
        if kind in ("document", "release_notes", "release_listing", "component_inventory"):
            candidates = [url]
        for candidate in candidates:
            if (name, candidate) not in seen and _url(candidate, name):
                seen.add((name, candidate))
                targets.append(dict(vendor=name, url=candidate))
    observations = [_preview(db, r["vendor"], r["url"]) for r in targets[:limit]]
    previews = [preview for preview, _ in observations]
    preview_map = {(r["vendor"], target["url"]): r for target, r in zip(targets, previews)}
    preview_urls = {
        (target["vendor"], target["url"]): resolved
        for target, (_, resolved) in zip(targets, observations)
    }
    rows = []
    for (name, url, kind, _), row in sources.items():
        invocation = row["invocation"]
        if invocation:
            items = list(
                db.execute(
                    "SELECT DISTINCT i.* FROM archive_items i JOIN switching_backfill_documents d ON d.item_id=i.id WHERE d.run_id=?",
                    (invocation["run_id"],),
                )
            )
        elif row["archive_id"] is not None:
            items = list(
                db.execute(
                    "SELECT * FROM archive_items WHERE source_id=? AND kind='document' ORDER BY id",
                    (row["archive_id"],),
                )
            )
        else:
            items = []
        doc_urls = list(dict.fromkeys([i["url"] for i in items]))
        row["observed_window"], links = windows[(name, url, kind)]
        if not invocation:
            doc_urls = list(dict.fromkeys(doc_urls + [link for link in links if _url(link, name)]))
            root = _evidence(db, url)
            if (
                root is not None
                and db.execute(
                    "SELECT 1 FROM revisions WHERE vendor=? AND evidence_id=? LIMIT 1",
                    (name, root["id"]),
                ).fetchone()
                and url not in doc_urls
            ):
                doc_urls.append(url)
        if not items and kind in (
            "document",
            "release_notes",
            "component_inventory",
            "release_listing",
        ):
            doc_urls = [url]
        queue = dict(
            discovered=len(items),
            **{
                state: sum(i["state"] == state for i in items)
                for state in ("pending", "done", "not_applicable", "error")
            },
            retrieved=0,
            retrieval_failures=0,
            unsupported=0,
            other_errors=0,
        )
        for i in items:
            queue["retrieved"] += _evidence(db, i["resolved_url"] or i["url"]) is not None
            if i["state"] == "error":
                queue[
                    "retrieval_failures"
                    if i["error_code"] in RETRIEVAL_ERRORS
                    else "unsupported"
                    if i["error_code"] == "unsupported_or_invalid_document"
                    else "other_errors"
                ] += 1
        identities = set()
        unlinked = set()
        known_representations = 0
        parsed = 0
        dates = []
        refs = {}

        def retain(e):
            if e is not None:
                refs[e["id"]] = dict(
                    evidence_id=e["id"],
                    source_url=_url(e["source_url"], name),
                    sha256=e["sha256"],
                    observed_at=e["observed_at"],
                )

        retain(_evidence(db, url))
        for target in doc_urls:
            matching = [i for i in items if i["url"] == target]
            resolved = next((i["resolved_url"] for i in matching if i["resolved_url"]), target)
            # Queue pointers/timestamps cannot prove a wrapper's current alias,
            # especially after a cache A -> B -> A reversion.
            current_requested = _evidence(db, target)
            current = current_requested if resolved == target else None
            preview = preview_map.get((name, target), {})
            preview_url = preview_urls.get((name, target))
            if preview.get("outcome") in {"parsed_preview", "retained_unlinked_notice"}:
                current = None
                candidate = _evidence(db, preview_url)
                # This also handles unqueued wrapper pins/listing links. A preview
                # establishes a relationship, never a persisted normalized record.
                if candidate is not None and candidate["sha256"] == preview["source_sha256"]:
                    current = candidate
            elif current_requested is not None:
                selection = db.execute(
                    "SELECT * FROM source_selections WHERE vendor=? AND requested_url=? ORDER BY id DESC LIMIT 1",
                    (name, target),
                ).fetchone()
                if (
                    selection
                    and db.execute(
                        "SELECT 1 FROM source_selection_views WHERE selection_id=? AND evidence_id=?",
                        (selection["id"], current_requested["id"]),
                    ).fetchone()
                ):
                    candidate = db.execute(
                        "SELECT * FROM evidence WHERE id=?", (selection["selected_evidence_id"],)
                    ).fetchone()
                    selected_current = _evidence(db, candidate["source_url"]) if candidate else None
                    if selected_current is not None and selected_current["id"] == candidate["id"]:
                        current = candidate
            retain(current_requested)
            retain(current)
            if current is None:
                continue
            revisions = db.execute(
                "SELECT normalized FROM revisions WHERE id IN (SELECT max(id) FROM revisions WHERE vendor=? AND evidence_id=? GROUP BY advisory_id)",
                (name, current["id"]),
            ).fetchall()
            known = False
            for revision in revisions:
                normalized = json.loads(revision[0])
                if normalized.get("cves"):
                    known = True
                    identities.add(normalized["advisory_id"])
                    parsed += 1
                    if parse_date(normalized.get("published_at")):
                        dates.append(normalized["published_at"])
                elif registry.get(name).retain_unlinked_notice(normalized):
                    known = True
                    unlinked.add(normalized["advisory_id"])
            known_representations += known
        checks = list(
            db.execute(
                "SELECT * FROM collection_runs WHERE vendor=? AND source_url=? ORDER BY id",
                (name, url),
            )
        )
        last = checks[-1] if checks else None
        row["health"] = (
            dict(
                checked_at=last["checked_at"],
                outcome=last["outcome"]
                if last["outcome"]
                in {
                    "ok",
                    "error",
                    "partial",
                    "not_applicable",
                    "reprocessed",
                    "unchanged",
                    "imported",
                }
                else "unknown",
                error_code=_code(last["error_code"]),
            )
            if last
            else None
        )
        replay_counts = dict(attempts=0, **{k: 0 for k in REPLAYS})
        if items:
            item_ids = {i["id"] for i in items}
            for replay in db.execute("SELECT item_id,outcome FROM archive_parser_replays"):
                if replay["item_id"] in item_ids:
                    replay_counts["attempts"] += 1
                    if replay["outcome"] in REPLAYS:
                        replay_counts[replay["outcome"]] += 1
        row["history"] = dict(
            collection_attempts=len(checks),
            collection_errors=sum(c["outcome"] == "error" for c in checks),
            parser_replays=replay_counts,
        )
        row["queue"] = queue
        row["current"] = dict(
            parsed_advisories=len(identities),
            parsed_representations=parsed,
            retained_unlinked_notices=len(unlinked),
            unknown_aliases=len(doc_urls) - known_representations,
            publisher_total=None,
            portfolio_completeness="not_established",
            model_classification="unknown",
            human_review="not_established",
            publisher_date_range=dict(
                earliest=min(dates, key=parse_date) if dates else None,
                latest=max(dates, key=parse_date) if dates else None,
            ),
        )
        sample = [
            preview_map[(name, target)] for target in doc_urls if (name, target) in preview_map
        ]
        counts = Counter(p["outcome"] for p in sample)
        row["triage"] = dict(
            sampled=len(sample),
            unsampled=len(doc_urls) - len(sample),
            **{k: counts[k] for k in OUTCOMES},
        )
        row["evidence"] = dict(
            available=len(refs), retained=list(refs.values())[:20], truncated=len(refs) > 20
        )
        rows.append(row)
    last = db.execute("SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 1").fetchone()
    result = dict(
        schema_version=1,
        generated_at=now(),
        scope=dict(vendor=vendor, sample_limit=limit),
        last_run=dict(
            scope="global_persisted_pipeline_run",
            started_at=last["started_at"],
            finished_at=last["finished_at"],
            outcome=last["outcome"]
            if last["outcome"] in {"ok", "error", "partial", "running", "interrupted"}
            else "unknown",
            imported=last["imported"],
            failures=last["failures"],
        )
        if last
        else None,
        sources=rows,
        triage=dict(
            available=len(targets),
            sampled=len(previews),
            unsampled=len(targets) - len(previews),
            truncated=len(targets) > len(previews),
            documents=previews,
        ),
        limitations=[
            "source_rows_nonadditive",
            "publisher_totals_unknown",
            "aliases_unresolved_unless_retained_identity",
            "preview_not_ingestion_or_human_review",
            "retrieval_time_not_historical_availability",
            "parsed_not_applicability",
            "queue_not_applicable_not_notice_proof",
            "historical_attempts_not_current_failures",
            "global_last_run_not_vendor_allocated",
            "no_network_or_credentials",
        ],
    )
    Draft202012Validator(
        json.loads((PACKAGE / "schemas/coverage-gaps-v1.json").read_text())
    ).validate(result)
    return result
