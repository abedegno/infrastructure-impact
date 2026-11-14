"""One installed, source-pinned Arista maintenance batch; no discovery or ambient storage."""

import json
import re
from copy import deepcopy
from hashlib import sha256

from ..adapters import arista_sa0137 as sa137
from ..collection.maintenance_profiles import batch_metadata


def joomla_csrf_digest(raw):
    """Mask one validated head-options nonce span; hash every other original byte."""
    from ..adapters.common import HTML

    class OptionsHTML(HTML):
        def handle_data(self, text):
            if self.stack[-1].tag == "script":
                self.stack[-1].children.append(text)
            else:
                super().handle_data(text)

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    try:
        if type(raw) is not bytes or len(raw) > 2_000_000:
            raise ValueError()
        root = OptionsHTML(raw).root
        heads = list(root.find({"head"}))
        bodies = list(root.find({"body"}))
        scripts = [
            n
            for n in root.find({"script"})
            if "joomla-script-options" in n.attrs.get("class", "").split()
        ]
        if len(heads) != 1 or len(bodies) != 1 or len(scripts) != 1:
            raise ValueError()
        html = heads[0].parent
        if (
            html.tag != "html"
            or html.parent is not root
            or bodies[0].parent is not html
            or html.children.index(heads[0]) > html.children.index(bodies[0])
        ):
            raise ValueError()
        script = scripts[0]
        ancestor = script.parent
        while ancestor is not None and ancestor is not heads[0]:
            ancestor = ancestor.parent
        if ancestor is None or script.attrs.get("type") != "application/json":
            raise ValueError()
        if not script.children or any(type(c) is not str for c in script.children):
            raise ValueError()
        content = "".join(script.children).encode("utf-8")

        def finite_constant(_value):
            raise ValueError("invalid_json_constant")

        options = json.loads(content, object_pairs_hook=unique, parse_constant=finite_constant)
        matches = list(re.finditer(rb'"csrf\.token"\s*:\s*"([0-9a-f]{32})"', content))
        if (
            type(options) is not dict
            or len(matches) != 1
            or options.get("csrf.token") != matches[0][1].decode("ascii")
            or len(re.findall(rb'"csrf\.token"\s*:', raw)) != 1
            or raw.count(content) != 1
        ):
            raise ValueError()
        start = raw.index(content) + matches[0].start(1)
        end = start + 32
        return sha256(raw[:start] + b"0" * 32 + raw[end:]).hexdigest()
    except (ValueError, TypeError, AttributeError, UnicodeError):
        raise ValueError("maintenance_html_projection_invalid") from None


def _capture_matches(raw, pin):
    if type(raw) is not bytes or len(raw) != pin["bytes"]:
        return False
    if sha256(raw).hexdigest() == pin["sha256"]:
        return True
    if pin["kind"] != "html" or not pin.get("joomla_csrf_sha256"):
        return False
    try:
        return joomla_csrf_digest(raw) == pin["joomla_csrf_sha256"]
    except ValueError:
        return False


def _retained_capture(row, pin):
    raw = bytes(row["raw"])
    if row["source_url"] != pin["url"] or sha256(raw).hexdigest() != row["sha256"]:
        raise ValueError("maintenance_capture_changed")
    if not _capture_matches(raw, pin):
        return None
    return raw, dict(url=row["source_url"], sha256=row["sha256"], retrieved_at=row["observed_at"])


def exact_capture(db, pin):
    """Prefer exact reference bytes; otherwise verify the latest HTML nonce variant."""
    row = db.execute(
        "SELECT * FROM evidence WHERE source_url=? AND sha256=?",
        (pin["url"], pin["sha256"]),
    ).fetchone()
    if row is not None:
        capture = _retained_capture(row, pin)
        if capture is None:
            raise ValueError("maintenance_capture_changed")
        return capture
    if pin["kind"] == "html":
        row = db.execute(
            "SELECT * FROM evidence WHERE source_url=? ORDER BY id DESC LIMIT 1", (pin["url"],)
        ).fetchone()
        if row is not None:
            return _retained_capture(row, pin)
    return None


def _reviewed_refresh(owner, pin, batch):
    """This installed batch permits one reviewed SA178 source transition only."""
    refreshes = batch.get("reviewed_owner_refreshes", [])
    if pin["number"] != 178 or pin["kind"] != "csaf" or len(refreshes) != 1:
        return None
    refresh = refreshes[0]
    if (
        refresh["advisory_id"] == owner["advisory_id"] == "Arista Networks Security Advisory 178"
        and refresh["source_url"] == owner["source_url"] == pin["url"]
        and refresh["old_sha256"] == owner["sha256"]
        and refresh["cve_ids"] == owner["cves"] == pin["cve_ids"]
        and refresh["old_document_status"] == owner.get("document_status")
        and refresh["new_sha256"] == pin["sha256"]
        and refresh["new_bytes"] == pin["bytes"]
    ):
        return refresh
    return None


def _verified_refreshes(db, records):
    """Verify the actual retained old capture before any retrieval or normalization."""
    batch = batch_metadata()
    pin = next(p for p in batch["captures"] if p["number"] == 178 and p["kind"] == "csaf")
    owners = [
        r
        for r in records
        if r["vendor"] == "arista" and r["advisory_id"] == "Arista Networks Security Advisory 178"
    ]
    if len(owners) != 1:
        return {}
    owner = owners[0]
    refresh = _reviewed_refresh(owner, pin, batch)
    if refresh is None:
        return {}
    row = db.execute("SELECT * FROM evidence WHERE id=?", (owner["evidence_id"],)).fetchone()
    if (
        row is None
        or row["source_url"] != refresh["source_url"]
        or row["sha256"] != refresh["old_sha256"]
    ):
        raise ValueError("maintenance_reviewed_owner_capture_missing")
    raw = bytes(row["raw"])
    if len(raw) > 2_000_000 or sha256(raw).hexdigest() != refresh["old_sha256"]:
        raise ValueError("maintenance_reviewed_owner_capture_changed")
    data = json.loads(raw)
    document = data["document"]
    if (
        document["tracking"]["id"] != refresh["advisory_id"]
        or document["tracking"]["status"] != refresh["old_document_status"]
        or document["title"] != refresh["document_title"]
        or owner["title"] != refresh["document_title"]
        or sorted({v["cve"] for v in data["vulnerabilities"]}) != refresh["cve_ids"]
    ):
        raise ValueError("maintenance_reviewed_owner_header_changed")
    return {pin["url"]: refresh}


def _blocking_owner_issues(db, records):
    return [
        issue for issue in owner_issues(records, db=db) if issue["code"] != "reviewed_owner_refresh"
    ]


def owner_issues(records, *, db):
    """CSAF owners are mandatory; an existing SA137 HTML owner must also match."""
    batch = batch_metadata()
    issues = []
    for pin in batch["captures"]:
        required = pin["kind"] in {"csaf", "csaf_draft"}
        if not required and pin["url"] != sa137.URL:
            continue
        identity = (
            sa137.ID
            if pin["url"] == sa137.URL
            else f"Arista Networks Security Advisory {pin['number']}"
        )
        owners = [r for r in records if r["vendor"] == "arista" and r["advisory_id"] == identity]
        if not owners and required:
            issues.append(dict(code="missing_required_owner", source_url=pin["url"]))
        elif len(owners) == 1 and _reviewed_refresh(owners[0], pin, batch):
            issues.append(dict(code="reviewed_owner_refresh", source_url=pin["url"]))
        elif owners and (
            len(owners) != 1
            or owners[0]["source_url"] != pin["url"]
            or (pin["kind"] != "html" and owners[0]["sha256"] != pin["sha256"])
            or owners[0]["cves"] != pin["cve_ids"]
        ):
            issues.append(dict(code="changed_required_owner", source_url=pin["url"]))
        elif owners and pin["kind"] == "html":
            row = db.execute(
                "SELECT * FROM evidence WHERE id=?", (owners[0]["evidence_id"],)
            ).fetchone()
            try:
                valid = (
                    row is not None
                    and row["sha256"] == owners[0]["sha256"]
                    and _retained_capture(row, pin) is not None
                )
            except ValueError:
                valid = False
            if not valid:
                issues.append(dict(code="changed_required_owner", source_url=pin["url"]))
    return issues


def capture_state(db):
    """Bind exact capture identities, bytes, original timestamps and explicit absence."""
    states = []
    issues = []
    batch = batch_metadata()
    for pin in batch["captures"]:
        refresh_hashes = [
            r["old_sha256"]
            for r in batch.get("reviewed_owner_refreshes", [])
            if r["source_url"] == pin["url"]
        ]
        hashes = [pin["sha256"], *refresh_hashes]
        marks = ",".join("?" for _ in hashes)
        owner_id = None
        if pin["kind"] == "html" and pin["url"] == sa137.URL:
            owner = db.execute(
                "SELECT evidence_id FROM revisions WHERE vendor='arista' AND advisory_id=? ORDER BY id DESC LIMIT 1",
                (sa137.ID,),
            ).fetchone()
            owner_id = owner["evidence_id"] if owner else None
        rows = db.execute(
            "SELECT id,source_url,sha256,observed_at,length(raw) AS bytes,raw FROM evidence "
            "WHERE (source_url=? AND (sha256 IN ("
            + marks
            + ") OR id=(SELECT MAX(id) FROM evidence WHERE source_url=?))) OR id=? ORDER BY id",
            (pin["url"], *hashes, pin["url"], owner_id),
        ).fetchall()
        states.append(
            dict(
                source_url=pin["url"],
                captures=[
                    dict(
                        id=r["id"],
                        source_url=r["source_url"],
                        sha256=r["sha256"],
                        observed_at=r["observed_at"],
                        bytes=r["bytes"],
                        body_sha256=sha256(r["raw"]).hexdigest(),
                    )
                    for r in rows
                ],
            )
        )
        try:
            present = exact_capture(db, pin) is not None
        except ValueError:
            issues.append(dict(code="invalid_pinned_capture", source_url=pin["url"]))
            continue
        if not present:
            issues.append(
                dict(
                    code="missing_optional_rss"
                    if pin["kind"] == "rss"
                    else "missing_required_capture",
                    source_url=pin["url"],
                )
            )
    return states, issues


def apply_batch(db, selected, before, *, fetcher=None):
    """Prepare all 34 records before writing; the maintenance caller owns the lock."""
    import sqlite3

    from ..adapters.arista_chronology import reconcile
    from ..collection.errors import failure_code
    from ..collection.service import resolve_document, retain_resolution
    from ..collection.transport import fetch
    from ..plugins.registry import default_registry
    from ..storage.repository import evidence, ingest, latest, now
    from . import maintenance, switching_evidence
    from .arista_chronology_repair import validate_cases
    from .current_evidence import collect_policy_input, partition, report_bytes
    from .evidence_identity import record_key

    batch = batch_metadata()
    pins = batch["captures"]
    by_url = {p["url"]: p for p in pins}
    supplements = [p for p in pins if p["url"] not in selected.primary_urls]
    receipt = dict(
        format="impact-maintenance-apply",
        schema_version=1,
        profile_id=selected.profile_id,
        profile_version=selected.version,
        observed_at=now(),
        preview_fingerprint=before["fingerprint"],
        baseline_fingerprint=before["baseline_fingerprint"],
        profile_fingerprint=selected.fingerprint,
        policy_fingerprint=selected.policy_fingerprint,
        normalizer_fingerprint=before["normalizer_fingerprint"],
        outcome="failed_primary_validation",
        primary_outcomes=[],
        alternate_outcomes=[
            dict(source_url=p["url"], outcome="not_attempted") for p in supplements
        ],
        imported=0,
        unchanged=0,
        before_keys=sorted(record_key(r) for r in latest(db)),
        after_keys=[],
        decisions=[],
        proof_fingerprints=[],
        issues=[],
    )

    def finish(outcome):
        receipt["outcome"] = outcome
        receipt["after_keys"] = sorted(record_key(r) for r in latest(db))
        maintenance.receipt_bytes(receipt)
        return receipt

    captures = {}
    accepted_bytes = 0
    retrieve = fetcher or fetch
    active_refreshes = {}
    source_refreshed = False

    def load(pin):
        nonlocal accepted_bytes
        url = pin["url"]
        capture = exact_capture(db, pin)
        if capture is None:
            if pin["kind"] == "rss":
                return None
            if pin["kind"] != "html" and url not in active_refreshes:
                raise ValueError("maintenance_required_capture_missing")
            raw = retrieve(
                db, url, "arista", max_bytes=selected.max_bytes, allowed_urls=selected.allowed_urls
            )
            if not _capture_matches(raw, pin):
                raise ValueError("maintenance_capture_changed")
            # Preserve actual runner retrieval time. Reference pin timestamps are never used here.
            with db:
                row = evidence(
                    db, raw, url, "text/html" if pin["kind"] == "html" else "application/json"
                )
            capture = _retained_capture(row, pin)
        accepted_bytes += len(capture[0])
        if accepted_bytes > batch["reference_capture_bytes"]:
            raise ValueError("maintenance_capture_budget")
        captures[url] = capture
        return capture

    def cached_fetch(connection, url, vendor):
        if connection is not db or vendor != "arista" or url not in captures:
            raise ValueError("maintenance_url_rejected")
        return captures[url][0]

    try:
        # Verify the one exact old owner and every other structured capture before HTTP.
        records = latest(db)
        if _blocking_owner_issues(db, records):
            return finish("failed_primary_validation")
        active_refreshes = _verified_refreshes(db, records)
        pending_refresh = []
        for pin in pins:
            if pin["kind"] in {"csaf", "csaf_draft"}:
                if pin["url"] in active_refreshes and exact_capture(db, pin) is None:
                    pending_refresh.append(pin)
                else:
                    load(pin)
        for pin in pending_refresh:
            load(pin)
        for pin in pins:
            if pin["kind"] not in {"csaf", "csaf_draft"}:
                load(pin)
        for outcome in receipt["alternate_outcomes"]:
            if outcome["source_url"] in captures:
                outcome["outcome"] = "validated"
        draft = captures[sa137.CSAF][0]
        if sha256(draft).hexdigest() != sa137.REVIEWED_SHA256 or not sa137.draft_shape(draft):
            return finish("failed_alternate_validation")
        registry = default_registry()
        prepared = []
        source_refreshes = []
        chronologies = {}
        rss_pin = next(p for p in pins if p["kind"] == "rss")
        rss = captures.get(rss_pin["url"])
        # All required captures have validated; the pure normalizers cannot write.
        for url, advisory_id, cves in selected.expected_primaries:
            pin = by_url[url]
            resolved = None
            if url == sa137.URL:
                resolved = resolve_document(db, url, "arista", fetcher=cached_fetch)
                if (
                    resolved[0] != url
                    or resolved.source_failures
                    or len(resolved.selection.alternatives) != 1
                ):
                    raise ValueError("maintenance_selection_changed")
            raw, source = captures[url]
            parsed = registry.normalize(raw, url, "arista")
            if parsed["advisory_id"] != advisory_id or parsed["cves"] != list(cves):
                raise ValueError("maintenance_primary_identity_changed")
            if url in active_refreshes:
                source_refreshes.append((url, raw, deepcopy(parsed)))
            if pin["kind"] == "csaf":
                h = next(p for p in pins if p["number"] == pin["number"] and p["kind"] == "html")
                html = captures[h["url"]]
                parsed["source_observed_at"] = source["retrieved_at"]
                result = reconcile(
                    parsed,
                    html_raw=html[0],
                    html_source=html[1],
                    csaf_raw=raw,
                    rss_raw=rss[0] if rss else None,
                    rss_source=rss[1] if rss else None,
                )
                if result["status"] != "corrected" or not result["chronology"]:
                    raise ValueError("maintenance_chronology_unresolved")
                fixed = result["corrected_record"]
                # Reconciliation may change only initial publication and attach its proof.
                restored = {k: v for k, v in fixed.items() if k != "publisher_chronology"}
                restored["published_at"] = parsed["published_at"]
                if restored != parsed:
                    raise ValueError("maintenance_chronology_scope_changed")
                fixed.pop("source_observed_at", None)
                chronologies[advisory_id] = fixed["published_at"]
                parsed = fixed
            prepared.append((url, raw, parsed, resolved))
            receipt["primary_outcomes"].append(dict(source_url=url, outcome="validated"))
        if (
            len(prepared) != 34
            or len(chronologies) != 33
            or _blocking_owner_issues(db, latest(db))
            or _verified_refreshes(db, latest(db)) != active_refreshes
        ):
            return finish("failed_primary_validation")
        # Every required pair is prepared before retaining the reviewed vendor revision.
        # Its changed fixes are a source update, followed by the existing chronology repair.
        for url, raw, fresh in source_refreshes:
            source_refreshed = (
                bool(ingest(db, raw, url, lambda *_args, fresh=fresh: fresh, "arista"))
                or source_refreshed
            )
        for i, (url, raw, parsed, resolved) in enumerate(prepared):
            changed = ingest(db, raw, url, lambda *_args, parsed=parsed: parsed, "arista")
            state = "imported" if changed else "unchanged"
            receipt[state] += 1
            receipt["primary_outcomes"][i]["outcome"] = state
            if resolved is not None:
                retain_resolution(db, "arista", url, resolved)
        records = latest(db)
        # Finalize real claim IDs only after the accepted chronology has been attached.
        chronology_records = [
            r for r in records if r["vendor"] == "arista" and r["advisory_id"] in chronologies
        ]
        projected = switching_evidence.project(
            switching_evidence.inputs(db, chronology_records),
            publication=None,
            generated_at=receipt["observed_at"],
        )
        validation_rows = []
        for identity, initial in chronologies.items():
            claims = [
                c
                for c in projected["claims"]
                if c["vendor"] == "arista" and c["advisory_id"] == identity
            ]
            if not claims or {c["initial_published_at"] for c in claims} != {initial}:
                return finish("failed_cleanup_proof")
            fixed = next(
                parsed for _, _, parsed, _ in prepared if parsed["advisory_id"] == identity
            )
            meta = fixed["publisher_chronology"]
            rss_dates = [
                o["value"] for o in meta["observations"] if o["event"] == "rss_publication"
            ]
            validation_rows.append(
                dict(
                    number=int(identity.rsplit(" ", 1)[1]),
                    status="corrected",
                    source_hashes=dict(
                        html=meta["html_source"]["sha256"],
                        csaf=meta["csaf_source"]["sha256"],
                        rss=meta["rss_source"]["sha256"] if meta["rss_source"] else None,
                    ),
                    effective_initial=initial,
                    csaf_initial=meta["original_published_at"],
                    rss_publication=rss_dates[0] if rss_dates else None,
                    claim_initials=[initial],
                    finalized_claim_initials=sorted({c["initial_published_at"] for c in claims}),
                    claim_scope_and_fixes_unchanged=True,
                )
            )
        if any(c["automated_validation"] == "failed" for c in validate_cases(validation_rows)):
            return finish("failed_cleanup_proof")
        report = partition(
            records,
            collect_policy_input(db, records, registry=registry),
            registry=registry,
            publication=None,
            generated_at=receipt["observed_at"],
        )["current_evidence"]
        report_bytes(report)
        receipt["decisions"] = report["decisions"]
        receipt["issues"] = report["issues"]
        receipt["proof_fingerprints"] = sorted(
            {maintenance._digest(p) for d in report["decisions"] for p in d["proofs"]}
        )
        draft_records = [
            r
            for r in records
            if r["vendor"] == "arista"
            and r["advisory_id"] == sa137.CSAF_ID
            and r["source_url"] == sa137.CSAF
            and r["sha256"] == sa137.REVIEWED_SHA256
        ]
        if (
            len(draft_records) != 1
            or not any(d["target_key"] == record_key(draft_records[0]) for d in report["decisions"])
            or report["issues"]
            or not maintenance._batch_completed(receipt, selected)
        ):
            return finish("failed_cleanup_proof")
        return finish("completed")
    except sqlite3.Error:
        db.rollback()
        return finish("failed_storage")
    except (ValueError, KeyError, TypeError):
        return finish(
            "failed_primary_validation"
            if not source_refreshed and not receipt["imported"] and not receipt["unchanged"]
            else "failed_cleanup_proof"
        )
    except Exception as error:
        # Transport errors never expose response bodies or arbitrary exception text.
        if not receipt["primary_outcomes"]:
            receipt["primary_outcomes"] = [
                dict(
                    source_url=selected.primary_urls[0],
                    outcome="failed",
                    error_code=failure_code(error),
                )
            ]
        return finish(
            "failed_cleanup_proof"
            if source_refreshed or receipt["imported"] or receipt["unchanged"]
            else "failed_primary_validation"
        )
