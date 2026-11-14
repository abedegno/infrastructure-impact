"""One installed, source-pinned Arista maintenance batch; no discovery or ambient storage."""

from hashlib import sha256

from ..adapters import arista_sa0137 as sa137
from ..collection.maintenance_profiles import batch_metadata


def exact_capture(db, pin):
    """Return verified exact retained bytes and their actual runner receipt."""
    row = db.execute(
        "SELECT * FROM evidence WHERE source_url=? AND sha256=?",
        (pin["url"], pin["sha256"]),
    ).fetchone()
    if row is None:
        return None
    raw = bytes(row["raw"])
    if len(raw) != pin["bytes"] or sha256(raw).hexdigest() != pin["sha256"]:
        raise ValueError("maintenance_capture_changed")
    return raw, dict(url=row["source_url"], sha256=row["sha256"], retrieved_at=row["observed_at"])


def owner_issues(records):
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
        elif owners and (
            len(owners) != 1
            or owners[0]["source_url"] != pin["url"]
            or owners[0]["sha256"] != pin["sha256"]
            or owners[0]["cves"] != pin["cve_ids"]
        ):
            issues.append(dict(code="changed_required_owner", source_url=pin["url"]))
    return issues


def capture_state(db):
    """Bind exact capture identities, bytes, original timestamps and explicit absence."""
    states = []
    issues = []
    for pin in batch_metadata()["captures"]:
        rows = db.execute(
            "SELECT id,sha256,observed_at,length(raw) AS bytes,raw FROM evidence "
            "WHERE source_url=? AND (sha256=? OR id=(SELECT MAX(id) FROM evidence WHERE source_url=?)) ORDER BY id",
            (pin["url"], pin["sha256"], pin["url"]),
        ).fetchall()
        states.append(
            dict(
                source_url=pin["url"],
                captures=[
                    dict(
                        id=r["id"],
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

    def load(pin):
        nonlocal accepted_bytes
        url = pin["url"]
        capture = exact_capture(db, pin)
        if capture is None:
            if pin["kind"] == "rss":
                return None
            if pin["kind"] != "html":
                raise ValueError("maintenance_required_capture_missing")
            raw = retrieve(
                db, url, "arista", max_bytes=selected.max_bytes, allowed_urls=selected.allowed_urls
            )
            if (
                type(raw) is not bytes
                or len(raw) != pin["bytes"]
                or sha256(raw).hexdigest() != pin["sha256"]
            ):
                raise ValueError("maintenance_capture_changed")
            # Preserve actual runner retrieval time. Reference pin timestamps are never used here.
            with db:
                evidence(db, raw, url, "text/html")
            capture = exact_capture(db, pin)
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
        # All current owners and all mandatory retained structured captures precede HTTP.
        if owner_issues(latest(db)):
            return finish("failed_primary_validation")
        for pin in pins:
            if pin["kind"] in {"csaf", "csaf_draft"}:
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
        if len(prepared) != 34 or len(chronologies) != 33 or owner_issues(latest(db)):
            return finish("failed_primary_validation")
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
            if not receipt["imported"] and not receipt["unchanged"]
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
            if receipt["imported"] or receipt["unchanged"]
            else "failed_primary_validation"
        )
