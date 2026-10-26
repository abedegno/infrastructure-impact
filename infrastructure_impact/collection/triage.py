"""Bounded archive layout triage; source capture is separate from queue ingestion."""

import hashlib
import json
import re
from collections import Counter, defaultdict

from ..adapters.common import HTML
from ..plugins.contracts import SourceNotApplicable
from ..plugins.registry import default_registry
from ..storage.repository import now
from .errors import check_access_response, failure_code
from .service import resolve_document
from .transport import allowed


def layout_key(raw):
    """Describe structure only; matching keys do not certify equivalent scope."""
    try:
        document = json.loads(raw)
        if isinstance(document, dict):
            return (
                "csaf"
                if "document" in document
                else "cve-json"
                if "cveMetadata" in document
                else "json-other"
            )
    except (ValueError, UnicodeDecodeError):
        pass
    if raw.startswith(b"%PDF"):
        return "pdf"
    tree = HTML(raw).root
    article = next(
        (n for n in tree.find({"div"}) if "item-page" in n.attrs.get("class", "").split()), tree
    )
    headings = [re.sub(r"\d+", "#", n.text())[:180] for n in article.find({"h2", "h3", "h4", "h6"})]
    signature = hashlib.sha256(json.dumps(headings, separators=(",", ":")).encode()).hexdigest()[
        :16
    ]
    return "html-headings:" + signature


def review_batch(db, *, vendor=None, limit=32, retrieve=False):
    registry = default_registry()
    if vendor is not None:
        registry.get(vendor)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("Triage limit must be an integer from 1 to 200")
    available = db.execute(
        "SELECT count(*) FROM (SELECT s.vendor,i.url FROM archive_items i JOIN archive_sources s ON s.id=i.source_id WHERE i.kind='document' AND i.state IN ('pending','error') AND (? IS NULL OR s.vendor=?) GROUP BY s.vendor,i.url)",
        (vendor, vendor),
    ).fetchone()[0]
    targets = list(
        db.execute(
            "SELECT s.vendor,i.url,min(i.id) AS item_id,max(i.state='error') AS has_error FROM archive_items i JOIN archive_sources s ON s.id=i.source_id WHERE i.kind='document' AND i.state IN ('pending','error') AND (? IS NULL OR s.vendor=?) GROUP BY s.vendor,i.url ORDER BY has_error DESC,item_id LIMIT ?",
            (vendor, vendor, limit),
        )
    )
    rows = []
    for target in targets:
        name, url = target["vendor"], target["url"]
        row = dict(
            vendor=name,
            source_url=url,
            queue_state="error" if target["has_error"] else "pending",
            resolved_url=None,
            source_sha256=None,
            layout="not_retained",
            source_format=None,
            cves=None,
            assessments=None,
            outcome="not_retained",
            error_code=None,
            diagnostic=None,
        )
        try:
            if retrieve:
                resolved, raw = resolve_document(db, url, name)
            else:
                resolved, raw = resolve_document(db, url, name, fetcher=retained_fetch)
            row.update(
                resolved_url=resolved,
                source_sha256=hashlib.sha256(raw).hexdigest(),
                layout=layout_key(raw),
            )
            normalized = registry.normalize(raw, resolved, name)
            if not normalized["cves"] and not registry.get(name).retain_unlinked_notice(normalized):
                raise ValueError("No retained CVE identity or reviewed unlinked notice")
            row.update(
                outcome="normalized",
                source_format=normalized["source_format"],
                cves=len(normalized["cves"]),
                assessments=len(normalized["assessments"]),
            )
        except SourceNotApplicable as error:
            row.update(outcome="not_applicable", diagnostic=str(error)[:240])
        except SourceNotRetained:
            row.update(outcome="not_retained")
        except Exception as error:
            row.update(outcome="error", error_code=failure_code(error), diagnostic=str(error)[:240])
        rows.append(row)
    groups = defaultdict(list)
    for row in rows:
        groups[
            (
                row["vendor"],
                row["layout"],
                row["source_format"],
                row["outcome"],
                row["error_code"],
                row["diagnostic"],
            )
        ].append(row["source_url"])
    return dict(
        schema_version=1,
        checked_at=now(),
        limit=limit,
        selected=len(rows),
        available_documents=available,
        truncated=available > len(rows),
        network_retrieval=retrieve,
        queue_mutated=False,
        dispositions=dict(Counter(r["outcome"] for r in rows)),
        groups=[
            dict(
                vendor=key[0],
                layout=key[1],
                source_format=key[2],
                outcome=key[3],
                error_code=key[4],
                diagnostic=key[5],
                documents=len(urls),
                example_urls=urls[:5],
            )
            for key, urls in groups.items()
        ],
        documents=rows,
        method="Bounded pending/error archive sample. Optional retrieval retains source bytes in the private vault. No ingestion, queue state changes, independent review or applicability inference from layout similarity. Normalized means current schema-validated parser output, not manual certification.",
    )


class SourceNotRetained(ValueError):
    """A dependency of the normal resolution path has no retained bytes."""


def retained_fetch(db, url, vendor):
    if not allowed(url, vendor):
        raise ValueError("Retained triage source outside vendor routes")
    row = db.execute(
        "SELECT e.raw FROM http_cache h JOIN evidence e ON e.id=h.evidence_id WHERE h.url=?", (url,)
    ).fetchone()
    if row is None:
        row = db.execute(
            "SELECT raw FROM evidence WHERE source_url=? ORDER BY id DESC LIMIT 1", (url,)
        ).fetchone()
    if row is None:
        raise SourceNotRetained("Source bytes are not retained")
    check_access_response(row["raw"])
    return row["raw"]
