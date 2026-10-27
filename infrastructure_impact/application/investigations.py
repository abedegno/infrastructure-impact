"""Dated assistant research dispositions, bound to exact retained source bytes."""

import json
import re

from ..settings import PACKAGE
from ..source_policy import allowed


def investigation(lead):
    spec = json.loads((PACKAGE / "resources/disclosure-investigations.json").read_text())
    sources = {(e["source_url"], e["source_sha256"]) for e in lead["evidence"]}
    for item in spec["investigations"]:
        if (item["vendor"], item["kind"], sorted(item["cve_ids"])) != (
            lead["vendor"],
            lead["kind"],
            sorted(lead["cve_ids"]),
        ):
            continue
        token = item["required_detail_token"]
        if token and not re.search(r"(?<!\d)" + re.escape(token) + r"(?!\d)", lead["details"]):
            continue
        if not any(
            s["source_url"] in {e["source_url"] for e in lead["evidence"]}
            for s in item["source_bindings"]
        ):
            continue
        if any(not allowed(url, item["vendor"]) for url in item["uncollected_search_leads"]):
            raise ValueError("Investigation leads require official vendor sources")
        matched = sources == {
            (e["source_url"], e["source_sha256"]) for e in item["source_bindings"]
        }
        return dict(
            id=item["id"],
            version=spec["version"],
            reviewed_at=item["reviewed_at"],
            review_method=spec["review_method"],
            source_state="matches_reviewed_sources"
            if matched
            else "source_changed_review_required",
            disposition=item["disposition"] if matched else "source_changed_review_required",
            summary=item["summary"]
            if matched
            else "Current lead bytes differ from the dated research inputs. Re-review the changed sources before applying the earlier disposition.",
            search_scope=item["search_scope"],
            remaining_evidence=item["remaining_evidence"],
            uncollected_search_leads=item["uncollected_search_leads"],
            independent_human_review_completed=False,
            concealment="not_established",
        )
    return None
