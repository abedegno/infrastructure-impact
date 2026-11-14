"""Conservative Cisco model ownership. Unreviewed prose never assigns a model.

Note rules pin the complete public source and complete note, CVE and status.
They qualify affected OS evidence only, retaining every literal qualification;
no release comparison or remediation projection is performed here.
"""

import hashlib
import json
from functools import lru_cache
from importlib.resources import files

# Literal names reviewed in publisher product lists. Never match a substring,
# normalize a suffix, or turn a 9400/9600 family into a chassis identity.
STRUCTURAL_NAMES = {
    f"{prefix}{model} Series Switches": model
    for prefix in ("Cisco Catalyst ", "Catalyst ")
    for model in ("9200", "9300", "9300L", "9500")
}


@lru_cache(maxsize=1)
def _rules():
    return json.loads(
        files("infrastructure_impact").joinpath("resources/cisco-model-notes.json").read_text()
    )["entries"]


def note_bindings(data, url, digest, cve_id, status, family, product):
    """Return fresh ``bindings``, literal ``conditions`` and ``diagnostics`` lists.

    Exact-source abstention is local: a new revision keeps the original OS claim.
    Document-wide notes apply only to a pinned CVE's affected IOS XE Software row,
    never another software family, a fixed row, or a wireless subtype.
    """
    result = dict(bindings=[], conditions=[], diagnostics=[])
    if (
        family != "cisco-iosxe"
        or product not in {"Cisco IOS XE Software", "IOS XE Software", "Cisco IOS XE", "IOS XE"}
        or status != "affected"
    ):
        return result
    if not isinstance(data, dict) or not isinstance(data.get("document"), dict):
        result["diagnostics"].append("cisco_model_note_malformed")
        return result
    document = data["document"]
    notes = document.get("notes", [])
    if not isinstance(notes, list) or not isinstance(document.get("tracking", {}), dict):
        result["diagnostics"].append("cisco_model_note_malformed")
        return result
    rules = [r for r in _rules() if r["source_url"] == url]
    for rule in rules:
        index = int(rule["locator"].split("/")[3])
        note = notes[index] if isinstance(notes, list) and len(notes) > index else None
        if (
            digest != rule["source_sha256"]
            or document.get("tracking", {}).get("id") != rule["advisory_id"]
            or cve_id not in rule["cve_ids"]
            or not isinstance(note, dict)
            or note.get("title") != "Vulnerable Products"
            or not isinstance(note.get("text"), str)
            or hashlib.sha256(note["text"].encode()).hexdigest() != rule["note_sha256"]
        ):
            result["diagnostics"].append("cisco_model_note_rule_mismatch")
            continue
        result["conditions"].append(note["text"])
        for platform, model in rule["platforms"].items():
            result["bindings"].append(
                dict(
                    platform=platform,
                    model=model,
                    basis="publisher_explicit",
                    source=dict(
                        source_url=url,
                        source_sha256=digest,
                        retrieved_at=None,
                        source_locator=rule["locator"],
                    ),
                )
            )
    if not result["bindings"] and not result["diagnostics"]:
        text = "\n".join(
            n.get("text", "")
            for n in notes
            if isinstance(n, dict)
            and n.get("title") == "Vulnerable Products"
            and isinstance(n.get("text"), str)
        )
        reason = (
            "unsupported_rommon_qualification"
            if "ROMMON" in text
            else "embedded_controller_host_context"
            if "Embedded Wireless Controller" in text
            else "family_only_9400_9600_context"
            if any(name in text for name in ("Catalyst 9400", "Catalyst 9600"))
            else "unreviewed_note_layout"
        )
        result["diagnostics"].append("cisco_model_" + reason)
    return result
