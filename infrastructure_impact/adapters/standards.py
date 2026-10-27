"""Reviewed standards source normalization."""

import json

from .common import availability, base, cves, remediation_reference


def csaf(raw, url, vendor):
    d = json.loads(raw)
    doc = d["document"]
    tracking = doc["tracking"]
    out = base(
        vendor,
        url,
        tracking["id"],
        doc["title"],
        tracking.get("initial_release_date"),
        tracking.get("current_release_date"),
    )
    out["source_format"] = "CSAF"
    out["document_status"] = tracking.get("status", "unknown")
    out["timeline"] = tracking.get("revision_history", [])
    products = {}

    def walk(branches, ancestry=()):
        for b in branches:
            path = ancestry + ((b.get("category", ""), b.get("name", "")),)
            if "product" in b:
                p = b["product"]
                products[p["product_id"]] = {"name": p["name"], "ancestry": path}
            walk(b.get("branches", []), path)

    tree = d.get("product_tree", {})
    walk(tree.get("branches", []))
    for p in tree.get("full_product_names", []):
        products[p["product_id"]] = {"name": p["name"], "ancestry": ()}
    for r in tree.get("relationships", []):
        p = r["full_product_name"]
        products[p["product_id"]] = {"name": p["name"], "ancestry": (), "relationship": r}
    groups = {g["group_id"]: g.get("product_ids", []) for g in tree.get("product_groups", [])}

    def applies(rem, pid):
        ids = rem.get("product_ids", []) + [
            p for g in rem.get("group_ids", []) for p in groups.get(g, [])
        ]
        return not ids or pid in ids

    statuses = {
        "known_affected": "affected",
        "first_affected": "affected",
        "last_affected": "affected",
        "known_not_affected": "unaffected",
        "under_investigation": "investigating",
        "fixed": "fixed",
        "first_fixed": "fixed",
        "recommended": "recommended",
    }
    seen_entries = {}
    for entry_index, v in enumerate(d.get("vulnerabilities", [])):
        # Exact repeated source entries add no new scope. Different dispositions,
        # ranges or rationale still reach validation and fail closed on identity.
        fingerprint = json.dumps(v, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen_entries:
            out["warnings"].append(
                f"Exact duplicate CSAF vulnerability entry vulnerabilities[{entry_index}] equals vulnerabilities[{seen_entries[fingerprint]}]; normalized once. Original source bytes retain both entries."
            )
            continue
        seen_entries[fingerprint] = entry_index
        if not v.get("cve"):
            continue
        cid = v["cve"].upper()
        out["cves"].append(cid)
        out["notes"] += [{"cve_id": cid, **n} for n in v.get("notes", [])]
        out["metrics"] += [{"cve_id": cid, **s} for s in v.get("scores", [])]
        by_pid = {}
        for source_status, ids in v.get("product_status", {}).items():
            for pid in ids:
                by_pid.setdefault(pid, []).append(source_status)
        for pid, source_statuses in by_pid.items():
            p = products.get(pid, {"name": pid, "ancestry": ()})
            resolved = sorted({statuses[s] for s in source_statuses if s in statuses})
            # Multiple simultaneous incompatible dispositions remain visible.
            status = resolved[0] if len(resolved) == 1 else "conflicting" if resolved else "unknown"
            remediations = []
            for index, rem in enumerate(v.get("remediations", [])):
                if applies(rem, pid):
                    # Do not repeat a large shared product-ID list on every product row.
                    remediations.append(
                        {
                            **{
                                k: value
                                for k, value in rem.items()
                                if k not in ("product_ids", "group_ids")
                            },
                            "source_scope": "explicit_product_or_group"
                            if rem.get("product_ids") or rem.get("group_ids")
                            else "advisory",
                            "source_locator": f"vulnerabilities[cve={cid}].remediations[{index}]",
                            "availability": availability(
                                rem.get("details", ""),
                                rem.get("category"),
                                rem.get("date"),
                                as_of=remediation_reference(out),
                            ),
                        }
                    )
            threats = [t for t in v.get("threats", []) if applies(t, pid)]
            if status == "fixed" and any(
                r["availability"] == "partial_mitigation" for r in remediations
            ):
                status = "partially_mitigated"
                out["warnings"].append(
                    f"{pid}: source labels this version fixed, but its remediation describes partial mitigation; a full fix is not established."
                )
            out["assessments"].append(
                {
                    "cve_id": cid,
                    "product_id": pid,
                    "product": p["name"],
                    "product_family": next(
                        (
                            n
                            for category, n in reversed(p["ancestry"])
                            if category in ("product_name", "product_family")
                        ),
                        None,
                    ),
                    "product_context": list(p["ancestry"]),
                    "relationship": p.get("relationship"),
                    "status": status,
                    "source_statuses": source_statuses,
                    "scope": "cve_specific",
                    "versions": [],
                    "remediations": remediations,
                    "exposure": threats,
                    "evidence_locator": f"vulnerabilities[cve={cid}].product_status / {pid}",
                }
            )
            if pid not in products:
                out["warnings"].append(f"Unresolved CSAF product id {pid}")
    out["cves"] = sorted(set(out["cves"]))
    if not out["cves"]:
        # Some publishers issue a valid document envelope before populating products.
        out["cves"] = cves(doc.get("title", ""))
        out["warnings"].append(
            "CSAF envelope has no CVE vulnerability entries. Title references are discovery only; no product assessment established."
        )
    if not out["assessments"]:
        out["warnings"].append(
            "No encoded product assessments in this CSAF document. Consult the publisher HTML or other primary documents; this export does not establish product applicability."
        )
    if out["document_status"] != "final":
        out["warnings"].append(
            "Source document is not final; assess publisher status before relying on its assertions."
        )
    return out


def cna(raw, url, vendor):
    d = json.loads(raw)
    c = d["containers"]["cna"]
    cid = d["cveMetadata"]["cveId"]
    title = c.get("title", cid)
    ids = sorted(set(cves(cid) + cves(title)))
    timeline = c.get("timeline", [])
    out = base(
        vendor,
        url,
        cid,
        title,
        c.get("datePublic"),
        max((t["time"] for t in timeline), default=c.get("datePublic")),
    )
    out["source_format"] = "CVE JSON"
    out["document_status"] = d["cveMetadata"].get("state", "unknown").lower()
    out["cves"], out["timeline"], out["metrics"] = ids, timeline, c.get("metrics", [])
    out["notes"] = [
        {"category": k, "text": i.get("value", "")}
        for k in ("descriptions", "solutions", "workarounds", "exploits")
        for i in c.get(k, [])
    ]
    if len(ids) > 1:
        out["warnings"].append(
            "Shared product table from a multi-CVE bulletin; individual CVE applicability is not separately encoded."
        )
    out["warnings"].append(
        "Unmapped solution/workaround text is retained at advisory scope; it is not automatically applied to every product."
    )
    for p, source_indices in cna_product_rows(c.get("affected", []), out["warnings"]):
        platforms = p.get("platforms", [])
        product_label = p["product"].strip() + (f" ({', '.join(platforms)})" if platforms else "")
        product_identity = p["product"].strip() + (
            ":platforms=" + ",".join(sorted(platforms)) if platforms else ""
        )
        versions = p.get("versions", [])
        states = {v.get("status", "unknown") for v in versions}
        status = next(iter(states)) if len(states) == 1 else "mixed" if states else "unknown"
        remediations = []
        for solution in c.get("solutions", []):
            details = solution.get("value", "")
            if details.split("\n", 1)[0].strip() == p["product"].strip():
                remediations.append(
                    {
                        "category": "vendor_fix",
                        "details": details,
                        "availability": availability(
                            details, "vendor_fix", as_of=remediation_reference(out)
                        ),
                        "scope": "explicit_product_heading",
                    }
                )
        # Mixed affected/unaffected version rows must remain independently counted
        # and visible. A single 'mixed' disposition hides documented affectedness.
        groups = (
            {s: [v for v in versions if v.get("status", "unknown") == s] for s in states}
            if len(states) > 1
            else {status: versions}
        )
        for group_status, group_versions in groups.items():
            for cv in ids:
                out["assessments"].append(
                    {
                        "cve_id": cv,
                        "product_id": product_identity
                        + (f":{group_status}" if len(groups) > 1 else ""),
                        "product": product_label,
                        "product_family": p["product"].strip() if platforms else None,
                        "platforms": platforms,
                        "identifiers": {"cpe": p.get("cpes", [])},
                        "product_context": [["platform", platform] for platform in platforms],
                        "status": group_status,
                        "source_statuses": [group_status],
                        "scope": "bulletin_shared" if len(ids) > 1 else "cve_specific",
                        "versions": group_versions,
                        "remediations": remediations if group_status != "unaffected" else [],
                        "exposure": [],
                        "evidence_locator": f"containers.cna.affected[indices={source_indices};product={p['product']}].versions[status={group_status}]",
                    }
                )
    return out


def cna_product_rows(rows, warnings):
    """Combine same-status release branches only when all other scope agrees."""
    grouped = {}
    for index, row in enumerate(rows):
        key = row["product"].strip(), tuple(sorted(row.get("platforms", [])))
        grouped.setdefault(key, []).append((index, row))
    for entries in grouped.values():
        indices = [i for i, _ in entries]
        result = dict(entries[0][1])
        if len(entries) > 1:

            def scope(row):
                return {
                    **{k: v for k, v in row.items() if k not in {"versions", "cpes", "platforms"}},
                    "platforms": sorted(row.get("platforms", [])),
                }

            states = [
                {v.get("status", "unknown") for v in row.get("versions", [])} for _, row in entries
            ]
            if (
                any(scope(row) != scope(result) for _, row in entries)
                or len(states[0]) != 1
                or any(s != states[0] for s in states)
            ):
                raise ValueError("Conflicting repeated CNA product/platform scope requires review")
            versions = {}
            starts = {}
            for _, row in entries:
                for version in row.get("versions", []):
                    fingerprint = json.dumps(version, sort_keys=True)
                    start = version.get("version")
                    if start in starts and starts[start] != fingerprint:
                        raise ValueError("Conflicting repeated CNA range start requires review")
                    starts[start] = fingerprint
                    versions[fingerprint] = version
            result["versions"] = list(versions.values())
            result["cpes"] = sorted({cpe for _, row in entries for cpe in row.get("cpes", [])})
            warnings.append(
                f"Repeated CNA product/platform rows {indices} retain their same-status release ranges and CPEs together. Other scope fields agree; range overlap and version ordering are not inferred."
            )
        yield result, indices
