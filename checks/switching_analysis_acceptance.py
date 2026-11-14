"""Public selected-analysis reference, emitted only after full native candidate proof."""

import argparse
import hashlib
import json
import re
from pathlib import Path

from infrastructure_impact.application import switching_analysis as analysis
from infrastructure_impact.application.publication_reader import PublicationReader
from infrastructure_impact.application.switching_analysis_profiles import hosted_profile
from infrastructure_impact.publication_codec import MAX_SELECTED


def _measurement(raw):
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def _owned_api_proofs(selected, source_frame):
    receipts = {}
    for frame in source_frame["api_results"]:
        source = frame["source"]
        for context in frame["advisory_context"]:
            key = (
                source["url"],
                source["sha256"],
                source["retrieved_at"],
                context["source_locator"],
            )
            receipts[key] = (context, ".".join(frame["query_release"].split(".")[:2]))
    compact = selected.get("upgrades", {}).get("requirements")
    if compact is None:
        return 0
    accepted = set()
    for requirement in compact["requirements"]:
        owner = compact["members"].get(requirement["claim_id"], {})
        if (
            owner.get("vendor") != "cisco"
            or owner.get("family") != "cisco-iosxe"
            or requirement.get("scenario") != "publisher_first_fixed"
            or requirement["target"] is None
            or requirement.get("issues")
        ):
            continue
        for proof in compact["facts"][requirement["proof_ref"]]:
            if (
                proof.get("method") == "openvuln_api"
                and proof.get("kind") == "publisher_api_first_fixed"
            ):
                source = proof["source"]
                key = (
                    source["source_url"],
                    source["source_sha256"],
                    source["retrieved_at"],
                    source["source_locator"],
                )
                context, train = receipts.get(key, ({}, None))
                if (
                    context.get("advisory_id") == owner["advisory_id"]
                    and owner["cve_id"] in context.get("cve_refs", [])
                    and context.get("first_fixed_state") == "present"
                    and requirement["target"] in context.get("source_first_fixed", [])
                    and requirement["train"] == train
                    and proof["locator"] == source["source_locator"]
                ):
                    accepted.add((requirement["claim_id"], requirement["target"]))
    return len(accepted)


def write_reference(publication, profile_id, output):
    selected_profile = hosted_profile(profile_id, publication_format="v2")
    if selected_profile is None:
        raise ValueError("Explicit analysis profile required")
    reader = PublicationReader(publication)
    selected = reader.switching_analysis()
    if selected["availability"] != "available" or not _owned_api_proofs(
        selected, selected_profile.build_options()["switching_analysis_input"]
    ):
        raise ValueError("No owned openvuln API proof in selected analysis")
    csv = analysis.analysis_csv_export(selected).encode("utf-8")
    upgrades = analysis.csv_export(selected["upgrades"]).encode("utf-8")
    # Validate all semantic/export gates before creating the public output.
    output = Path(output)
    output.mkdir(exist_ok=False)
    digest = hashlib.sha256()
    size = 0
    try:
        with (output / "selected-analysis.json").open("xb") as stream:
            for chunk in json.JSONEncoder(
                ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).iterencode(selected):
                raw = chunk.encode("utf-8")
                size += len(raw)
                if size > MAX_SELECTED:
                    raise ValueError("Selected analysis exceeds existing selected bound")
                digest.update(raw)
                stream.write(raw)
        proof = {
            "schema_version": 1,
            **reader.identity,
            "profile": selected_profile.identity(),
            "analysis_json": {
                "path": "selected-analysis.json",
                "sha256": digest.hexdigest(),
                "bytes": size,
            },
            "analysis_csv": _measurement(csv),
            "upgrades_csv": _measurement(upgrades),
        }
        (output / "proof.json").write_text(
            json.dumps(proof, allow_nan=False) + "\n", encoding="utf-8"
        )
        return proof
    except Exception:
        for path in (output / "selected-analysis.json", output / "proof.json"):
            path.unlink(missing_ok=True)
        output.rmdir()
        raise


def prepare_artifacts(root, profile_id, source_commit):
    """Release public proof only for the exact completed stage generation."""
    from infrastructure_impact.application.target_import_contracts import result_bytes
    from infrastructure_impact.collection.target_import_profiles import PROFILE_ID, profile

    if not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        raise ValueError("Invalid source commit")
    hosted_profile(profile_id, publication_format="v2")
    root = Path(root)
    receipt = root / "stage-result.json"
    with receipt.open("rb") as stream:
        raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("Stage receipt exceeds bound")
    value = json.loads(
        result_bytes(json.loads(raw), selected=profile(PROFILE_ID), publication_format="v2")
    )
    if value["outcome"] != "completed" or not all(v is True for v in value["checks"].values()):
        raise ValueError("Completed validated stage required")
    public = root / "private-stage/public"
    reader = PublicationReader(public)
    with (public / "manifest.json").open("rb") as stream:
        manifest = stream.read(2_000_001)
    if len(manifest) > 2_000_000 or (
        reader.identity["publication"]["id"] != value["candidate"]["generation"]
        or hashlib.sha256(manifest).hexdigest() != value["candidate"]["manifest_sha256"]
    ):
        raise ValueError("Stage public generation differs")
    proof = write_reference(public, profile_id, root / "public-analysis-proof")
    attestation = {
        "schema_version": 1,
        "source_commit": source_commit,
        "profile": proof["profile"],
        "publication": proof["publication"],
        "generated_at": proof["generated_at"],
        "manifest_sha256": value["candidate"]["manifest_sha256"],
        "stage_outcome": "completed",
        "checks": value["checks"],
    }
    (root / "public-analysis-proof/attestation.json").write_text(
        json.dumps(attestation, allow_nan=False) + "\n", encoding="utf-8"
    )
    return attestation


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_reference(args.publication, args.profile, args.output)


if __name__ == "__main__":
    main()
