"""Hosted promotion of a completed isolated exact-target import only."""

import json
import shutil
import tempfile
from pathlib import Path

from infrastructure_impact.application import target_import, target_import_stage
from infrastructure_impact.application.target_import_contracts import (
    MAX_RECEIPT_BYTES,
    result_bytes,
    validate_preview,
)
from ops import hosted_job as hosted


def _encoded(value):
    raw = json.dumps(value, allow_nan=False, separators=(",", ":")) + "\n"
    if len(raw.encode("utf-8")) > MAX_RECEIPT_BYTES:
        raise ValueError("target_import_receipt_size")
    return raw


def apply(args, selected, state, output, home, database, key, store, limit) -> None:
    """Promote staged private recovery, then release only its validated public tree."""
    step = "preview"
    receipt = None
    recovered = False
    try:
        accepted = validate_preview(target_import.preview(database, selected.profile_id), selected)
        if accepted["fingerprint"] != args.maintenance_preview_fingerprint:
            raise ValueError("stale_preview")
        acquisition_options = {}
        if getattr(args, "acquisition_cache", False):
            acquisition_root = state.parent / "acquisitions"
            acquisition_state = acquisition_root / selected.fingerprint
            cache = home / "captures" / (selected.fingerprint + ".sqlite3")
            from infrastructure_impact.storage.capture_cache import validate_path

            validate_path(cache, database, output)
            if any(p.is_symlink() for p in (acquisition_state, *acquisition_state.parents)):
                raise ValueError("Acquisition state must not use symbolic links")
            root = acquisition_root.resolve()
            for other in (output.resolve(), state.resolve()):
                if other.is_relative_to(root) or root.is_relative_to(other):
                    raise ValueError(
                        "Acquisition state, accepted state and public output require separate directory trees"
                    )
            hosted.restore_current(
                acquisition_state, cache, key, store=store, vault_limit_bytes=limit
            )

            def checkpoint(cache_path):
                hosted.backup_acquisitions(
                    acquisition_state, cache_path, key, store=store, args=args, limit=limit
                )

            acquisition_options = {"capture_cache": cache, "acquisition_checkpoint": checkpoint}
        # A separate generated root is outside the restored home/lock scope.
        # resolve() handles macOS /var aliases only for this trusted temp path.
        with tempfile.TemporaryDirectory(prefix="impact-target-import-") as directory:
            stage = Path(directory).resolve() / "stage"
            step = "staging"
            result = target_import_stage.stage(
                database,
                selected,
                args.maintenance_preview_fingerprint,
                stage,
                lock_home=home,
                accepted_preview=accepted,
                base_path=args.base_path,
                **acquisition_options,
                **({"publication_format": "v2"} if args.publication_format == "v2" else {}),
            )
            step = "receipt_validation"
            validated = json.loads(
                result_bytes(
                    result,
                    selected=selected,
                    **({"publication_format": "v2"} if args.publication_format == "v2" else {}),
                )
            )
            if validated["fingerprint"] != accepted["fingerprint"]:
                raise ValueError("invalid_target_import_result_binding")
            receipt = validated
            if receipt["outcome"] != "completed":
                raise RuntimeError("Target import stage failed validation")
            staged_database = stage / receipt["staged_database"]
            step = "capacity"
            if staged_database.stat().st_size > limit:
                raise ValueError("Target import vault exceeds supported size")
            # Bound the eventual hosted envelope before recovery promotion. It is
            # emitted only after every effect it describes has actually occurred.
            success = _encoded(
                {
                    "mode": "apply",
                    "outcome": "completed",
                    "maintenance": receipt,
                    "benchmark_acquisition": "not_run",
                    "private_backup": "saved",
                    "private_recovery": "verified",
                    "vault_profile": args.vault_profile,
                    "vault_limit_bytes": limit,
                }
            )
            step = "backup"
            hosted.backup_verified(state, staged_database, key, store=store, args=args, limit=limit)
            recovered = True
            step = "public_copy"
            shutil.copytree(stage / receipt["public_directory"], output)
            hosted.workflow_effect("publish_ready")
            print(success, end="")
    except Exception:
        failure = {
            "mode": "apply",
            "outcome": "error",
            "stage": step,
            "benchmark_acquisition": "not_run",
        }
        if recovered:
            failure.update(private_backup="saved", private_recovery="verified")
        if receipt is not None:
            failure["maintenance"] = receipt
        try:
            raw = _encoded(failure)
        except ValueError:
            # Explicit receipt-size failure, never silently truncate target facts.
            failure.pop("maintenance", None)
            failure["failure_code"] = "target_import_receipt_size"
            raw = _encoded(failure)
        print(raw, end="")
        raise
