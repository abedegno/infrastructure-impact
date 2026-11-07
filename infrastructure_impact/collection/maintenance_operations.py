"""Closed hosted operation dispatch; operators cannot supply import manifests."""

from . import maintenance_profiles, target_import_profiles


def resolve_profile(profile_id: str) -> tuple[str, object]:
    """Resolve installed kinds before any key, recovery or collection access."""
    try:
        return "arista-refresh", maintenance_profiles.profile(profile_id)
    except ValueError:
        pass
    try:
        return "target-import", target_import_profiles.profile(profile_id)
    except ValueError:
        raise ValueError("unknown_maintenance_profile") from None
