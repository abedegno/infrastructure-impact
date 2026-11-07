"""Closed, local maintenance profiles; callers cannot supply retrieval URLs."""

from dataclasses import dataclass
from hashlib import sha256

from ..adapters.arista_reconciliation import CSAF103, URL99, URL103
from ..application.current_evidence import policy_metadata
from ..application.evidence_identity import canonical_json
from ..plugins.registry import default_registry


@dataclass(frozen=True)
class MaintenanceProfile:
    profile_id: str
    version: str
    vendor: str
    primary_urls: tuple[str, ...]
    allowed_urls: frozenset[str]
    max_bytes: int
    expected_primaries: tuple[tuple[str, str, tuple[str, ...]], ...]
    policy_fingerprint: str

    def metadata(self):
        return {
            "profile_id": self.profile_id,
            "version": self.version,
            "vendor": self.vendor,
            "primary_urls": list(self.primary_urls),
            "allowed_urls": sorted(self.allowed_urls),
            "max_bytes": self.max_bytes,
            "policy_fingerprint": self.policy_fingerprint,
            "targets": [
                {"source_url": u, "advisory_id": a, "cves": list(c)}
                for u, a, c in self.expected_primaries
            ],
        }

    @property
    def fingerprint(self):
        return sha256(canonical_json(self.metadata())).hexdigest()


def profile(profile_id: str) -> MaintenanceProfile:
    if profile_id != "arista-reviewed-2024-0099-0103-v1":
        raise ValueError("unknown_maintenance_profile")
    policy = policy_metadata(default_registry().get("arista"))
    return MaintenanceProfile(
        profile_id,
        "1",
        "arista",
        (URL99, URL103),
        frozenset((URL99, URL103, CSAF103)),
        2_000_000,
        (
            (URL99, "19862-security-advisory-0099", ("CVE-2024-27890", "CVE-2024-27892")),
            (URL103, "19917-security-advisory-0103", ("CVE-2024-6858",)),
        ),
        policy["fingerprint"],
    )
