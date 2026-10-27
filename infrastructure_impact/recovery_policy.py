"""Bounded recovery profiles shared by the hosted writer and standalone monitor.

Standard-library only: operational checks must work without installed runtime
or cryptography dependencies. A manifest never selects an operator's limit.
"""

MIB = 1024 * 1024
VAULT_PROFILES = {"standard": 512 * MIB, "large": 1024 * MIB}
DEFAULT_PROFILE = "standard"
ARCHIVE_LIMIT = 50 * MIB
DECODER_MEMORY_LIMIT = 64 * MIB


def vault_limit(profile=DEFAULT_PROFILE):
    if not isinstance(profile, str) or profile not in VAULT_PROFILES:
        raise ValueError("Recovery profile must be standard or large")
    return VAULT_PROFILES[profile]


def checked_limit(value):
    """Internal byte budgets may be smaller for tests, never larger than 1 GiB."""
    if type(value) is not int or not 0 < value <= max(VAULT_PROFILES.values()):
        raise ValueError("Recovery byte budget must be positive and at most 1 GiB")
    return value
