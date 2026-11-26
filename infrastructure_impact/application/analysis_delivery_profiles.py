"""Reviewed publication options for the installed, opt-in eight-view delivery profile."""

from dataclasses import dataclass
from hashlib import sha256
from importlib.resources import files

from . import switching_analysis_profiles
from .strict_json import loads

PROFILE_ID = "campus-switching-common-views-v1"
INPUT_SHA256 = "79de64408c9df10cebeee363422784940e5288073d14dc0f7925e9b1d5e10dfc"
MAX_RESOURCE_BYTES = 4096


def _decode(raw, *, expected_sha256):
    if type(raw) is not bytes or len(raw) > MAX_RESOURCE_BYTES:
        raise ValueError("invalid_analysis_delivery_profile_size")
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("analysis_delivery_profile_digest_mismatch")
    options = loads(raw, budget=MAX_RESOURCE_BYTES, label="Analysis delivery profile")
    expected = [
        dict(vendor=vendor, window=window, scope_level="os_family", cve_ids=None)
        for vendor in (None, "cisco", "aruba", "arista")
        for window in ("all", "2025")
    ]
    if options != expected:
        raise ValueError("invalid_analysis_delivery_options")
    return options


@dataclass(frozen=True)
class DeliveryProfile:
    _raw: bytes

    def __post_init__(self):
        self.options()

    def identity(self):
        return {"profile_id": PROFILE_ID, "input_sha256": INPUT_SHA256}

    def options(self):
        return _decode(self._raw, expected_sha256=INPUT_SHA256)

    def build_options(self):
        return {
            "analysis_precomputed_delivery": True,
            "analysis_precomputed_options": self.options(),
        }


def profile(profile_id: str) -> DeliveryProfile:
    if type(profile_id) is not str or profile_id != PROFILE_ID:
        raise ValueError("unknown_analysis_delivery_profile")
    resource = files("infrastructure_impact").joinpath(
        "resources/analysis-delivery", PROFILE_ID + ".json"
    )
    with resource.open("rb") as stream:
        return DeliveryProfile(stream.read(MAX_RESOURCE_BYTES + 1))


def build_profile(profile_id="", *, publication_format="v1", include_switching_analysis=False):
    if type(profile_id) is str and profile_id == "":
        return None
    selected = profile(profile_id)
    if publication_format != "v2" or include_switching_analysis is not True:
        raise ValueError("Analysis delivery requires v2 and explicit switching analysis")
    return selected


def hosted_profiles(
    switching_analysis_profile="", analysis_delivery_profile="", *, publication_format="v1"
):
    science = switching_analysis_profiles.hosted_profile(
        switching_analysis_profile, publication_format=publication_format
    )
    delivery = build_profile(
        analysis_delivery_profile,
        publication_format=publication_format,
        include_switching_analysis=science is not None,
    )
    return science, delivery


def hosted_profile(profile_id="", *, publication_format="v1", switching_analysis_profile=""):
    return hosted_profiles(
        switching_analysis_profile, profile_id, publication_format=publication_format
    )[1]
