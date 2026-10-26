"""Synthetic lifecycle panels protect product, date and release-train scope."""

import pytest

from infrastructure_impact.adapters.arista_history import arista_release_history
from infrastructure_impact.collection.errors import (
    AccessVerificationRequired,
    check_access_response,
)

URL = "https://www.arista.com/en/support/product-documentation/cloudvision-life-cycle-policy"


def panel():
    return """<div role="tabpanel"><h3>CloudVision Software Lifecycle</h3><table><tr><th>CVP Release</th><th>Current Status</th><th>Initial Release Date</th><th>End of Support</th></tr><tr><td>2025.1</td><td>Support Only</td><td>31-March-2025</td><td>31-March-2027</td></tr><tr><td>2024.3 and earlier release trains are End of Support</td></tr></table><p>Last Updated: October 21, 2026</p></div>"""


def test_initial_train_date_is_not_end_of_support_or_a_patch_fix_date():
    result = arista_release_history(panel(), URL, "arista")
    assert result["product"] == "CloudVision Portal"
    assert result["version_granularity"] == "release_train"
    assert result["releases"] == [
        dict(version="2025.1", reported_released_at="2025-03-31", publisher_reports_posted=True)
    ]


@pytest.mark.parametrize(
    "before,after",
    [
        ("CloudVision Software Lifecycle", "CV-CUE Software Life Cycle"),
        ("Initial Release Date", "Maintenance date"),
        ("31-March-2025", "31-March-2027"),
        ("Support Only", "Pending release"),
    ],
)
def test_other_product_layout_and_planned_dates_are_rejected(before, after):
    with pytest.raises(ValueError):
        arista_release_history(panel().replace(before, after), URL, "arista")


def test_client_challenge_is_not_valid_lifecycle_content():
    with pytest.raises(AccessVerificationRequired):
        check_access_response(
            b'<!DOCTYPE html><title>Client Challenge</title><script src="/_fs-ch-example/script.js"></script>JavaScript is disabled'
        )
