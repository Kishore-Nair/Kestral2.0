import pytest

from app.schemas.validation import Comparison
from app.validation.compare import verdict


def comparison(resolved=True):
    return Comparison(
        target_resolved=resolved,
        target_remaining=[],
        resolved=[],
        introduced=[],
        introduced_suspicious=[],
        before_counts={},
        after_counts={},
        package_changes={},
        changed_packages=[],
    )


@pytest.mark.parametrize("status", ["not_run", "no_tests", "error", "failed_before_and_after"])
def test_incomplete_tests_cannot_authorize_verified_fix(status):
    assert verdict(comparison(), status)[0] == "FAILED"


def test_unknown_target_cannot_authorize_verified_fix():
    assert verdict(comparison(None), "passed")[0] == "FAILED"


def test_resolved_target_and_passing_tests():
    assert verdict(comparison(), "passed")[0] == "FIXED"
