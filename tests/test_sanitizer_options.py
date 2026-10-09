"""Tests for the allowlisted ASAN_OPTIONS merge."""

import pytest

from fx_audit_mcp.sanitizer_options import ALLOWED_ASAN_OPTIONS, asan_options_env


def test_no_options_leaves_the_environment_alone() -> None:
    """An empty request returns None so the caller sets nothing."""
    assert asan_options_env(None, "detect_leaks=0") is None
    assert asan_options_env({}, None) is None


def test_caller_values_win_and_existing_keys_are_kept() -> None:
    """Named keys are overwritten; everything else in the environment survives."""
    merged = asan_options_env(
        {"quarantine_size_mb": 0, "detect_stack_use_after_return": False},
        "detect_leaks=0:quarantine_size_mb=256",
    )
    assert merged is not None
    assert set(merged.split(":")) == {
        "detect_leaks=0",
        "quarantine_size_mb=0",
        "detect_stack_use_after_return=0",
    }


@pytest.mark.parametrize("option", ["log_path", "halt_on_error", "exitcode"])
def test_reporting_and_termination_options_are_rejected(option: str) -> None:
    """Options that change what a report means are refused by name."""
    assert option not in ALLOWED_ASAN_OPTIONS
    with pytest.raises(ValueError, match=f"not allowed: {option}"):
        asan_options_env({option: "1"})


@pytest.mark.parametrize("value", ["/tmp/x", "a:b", "1 2", ""])
def test_malformed_values_are_rejected(value: str) -> None:
    """A path, a separator or an empty value never reaches the option string."""
    with pytest.raises(ValueError, match="malformed value"):
        asan_options_env({"redzone": value})
