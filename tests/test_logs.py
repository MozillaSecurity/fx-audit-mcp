"""Tests for the shared log-writing and log-scanning helpers."""

import tempfile
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.logs import LOG_DIR_PREFIX, log_contains, write_logs


def test_silent_run_still_returns_a_cleanable_path() -> None:
    """Verify that a run with no output leaves no directory the caller cannot find."""
    logs = write_logs(b"", b"")

    assert len(logs.stdout) == 1
    assert len(logs.stderr) == 1
    assert Path(logs.stderr[0]).parent.is_dir()


def test_failed_write_leaves_no_directory_behind(mocker: MockerFixture) -> None:
    """Verify that a write failure strands nothing, since no path is returned."""
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob(f"{LOG_DIR_PREFIX}*"))
    mocker.patch.object(Path, "write_bytes", side_effect=OSError("No space left"))

    with pytest.raises(OSError, match="No space left"):
        write_logs(b"a", b"b")

    assert set(temp_root.glob(f"{LOG_DIR_PREFIX}*")) == before


def test_output_is_written_byte_exact() -> None:
    """Verify that undecodable bytes and CRLF survive to disk unaltered."""
    raw = b"caf\xe9\r\nsecond line\r\n"

    logs = write_logs(b"", raw)

    assert Path(logs.stderr[0]).read_bytes() == raw


@pytest.mark.parametrize(
    ("content", "markers", "expected"),
    [
        (b"[ RUN ]\n==1==ERROR: AddressSanitizer: boom\n", ("AddressSanitizer",), True),
        (b"all tests passed\n", ("AddressSanitizer",), False),
        (
            b"UndefinedBehaviorSanitizer: overflow\n",
            ("AddressSanitizer", "UndefinedBehaviorSanitizer"),
            True,
        ),
        (b"", ("AddressSanitizer",), False),
    ],
)
def test_log_contains_matches_any_marker(
    tmp_path: Path, content: bytes, markers: tuple[str, ...], expected: bool
) -> None:
    log = tmp_path / "log.txt"
    log.write_bytes(content)

    assert log_contains(log, *markers) is expected


def test_log_contains_survives_undecodable_bytes(tmp_path: Path) -> None:
    """Verify that invalid UTF-8 around a marker does not hide it."""
    log = tmp_path / "log.txt"
    log.write_bytes(b"\xff\xfe garbage \xff AddressSanitizer: boom\n")

    assert log_contains(log, "AddressSanitizer") is True
