"""Tests for the shared subprocess log-writing helper."""

import tempfile
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.logs import LOG_DIR_PREFIX, write_subprocess_logs


def test_silent_run_still_returns_a_cleanable_path() -> None:
    """Verify that a run with no output leaves no directory the caller cannot find."""
    logs = write_subprocess_logs(b"", b"")

    assert len(logs.stdout) == 1
    assert len(logs.stderr) == 1
    assert Path(logs.stderr[0]).parent.is_dir()


def test_crashdata_reuses_the_reporting_stream_file() -> None:
    """Verify that diagnostics are listed under crashdata without a second copy."""
    logs = write_subprocess_logs(b"out", b"AddressSanitizer: boom", ("stderr",))

    assert logs.crashdata == logs.stderr
    assert len(list(Path(logs.stderr[0]).parent.iterdir())) == 2


def test_crashdata_can_name_several_streams() -> None:
    """Verify that diagnostics split across both streams list both files."""
    logs = write_subprocess_logs(b"a", b"b", ("stdout", "stderr"))

    assert logs.crashdata == [logs.stdout[0], logs.stderr[0]]


def test_no_crashdata_by_default() -> None:
    """Verify that a run reporting no diagnostics leaves crashdata empty."""
    logs = write_subprocess_logs(b"a", b"b")

    assert not logs.crashdata


def test_failed_write_leaves_no_directory_behind(mocker: MockerFixture) -> None:
    """Verify that a write failure strands nothing, since no path is returned."""
    temp_root = Path(tempfile.gettempdir())
    before = set(temp_root.glob(f"{LOG_DIR_PREFIX}*"))
    mocker.patch.object(Path, "write_bytes", side_effect=OSError("No space left"))

    with pytest.raises(OSError, match="No space left"):
        write_subprocess_logs(b"a", b"b")

    assert set(temp_root.glob(f"{LOG_DIR_PREFIX}*")) == before


def test_output_is_written_byte_exact() -> None:
    """Verify that undecodable bytes and CRLF survive to disk unaltered."""
    raw = b"caf\xe9\r\nsecond line\r\n"

    logs = write_subprocess_logs(b"", raw)

    assert Path(logs.stderr[0]).read_bytes() == raw
