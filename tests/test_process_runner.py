"""Tests for the shared subprocess runner."""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from pytest_mock import MockerFixture

import fx_audit_mcp.process_runner as pr_module
from fx_audit_mcp.logs import LOG_DIR_PREFIX
from fx_audit_mcp.process_runner import run

if TYPE_CHECKING:
    from unittest.mock import MagicMock


def _log_dirs() -> set[Path]:
    return set(Path(tempfile.gettempdir()).glob(f"{LOG_DIR_PREFIX}*"))


@pytest.mark.anyio
async def test_captures_output_and_exit_code() -> None:
    result = await run("sh", "-c", "printf out; printf err >&2; exit 3", timeout=10)

    assert result.exit_code == 3
    assert result.timed_out is False
    assert result.stdout.read_bytes() == b"out"
    assert result.stderr.read_bytes() == b"err"


@pytest.mark.anyio
async def test_output_is_written_byte_exact() -> None:
    """Verify that undecodable bytes and CRLF survive to disk unaltered."""
    result = await run("sh", "-c", r"printf 'caf\351\r\n'", timeout=10)

    assert result.stdout.read_bytes() == b"caf\xe9\r\n"


@pytest.mark.anyio
async def test_signal_death_reports_negative_exit_code() -> None:
    result = await run("sh", "-c", "kill -SEGV $$", timeout=10)

    assert result.exit_code == -11
    assert result.timed_out is False


@pytest.mark.anyio
async def test_timeout_kills_and_keeps_partial_output() -> None:
    result = await run("sh", "-c", "echo partial; sleep 30", timeout=1)

    assert result.timed_out is True
    assert result.exit_code == -9
    assert result.stdout.read_bytes() == b"partial\n"


@pytest.mark.anyio
async def test_timeout_kills_the_whole_process_tree() -> None:
    """Verify that children of the command do not outlive the timeout."""
    result = await run("sh", "-c", "sleep 30 & echo $!; wait", timeout=1)

    assert result.timed_out is True
    child_pid = int(result.stdout.read_bytes().split()[0])
    for _ in range(50):
        try:
            os.kill(child_pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.1)
    else:
        pytest.fail(f"child {child_pid} survived the group kill")


@pytest.mark.anyio
async def test_missing_binary_raises_and_cleans_up() -> None:
    """Verify that a spawn failure strands nothing, since no path is returned."""
    before = _log_dirs()

    with pytest.raises(FileNotFoundError):
        await run("/nonexistent/prog", timeout=10)

    assert _log_dirs() == before


@pytest.mark.anyio
async def test_unreaped_process_raises_and_cleans_up(mocker: MockerFixture) -> None:
    """Verify that a process that survives its kill reports the wedge."""

    async def hang() -> None:
        await asyncio.sleep(3600)

    proc: MagicMock = mocker.MagicMock()
    proc.returncode = None
    proc.wait = hang
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    kill_tree = mocker.patch.object(pr_module, "_kill_tree")
    mocker.patch.object(pr_module, "_REAP_TIMEOUT", 0.01)
    before = _log_dirs()

    with pytest.raises(RuntimeError, match="did not exit"):
        await run("wedged", timeout=1)

    kill_tree.assert_called_once_with(proc)
    assert _log_dirs() == before


@pytest.mark.anyio
async def test_extra_env_is_layered_over_the_environment() -> None:
    result = await run(
        "sh",
        "-c",
        'printf %s "$FX_AUDIT_TEST_VAR"',
        timeout=10,
        extra_env={"FX_AUDIT_TEST_VAR": "bar"},
    )

    assert result.stdout.read_bytes() == b"bar"


@pytest.mark.anyio
async def test_cwd_sets_the_working_directory(tmp_path: Path) -> None:
    result = await run("sh", "-c", "pwd", timeout=10, cwd=tmp_path)

    reported = Path(result.stdout.read_bytes().decode().strip())
    assert reported.resolve() == tmp_path.resolve()
