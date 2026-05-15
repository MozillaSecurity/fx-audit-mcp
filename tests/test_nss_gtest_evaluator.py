"""Tests for nss_gtest_evaluator tool."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.nss_gtest_evaluator import nss_gtest_evaluator


def _mock_proc(
    mocker: MockerFixture,
    *,
    returncode: int,
    stdout: bytes = b"",
    stderr: bytes = b"",
    communicate: AsyncMock | None = None,
) -> MagicMock:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = returncode
    proc.communicate = communicate or AsyncMock(return_value=(stdout, stderr))
    return proc


@pytest.mark.anyio
async def test_clean_run_reports_no_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(mocker, returncode=0, stdout=b"[ PASSED ] 1 test\n")
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is False
    assert result.message == "No crash detected"


@pytest.mark.anyio
async def test_asan_in_stdout_signals_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(
        mocker,
        returncode=1,
        stdout=b"==1==ERROR: AddressSanitizer: heap-use-after-free\n",
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is True


@pytest.mark.anyio
async def test_asan_in_stderr_signals_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(
        mocker,
        returncode=1,
        stderr=b"AddressSanitizer: stack-buffer-overflow\n",
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is True


@pytest.mark.anyio
async def test_nonzero_exit_without_asan_is_gtest_error(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(mocker, returncode=1, stdout=b"[ FAILED ]\n")
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is False
    assert "Gtest error" in result.message


@pytest.mark.anyio
async def test_timeout_kills_and_returns_no_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=[TimeoutError, (b"", b"")])
    proc.kill = MagicMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir, timeout=1)
    proc.kill.assert_called_once()
    assert result.crashed is False
    assert "Timed out after 1s" in result.message


@pytest.mark.anyio
async def test_env_passes_through_to_subprocess(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    spawn = mocker.patch(
        "asyncio.create_subprocess_exec",
        return_value=_mock_proc(mocker, returncode=0),
    )
    await nss_gtest_evaluator("Suite.MyTest", firefox_dir)
    env = spawn.call_args.kwargs["env"]
    assert env["DOMSUF"] == "localdomain"
    assert env["HOST"] == "localhost"
    assert env["NSS_TESTS"] == "gtests ssl_gtests"
    assert env["NSS_CYCLES"] == "standard"
    assert env["GTESTFILTER"] == "Suite.MyTest"


@pytest.mark.anyio
async def test_subprocess_exception_returns_failure(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is False
    assert "OSError" in result.message
    assert "Permission denied" in result.message
