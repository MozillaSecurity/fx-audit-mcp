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
    assert result.exit_code == 0


@pytest.mark.anyio
async def test_asan_in_stdout_signals_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(
        mocker,
        returncode=1,
        stdout=b"==1==ERROR: AddressSanitizer: heap-use-after-free\n",
        stderr=b"[ RUN      ] Suite.Test\n",
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is True
    # Both streams have content, so crashdata must follow the reporting one
    # rather than simply listing every file written.
    assert result.logs.crashdata == result.logs.stdout


@pytest.mark.anyio
async def test_asan_in_stderr_signals_crash(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc = _mock_proc(
        mocker,
        returncode=1,
        stdout=b"[ RUN      ] Suite.Test\n",
        stderr=b"AddressSanitizer: stack-buffer-overflow\n",
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)
    assert result.crashed is True
    assert result.logs.crashdata == result.logs.stderr


@pytest.mark.anyio
async def test_nonzero_exit_without_asan_is_gtest_error(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    """Verify that a failing gtest returns its output rather than raising."""
    proc = _mock_proc(mocker, returncode=1, stdout=b"[ FAILED ] Suite.Test\n")
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)

    result = await nss_gtest_evaluator("Suite.Test", firefox_dir)

    assert result.crashed is False
    assert result.exit_code == 1
    assert result.logs.crashdata == []
    stdout_log = Path(result.logs.stdout[0]).read_bytes()
    assert stdout_log == b"[ FAILED ] Suite.Test\n"


@pytest.mark.anyio
async def test_timeout_kills_and_raises(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=[TimeoutError, (b"", b"")])
    proc.kill = MagicMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    with pytest.raises(TimeoutError, match="timed out after 1s"):
        await nss_gtest_evaluator("Suite.Test", firefox_dir, timeout=1)
    proc.kill.assert_called_once()


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
async def test_subprocess_exception_raises(
    mocker: MockerFixture, firefox_dir: Path
) -> None:
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )
    with pytest.raises(OSError, match="Permission denied"):
        await nss_gtest_evaluator("Suite.Test", firefox_dir)
