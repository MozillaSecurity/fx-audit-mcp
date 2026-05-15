"""Tests for js_shell_evaluator tool."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.js_shell_evaluator import MAX_LOG_SIZE, js_shell_evaluator


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
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    return proc


@pytest.mark.anyio
async def test_clean_exit_reports_no_crash(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=0, stdout=b"42\n")
    result = await js_shell_evaluator("print(42)", js_binary)
    assert result.crashed is False
    assert result.message == "No crash detected"


@pytest.mark.anyio
async def test_negative_exit_code_signals_crash(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=-11, stderr=b"")
    result = await js_shell_evaluator("crash()", js_binary)
    assert result.crashed is True
    assert "SIGSEGV" in result.message


@pytest.mark.anyio
async def test_unknown_signal_falls_back_to_number(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=-999, stderr=b"")
    result = await js_shell_evaluator("x", js_binary)
    assert result.crashed is True
    assert "999" in result.message


@pytest.mark.anyio
async def test_address_sanitizer_in_stderr_with_zero_exit(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(
        mocker,
        returncode=0,
        stderr=b"==1234==ERROR: AddressSanitizer: heap-buffer-overflow\n",
    )
    result = await js_shell_evaluator("oob()", js_binary)
    assert result.crashed is True


@pytest.mark.anyio
async def test_ubsan_in_stderr(mocker: MockerFixture, js_binary: Path) -> None:
    _mock_proc(
        mocker,
        returncode=0,
        stderr=b"UndefinedBehaviorSanitizer: signed-integer-overflow\n",
    )
    result = await js_shell_evaluator("x", js_binary)
    assert result.crashed is True


@pytest.mark.anyio
async def test_positive_nonzero_exit_is_js_error_not_crash(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=3, stderr=b"SyntaxError\n")
    result = await js_shell_evaluator("(", js_binary)
    assert result.crashed is False
    assert "JS error" in result.message


@pytest.mark.anyio
async def test_timeout_kills_and_returns_no_crash(
    mocker: MockerFixture, js_binary: Path
) -> None:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=[TimeoutError, (b"", b"")])
    proc.kill = MagicMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)

    result = await js_shell_evaluator("while(1){}", js_binary, timeout=1)

    proc.kill.assert_called_once()
    assert result.crashed is False
    assert "Timed out after 1s" in result.message


@pytest.mark.anyio
async def test_stdout_stderr_are_tail_truncated(
    mocker: MockerFixture, js_binary: Path
) -> None:
    long = b"abcdefghij" * (MAX_LOG_SIZE // 10 + 100)
    crash_marker = b"AddressSanitizer\n"
    _mock_proc(mocker, returncode=-11, stdout=long, stderr=long + crash_marker)

    result = await js_shell_evaluator("x", js_binary)

    assert result.logs is not None
    assert len(result.logs.stdout) == MAX_LOG_SIZE
    assert len(result.logs.stderr) == MAX_LOG_SIZE
    # tail-truncated: the end of the original input must remain
    assert result.logs.stderr.endswith("AddressSanitizer\n")


@pytest.mark.anyio
async def test_missing_js_binary_returns_failure(tmp_path: Path) -> None:
    result = await js_shell_evaluator("x", tmp_path / "missing")
    assert result.crashed is False
    assert "not found" in result.message


@pytest.mark.anyio
async def test_extra_flags_are_passed_through(
    mocker: MockerFixture, js_binary: Path
) -> None:
    spawn = mocker.patch(
        "asyncio.create_subprocess_exec",
        return_value=mocker.AsyncMock(
            returncode=0,
            communicate=AsyncMock(return_value=(b"", b"")),
        ),
    )
    await js_shell_evaluator("x", js_binary, flags=["--no-jit", "--baseline-eager"])
    args = spawn.call_args.args
    assert "--fuzzing-safe" in args
    assert "--no-jit" in args
    assert "--baseline-eager" in args


@pytest.mark.anyio
async def test_subprocess_exception_returns_failure(
    mocker: MockerFixture, js_binary: Path
) -> None:
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=RuntimeError("spawn failed"),
    )
    result = await js_shell_evaluator("x", js_binary)
    assert result.crashed is False
    assert "RuntimeError" in result.message
