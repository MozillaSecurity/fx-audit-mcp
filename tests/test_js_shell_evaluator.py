"""Tests for js_shell_evaluator tool."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.js_shell_evaluator import js_shell_evaluator


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
    assert result.exit_code == 0


@pytest.mark.anyio
async def test_negative_exit_code_signals_crash(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=-11, stderr=b"")
    result = await js_shell_evaluator("crash()", js_binary)
    assert result.crashed is True
    assert result.exit_code == -11


@pytest.mark.anyio
async def test_unknown_signal_falls_back_to_number(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(mocker, returncode=-999, stderr=b"")
    result = await js_shell_evaluator("x", js_binary)
    assert result.crashed is True
    assert result.exit_code == -999


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
    """Verify that a rejected testcase returns its output rather than raising."""
    _mock_proc(mocker, returncode=3, stderr=b"SyntaxError: unexpected token\n")

    result = await js_shell_evaluator("(", js_binary)

    assert result.crashed is False
    assert result.exit_code == 3
    assert result.logs.crashdata == []
    stderr_log = Path(result.logs.stderr[0]).read_bytes()
    assert stderr_log == b"SyntaxError: unexpected token\n"


@pytest.mark.anyio
async def test_timeout_kills_and_raises(mocker: MockerFixture, js_binary: Path) -> None:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = None
    proc.communicate = AsyncMock(side_effect=[TimeoutError, (b"", b"")])
    proc.kill = MagicMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)

    with pytest.raises(TimeoutError, match="timed out after 1s"):
        await js_shell_evaluator("while(1){}", js_binary, timeout=1)

    proc.kill.assert_called_once()


@pytest.mark.anyio
async def test_logs_are_written_to_disk_untruncated(
    mocker: MockerFixture, js_binary: Path
) -> None:
    long = b"abcdefghij" * 400_000
    crash_marker = b"AddressSanitizer\n"
    _mock_proc(mocker, returncode=-11, stdout=long, stderr=long + crash_marker)

    result = await js_shell_evaluator("x", js_binary)

    assert Path(result.logs.stdout[0]).read_bytes() == long
    assert Path(result.logs.stderr[0]).read_bytes() == long + crash_marker


@pytest.mark.anyio
async def test_crashdata_points_at_the_stderr_log(
    mocker: MockerFixture, js_binary: Path
) -> None:
    _mock_proc(
        mocker,
        returncode=-11,
        stderr=b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
    )

    result = await js_shell_evaluator("oob()", js_binary)

    assert result.logs.crashdata == result.logs.stderr
    report = Path(result.logs.crashdata[0]).read_text(encoding="utf-8")
    assert "AddressSanitizer" in report


@pytest.mark.anyio
async def test_assertion_abort_still_reports_crashdata(
    mocker: MockerFixture, js_binary: Path
) -> None:
    """Verify that a MOZ_ASSERT abort exposes its message, with no sanitizer marker."""
    assertion = (
        b"Assertion failure: obj->is<JSFunction>(), at js/src/vm/JSObject.cpp:1\n"
    )
    _mock_proc(mocker, returncode=-6, stderr=assertion)

    result = await js_shell_evaluator("boom()", js_binary)

    assert result.crashed is True
    assert result.logs.crashdata == result.logs.stderr
    assert Path(result.logs.crashdata[0]).read_bytes() == assertion


@pytest.mark.anyio
async def test_testcase_is_run_under_a_stable_name(
    mocker: MockerFixture, js_binary: Path
) -> None:
    """Verify the shell is handed a predictable filename, not a random temp name."""
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = 0
    proc.communicate = AsyncMock(return_value=(b"", b""))
    seen: dict[str, str] = {}

    async def capture(*args: str, **_kwargs: object) -> MagicMock:
        # The temp directory is removed once the tool returns, so read it here.
        path = Path(args[-1])
        seen["name"] = path.name
        seen["content"] = path.read_text(encoding="utf-8")
        return proc

    mocker.patch("asyncio.create_subprocess_exec", side_effect=capture)

    await js_shell_evaluator("boom()", js_binary)

    assert seen == {"name": "testcase.js", "content": "boom()"}


@pytest.mark.anyio
async def test_missing_js_binary_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        await js_shell_evaluator("x", tmp_path / "missing")


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
async def test_subprocess_exception_raises(
    mocker: MockerFixture, js_binary: Path
) -> None:
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=RuntimeError("spawn failed"),
    )
    with pytest.raises(RuntimeError, match="spawn failed"):
        await js_shell_evaluator("x", js_binary)
