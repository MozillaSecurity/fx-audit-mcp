"""Tests for js_shell_evaluator tool."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.js_shell_evaluator import NTSTATUS_ERROR_BASE, js_shell_evaluator

from .conftest import MakeRunResult

RUN = "fx_audit_mcp.js_shell_evaluator.run"


@pytest.mark.parametrize(
    ("exit_code", "expected"),
    [
        (0, False),
        (3, False),  # JS error, not a crash
        (-11, True),  # SIGSEGV
        (-999, True),  # unknown signal number
        (0xC0000005, True),  # STATUS_ACCESS_VIOLATION
        (0xC0000374, True),  # STATUS_HEAP_CORRUPTION
        (NTSTATUS_ERROR_BASE - 1, False),  # below the error range
    ],
)
@pytest.mark.anyio
async def test_exit_code_crash_classification(
    mocker: MockerFixture,
    make_run_result: MakeRunResult,
    js_binary: Path,
    exit_code: int,
    expected: bool,
) -> None:
    """A crash is an exit status the OS flagged: a signal or an NTSTATUS error."""
    mocker.patch(RUN, AsyncMock(return_value=make_run_result(exit_code=exit_code)))

    result = await js_shell_evaluator("x", js_binary)

    assert result.crashed is expected
    assert result.exit_code == exit_code


@pytest.mark.parametrize("marker", ["AddressSanitizer", "UndefinedBehaviorSanitizer"])
@pytest.mark.anyio
async def test_sanitizer_in_stderr_with_zero_exit_signals_crash(
    mocker: MockerFixture,
    make_run_result: MakeRunResult,
    js_binary: Path,
    marker: str,
) -> None:
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(
                stderr=f"==1==ERROR: {marker}: boom\n".encode()
            )
        ),
    )

    result = await js_shell_evaluator("oob()", js_binary)

    assert result.crashed is True


@pytest.mark.anyio
async def test_js_error_returns_its_output(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    """Verify that a rejected testcase returns its output rather than raising."""
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(
                exit_code=3, stderr=b"SyntaxError: unexpected token\n"
            )
        ),
    )

    result = await js_shell_evaluator("(", js_binary)

    assert result.crashed is False
    assert result.logs.crashdata == []
    assert (
        Path(result.logs.stderr[0]).read_bytes() == b"SyntaxError: unexpected token\n"
    )


@pytest.mark.anyio
async def test_timed_out_run_is_never_a_crash(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    """The kill signal's exit code and any partial output must not read as a crash."""
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(
                exit_code=-9, timed_out=True, stderr=b"partial AddressSanitizer\n"
            )
        ),
    )

    result = await js_shell_evaluator("while(1){}", js_binary, timeout=1)

    assert result.timed_out is True
    assert result.crashed is False
    assert result.logs.crashdata == []


@pytest.mark.anyio
async def test_crashdata_points_at_the_stderr_log(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    mocker.patch(
        RUN,
        AsyncMock(
            return_value=make_run_result(
                exit_code=-11,
                stderr=b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
            )
        ),
    )

    result = await js_shell_evaluator("oob()", js_binary)

    assert result.logs.crashdata == result.logs.stderr
    report = Path(result.logs.crashdata[0]).read_text(encoding="utf-8")
    assert "AddressSanitizer" in report


@pytest.mark.anyio
async def test_assertion_abort_still_reports_crashdata(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    """Verify that a MOZ_ASSERT abort exposes its message, with no sanitizer marker."""
    assertion = (
        b"Assertion failure: obj->is<JSFunction>(), at js/src/vm/JSObject.cpp:1\n"
    )
    mocker.patch(
        RUN, AsyncMock(return_value=make_run_result(exit_code=-6, stderr=assertion))
    )

    result = await js_shell_evaluator("boom()", js_binary)

    assert result.crashed is True
    assert result.logs.crashdata == result.logs.stderr
    assert Path(result.logs.crashdata[0]).read_bytes() == assertion


@pytest.mark.anyio
async def test_testcase_is_run_under_a_stable_name(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    """Verify the shell is handed a predictable filename, not a random temp name."""
    seen: dict[str, str] = {}

    async def capture(*args: str, **_kwargs: object) -> object:
        # The temp directory is removed once the tool returns, so read it here.
        path = Path(args[-1])
        seen["name"] = path.name
        seen["content"] = path.read_text(encoding="utf-8")
        return make_run_result()

    mocker.patch(RUN, side_effect=capture)

    await js_shell_evaluator("boom()", js_binary)

    assert seen == {"name": "testcase.js", "content": "boom()"}


@pytest.mark.anyio
async def test_flags_and_timeout_are_passed_through(
    mocker: MockerFixture, make_run_result: MakeRunResult, js_binary: Path
) -> None:
    run_mock = mocker.patch(RUN, AsyncMock(return_value=make_run_result()))

    await js_shell_evaluator(
        "x", js_binary, timeout=42, flags=["--no-jit", "--baseline-eager"]
    )

    args = run_mock.call_args.args
    assert args[0] == str(js_binary)
    assert args[1] == "--fuzzing-safe"
    assert "--no-jit" in args
    assert "--baseline-eager" in args
    assert run_mock.call_args.kwargs["timeout"] == 42


@pytest.mark.anyio
async def test_missing_js_binary_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="not found"):
        await js_shell_evaluator("x", tmp_path / "missing")
