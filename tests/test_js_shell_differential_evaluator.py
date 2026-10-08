"""Tests for js_shell_differential_evaluator tool."""

import stat
from pathlib import Path

import pytest

from fx_audit_mcp.js_shell_differential_evaluator import (
    js_shell_differential_evaluator,
)


def fake_shell(directory: Path, name: str, body: str) -> Path:
    """Write an executable stand-in shell that ignores the testcase it is handed.

    Real subprocesses rather than mocks: what is under test is how two
    concurrent runs are compared, so the exit statuses have to be produced by
    actual processes.

    Args:
        directory: Where to write it.
        name: Binary name; the evaluator guesses the engine from it.
        body: Shell body run in place of executing the JS.
    """
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


@pytest.mark.anyio
async def test_both_shells_succeeding_is_not_a_discrepancy(tmp_path: Path) -> None:
    """Two shells that both run the testcase cleanly is not a finding."""
    shell = fake_shell(tmp_path, "js", "exit 0")
    result = await js_shell_differential_evaluator("check()", shell, shell)
    assert result.differs is False
    assert result.shell_a.succeeded is True
    assert result.shell_b.succeeded is True


@pytest.mark.anyio
async def test_both_shells_failing_is_not_a_discrepancy(tmp_path: Path) -> None:
    """A testcase both engines reject says nothing about either of them."""
    result = await js_shell_differential_evaluator(
        "syntax error",
        fake_shell(tmp_path, "js", "exit 3"),
        fake_shell(tmp_path, "d8", "exit 1"),
    )
    assert result.differs is False
    assert result.shell_a.succeeded is False
    assert result.shell_b.succeeded is False


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("body_a", "body_b", "succeeded_a"),
    [("exit 0", "exit 1", True), ("exit 1", "exit 0", False)],
)
async def test_one_shell_failing_is_a_discrepancy(
    body_a: str, body_b: str, succeeded_a: bool, tmp_path: Path
) -> None:
    """Exactly one shell throwing is the signal, whichever side it is."""
    result = await js_shell_differential_evaluator(
        "if (x !== 1) throw new Error()",
        fake_shell(tmp_path, "js", body_a),
        fake_shell(tmp_path, "d8", body_b),
    )
    assert result.differs is True
    assert result.shell_a.succeeded is succeeded_a
    assert result.shell_b.succeeded is not succeeded_a


@pytest.mark.anyio
async def test_differing_stdout_alone_is_not_a_discrepancy(tmp_path: Path) -> None:
    """Only the exit status is compared; printed output is captured, not judged.

    Engines format output differently for reasons that are not bugs, so a
    testcase has to turn a wrong answer into a throw to be detected.
    """
    result = await js_shell_differential_evaluator(
        "print(x)",
        fake_shell(tmp_path, "js", "echo 42"),
        fake_shell(tmp_path, "d8", "echo 43"),
    )
    assert result.differs is False
    assert Path(result.shell_a.logs.stdout[0]).read_text(encoding="utf-8") == "42\n"
    assert Path(result.shell_b.logs.stdout[0]).read_text(encoding="utf-8") == "43\n"


@pytest.mark.anyio
async def test_fuzzing_safe_is_added_for_spidermonkey_only(tmp_path: Path) -> None:
    """The shell harness flag goes to SpiderMonkey and never to V8."""
    result = await js_shell_differential_evaluator(
        "print(1)",
        fake_shell(tmp_path, "js", "echo ok"),
        fake_shell(tmp_path, "d8", "echo ok"),
        flags_a=["--ion-eager"],
    )
    assert result.shell_a.argv[1:3] == ["--fuzzing-safe", "--ion-eager"]
    assert result.shell_a.fuzzing_safe is True
    assert "--fuzzing-safe" not in result.shell_b.argv
    assert result.shell_b.fuzzing_safe is False


@pytest.mark.anyio
async def test_explicit_engine_overrides_the_name_guess(tmp_path: Path) -> None:
    """A V8 shell under an unusual name still gets no --fuzzing-safe."""
    result = await js_shell_differential_evaluator(
        "print(1)",
        fake_shell(tmp_path, "js", "echo ok"),
        fake_shell(tmp_path, "v8-shell-renamed", "echo ok"),
        engine_b="v8",
    )
    assert result.shell_b.engine == "v8"
    assert result.shell_b.fuzzing_safe is False


@pytest.mark.anyio
async def test_timeout_counts_as_a_failure_rather_than_hanging(tmp_path: Path) -> None:
    """A wedged shell is torn down and scored as the failing side."""
    result = await js_shell_differential_evaluator(
        "while(1);",
        fake_shell(tmp_path, "js", "echo ok"),
        fake_shell(tmp_path, "js-slow", "sleep 30"),
        timeout=1,
    )
    assert result.differs is True
    assert result.shell_b.timed_out is True
    assert result.shell_b.succeeded is False


@pytest.mark.anyio
@pytest.mark.parametrize("missing", ["A", "B"])
async def test_missing_shell_raises(missing: str, tmp_path: Path) -> None:
    """A shell path that is not there raises rather than reporting a result."""
    present = fake_shell(tmp_path, "js", "echo ok")
    absent = tmp_path / "nope"
    shell_a, shell_b = (absent, present) if missing == "A" else (present, absent)
    with pytest.raises(FileNotFoundError, match=f"Shell {missing} not found"):
        await js_shell_differential_evaluator("print(1)", shell_a, shell_b)


@pytest.mark.anyio
async def test_stderr_is_captured_for_both_shells(tmp_path: Path) -> None:
    """Each side's stderr comes back, so a crash report is not lost."""
    result = await js_shell_differential_evaluator(
        "print(1)",
        fake_shell(tmp_path, "js", "echo boom >&2; exit 1"),
        fake_shell(tmp_path, "d8", "echo ok"),
    )
    assert Path(result.shell_a.logs.stderr[0]).read_text(encoding="utf-8") == "boom\n"
