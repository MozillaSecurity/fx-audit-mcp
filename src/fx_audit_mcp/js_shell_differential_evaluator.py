"""Differential evaluator: run one JS testcase in two shells and compare.

Runs the same testcase in two JS engine shells (two SpiderMonkey builds or
configurations, or SpiderMonkey against V8's ``d8``). The discrepancy looked
for is: **exactly one shell succeeds (exit code 0) while the other fails**
(non-zero exit, crash, or timeout -- i.e. it threw/raised). Which one fails
does not matter. If both succeed, or both fail, that is NOT a discrepancy.

The goal when authoring a testcase is therefore to find input that one engine
accepts/executes cleanly while the other rejects it -- a behavioural divergence
between the two engines.

``--fuzzing-safe`` is added only for SpiderMonkey shells, never for V8/d8.
"""

import asyncio
import tempfile
from pathlib import Path

from .models import Engine, JSShellDifferentialInfo, LogPaths, ShellRun
from .process_runner import run


async def _run_one(
    shell: Path,
    engine: Engine,
    flags: list[str] | None,
    testcase_path: Path,
    timeout: int,
) -> ShellRun:
    """Run the testcase in a single shell.

    Args:
        shell: Path to the JS shell binary.
        engine: Which engine the shell is; decides whether ``--fuzzing-safe``
            is added.
        flags: Additional runtime flags for the shell.
        testcase_path: The testcase file to run.
        timeout: Seconds to wait before the shell is killed.

    Returns:
        ShellRun describing how the shell ran and where its output went.
    """
    fuzzing_safe = engine == "spidermonkey"
    argv = [str(shell)]
    if fuzzing_safe:
        argv.append("--fuzzing-safe")
    argv.extend(flags or [])
    argv.append(str(testcase_path))

    result = await run(*argv, timeout=timeout)
    return ShellRun(
        path=str(shell),
        engine=engine,
        argv=argv,
        fuzzing_safe=fuzzing_safe,
        exit_code=result.exit_code,
        timed_out=result.timed_out,
        succeeded=not result.timed_out and result.exit_code == 0,
        logs=LogPaths(stdout=[str(result.stdout)], stderr=[str(result.stderr)]),
    )


def detect_engine(shell: Path) -> Engine:
    """Guess which engine a shell binary is, from its name.

    Args:
        shell: Path to the JS shell binary.

    Returns:
        ``"v8"`` when the name looks like a V8 shell, else ``"spidermonkey"``.
    """
    name = shell.name.lower()
    if "d8" in name or "v8" in name:
        return "v8"
    return "spidermonkey"


async def js_shell_differential_evaluator(
    content: str,
    shell_a: Path,
    shell_b: Path,
    timeout: int = 30,
    flags_a: list[str] | None = None,
    flags_b: list[str] | None = None,
    engine_a: Engine | None = None,
    engine_b: Engine | None = None,
) -> JSShellDifferentialInfo:
    """Run one JS testcase in two shells and detect a success/failure
    divergence.

    Differential testing across engines (e.g. two SpiderMonkey builds or JIT
    configurations, or SpiderMonkey vs. V8's d8). The goal: find a testcase that
    ONE shell runs successfully (exit code 0) while the OTHER fails (non-zero
    exit, crash, or timeout -- i.e. it throws/raises). Which shell fails does not
    matter. The result has ``differs=true`` only when exactly one shell succeeds;
    if both succeed or both fail it is ``differs=false``. Build your testcase so
    that one engine accepts it and the other rejects it -- compute the value
    under test and ``throw`` when it is not what it should be, so a wrong answer
    becomes a failing exit rather than a difference in printed output.

    ``--fuzzing-safe`` is added to SpiderMonkey shells and never to V8. The
    engine is guessed from the binary name unless given explicitly. Each
    shell's logs are written to a temporary directory. The caller is
    responsible for cleanup.

    Args:
        content: Testcase JS source code as a string (not a filename or path).
            The same source is written to one temp file and run in both shells.
        shell_a: Path to the first JS shell binary.
        shell_b: Path to the second JS shell binary; may be the same path as
            ``shell_a`` when comparing two flag sets.
        timeout: Per-shell timeout in seconds before that shell is killed.
        flags_a: Additional runtime flags for shell A.
        flags_b: Additional runtime flags for shell B.
        engine_a: ``"spidermonkey"`` or ``"v8"`` for shell A; guessed from the
            binary name when omitted. Controls whether --fuzzing-safe is added
            (SpiderMonkey only; never for V8/d8).
        engine_b: Same as ``engine_a``, for shell B.

    Returns:
        JSShellDifferentialInfo with:
        - differs: True only when exactly one shell succeeded.
        - shell_a / shell_b: How each shell ran (engine, argv, exit code,
          timed_out, succeeded) and paths to its stdout/stderr log files.
    """
    if not shell_a.exists():
        raise FileNotFoundError(f"Shell A not found at {shell_a}")
    if not shell_b.exists():
        raise FileNotFoundError(f"Shell B not found at {shell_b}")

    with tempfile.TemporaryDirectory(prefix="fx_audit_jsdiff_") as tmp_dir:
        testcase_path = Path(tmp_dir) / "testcase.js"
        testcase_path.write_text(content, encoding="utf-8")

        run_a, run_b = await asyncio.gather(
            _run_one(
                shell_a,
                engine_a or detect_engine(shell_a),
                flags_a,
                testcase_path,
                timeout,
            ),
            _run_one(
                shell_b,
                engine_b or detect_engine(shell_b),
                flags_b,
                testcase_path,
                timeout,
            ),
        )

    # The signal: exactly ONE shell succeeds (exit 0) while the other fails
    # (non-zero exit, crash, or timeout). Both-succeed and both-fail are NOT
    # discrepancies, regardless of the exact codes.
    return JSShellDifferentialInfo(
        differs=run_a.succeeded != run_b.succeeded,
        shell_a=run_a,
        shell_b=run_b,
    )
