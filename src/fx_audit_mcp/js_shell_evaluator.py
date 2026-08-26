"""Evaluate testcase tool for testing vulnerabilities in the SpiderMonkey JS shell."""

import asyncio
import os
import tempfile
from pathlib import Path

from .logs import write_crash_logs
from .models import JSShellCrashInfo

# Windows has no signals to report: an unhandled exception becomes the
# process's exit code as an NTSTATUS value, and 0xC0000000 opens the range
# reserved for errors (0xC0000005 is an access violation). A POSIX exit status
# never reaches this far, so the check needs no platform guard.
NTSTATUS_ERROR_BASE = 0xC0000000


async def js_shell_evaluator(
    content: str,
    js_binary: Path,
    timeout: int = 30,
    flags: list[str] | None = None,
) -> JSShellCrashInfo:
    """Reproduce a SpiderMonkey JS crash by running JS source code in the
    SpiderMonkey shell with --fuzzing-safe and detecting ASAN/UBSAN output
    or signal exits.

    Always runs the shell with ``--fuzzing-safe``. A crash is reported when the
    OS reported the fault in the exit status - a signal on POSIX (negative exit
    code), an NTSTATUS error on Windows (0xC0000005 and up) - or when
    ``AddressSanitizer`` / ``UndefinedBehaviorSanitizer`` appears in stderr.
    A JS error (positive non-zero exit) is not a crash but is still a result:
    it returns ``crashed: false`` with the shell's output, since the run itself
    succeeded. Only an operational failure raises, when the shell could not be
    run to completion at all: a missing binary or a timeout.

    stdout and stderr are written to a fresh temporary directory and the
    returned ``logs`` holds their paths. That directory is never deleted; the
    caller owns it. Crash diagnostics arrive on stderr, whether a sanitizer
    report or a bare ``Assertion failure:`` message, so on a crash
    ``logs.crashdata`` names that same stderr file. A crash that printed
    nothing at all leaves ``logs.crashdata`` empty.

    Args:
        content: Testcase JS source code as a string (not a filename or path).
            The tool writes it to a temp file and runs that.
        js_binary: Path to the SpiderMonkey JS shell binary (e.g.
            ``/path/to/firefox/obj-fuzz/dist/bin/js``).
        timeout: Per-run timeout in seconds before the shell is killed.
        flags: Optional additional runtime flags for the JS shell (e.g.
            ``["--no-jit", "--baseline-eager"]``).

    Returns:
        JSShellCrashInfo.
    """
    if not js_binary.exists():
        raise FileNotFoundError(f"JS shell binary not found at {js_binary}")

    with tempfile.TemporaryDirectory(prefix="fx_audit_js_") as tmp_dir:
        testcase_path = Path(tmp_dir) / "testcase.js"
        testcase_path.write_text(content, encoding="utf-8")

        proc = await asyncio.create_subprocess_exec(
            str(js_binary),
            "--fuzzing-safe",
            *(flags or []),
            str(testcase_path),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ},
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            raise TimeoutError(f"JS shell timed out after {timeout}s") from None

        # Only stderr is decoded; the logs are written from the raw bytes.
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        # communicate() only returns once the process has exited.
        assert proc.returncode is not None
        exit_code = proc.returncode

        # Detect crash: died on a fault the OS reported, or ASAN/UBSAN in stderr
        died_on_fault = exit_code < 0 or exit_code >= NTSTATUS_ERROR_BASE
        has_sanitizer = (
            "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr
        )

        crashed = died_on_fault or has_sanitizer
        # A crash puts its diagnostics on stderr, sanitizer report or bare
        # assertion message, so crashdata names that file. A process killed
        # before it printed anything (SIGKILL from the OOM killer, a segfault
        # in a build with no sanitizer) leaves it empty, and naming an empty
        # file would promise diagnostics that aren't there.
        logs = write_crash_logs(
            stdout_bytes,
            stderr_bytes,
            crashdata=("stderr",) if crashed and stderr_bytes else (),
        )

        if not crashed:
            return JSShellCrashInfo(
                crashed=False,
                exit_code=exit_code,
                logs=logs,
            )

        return JSShellCrashInfo(
            crashed=True,
            exit_code=exit_code,
            logs=logs,
        )
