"""Evaluate testcase tool for testing vulnerabilities in the SpiderMonkey JS shell."""

import tempfile
from pathlib import Path

from .logs import log_contains
from .models import JSShellCrashInfo
from .process_runner import run

# Windows has no signals to report: an unhandled exception becomes the
# process's exit code as an NTSTATUS value, and 0xC0000000 opens the range
# reserved for errors (0xC0000005 is an access violation). A POSIX exit status
# never reaches this far, so the check needs no platform guard.
NTSTATUS_ERROR_BASE = 0xC0000000

SANITIZER_MARKERS = ("AddressSanitizer", "UndefinedBehaviorSanitizer")


async def js_shell_evaluator(
    content: str,
    js_binary: Path,
    timeout: int = 30,
    flags: list[str] | None = None,
) -> JSShellCrashInfo:
    """Reproduce a SpiderMonkey JS crash by running JS source code in the
    SpiderMonkey shell with --fuzzing-safe and detecting ASAN/UBSAN output
    or signal exits.

    Always runs the shell with ``--fuzzing-safe``. A crash is reported when
    the shell exits via signal (negative exit code) or when
    ``AddressSanitizer`` / ``UndefinedBehaviorSanitizer`` appears in stderr;
    JS errors (positive non-zero exit) are not treated as crashes. Logs are
    written to a temporary directory. The caller is responsible for cleanup.

    Args:
        content: Testcase JS source code as a string (not a filename or path).
            The tool writes it to a temp file and runs that.
        js_binary: Path to the SpiderMonkey JS shell binary (e.g.
            ``/path/to/firefox/obj-fuzz/dist/bin/js``).
        timeout: Per-run timeout in seconds before the shell is killed.
        flags: Optional additional runtime flags for the JS shell (e.g.
            ``["--no-jit", "--baseline-eager"]``).

    Returns:
        JSShellCrashInfo with:
        - crashed: Boolean indicating if the testcase triggered a crash.
        - timed_out: Boolean indicating if the testcase timed out.
        - exit_code: The shell's exit status.
        - logs: Paths to the run's stdout/stderr/crashdata log files.
    """
    if not js_binary.exists():
        raise FileNotFoundError(f"JS shell binary not found at {js_binary}")

    with tempfile.TemporaryDirectory(prefix="fx_audit_js_") as tmp_dir:
        testcase_path = Path(tmp_dir) / "testcase.js"
        testcase_path.write_text(content, encoding="utf-8")

        result = await run(
            str(js_binary),
            "--fuzzing-safe",
            *(flags or []),
            str(testcase_path),
            timeout=timeout,
        )

    # Detect crash: died on a fault the OS reported, or ASAN/UBSAN in
    # stderr. A timed-out run is never a crash: its negative exit code is
    # the kill signal, not a fault.
    died_on_fault = result.exit_code < 0 or result.exit_code >= NTSTATUS_ERROR_BASE
    crashed = not result.timed_out and (
        died_on_fault or log_contains(result.stderr, *SANITIZER_MARKERS)
    )
    # A crash puts its diagnostics on stderr, sanitizer report or bare
    # assertion message, so crashdata names that file.
    crashdata: list[Path] = []
    if crashed:
        crashdata = [result.stderr]

    return JSShellCrashInfo(
        crashed=crashed,
        timed_out=result.timed_out,
        exit_code=result.exit_code,
        logs=result.crash_logs(crashdata),
    )
