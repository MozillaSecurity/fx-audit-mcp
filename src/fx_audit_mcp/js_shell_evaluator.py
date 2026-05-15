"""Evaluate testcase tool for testing vulnerabilities in the SpiderMonkey JS shell."""

import asyncio
import os
import signal
import tempfile
from pathlib import Path

from .models import JSShellCrashInfo, Logs

MAX_LOG_SIZE = 1_048_576  # bytes; logs are tail-truncated to this limit


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
    JS errors (positive non-zero exit) are not treated as crashes. Timed-out
    processes are killed and return no crash. Captured stdout/stderr are
    tail-truncated to MAX_LOG_SIZE.

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
        return JSShellCrashInfo(
            crashed=False,
            message=f"JS shell binary not found at {js_binary}",
        )

    try:
        with tempfile.TemporaryDirectory(prefix="fx_audit_js_") as tmp_dir:
            fd, tmp_path = tempfile.mkstemp(suffix=".js", dir=tmp_dir)
            testcase_path = Path(tmp_path)
            os.close(fd)
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
                return JSShellCrashInfo(
                    crashed=False,
                    message=f"Timed out after {timeout}s — no crash detected",
                    logs=Logs(stderr="", stdout=""),
                )

            stdout_raw = stdout_bytes.decode("utf-8", errors="replace")
            stderr_raw = stderr_bytes.decode("utf-8", errors="replace")
            stdout = (
                stdout_raw[-MAX_LOG_SIZE:]
                if len(stdout_raw) > MAX_LOG_SIZE
                else stdout_raw
            )
            stderr = (
                stderr_raw[-MAX_LOG_SIZE:]
                if len(stderr_raw) > MAX_LOG_SIZE
                else stderr_raw
            )
            exit_code = proc.returncode

            # Detect crash: killed by signal or ASAN/UBSAN in stderr
            killed_by_signal = exit_code is not None and exit_code < 0
            has_sanitizer = (
                "AddressSanitizer" in stderr or "UndefinedBehaviorSanitizer" in stderr
            )

            crashed = killed_by_signal or has_sanitizer

            if not crashed:
                msg = (
                    f"JS shell exited with code {exit_code} (JS error, not a crash)"
                    if exit_code != 0
                    else "No crash detected"
                )
                return JSShellCrashInfo(
                    crashed=False,
                    message=msg,
                    logs=Logs(stderr=stderr, stdout=stdout),
                )

            signal_name = ""
            if killed_by_signal and exit_code is not None:
                sig_num = -exit_code
                try:
                    sig = signal.Signals(sig_num)
                    signal_name = f" (signal {sig.name})"
                except ValueError:
                    signal_name = f" (signal {sig_num})"

            return JSShellCrashInfo(
                crashed=True,
                message=f"Crash detected{signal_name}",
                files={testcase_path.name: content},
                logs=Logs(
                    stderr=stderr,
                    stdout=stdout,
                    crashdata=stderr,  # ASAN output goes to stderr
                ),
            )
    except Exception as e:
        return JSShellCrashInfo(
            crashed=False,
            message=f"Error running JS shell: {type(e).__name__}: {e!s}",
        )
