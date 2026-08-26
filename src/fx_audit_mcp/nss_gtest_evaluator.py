"""Evaluate testcase tool for testing vulnerabilities in NSS via GTest."""

import asyncio
import os
from pathlib import Path

from .logs import StreamName, write_crash_logs
from .models import NSSGtestCrashInfo


async def nss_gtest_evaluator(
    gtest_name: str,
    firefox_dir: Path,
    timeout: int = 30,
) -> NSSGtestCrashInfo:
    """Reproduce an NSS AddressSanitizer crash by running a specific NSS GTest
    filter and reporting any ASAN output.

    Invokes ``security/nss/tests/all.sh`` with DOMSUF / HOST / NSS_TESTS /
    NSS_CYCLES / GTESTFILTER set. A crash is reported when
    ``AddressSanitizer`` appears in stdout or stderr. A non-zero exit without
    ASan output is a gtest failure, not a crash, but is still a result: it
    returns ``crashed: false`` with the harness output, since the run itself
    succeeded. Only an operational failure raises, when the harness could not
    be run to completion at all: currently a timeout.

    stdout and stderr are written to a fresh temporary directory and the
    returned ``logs`` holds their paths. That directory is never deleted; the
    caller owns it.

    On ``crashed: false`` examine ``logs.stderr`` / ``logs.stdout`` for the
    failure mode. On ``crashed: true`` ``logs.crashdata`` names whichever of
    those files carried the ASAN report.

    Args:
        gtest_name: GTest filter (e.g. ``SuiteName.TestName``) passed via
            GTESTFILTER.
        firefox_dir: Path to the Firefox source tree (where
            ``security/nss/tests/all.sh`` lives).
        timeout: Per-run timeout in seconds before the gtest is killed.

    Returns:
        NSSGtestCrashInfo.
    """
    process = await asyncio.create_subprocess_exec(
        str(firefox_dir / "security/nss/tests/all.sh"),
        cwd=firefox_dir,
        env={
            **os.environ,
            "DOMSUF": "localdomain",
            "HOST": "localhost",
            "NSS_TESTS": "gtests ssl_gtests",
            "NSS_CYCLES": "standard",
            "GTESTFILTER": gtest_name,
        },
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.communicate()
        raise TimeoutError(f"NSS GTest timed out after {timeout}s") from None

    stdout_bytes = stdout or b""
    stderr_bytes = stderr or b""
    stdout_output = stdout_bytes.decode("utf-8", errors="replace")
    stderr_output = stderr_bytes.decode("utf-8", errors="replace")

    streams: tuple[tuple[StreamName, str], ...] = (
        ("stdout", stdout_output),
        ("stderr", stderr_output),
    )
    asan_streams = tuple(name for name, text in streams if "AddressSanitizer" in text)
    logs = write_crash_logs(stdout_bytes, stderr_bytes, crashdata=asan_streams)

    if asan_streams:
        return NSSGtestCrashInfo(
            crashed=True,
            message="ASan crash detected",
            logs=logs,
        )

    return NSSGtestCrashInfo(
        crashed=False,
        message=(
            f"No crash detected - gtest exited with code {process.returncode}"
            " (gtest failure, not a crash)"
            if process.returncode != 0
            else "No crash detected"
        ),
        logs=logs,
    )
