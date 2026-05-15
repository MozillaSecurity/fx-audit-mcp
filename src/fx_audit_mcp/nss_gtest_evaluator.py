"""Evaluate testcase tool for testing vulnerabilities in NSS via GTest."""

import asyncio
import os
from pathlib import Path

from .models import Logs, NSSGtestCrashInfo


async def nss_gtest_evaluator(
    gtest_name: str,
    firefox_dir: Path,
    timeout: int = 30,
) -> NSSGtestCrashInfo:
    """Reproduce an NSS AddressSanitizer crash by running a specific NSS GTest
    filter and reporting any ASAN output.

    Invokes ``security/nss/tests/all.sh`` with DOMSUF / HOST / NSS_TESTS /
    NSS_CYCLES / GTESTFILTER set. A crash is reported when
    ``AddressSanitizer`` appears in stdout or stderr; a non-zero exit
    without ASan output is a gtest failure, not a crash. Timed-out runs
    are killed.

    On ``crashed: false`` examine ``logs.stderr`` / ``logs.stdout`` for the
    failure mode. On ``crashed: true`` the stack trace is in ``logs.stderr``.

    Args:
        gtest_name: GTest filter (e.g. ``SuiteName.TestName``) passed via
            GTESTFILTER.
        firefox_dir: Path to the Firefox source tree (where
            ``security/nss/tests/all.sh`` lives).
        timeout: Per-run timeout in seconds before the gtest is killed.

    Returns:
        NSSGtestCrashInfo.
    """
    try:
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
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except TimeoutError:
            process.kill()
            await process.communicate()
            return NSSGtestCrashInfo(
                crashed=False,
                message=f"Timed out after {timeout}s",
                logs=Logs(stderr="", stdout=""),
            )

        stdout_output = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_output = stderr.decode("utf-8", errors="replace") if stderr else ""

        if "AddressSanitizer" in stdout_output or "AddressSanitizer" in stderr_output:
            return NSSGtestCrashInfo(
                crashed=True,
                message="ASan crash detected",
                logs=Logs(stdout=stdout_output, stderr=stderr_output),
            )

        if process.returncode == 0:
            return NSSGtestCrashInfo(
                crashed=False,
                message="No crash detected",
                logs=Logs(stdout=stdout_output, stderr=stderr_output),
            )

        return NSSGtestCrashInfo(
            crashed=False,
            message=(
                f"Gtest exited with code {process.returncode}"
                " (Gtest error, not a crash)"
            ),
            logs=Logs(stdout=stdout_output, stderr=stderr_output),
        )
    except Exception as e:
        return NSSGtestCrashInfo(
            crashed=False,
            message=f"Error running NSS GTest: {type(e).__name__}: {e!s}",
        )
