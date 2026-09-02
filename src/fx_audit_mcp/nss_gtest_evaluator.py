"""Evaluate testcase tool for testing vulnerabilities in NSS via GTest."""

from pathlib import Path

from .logs import log_contains
from .models import NSSGtestCrashInfo
from .process_runner import run

ASAN_MARKER = "AddressSanitizer"


async def nss_gtest_evaluator(
    gtest_name: str,
    firefox_dir: Path,
    timeout: int = 30,
) -> NSSGtestCrashInfo:
    """Run an NSS GTest testcase and report whether it crashed.

    Invokes ``security/nss/tests/all.sh`` with these environment variables set:

    - DOMSUF=localdomain
    - HOST=localhost
    - NSS_TESTS="gtests ssl_gtests"
    - NSS_CYCLES=standard
    - GTESTFILTER=<gtest_name>

    A gtest failure is not a crash. Logs are written to a temporary
    directory. The caller is responsible for cleanup.

    Args:
        gtest_name: GTest filter (e.g. ``SuiteName.TestName``).
        firefox_dir: Path to the Firefox source tree (where
            ``security/nss/tests/all.sh`` lives).
        timeout: Per-run timeout in seconds before the gtest is killed.

    Returns:
        NSSGtestCrashInfo with:
        - crashed: Boolean indicating if the testcase triggered a crash.
        - timed_out: Boolean indicating if the testcase timed out.
        - exit_code: The harness's exit status.
        - logs: Paths to the run's stdout/stderr/crashdata log files.
    """
    result = await run(
        str(firefox_dir / "security/nss/tests/all.sh"),
        timeout=timeout,
        cwd=firefox_dir,
        extra_env={
            "DOMSUF": "localdomain",
            "HOST": "localhost",
            "NSS_TESTS": "gtests ssl_gtests",
            "NSS_CYCLES": "standard",
            "GTESTFILTER": gtest_name,
        },
    )

    # A timed-out run is never a crash, so its partial output is not scanned
    # for a report and no log is named as crashdata.
    crashdata: list[Path] = []
    if not result.timed_out:
        crashdata = [
            path
            for path in (result.stdout, result.stderr)
            if log_contains(path, ASAN_MARKER)
        ]

    return NSSGtestCrashInfo(
        crashed=bool(crashdata),
        timed_out=result.timed_out,
        exit_code=result.exit_code,
        logs=result.crash_logs(crashdata),
    )
