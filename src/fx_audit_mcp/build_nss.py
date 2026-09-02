"""Build NSS tool for compiling NSS with ASAN."""

import asyncio
import os
from pathlib import Path

from .logs import write_logs
from .models import BuildResult


async def build_nss(firefox_dir: Path) -> BuildResult:
    """Build the ASAN-instrumented NSS libraries needed by nss_gtest_evaluator.

    Invokes ``security/nss/build.sh -c --asan`` and returns the build directory.
    Symlinks ``nsprpub`` into the location NSS's build expects (``../nspr``
    relative to ``security/nss``) before invoking the build.

    Logs are written to a temporary directory. The caller is responsible for
    cleanup.

    Args:
        firefox_dir: Path to the Firefox source directory (e.g. ``./firefox``).

    Returns:
        BuildResult with:
        - success: Boolean indicating if the build completed successfully.
        - exit_code: The build's exit status.
        - logs: Paths to the build's stdout/stderr log files.
        - build_dir: The build directory on success.
    """
    nspr_dir = firefox_dir / "nsprpub"
    nss_dir = firefox_dir / "security/nss"
    symlink_dir = nss_dir / "../nspr"

    if not firefox_dir.exists():
        raise FileNotFoundError(f"Firefox directory not found at {firefox_dir}")

    if not nspr_dir.exists():
        raise FileNotFoundError(f"NSPR directory not found at {nspr_dir}")

    if not nss_dir.exists():
        raise FileNotFoundError(f"NSS directory not found at {nss_dir}")

    # Symlink NSPR to where NSS expects it to be
    if not symlink_dir.exists():
        symlink_dir.symlink_to(nspr_dir)

    # Expected build directory
    build_dir = nss_dir / "../dist/Debug"

    process = await asyncio.create_subprocess_exec(
        str(nss_dir / "build.sh"),
        "-c",
        "--asan",
        cwd=nss_dir,
        env={**os.environ},
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout, stderr = await process.communicate()
    # communicate() only returns once the process has exited.
    assert process.returncode is not None
    logs = write_logs(stdout or b"", stderr or b"")

    if process.returncode == 0:
        return BuildResult(
            success=True,
            build_dir=str(build_dir),
            exit_code=process.returncode,
            logs=logs,
        )

    return BuildResult(
        success=False,
        exit_code=process.returncode,
        logs=logs,
    )
