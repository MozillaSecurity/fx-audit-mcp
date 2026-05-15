"""Build NSS tool for compiling NSS with ASAN."""

import asyncio
import os
from pathlib import Path

from .models import BuildResult


async def build_nss(firefox_dir: Path) -> BuildResult:
    """Build the ASAN-instrumented NSS libraries needed by nss_gtest_evaluator:
    invokes ``security/nss/build.sh -c --asan`` and returns the build directory.

    Symlinks ``nsprpub`` into the location NSS's build expects (``../nspr``
    relative to ``security/nss``) before invoking the build.

    Args:
        firefox_dir: Path to the Firefox source directory (e.g. ``./firefox``).

    Returns:
        BuildResult with the build directory path on success.
    """
    try:
        nspr_dir = firefox_dir / "nsprpub"
        nss_dir = firefox_dir / "security/nss"
        symlink_dir = nss_dir / "../nspr"

        if not firefox_dir.exists():
            return BuildResult(
                success=False,
                message=f"Firefox directory not found at {firefox_dir}",
            )

        if not nspr_dir.exists():
            return BuildResult(
                success=False,
                message=f"NSPR directory not found at {nspr_dir}",
            )

        if not nss_dir.exists():
            return BuildResult(
                success=False,
                message=f"NSS directory not found at {nss_dir}",
            )

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
        stdout_output = stdout.decode("utf-8", errors="replace") if stdout else ""
        stderr_output = stderr.decode("utf-8", errors="replace") if stderr else ""

        if process.returncode == 0:
            return BuildResult(
                success=True,
                build_dir=str(build_dir),
                message="NSS build completed successfully",
                stdout=stdout_output,
                stderr=stderr_output,
            )

        return BuildResult(
            success=False,
            message=f"NSS build failed with exit code {process.returncode}",
            stdout=stdout_output,
            stderr=stderr_output,
        )

    except Exception as e:
        return BuildResult(
            success=False,
            message=f"Error building NSS: {type(e).__name__}: {e!s}",
        )
