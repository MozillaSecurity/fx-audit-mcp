"""Build Firefox tool for compiling Firefox with ASAN fuzzing configuration."""

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from shutil import which

from .models import BuildResult

# Root of a mozilla-build installation on Windows; overridable for tests.
MOZILLA_BUILD_ROOT = Path("C:/mozilla-build")


def _windows_build_env(env: dict[str, str]) -> dict[str, str]:
    """Prepend Windows PATH entries needed by ``mach build``.

    Adds (when present): ``~/.cargo/bin``, ``c:/mozilla-build/python3``,
    ``c:/mozilla-build/msys2/usr/bin``, and the clang ASAN runtime DLL
    directory under ``~/.mozbuild/clang/lib/clang/*/lib/windows`` so that
    Rust build-script binaries linked against ``clang_rt.asan_dynamic`` can
    execute during full rebuilds.

    Args:
        env: Environment dict whose ``PATH`` will be updated in place.

    Returns:
        The same environment dict (returned for chaining convenience).
    """
    home = Path.home()
    extra: list[str] = []

    cargo_bin = home / ".cargo" / "bin"
    if cargo_bin.is_dir():
        extra.append(str(cargo_bin))

    if MOZILLA_BUILD_ROOT.is_dir():
        extra.append(str(MOZILLA_BUILD_ROOT / "python3"))
        msys2 = MOZILLA_BUILD_ROOT / "msys2" / "usr" / "bin"
        if msys2.is_dir():
            extra.append(str(msys2))

    clang_base = home / ".mozbuild" / "clang" / "lib" / "clang"
    if clang_base.is_dir():
        asan_dirs = sorted(clang_base.glob("*/lib/windows"))
        if asan_dirs:
            extra.append(str(asan_dirs[0]))

    if extra:
        env["PATH"] = ";".join(extra) + ";" + env.get("PATH", "")

    return env


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build Firefox with ASAN fuzzing configuration"
    )
    parser.add_argument(
        "--firefox-dir",
        type=Path,
        default=Path(os.environ.get("FIREFOX_SOURCE_ROOT", "./firefox")),
        help=(
            "Path to the Firefox source directory "
            "(default: $FIREFOX_SOURCE_ROOT or ./firefox)"
        ),
    )
    parser.add_argument(
        "--mozconfig",
        type=Path,
        default=None,
        help="Path to the MOZCONFIG file",
    )
    return parser.parse_args(argv)


async def _get_build_dir(py3: str, firefox_dir: Path, env: dict[str, str]) -> str:
    """Return the configured objdir by querying ``mach environment``.

    Args:
        py3: Path to the python3 executable.
        firefox_dir: Firefox source directory (cwd for mach).
        env: Environment to pass to the subprocess.

    Returns:
        Absolute path to the build output directory.

    Raises:
        RuntimeError: If ``mach environment`` fails or produces unexpected output.
    """
    proc = await asyncio.create_subprocess_exec(
        py3,
        "mach",
        "environment",
        "--format",
        "json",
        cwd=firefox_dir,
        env=env,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()
    data: dict[str, object] = json.loads(stdout)
    objdir = data.get("topobjdir")
    if not objdir:
        raise RuntimeError("mach environment output missing topobjdir")
    return str(objdir)


async def build_firefox(
    firefox_dir: Path,
    mozconfig_path: Path,
) -> BuildResult:
    """Build the Firefox binary needed by browser_evaluator: invokes
    ``mach build`` with the given MOZCONFIG (typically an ASAN fuzzing config)
    and returns the objdir on success.

    The build output directory is determined automatically from the
    MOZCONFIG via ``mach environment`` and returned as ``build_dir``.

    Args:
        firefox_dir: Path to the Firefox source directory (e.g. ``./firefox``).
        mozconfig_path: Path to the MOZCONFIG file controlling build flags
            (e.g. ``./mozconfigs/mozconfig.linux.asan.fuzzing``).

    Returns:
        BuildResult with ``build_dir`` set to the objdir on success.
    """
    try:
        if not firefox_dir.exists():
            return BuildResult(
                success=False,
                message=f"Firefox directory not found at {firefox_dir}",
            )

        if not mozconfig_path.exists():
            return BuildResult(
                success=False,
                message=f"MOZCONFIG file not found at {mozconfig_path}",
            )

        env = {k: v for k, v in os.environ.items() if not k.startswith("TASKCLUSTER_")}
        env["MOZCONFIG"] = str(mozconfig_path.resolve())
        env["CLAUDECODE"] = "1"

        if sys.platform == "win32":
            _windows_build_env(env)

        py3 = which("python3", path=env["PATH"])
        assert py3, "Couldn't find python3 executable in PATH"

        build_dir = await _get_build_dir(py3, firefox_dir, env)

        process = await asyncio.create_subprocess_exec(
            py3,
            "mach",
            "build",
            cwd=firefox_dir,
            env=env,
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
                build_dir=build_dir,
                message="Firefox build completed successfully",
                stdout=stdout_output,
                stderr=stderr_output,
            )

        return BuildResult(
            success=False,
            message=f"Firefox build failed with exit code {process.returncode}",
            stdout=stdout_output,
            stderr=stderr_output,
        )

    except Exception as e:
        return BuildResult(
            success=False,
            message=f"Error building Firefox: {type(e).__name__}: {e!s}",
        )


def main() -> None:
    """CLI entry point for the build_firefox tool."""
    args = _parse_args()

    if args.mozconfig is None:
        print("--mozconfig is required", file=sys.stderr)
        sys.exit(1)

    mozconfig_path = args.mozconfig

    print(f"Firefox dir: {args.firefox_dir}")
    print(f"Mozconfig:   {mozconfig_path}")
    print()

    result = asyncio.run(build_firefox(args.firefox_dir, mozconfig_path))

    print(f"Success: {result.success}")
    print(f"Message: {result.message}")
    if result.build_dir:
        print(f"Build dir: {result.build_dir}")
    if result.stdout:
        print(f"\n--- stdout ---\n{result.stdout}")
    if result.stderr:
        print(f"\n--- stderr ---\n{result.stderr}")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
