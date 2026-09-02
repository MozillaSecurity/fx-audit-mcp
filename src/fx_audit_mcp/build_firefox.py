"""Build Firefox tool for compiling Firefox with ASAN fuzzing configuration."""

import argparse
import asyncio
import json
import os
import sys
from contextlib import suppress
from pathlib import Path
from shutil import which

from fastmcp import Context

from .logs import write_logs
from .models import BuildResult
from .process_output import stream_process_output

PROCESS_TERMINATION_TIMEOUT = 5.0

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
    ctx: Context | None = None,
) -> BuildResult:
    """Build the Firefox binary needed by browser_evaluator.

    Invokes ``mach build`` with the given MOZCONFIG and returns the objdir on
    success. The build output directory is determined automatically from the
    MOZCONFIG via ``mach environment`` and returned as ``build_dir``.

    Logs are written to a temporary directory. The caller is responsible for
    cleanup.

    Args:
        firefox_dir: Path to the Firefox source directory (e.g. ``./firefox``).
        mozconfig_path: Path to the MOZCONFIG file controlling build flags
            (e.g. ``./mozconfigs/mozconfig.linux.asan.fuzzing``).
        ctx: FastMCP request context used to send live output notifications.
            When absent, output is written directly to stdout/stderr.

    Returns:
        BuildResult with:
        - success: Boolean indicating if the build completed successfully.
        - exit_code: The build's exit status.
        - logs: Paths to the build's stdout/stderr log files.
        - build_dir: The objdir on success.
    """
    if not firefox_dir.exists():
        raise FileNotFoundError(f"Firefox directory not found at {firefox_dir}")

    if not mozconfig_path.exists():
        raise FileNotFoundError(f"MOZCONFIG file not found at {mozconfig_path}")

    env = {k: v for k, v in os.environ.items() if not k.startswith("TASKCLUSTER_")}
    env["MOZCONFIG"] = str(mozconfig_path.resolve())
    env["CLAUDECODE"] = "1"

    if sys.platform == "win32":
        _windows_build_env(env)

    py3 = which("python3", path=env.get("PATH", os.defpath))
    if not py3:
        raise FileNotFoundError("Couldn't find python3 executable in PATH")

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

    notifications_enabled = ctx is not None

    async def emit_output(text: str, stream_name: str) -> None:
        nonlocal notifications_enabled
        if ctx is None:
            destination = sys.stdout if stream_name == "stdout" else sys.stderr
            try:
                print(text, end="", file=destination, flush=True)
            except (BrokenPipeError, UnicodeEncodeError):
                notifications_enabled = False
        elif notifications_enabled:
            try:
                await ctx.info(text, logger_name=f"mach.{stream_name}")
            except Exception:
                notifications_enabled = False

    assert process.stdout is not None
    assert process.stderr is not None
    try:
        stdout_output, stderr_output = await stream_process_output(
            process.stdout,
            process.stderr,
            emit_output,
        )
    except BaseException:
        if process.returncode is None:
            with suppress(ProcessLookupError):
                process.terminate()
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=PROCESS_TERMINATION_TIMEOUT,
                )
            except TimeoutError:
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=PROCESS_TERMINATION_TIMEOUT,
                    )
        raise

    await process.wait()
    # wait() has returned, so the process has exited.
    assert process.returncode is not None
    logs = write_logs(stdout_output, stderr_output)
    if process.returncode == 0:
        return BuildResult(
            success=True,
            build_dir=build_dir,
            exit_code=process.returncode,
            logs=logs,
        )

    return BuildResult(
        success=False,
        exit_code=process.returncode,
        logs=logs,
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

    try:
        result = asyncio.run(build_firefox(args.firefox_dir, mozconfig_path))
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)

    print(f"Success: {result.success}")
    print(f"Exit code: {result.exit_code}")
    if result.build_dir:
        print(f"Build dir: {result.build_dir}")
    if result.logs.stdout:
        # The build already streamed to this terminal, so these files are a
        # duplicate; name the directory so it can be removed rather than
        # accumulating one full build log per invocation.
        print(f"Logs: {Path(result.logs.stdout[0]).parent}")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":  # pragma: no cover
    main()
