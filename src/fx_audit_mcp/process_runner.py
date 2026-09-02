"""Shared helper for running a subprocess with its output captured to disk."""

import asyncio
import os
import signal
import sys
import tempfile
from asyncio.subprocess import Process
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from shutil import rmtree

from .logs import LOG_DIR_PREFIX
from .models import CrashLogPaths

# Boolean indicating if process groups are supported.
_SUPPORTS_PG = sys.platform != "win32"

# Seconds to wait for a killed process to be reaped before abandoning it.
_REAP_TIMEOUT = 5.0


@dataclass(frozen=True)
class RunResult:
    """A finished subprocess run whose output was captured to log files."""

    exit_code: int
    """Exit status. On POSIX, negative means killed by that signal."""

    timed_out: bool
    """True if the process did not exit before the timeout and was killed."""

    stdout: Path
    """Path of the log file holding the run's stdout."""

    stderr: Path
    """Path of the log file holding the run's stderr."""

    def crash_logs(self, crashdata: Sequence[Path] = ()) -> CrashLogPaths:
        """Name this run's log files, tagging those that carry a crash report.

        Args:
            crashdata: Log files carrying crash diagnostics. Each is listed
                under crashdata as well as under its own stream, so a report is
                never written to disk twice.

        Returns:
            CrashLogPaths naming every log file this run wrote.
        """
        return CrashLogPaths(
            stdout=[str(self.stdout)],
            stderr=[str(self.stderr)],
            crashdata=[str(path) for path in crashdata],
        )


def _kill_tree(process: Process) -> None:
    """Kill a running process along with any children.

    Args:
        process: The process to kill. On POSIX it leads its own process group,
            so signaling the group reaches everything it spawned.
    """
    if process.returncode is not None:
        # Already exited and reaped, so the pid may name something else by now.
        return
    if not _SUPPORTS_PG:
        process.kill()
        return
    # The process can still exit between that check and the signal landing.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


async def _reap(process: Process) -> None:
    """Wait for a killed process, giving up rather than blocking forever.

    A process wedged in an uninterruptible syscall never reaps, and waiting on
    it would reintroduce the hang the timeout exists to bound.

    Args:
        process: The process that was signaled.
    """
    with suppress(TimeoutError):
        await asyncio.wait_for(process.wait(), timeout=_REAP_TIMEOUT)


async def run(
    *argv: str,
    timeout: int,
    cwd: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> RunResult:
    """Run a command to completion with its output written straight to disk.

    The process writes to the log files itself rather than through a pipe, so
    whatever it produced before exiting - or before being killed at the
    timeout - is already on disk when this returns. A timeout is not an error:
    the process is killed and the run is reported with timed_out set.

    Args:
        argv: The command and its arguments.
        timeout: Seconds to wait before killing the process.
        cwd: Working directory for the process, or None to inherit this one.
        extra_env: Environment variables to set on top of the inherited
            environment.

    Returns:
        RunResult describing how the process exited and where its output went.

    Raises:
        RuntimeError: The process was killed but never reaped.
    """
    log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))
    stdout_path = log_dir / "log_stdout.txt"
    stderr_path = log_dir / "log_stderr.txt"
    try:
        with (
            stdout_path.open("wb") as stdout_file,
            stderr_path.open("wb") as stderr_file,
        ):
            process = await asyncio.create_subprocess_exec(
                *argv,
                cwd=cwd,
                env={**os.environ, **(extra_env or {})},
                stdin=asyncio.subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                # A command can spawn children of its own; a fresh session
                # makes it a group leader so the timeout path can kill the
                # whole tree.
                start_new_session=_SUPPORTS_PG,
            )

            timed_out = False
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except TimeoutError:
                _kill_tree(process)
                await _reap(process)
                timed_out = True
            except BaseException:
                # Anything else leaving this scope - cancellation, above all -
                # would strand the process: start_new_session put it in its own
                # session, so no group-wide cleanup elsewhere can reach it.
                _kill_tree(process)
                with suppress(BaseException):
                    await _reap(process)
                raise

        if process.returncode is None:
            raise RuntimeError(
                f"{argv[0]} did not exit within {_REAP_TIMEOUT}s of being killed"
            )
    except BaseException:
        # Raising hands back no path to clean up with, so nothing may be
        # left behind.
        rmtree(log_dir, ignore_errors=True)
        raise
    return RunResult(
        exit_code=process.returncode,
        timed_out=timed_out,
        stdout=stdout_path,
        stderr=stderr_path,
    )
