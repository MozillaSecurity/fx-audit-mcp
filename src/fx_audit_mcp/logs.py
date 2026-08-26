"""Shared helpers for persisting captured subprocess output to disk."""

import tempfile
from collections.abc import Sequence
from pathlib import Path
from shutil import rmtree
from typing import Literal

from .models import CrashLogPaths, LogPaths

StreamName = Literal["stdout", "stderr"]

LOG_DIR_PREFIX = "fx_audit_logs_"


def _write_log_dir(stdout: bytes, stderr: bytes) -> dict[StreamName, str]:
    """Write both streams to a fresh log directory.

    Both are always written, so every run yields a path whose parent the caller
    can remove. The bytes are written verbatim rather than decoded, keeping the
    files byte-exact with what the process emitted. On success the directory is
    never removed and the caller owns it; a write that fails removes it, since
    raising hands back no path to clean up with.

    Args:
        stdout: Captured stdout.
        stderr: Captured stderr.

    Returns:
        Mapping of stream name to the absolute path written.
    """
    log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))
    written: dict[StreamName, str] = {}
    streams: tuple[tuple[StreamName, bytes], ...] = (
        ("stdout", stdout),
        ("stderr", stderr),
    )
    try:
        for name, content in streams:
            path = log_dir / f"log_{name}.txt"
            path.write_bytes(content)
            written[name] = str(path)
    except OSError:
        rmtree(log_dir, ignore_errors=True)
        raise

    return written


def write_logs(stdout: bytes, stderr: bytes) -> LogPaths:
    """Write captured output from a run whose crashes are not classified.

    Args:
        stdout: Captured stdout.
        stderr: Captured stderr.

    Returns:
        LogPaths naming the files written.
    """
    written = _write_log_dir(stdout, stderr)
    return LogPaths(stdout=[written["stdout"]], stderr=[written["stderr"]])


def write_crash_logs(
    stdout: bytes,
    stderr: bytes,
    crashdata: Sequence[StreamName] = (),
) -> CrashLogPaths:
    """Write captured output from a run whose crashes are classified.

    Args:
        stdout: Captured stdout.
        stderr: Captured stderr.
        crashdata: Names of the streams carrying crash diagnostics, each
            "stdout" or "stderr". Those files are listed under crashdata as
            well as under their own category, so a report is never written to
            disk twice.

    Returns:
        CrashLogPaths naming the files written.
    """
    written = _write_log_dir(stdout, stderr)
    return CrashLogPaths(
        stdout=[written["stdout"]],
        stderr=[written["stderr"]],
        crashdata=[written[name] for name in crashdata],
    )
