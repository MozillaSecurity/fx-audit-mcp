"""Shared helpers for persisting captured subprocess output to disk."""

import tempfile
from collections.abc import Sequence
from pathlib import Path
from shutil import rmtree

from .models import LogPaths

LOG_DIR_PREFIX = "fx_audit_logs_"


def write_subprocess_logs(
    stdout: bytes,
    stderr: bytes,
    crashdata: Sequence[str] = (),
) -> LogPaths:
    """Write captured subprocess output to a fresh log directory.

    Both streams are always written, so every run returns a path whose parent
    the caller can remove. The bytes are written verbatim rather than decoded,
    keeping the files byte-exact with what the process emitted. On success the
    directory is never removed and the caller owns it; a write that fails
    removes it, since raising hands back no path to clean up with.

    Args:
        stdout: Captured stdout.
        stderr: Captured stderr.
        crashdata: Names of the streams carrying crash diagnostics, each
            "stdout" or "stderr". Those files are listed under crashdata as
            well as under their own category, so a report is never written to
            disk twice.

    Returns:
        LogPaths naming the files written.
    """
    log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))
    written: dict[str, str] = {}
    try:
        for name, content in (("stdout", stdout), ("stderr", stderr)):
            path = log_dir / f"log_{name}.txt"
            path.write_bytes(content)
            written[name] = str(path)
    except OSError:
        # Raising hands back no paths, so leave nothing behind to strand.
        rmtree(log_dir, ignore_errors=True)
        raise

    return LogPaths(
        stdout=[written["stdout"]],
        stderr=[written["stderr"]],
        crashdata=[written[name] for name in crashdata],
    )
