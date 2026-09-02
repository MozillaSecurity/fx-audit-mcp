"""Shared helpers for writing subprocess output to disk and scanning it."""

import tempfile
from pathlib import Path
from shutil import rmtree

from .models import LogPaths

LOG_DIR_PREFIX = "fx_audit_logs_"


def write_logs(stdout: bytes, stderr: bytes) -> LogPaths:
    """Write captured output from a run whose crashes are not classified.

    Both streams are always written, so every run yields a path whose parent
    the caller can remove. The bytes are written verbatim rather than decoded,
    keeping the files byte-exact with what the process emitted.

    Args:
        stdout: Captured stdout.
        stderr: Captured stderr.

    Returns:
        LogPaths naming the files written.
    """
    log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))
    stdout_path = log_dir / "log_stdout.txt"
    stderr_path = log_dir / "log_stderr.txt"
    try:
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
    except OSError:
        rmtree(log_dir, ignore_errors=True)
        raise

    return LogPaths(stdout=[str(stdout_path)], stderr=[str(stderr_path)])


def log_contains(path: Path, *markers: str) -> bool:
    """Report whether a log file holds any of the given markers.

    The file is streamed a line at a time rather than read whole, since logs
    are untruncated and can be arbitrarily large. Scanning at line granularity
    loses nothing: a marker is emitted on a single line, so none can straddle a
    line boundary.

    Args:
        path: Log file to scan.
        markers: Substrings to look for.

    Returns:
        True if any marker appears on any line.
    """
    with path.open(encoding="utf-8", errors="replace") as log_file:
        return any(marker in line for line in log_file for marker in markers)
