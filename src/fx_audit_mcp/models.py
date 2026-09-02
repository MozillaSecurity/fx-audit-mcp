"""Pydantic return models for fx-audit-mcp MCP tools."""

from pydantic import BaseModel, ConfigDict


class ToolModel(BaseModel):
    """Base Tool Model.

    Disables model "extras" to ensure the resulting JSON schema has
    "additionalProperties": False.
    """

    model_config = ConfigDict(extra="forbid", use_attribute_docstrings=True)


class LogPaths(ToolModel):
    """Log files a tool invocation wrote to disk.

    Logs are written to a temporary directory. The caller is responsible for
    cleanup.
    """

    stderr: list[str]
    """Absolute paths to the run's stderr logs."""

    stdout: list[str]
    """Absolute paths to the run's stdout logs."""


class CrashLogPaths(LogPaths):
    """Log paths from a run that can crash, adding the crash diagnostics."""

    crashdata: list[str]
    """Absolute paths to the run's crash diagnostics: an ASAN/UBSAN report, or
    a bare assertion or abort message when the process died without one. A path
    also listed under stderr or stdout is that same file, not a copy."""


class BrowserCrashInfo(ToolModel):
    """Result of running a testcase under Firefox via browser_evaluator."""

    crashed: bool
    """True if Firefox crashed while running the testcase."""

    logs: CrashLogPaths
    """Paths to the run's stderr/stdout/crashdata log files. The ASAN report is
    in crashdata (log_ffp_asan_<pid>.txt), not stderr."""

    crashed_parent: bool | None = None
    """True if the crash occurred in the parent process."""

    crashed_content: bool | None = None
    """True if the crash occurred in a content ('tab') process."""

    crashed_gpu: bool | None = None
    """True if the crash occurred in the GPU process."""

    crashed_rdd: bool | None = None
    """True if the crash occurred in the RDD (media decode) process."""

    crashed_gmp: bool | None = None
    """True if the crash occurred in a GMP (Gecko Media Plugin) process."""

    crashed_socket: bool | None = None
    """True if the crash occurred in the socket process."""

    crashed_utility: bool | None = None
    """True if the crash occurred in a utility process."""


class JSShellCrashInfo(ToolModel):
    """Result of running a testcase under the SpiderMonkey JS shell."""

    crashed: bool
    """True if the JS shell crashed while running the testcase."""

    timed_out: bool
    """True if the testcase timed out."""

    exit_code: int
    """The shell's exit status. On POSIX, negative means killed by that
    signal. On Windows, a value in the NTSTATUS error range (0xC0000000 and
    up) is an unhandled exception."""

    logs: CrashLogPaths
    """Paths to the run's stdout/stderr/crashdata log files. Crash diagnostics
    arrive on stderr. If a crash produces a sanitizer report or assertion,
    crashdata mirrors stderr."""


class NSSGtestCrashInfo(ToolModel):
    """Result of running an NSS gtest under AddressSanitizer."""

    crashed: bool
    """True if AddressSanitizer detected a crash."""

    timed_out: bool
    """True if the testcase timed out."""

    exit_code: int
    """The harness's exit status. On POSIX, negative means killed by that
    signal."""

    logs: CrashLogPaths
    """Paths to the run's stdout/stderr/crashdata log files. crashdata names
    whichever of stdout/stderr carried the sanitizer report."""


class BuildResult(ToolModel):
    """Result of a Firefox or NSS build invocation."""

    success: bool
    """True if the build completed successfully."""

    exit_code: int
    """The build's exit status. On POSIX, negative means killed by that
    signal."""

    logs: LogPaths
    """Paths to the build's stdout/stderr log files."""

    build_dir: str | None = None
    """Absolute path to the build output directory on success."""
