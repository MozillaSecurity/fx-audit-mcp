"""Pydantic return models for fx-audit-mcp MCP tools."""

from pydantic import BaseModel, ConfigDict


class ToolModel(BaseModel):
    """Base Tool Model.

    Disables model "extras" to ensure the resulting JSON schema has
    "additionalProperties": False, and documents fields with attribute
    docstrings rather than Field descriptions.
    """

    model_config = ConfigDict(extra="forbid", use_attribute_docstrings=True)


class LogPaths(ToolModel):
    """Log files a tool invocation wrote to disk.

    The containing directory is never deleted; the caller owns it.
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

    message: str
    """Summary of the Firefox run outcome."""

    logs: CrashLogPaths
    """This run's Firefox logs. stderr holds the Gecko/MOZ_LOG output, including
    the '++PROCESS [pid = N] ... [type = T]' child-process launch records, and
    may collapse consecutive duplicate lines into a '[Previous line repeated N
    times]' marker. crashdata holds one log_ffp_asan_<pid>.txt per process that
    produced sanitizer output, plus log_minidump_<n>.txt and
    log_ffp_worker_<name>.txt when present; the ASAN report is there, not in
    stderr."""

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

    exit_code: int
    """Exit status. On POSIX, negative means killed by that signal."""

    logs: CrashLogPaths
    """This run's JS shell logs. The shell writes its crash diagnostics to
    stderr, whether a sanitizer report or a bare assertion message, so on a
    crash crashdata names that same stderr file."""


class NSSGtestCrashInfo(ToolModel):
    """Result of running an NSS gtest under AddressSanitizer."""

    crashed: bool
    """True if AddressSanitizer detected a crash."""

    exit_code: int
    """Exit status. On POSIX, negative means killed by that signal."""

    logs: CrashLogPaths
    """This run's all.sh logs. The gtest harness can write its sanitizer report
    to either stream, so crashdata names whichever of stdout/stderr carried
    it."""


class BuildResult(ToolModel):
    """Result of a Firefox or NSS build invocation."""

    success: bool
    """True if the build completed successfully."""

    exit_code: int
    """Exit status. On POSIX, negative means killed by that signal."""

    logs: LogPaths
    """Paths to this build's logs."""

    build_dir: str | None = None
    """Absolute path to the build output directory on success."""
