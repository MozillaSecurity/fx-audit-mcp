"""Pydantic return models for fx-audit-mcp MCP tools."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

# Which JS engine a shell binary is, deciding whether --fuzzing-safe
# applies to it.
Engine = Literal["spidermonkey", "v8"]


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
    """True if the testcase triggered a crash."""

    timed_out: bool
    """True if the testcase timed out: a browser process was still busy when
    the time limit expired."""

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
    """True if the testcase triggered a crash."""

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


class ShellRun(ToolModel):
    """One shell's side of a differential run."""

    path: str
    """Path to the shell binary that was run."""

    engine: Engine
    """Engine this shell was treated as."""

    argv: list[str]
    """The exact command line the shell was invoked with."""

    fuzzing_safe: bool
    """True if ``--fuzzing-safe`` was added, which happens for SpiderMonkey
    shells and never for V8."""

    exit_code: int
    """The shell's exit status. On POSIX, negative means killed by that
    signal; a timed-out shell reports the signal that killed it."""

    timed_out: bool
    """True if the shell was killed for exceeding the timeout."""

    succeeded: bool
    """True if the shell exited 0 without timing out."""

    logs: LogPaths
    """Paths to this shell's stdout/stderr log files."""


class JSShellDifferentialInfo(ToolModel):
    """Result of running one testcase in two JS shells and comparing them."""

    differs: bool
    """True if exactly one shell succeeded (exit 0) while the other failed
    (non-zero exit, crash, or timeout). Both succeeding or both failing is
    not a discrepancy."""

    shell_a: ShellRun
    """How the first shell ran."""

    shell_b: ShellRun
    """How the second shell ran."""


class NSSGtestCrashInfo(ToolModel):
    """Result of running an NSS gtest via nss_gtest_evaluator."""

    crashed: bool
    """True if the testcase triggered a crash."""

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
