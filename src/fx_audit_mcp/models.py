"""Pydantic return models for fx-audit-mcp MCP tools."""

from pydantic import BaseModel, ConfigDict, Field


class ToolModel(BaseModel):
    """Base Tool Model.

    Disables model "extras" to ensure the resulting JSON schema has
    "additionalProperties": False.
    """

    model_config = ConfigDict(extra="forbid", use_attribute_docstrings=True)


class Logs(ToolModel):
    """Captured process logs from a tool invocation."""

    stderr: str
    """Process stderr captured during the run."""

    stdout: str
    """Process stdout captured during the run."""

    crashdata: str = ""
    """ASAN/UBSAN sanitizer output."""


class LogPaths(ToolModel):
    """Paths to log files a tool invocation wrote to disk."""

    stderr: list[str] = Field(default_factory=list)
    """File paths, NOT log contents - read or grep these files to see the
    output. Absolute paths to the run's complete, untruncated stderr logs
    (Gecko/MOZ_LOG output, including the '++PROCESS [pid = N] ... [type = T]'
    child-process launch records). Files can be very large, so prefer
    grep/head/tail over reading a whole file. Consecutive duplicate lines may
    be collapsed into a '[Previous line repeated N times]' marker. The
    containing directory is not deleted by this tool."""

    stdout: list[str] = Field(default_factory=list)
    """File paths, NOT log contents - read or grep these files to see the
    output. Absolute paths to the run's complete, untruncated stdout logs. The
    containing directory is not deleted by this tool."""

    crashdata: list[str] = Field(default_factory=list)
    """File paths, NOT log contents - read or grep these files to see the
    output. Absolute paths to the run's sanitizer and crash logs: the
    ASAN/UBSAN report lives here, not in stderr. One log_ffp_asan_<pid>.txt
    per process that produced sanitizer output, where the trailing number is
    that process's PID, plus log_minidump_<n>.txt and log_ffp_worker_<name>.txt
    when present. The containing directory is not deleted by this tool."""


class BrowserCrashInfo(ToolModel):
    """Result of running a testcase under Firefox via browser_evaluator."""

    crashed: bool
    """True if Firefox crashed while running the testcase."""

    message: str
    """Summary of the Firefox run outcome."""

    logs: LogPaths
    """Paths to this run's complete, untruncated Firefox logs on disk,
    categorized into stderr/stdout/crashdata. The log contents are NOT in this
    response - read or grep the listed files."""

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

    files: dict[str, str] | None = None
    """Testcase files that reproduce the crash
    (relative filename -> file content)."""


class JSShellCrashInfo(ToolModel):
    """Result of running a testcase under the SpiderMonkey JS shell."""

    crashed: bool
    """True if the JS shell crashed while running the testcase."""

    message: str
    """Summary of the JS shell run outcome."""

    files: dict[str, str] | None = None
    """Testcase files captured on crash (relative filename -> file content)."""

    logs: Logs | None = None
    """stderr/stdout/crashdata captured from the JS shell."""


class NSSGtestCrashInfo(ToolModel):
    """Result of running an NSS gtest under AddressSanitizer."""

    crashed: bool
    """True if AddressSanitizer detected a crash."""

    message: str
    """Summary of the gtest run outcome."""

    logs: Logs | None = None
    """stderr/stdout captured from the gtest run."""


class BuildResult(ToolModel):
    """Result of a Firefox or NSS build invocation."""

    success: bool
    """True if the build completed successfully."""

    message: str
    """Summary of the build outcome."""

    build_dir: str | None = None
    """Absolute path to the build output directory on success."""

    stdout: str | None = None
    """Captured build stdout (may be truncated for large builds)."""

    stderr: str | None = None
    """Captured build stderr (may be truncated for large builds)."""
