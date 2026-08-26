"""Pydantic return models for fx-audit-mcp MCP tools."""

from pydantic import BaseModel, ConfigDict, Field


class ToolModel(BaseModel):
    """Base Tool Model.

    Disables model "extras" to ensure the resulting JSON schema has
    "additionalProperties": False.
    """

    model_config = ConfigDict(extra="forbid")


class LogPaths(ToolModel):
    """Paths to log files a tool invocation wrote to disk."""

    stderr: list[str] = Field(
        default_factory=list,
        description=(
            "File paths, NOT log contents - read or grep these files to see "
            "the output. Absolute paths to the run's complete, untruncated "
            "stderr logs. Files can be very large, so prefer grep/head/tail "
            "over reading a whole file. The containing directory is not "
            "deleted by this tool."
        ),
        examples=[["/tmp/fx_audit_logs_ab12cd34/log_stderr.txt"]],
    )
    stdout: list[str] = Field(
        default_factory=list,
        description=(
            "File paths, NOT log contents - read or grep these files to see "
            "the output. Absolute paths to the run's complete, untruncated "
            "stdout logs. The containing directory is not deleted by this "
            "tool."
        ),
        examples=[["/tmp/fx_audit_logs_ab12cd34/log_stdout.txt"]],
    )
    crashdata: list[str] = Field(
        default_factory=list,
        description=(
            "File paths, NOT log contents - read or grep these files to see "
            "the output. Absolute paths to the run's crash diagnostics: an "
            "ASAN/UBSAN report, or a bare assertion/abort message when the "
            "process died without one. A path also listed under stderr or "
            "stdout means the diagnostics were written to that stream. The "
            "containing directory is not deleted by this tool."
        ),
        examples=[["/tmp/fx_audit_logs_ab12cd34/log_ffp_asan_1234.txt"]],
    )


class BrowserCrashInfo(ToolModel):
    """Result of running a testcase under Firefox via browser_evaluator."""

    crashed: bool = Field(
        description="True if Firefox crashed while running the testcase.",
        examples=[True, False],
    )
    message: str = Field(
        description="Summary of the Firefox run outcome.",
        examples=["Crash detected", "No crash detected - check logs for clues"],
    )
    logs: LogPaths = Field(
        description=(
            "Paths to this run's complete, untruncated Firefox logs on disk, "
            "categorized into stderr/stdout/crashdata. The log contents are "
            "NOT in this response - read or grep the listed files. stderr "
            "holds the Gecko/MOZ_LOG output, including the "
            "'++PROCESS [pid = N] ... [type = T]' child-process launch "
            "records, and consecutive duplicate lines may be collapsed into a "
            "'[Previous line repeated N times]' marker. crashdata holds one "
            "log_ffp_asan_<pid>.txt per process that produced sanitizer "
            "output, where the trailing number is that process's PID, plus "
            "log_minidump_<n>.txt and log_ffp_worker_<name>.txt when present; "
            "the ASAN report is there, not in stderr."
        ),
    )
    crashed_parent: bool | None = Field(
        default=None,
        description="True if the crash occurred in the parent process.",
        examples=[True, False],
    )
    crashed_content: bool | None = Field(
        default=None,
        description="True if the crash occurred in a content ('tab') process.",
        examples=[True, False],
    )
    crashed_gpu: bool | None = Field(
        default=None,
        description="True if the crash occurred in the GPU process.",
        examples=[True, False],
    )
    crashed_rdd: bool | None = Field(
        default=None,
        description="True if the crash occurred in the RDD (media decode) process.",
        examples=[True, False],
    )
    crashed_gmp: bool | None = Field(
        default=None,
        description="True if the crash occurred in a GMP (Gecko Media Plugin) process.",
        examples=[True, False],
    )
    crashed_socket: bool | None = Field(
        default=None,
        description="True if the crash occurred in the socket process.",
        examples=[True, False],
    )
    crashed_utility: bool | None = Field(
        default=None,
        description="True if the crash occurred in a utility process.",
        examples=[True, False],
    )
    files: dict[str, str] | None = Field(
        default=None,
        description=(
            "Testcase files that reproduce the crash "
            "(relative filename -> file content)."
        ),
        examples=[{"test.html": "<html>...</html>"}],
    )


class JSShellCrashInfo(ToolModel):
    """Result of running a testcase under the SpiderMonkey JS shell."""

    crashed: bool = Field(
        description="True if the JS shell crashed while running the testcase.",
        examples=[True, False],
    )
    message: str = Field(
        description="Summary of the JS shell run outcome.",
        examples=["Crash detected (signal SIGSEGV)", "No crash detected"],
    )
    files: dict[str, str] | None = Field(
        default=None,
        description=(
            "Testcase files captured on crash (relative filename -> file content)."
        ),
        examples=[{"testcase.js": "var x = 1;"}],
    )
    logs: LogPaths = Field(
        description=(
            "Paths to this run's complete, untruncated JS shell logs on disk, "
            "categorized into stderr/stdout/crashdata. The log contents are "
            "NOT in this response - read or grep the listed files. The shell "
            "writes its crash diagnostics to stderr, whether a sanitizer "
            "report or a bare assertion message, so on a crash crashdata "
            "lists that same stderr file."
        ),
    )


class NSSGtestCrashInfo(ToolModel):
    """Result of running an NSS gtest under AddressSanitizer."""

    crashed: bool = Field(
        description="True if AddressSanitizer detected a crash.",
        examples=[True, False],
    )
    message: str = Field(
        description="Summary of the gtest run outcome.",
        examples=["ASan crash detected", "No crash detected"],
    )
    logs: LogPaths = Field(
        description=(
            "Paths to this run's complete, untruncated all.sh logs on disk, "
            "categorized into stderr/stdout/crashdata. The log contents are "
            "NOT in this response - read or grep the listed files. The gtest "
            "harness can write its sanitizer report to either stream, so "
            "crashdata lists whichever of stdout/stderr carried it."
        ),
    )


class BuildResult(ToolModel):
    """Result of a Firefox or NSS build invocation."""

    success: bool = Field(
        description="True if the build completed successfully.",
        examples=[True, False],
    )
    message: str = Field(
        description="Summary of the build outcome.",
        examples=[
            "Firefox build completed successfully",
            "Firefox build failed with exit code 1",
        ],
    )
    build_dir: str | None = Field(
        default=None,
        description="Absolute path to the build output directory on success.",
        examples=["/path/to/firefox/obj-fuzz"],
    )
    stdout: str | None = Field(
        default=None,
        description="Captured build stdout (may be truncated for large builds).",
    )
    stderr: str | None = Field(
        default=None,
        description="Captured build stderr (may be truncated for large builds).",
    )
