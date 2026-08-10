"""Pydantic return models for fx-audit-mcp MCP tools."""

from pydantic import BaseModel, ConfigDict, Field


class ToolModel(BaseModel):
    """Base Tool Model.

    Disables model "extras" to ensure the resulting JSON schema has
    "additionalProperties": False.
    """

    model_config = ConfigDict(extra="forbid")


class Logs(ToolModel):
    """Captured process logs from a tool invocation."""

    stderr: str = Field(
        description="Process stderr captured during the run.",
    )
    stdout: str = Field(
        description="Process stdout captured during the run.",
    )
    crashdata: str = Field(
        default="",
        description="ASAN/UBSAN sanitizer output.",
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
    logs: Logs | None = Field(
        default=None,
        description="stderr/stdout/crashdata captured from Firefox.",
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
    logs: Logs | None = Field(
        default=None,
        description="stderr/stdout/crashdata captured from the JS shell.",
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
    logs: Logs | None = Field(
        default=None,
        description="stderr/stdout captured from the gtest run.",
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
