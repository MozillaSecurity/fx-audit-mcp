"""Tests for the tool return models."""

from fx_audit_mcp.models import (
    BrowserCrashInfo,
    BuildResult,
    JSShellCrashInfo,
    NSSGtestCrashInfo,
)


def test_build_schema_omits_crash_diagnostics() -> None:
    """Verify that a build never advertises a crashdata field it cannot populate."""
    schema = BuildResult.model_json_schema()

    assert "crashdata" not in schema["$defs"]["LogPaths"]["properties"]


def test_evaluator_schemas_carry_crash_diagnostics() -> None:
    """Verify that every evaluator advertises crashdata to the agent."""
    for model in (BrowserCrashInfo, JSShellCrashInfo, NSSGtestCrashInfo):
        properties = model.model_json_schema()["$defs"]["CrashLogPaths"]["properties"]
        assert "crashdata" in properties, model.__name__
