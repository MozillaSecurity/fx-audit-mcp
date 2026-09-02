"""Tests for the tool return models."""

import pytest

from fx_audit_mcp.models import (
    BrowserCrashInfo,
    BuildResult,
    JSShellCrashInfo,
    NSSGtestCrashInfo,
    ToolModel,
)

TOOL_MODELS = (BrowserCrashInfo, JSShellCrashInfo, NSSGtestCrashInfo, BuildResult)


def test_build_schema_omits_crash_diagnostics() -> None:
    """Verify that a build never advertises a crashdata field it cannot populate."""
    schema = BuildResult.model_json_schema()

    assert "crashdata" not in schema["$defs"]["LogPaths"]["properties"]


def test_evaluator_schemas_carry_crash_diagnostics() -> None:
    """Verify that every evaluator advertises crashdata to the agent."""
    for model in (BrowserCrashInfo, JSShellCrashInfo, NSSGtestCrashInfo):
        properties = model.model_json_schema()["$defs"]["CrashLogPaths"]["properties"]
        assert "crashdata" in properties, model.__name__


@pytest.mark.parametrize("model", TOOL_MODELS, ids=lambda m: str(m.__name__))
def test_every_field_is_described_to_the_agent(model: type[ToolModel]) -> None:
    """Verify no field reaches the agent undocumented.

    Descriptions come from attribute docstrings, so a field written without one,
    or dropping use_attribute_docstrings from ToolModel, silently empties the
    tool schema instead of failing.
    """
    schema = model.model_json_schema()
    definitions = {model.__name__: schema, **schema.get("$defs", {})}
    undescribed = [
        f"{owner}.{name}"
        for owner, definition in definitions.items()
        for name, prop in definition.get("properties", {}).items()
        if not prop.get("description")
    ]

    assert not undescribed
