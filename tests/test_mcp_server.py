"""Tests for mcp_server.py."""

import inspect

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.browser_evaluator import browser_evaluator
from fx_audit_mcp.mcp_server import main, mcp

EXPECTED_TOOLS = {
    "browser_evaluator",
    "package_testcase",
    "js_shell_evaluator",
    "build_firefox",
    "build_nss",
    "nss_gtest_evaluator",
}


@pytest.mark.anyio
async def test_all_tools_registered() -> None:
    """All execution tools are registered on the mcp instance."""
    registered = {t.name for t in await mcp.list_tools()}
    assert registered == EXPECTED_TOOLS


class TestBrowserEvaluatorSchema:
    @pytest.mark.anyio
    async def test_docstring_prose_preserved_in_mcp_schema(self) -> None:
        """Verify the browser_evaluator prose docstring appears in the MCP schema."""
        assert browser_evaluator.__doc__ is not None
        # cleandoc to normalize indentation: Python 3.13 strips common leading
        # whitespace from __doc__ at compile time (PEP 257), 3.12 does not.
        prose = (
            inspect.cleandoc(browser_evaluator.__doc__)
            .split("Args:", maxsplit=1)[0]
            .strip()
        )
        tool = await mcp.get_tool("browser_evaluator")
        assert tool is not None
        description: str = tool.to_mcp_tool().model_dump()["description"]
        assert prose == description


def test_keyboard_interrupt_exits_zero(mocker: MockerFixture) -> None:
    """KeyboardInterrupt causes main() to exit 0."""
    mocker.patch("fx_audit_mcp.mcp_server.mcp.run", side_effect=KeyboardInterrupt)
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0


def test_unexpected_exception_exits_nonzero(
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Unexpected exceptions cause main() to exit 1 with an error message."""
    mocker.patch("fx_audit_mcp.mcp_server.mcp.run", side_effect=RuntimeError("boom"))
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 1
    assert "boom" in capsys.readouterr().err
