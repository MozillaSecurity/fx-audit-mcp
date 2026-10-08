"""FastMCP server exposing all fx-audit-mcp execution tools.

Serves browser_evaluator, android_browser_evaluator (Linux only),
package_testcase, js_shell_evaluator, js_shell_differential_evaluator,
build_firefox, build_nss, and nss_gtest_evaluator over stdio.

Configuration is via environment variables:
  FIREFOX_SOURCE_ROOT    — default Firefox source directory for build tools
  FIREFOX_BINARY         — path to Firefox binary; used to derive build_dir
  FIREFOX_PREF_BLOCKLIST — path to a file listing pref names (one per line) that
                           must not reach the browser; browser_evaluator raises
                           if any appears in the generated prefs.js
  FX_AUDIT_ENABLE_DIFFERENTIAL — when set to a non-empty value, register
                           js_shell_differential_evaluator; off by default,
                           so differential testing is opt-in per server
  ANDROID_SERIAL         — device for android_browser_evaluator to use instead
                           of the emulator it otherwise boots and manages
  ANDROID_HOME / ANDROID_SDK_ROOT — Android SDK location (default ~/Android/Sdk);
                           the emulator and system image are installed there
"""

from __future__ import annotations

import os
import sys
from logging import ERROR, getLogger
from typing import TYPE_CHECKING

from fastmcp import FastMCP

from .browser_evaluator import (
    android_browser_evaluator,
    browser_evaluator,
    package_testcase,
)
from .build_firefox import build_firefox
from .build_nss import build_nss
from .js_shell_differential_evaluator import js_shell_differential_evaluator
from .js_shell_evaluator import js_shell_evaluator
from .nss_gtest_evaluator import nss_gtest_evaluator

if TYPE_CHECKING:
    from collections.abc import Callable

# Environment variable gating js_shell_differential_evaluator registration.
DIFFERENTIAL_ENV = "FX_AUDIT_ENABLE_DIFFERENTIAL"

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)


def create_server() -> FastMCP:
    """Build the fx-audit server, registering tools per the environment.

    The differential evaluator is only registered when DIFFERENTIAL_ENV is set
    to a non-empty value, so a caller that has not opted into differential
    testing never shows the tool to its agent. The Android evaluator is only
    registered on Linux, the one host grizzly's Android target supports.
    """
    server = FastMCP("fx-audit")
    tools: list[Callable[..., object]] = [
        browser_evaluator,
        package_testcase,
        js_shell_evaluator,
        build_firefox,
        build_nss,
        nss_gtest_evaluator,
    ]
    if sys.platform == "linux":
        tools.insert(1, android_browser_evaluator)
    if os.environ.get(DIFFERENTIAL_ENV):
        tools.insert(-4, js_shell_differential_evaluator)
    for fn in tools:
        server.tool(fn)
    return server


mcp = create_server()


def main() -> None:
    """Run the fx-audit MCP server over stdio."""
    try:
        mcp.run(transport="stdio", show_banner=False)
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:
        print(f"Error running MCP server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":  # pragma: no cover
    main()
