"""FastMCP server exposing all fx-audit-mcp execution tools.

Serves browser_evaluator, package_testcase, js_shell_evaluator,
build_firefox, build_nss, and nss_gtest_evaluator over stdio.

Configuration is via environment variables:
  FIREFOX_SOURCE_ROOT    — default Firefox source directory for build tools
  FIREFOX_BINARY         — path to Firefox binary; used to derive build_dir
  FIREFOX_PREF_BLOCKLIST — path to a file listing pref names (one per line) that
                           must not reach the browser; browser_evaluator raises
                           if any appears in the generated prefs.js
"""

import sys
from logging import ERROR, getLogger

from fastmcp import FastMCP

from .browser_evaluator import browser_evaluator, package_testcase
from .build_firefox import build_firefox
from .build_nss import build_nss
from .js_shell_evaluator import js_shell_evaluator
from .nss_gtest_evaluator import nss_gtest_evaluator

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)

mcp = FastMCP("fx-audit")

for _fn in (
    browser_evaluator,
    package_testcase,
    js_shell_evaluator,
    build_firefox,
    build_nss,
    nss_gtest_evaluator,
):
    mcp.tool(_fn)


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
