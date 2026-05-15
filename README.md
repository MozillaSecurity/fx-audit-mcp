# fx-audit-mcp

MCP tools for Firefox security auditing. Provides async Python tools and a
FastMCP server for running testcases in Firefox and SpiderMonkey, building
Firefox and NSS with ASAN, and querying Bugzilla — all with structured
Pydantic return types suitable for use with LLM agent frameworks.

## Tools

| Tool | Description |
|------|-------------|
| `browser_evaluator` | Run a testcase in ASAN Firefox via grizzly replay, detect crashes |
| `package_testcase` | Bundle a testcase directory with prefs and env into a grizzly TestCase |
| `js_shell_evaluator` | Run a JS testcase in the SpiderMonkey shell, detect crashes and sanitizer output |
| `nss_gtest_evaluator` | Run an NSS GTest and report any ASan crash |
| `build_firefox` | Build Firefox via `mach build` with a specified MOZCONFIG |
| `build_nss` | Build NSS with ASAN via `security/nss/build.sh` |
| `search_bugs` | Search Bugzilla using raw REST query parameters |
| `get_bugs` | Fetch bugs by ID in bulk |
| `get_bug_comments` | Fetch all comments for a single bug |
| `get_bug_attachments` | Fetch attachments for a bug |

## Installation

```bash
pip install fx-audit-mcp
```

Requires Python 3.12+.

## Usage

### As Python functions

The execution tools (browser, JS shell, NSS gtest, Firefox/NSS build) are
async functions with structured Pydantic return types. The Bugzilla tools
are only available via the MCP server (see below).

```python
import asyncio
from pathlib import Path
from fx_audit_mcp import browser_evaluator, js_shell_evaluator

async def main():
    result = await browser_evaluator(
        content="<script>crashMe()</script>",
        filename="test.html",
        firefox_binary=Path("/path/to/obj-firefox-asan/dist/bin/firefox"),
        timeout=30,
    )
    print(result.crashed, result.message)
    if result.logs:
        print(result.logs.crashdata[:500])

asyncio.run(main())
```

### As an MCP server

`fx-audit-mcp` exposes all execution tools (browser, JS shell, NSS gtest,
Firefox/NSS build) as an MCP server over stdio:

```bash
fx-audit-mcp
```

`fx-audit-bugzilla-mcp` exposes the Bugzilla query tools separately:

```bash
BUGZILLA_API_KEY=your_key fx-audit-bugzilla-mcp
```

Set `BUGZILLA_URL` to override the default Mozilla Bugzilla instance.

**Claude Desktop / Claude Code `.mcp.json` example:**

```json
{
  "mcpServers": {
    "fx-audit": {
      "command": "fx-audit-mcp",
      "env": {
        "FIREFOX_SOURCE_ROOT": "/path/to/firefox",
        "FIREFOX_BINARY": "/path/to/firefox/obj-firefox-asan/dist/bin/firefox"
      }
    },
    "fx-audit-bugzilla": {
      "command": "fx-audit-bugzilla-mcp",
      "env": {
        "BUGZILLA_API_KEY": "your_key_here"
      }
    }
  }
}
```

### With pydantic-ai

Tools integrate directly with pydantic-ai agents:

```python
from pydantic_ai import Agent
from fx_audit_mcp import browser_evaluator, js_shell_evaluator

agent = Agent(
    "anthropic:claude-opus-4-7",
    tools=[browser_evaluator, js_shell_evaluator],
)
```

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `BUGZILLA_API_KEY` | `fx-audit-bugzilla-mcp` | Required; your Bugzilla API key |
| `BUGZILLA_URL` | `fx-audit-bugzilla-mcp` | Bugzilla REST base URL (default: Mozilla's) |
| `FIREFOX_SOURCE_ROOT` | `fx-audit-build-firefox` | Default `--firefox-dir` for the CLI entry point |

## Crash Detection

- **browser_evaluator**: Crash signatures in `ignored_signatures/` (FuzzManager
  format) are filtered out before returning, so common shutdown hangs don't
  pollute results.
- **js_shell_evaluator**: Detects crashes via negative exit code (signal) or
  `AddressSanitizer`/`UndefinedBehaviorSanitizer` in stderr. JS errors (positive
  exit codes) are not treated as crashes.
- **nss_gtest_evaluator**: Detects `AddressSanitizer` in stdout or stderr.

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest

# Lint and format
uv run ruff check --fix .
uv run ruff format .

# Type check
uv run mypy src/

# Install pre-commit hooks
uv run pre-commit install
```

## License

[Mozilla Public License 2.0](https://www.mozilla.org/en-US/MPL/2.0/)
