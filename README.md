# fx-audit-mcp

MCP tools for Firefox security auditing. Provides async Python tools and a
FastMCP server for running testcases in Firefox and SpiderMonkey, building
Firefox and NSS with ASAN, and querying Bugzilla — all with structured
Pydantic return types suitable for use with LLM agent frameworks.

## Tools

| Tool | Description |
|------|-------------|
| `browser_evaluator` | Run a multi-file testcase in ASAN Firefox via grizzly replay, detect crashes |
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
        # Maps the name each file takes in the testcase to its path on disk,
        # so testcases may span several files and include binary assets.
        # Use forward slashes for subdirectories ("sub/frame.html").
        file_paths={
            "test.html": Path("/repro/test.html"),
            "boom.js": Path("/repro/boom.js"),
            "font.woff2": Path("/repro/font.woff2"),
        },
        entry_point="test.html",
        firefox_binary=Path("/path/to/obj-firefox-asan/dist/bin/firefox"),
        timeout=30,
    )
    print(result.crashed, result.message)
    # Complete, untruncated logs are on disk; result.logs holds their paths,
    # grouped into stderr/stdout/crashdata.
    # The ASAN report is in crashdata (log_ffp_asan_<pid>.txt), not stderr.
    for log in result.logs.crashdata:
        print(Path(log).read_text()[:500])
    # Logs live in a fresh temp directory that is never deleted; cleaning it
    # up is up to you: shutil.rmtree(Path(result.logs.stderr[0]).parent)

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

Every evaluator writes complete logs to a fresh temp directory each run and
returns their paths in `logs` (grouped into `stderr`/`stdout`/`crashdata`)
instead of the contents, so they can be grepped rather than truncated to fit.
The directory is never deleted and logs are unbounded, so callers should clean
up — take the parent of any returned path. The returned paths are only
meaningful to a client sharing a filesystem with the server.

- **browser_evaluator**: Crash signatures in `ignored_signatures/` (FuzzManager
  format) are filtered out before returning, so common shutdown hangs don't
  pollute results. The ASAN report is in `crashdata`
  (`log_ffp_asan_<pid>.txt`), not `stderr`.
- **js_shell_evaluator**: Detects crashes via negative exit code (signal) or
  `AddressSanitizer`/`UndefinedBehaviorSanitizer` in stderr. JS errors (positive
  exit codes) are not treated as crashes. The report arrives on stderr, so
  `crashdata` names that same stderr file; a signal-only crash leaves
  `crashdata` empty.
- **nss_gtest_evaluator**: Detects `AddressSanitizer` in stdout or stderr, and
  `crashdata` names whichever of those files carried the report.

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
