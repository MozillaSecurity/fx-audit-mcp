# fx-audit-mcp

MCP tools for Firefox security auditing. Provides async Python tools and a
FastMCP server for running testcases in Firefox and SpiderMonkey, building
Firefox and NSS with ASAN, and querying Bugzilla — all with structured
Pydantic return types suitable for use with LLM agent frameworks.

## Tools

| Tool | Description |
|------|-------------|
| `browser_evaluator` | Run a multi-file testcase in ASAN Firefox via grizzly replay, detect crashes |
| `android_browser_evaluator` | Run a testcase in an ASAN GeckoView app (geckoview_example/Fenix) on a running Android emulator via grizzly + fxpoppet, symbolize the ASAN report on the host |
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
    print(result.crashed, result.timed_out)
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

### Firefox on Android

`android_browser_evaluator` runs the testcase in an ASAN-instrumented GeckoView
app (`geckoview_example` or Fenix, debuggable, with `wrap.sh`) on an Android
emulator, through grizzly's `FenixTarget` and fxpoppet. It needs the Android
SDK (`adb` and `aapt` on `PATH`), a booted emulator with KVM, and the APK.
Setting `FIREFOX_APK` registers the tool on the MCP server.

Several agents can share one machine by giving each its own emulator: every
instance boots the same AVD read-only on its own console port and the evaluator
locks the device it uses, so a second evaluator pointed at a busy device fails
fast instead of corrupting both runs.

```bash
# one emulator per agent; prints emulator-5554, emulator-5556, ...
fx-audit-android-emulator start --count 2
ANDROID_SERIAL=emulator-5554 FIREFOX_APK=/builds/geckoview_example.apk fx-audit-mcp
ANDROID_SERIAL=emulator-5556 FIREFOX_APK=/builds/geckoview_example.apk fx-audit-mcp
fx-audit-android-emulator stop
```

ASAN frames from the device only name a library and offset; the report in
`crashdata` (`log_asan.txt`) is symbolized on the host before it is returned.
Symbols come from the build's Breakpad archive (`target.crashreporter-symbols.zip`
unpacked to `symbols/` next to the APK, or `ANDROID_SYMBOLS_DIR`), matched to
each frame's BuildId, or from unstripped libraries (`ANDROID_UNSTRIPPED_LIB_DIR`,
e.g. a local objdir's `dist/bin`). The same logic is available standalone:

```bash
fx-audit-asan-symbolize --symbols /builds/symbols logcat.txt
```

## Environment Variables

| Variable | Used by | Description |
|----------|---------|-------------|
| `BUGZILLA_API_KEY` | `fx-audit-bugzilla-mcp` | Required; your Bugzilla API key |
| `BUGZILLA_URL` | `fx-audit-bugzilla-mcp` | Bugzilla REST base URL (default: Mozilla's) |
| `FIREFOX_SOURCE_ROOT` | `fx-audit-build-firefox` | Default `--firefox-dir` for the CLI entry point |
| `FIREFOX_APK` | `fx-audit-mcp` | GeckoView APK; registers `android_browser_evaluator` and is its default APK |
| `ANDROID_SERIAL` | `android_browser_evaluator` | adb serial of the emulator this server drives (one per agent) |
| `ANDROID_SYMBOLS_DIR` | `android_browser_evaluator` | Unpacked Breakpad symbols for the APK (default: `symbols/` beside it) |
| `ANDROID_UNSTRIPPED_LIB_DIR` | `android_browser_evaluator` | Unstripped libraries matching the APK, resolved with `llvm-symbolizer` |
| `ANDROID_SDK_ROOT` | `fx-audit-android-emulator` | Android SDK location (default: `~/.mozbuild/android-sdk-linux`) |
| `ANDROID_AVD_HOME` | `fx-audit-android-emulator` | AVD directory (default: mach bootstrap's `~/.mozbuild/android-device/avd`) |

## Crash Detection

Every tool writes complete logs to a fresh temp directory each run and
returns their paths in `logs` instead of the contents, so they can be grepped
rather than truncated to fit. The build tools return `stderr`/`stdout`; the
evaluators add `crashdata`.
The directory is never deleted and logs are unbounded, so callers should clean
up — take the parent of any returned path. The returned paths are only
meaningful to a client sharing a filesystem with the server.

- **browser_evaluator**: Crash signatures in `ignored_signatures/` (FuzzManager
  format) are filtered out before returning, so common shutdown hangs don't
  pollute results. The ASAN report is in `crashdata`
  (`log_ffp_asan_<pid>.txt`), not `stderr`.
- **js_shell_evaluator**: Detects crashes via negative exit code (signal) or
  `AddressSanitizer`/`UndefinedBehaviorSanitizer` in stderr. JS errors (positive
  exit codes) are not treated as crashes. Crash diagnostics arrive on stderr,
  so on a crash `crashdata` names that same stderr file.
- **nss_gtest_evaluator**: Detects `AddressSanitizer` in stdout or stderr, and
  `crashdata` names whichever of those files carried the report.

A run that hits its time limit does not raise: the evaluators return
`timed_out: true` with the logs, which show how far the run got before the
hang. For the browser this means a process was still busy executing when the
window expired (it is aborted to capture stacks); an idle browser at the time
limit is a normal clean run, since testcases are not expected to close the
browser. A timed-out browser is never reported as a crash, since the report
that abort produces is a hang.

The JS shell and NSS gtest evaluators do report a crash on a timed-out run,
when the log holds a sanitizer report the process finished writing — UBSAN does
not halt on error, so a testcase can trip it and then hang. Since a kill can
cut a report off mid-stack, a timeout is judged on the report's closing
`SUMMARY:` line rather than any mention of the sanitizer, and the exit code is
ignored because it is the kill signal rather than a fault.

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
