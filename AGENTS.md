# fx-audit-mcp

Firefox security audit MCP tools. Provides async Python functions and a FastMCP
server for running testcases in Firefox and SpiderMonkey, building Firefox/NSS
with ASAN.

## Project Structure

```
src/fx_audit_mcp/          # Main package
  __init__.py                  # Public API re-exports
  models.py                    # Pydantic return types (BrowserCrashInfo, BuildResult, ...)
  browser_evaluator.py         # Run testcase in ASAN Firefox via grizzly
  js_shell_evaluator.py        # Run testcase in SpiderMonkey JS shell
  nss_gtest_evaluator.py       # Run NSS GTest under ASAN
  build_firefox.py             # Build Firefox with mach build
  build_nss.py                 # Build NSS with ASAN
  ignored_signatures/          # FuzzManager crash signatures to suppress
    shutdown_hang_abort.json
tests/                         # Unit tests (mirrors src layout by tool file)
  conftest.py
  test_browser_evaluator.py
  test_build_firefox.py
  test_build_nss.py
  test_js_shell_evaluator.py
  test_nss_gtest_evaluator.py
```

## Key Design Patterns

- All tools are **async functions** with plain Python type hints. Parameter
  documentation lives in the function's Google-style `Args:` docstring (used by
  FastMCP/pydantic-ai for tool descriptions). Do **not** use
  `Annotated[T, Field(...)]` on tool parameters.
- All tools return **Pydantic BaseModel** instances defined in `models.py`.
  Exceptions are allowed to bubble (FastMCP surfaces them as `isError=True`):
  tools raise `FileNotFoundError` for missing binaries, etc.
  Do not wrap tool bodies in catch-all `try/except Exception` blocks.
- Crash detection via sanitizer output is always on stderr; logs are
  tail-truncated to `MAX_LOG_SIZE` (1 MiB) to avoid overwhelming LLM context.
- `browser_evaluator` loads `ignored_signatures/*.json` (FuzzManager format) at
  call time to suppress common noise crashes (e.g. shutdown hangs).
- The execution tools (browser/JS shell/NSS gtest/Firefox/NSS build) are also
  exported from `fx_audit_mcp` for direct use (e.g. as pydantic-ai tools).
- Don't introduce thin private wrappers around a public function (or vice
  versa) when one call site does all the work — inline.

## Entry Points

- `fx-audit-mcp` → `fx_audit_mcp.mcp_server:main` (main MCP server: browser/JS shell/NSS/build tools)
- `fx-audit-build-firefox` → `fx_audit_mcp.build_firefox:main` (CLI for building Firefox)

## Development

### Setup

```bash
uv sync --group dev
uv run pre-commit install
```

### After Making Changes

```bash
uv run pytest
uv run pre-commit run --all-files
```

### Tooling

- Python 3.12+, managed with `uv`
- Linting + formatting: `ruff` (run via pre-commit)
- Type checking: `mypy --strict` (run via pre-commit)
- Tests: `uv run pytest`
- Versioning: python-semantic-release, conventional commits

### Git / Commits

- Commit messages must follow conventional commit format.
- Never add Co-Authored-By trailers to commits.

### Code Style

#### Formatting

- Don't use dashed-line separator comments (e.g. `# --------`) between sections.

#### Imports

- Function-level imports are only acceptable when absolutely necessary; prefer
  module-level imports.
- Avoid `# noqa` bypasses; fix the underlying issue instead.

#### State

- Avoid mutable module-level globals paired with `global`. Use
  `@functools.cache` / `@functools.lru_cache` on loaders; clear via
  `loader.cache_clear()` in tests.

#### File Layout

Files must follow this top-to-bottom order:

1. Imports (isort sub-order: stdlib → third-party → local)
2. `__all__` (if present)
3. Type aliases, TypeVar, Protocol
4. Constants (`ALL_CAPS` module-level)
5. Exceptions (custom exception classes)
6. Classes (dataclasses first, then general)
7. Private functions (`_foo`)
8. Public functions

### Testing

#### Structure

- Tests live in `tests/`, named `test_<module_stem>.py`.
- Use `conftest.py` for shared fixtures (`anyio_backend`, `js_binary`,
  `firefox_dir`).
- Multi-line test data (ASAN reports, source snippets) go in a `fixtures/`
  subdirectory as flat files, not inline strings.

#### Style

- Test docstrings: short, describe the behaviour under test.
- Use `pytest-mock` where possible.
- When using `mocker`, import `MagicMock` / `AsyncMock` from `unittest.mock`
  for type annotations — don't downgrade to `Any`.
- Use `@pytest.mark.parametrize` to share assertions across multiple inputs.

#### Coverage

- Each test covers a distinct scenario; don't duplicate existing test logic.
- Don't write tautological tests (no round-trip assertions, no library
  behaviour checks).
- Adding a new tool function requires corresponding tests.

### Adding a New Ignored Signature

Drop a JSON file in `src/fx_audit_mcp/ignored_signatures/`. It must follow
the FuzzManager `CrashSignature` schema (see `shutdown_hang_abort.json` for an
example). Signatures are loaded at call time by `browser_evaluator`, so no code
changes are required.
