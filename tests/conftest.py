import tempfile
from collections.abc import Callable
from pathlib import Path

import pytest

from fx_audit_mcp.logs import LOG_DIR_PREFIX
from fx_audit_mcp.process_runner import RunResult

MakeRunResult = Callable[..., RunResult]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def make_run_result() -> MakeRunResult:
    """Build a RunResult backed by real log files, as process_runner.run would."""

    def _make(
        *,
        exit_code: int = 0,
        timed_out: bool = False,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> RunResult:
        log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))
        stdout_path = log_dir / "log_stdout.txt"
        stderr_path = log_dir / "log_stderr.txt"
        stdout_path.write_bytes(stdout)
        stderr_path.write_bytes(stderr)
        return RunResult(
            exit_code=exit_code,
            timed_out=timed_out,
            stdout=stdout_path,
            stderr=stderr_path,
        )

    return _make


@pytest.fixture(autouse=True)
def contained_tempdir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the tools' never-deleted log directories inside the test's tmp_path."""
    temp_root = tmp_path / "fx_tmp"
    temp_root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp_root))


@pytest.fixture
def js_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "js"
    binary.touch()
    return binary


@pytest.fixture
def firefox_dir(tmp_path: Path) -> Path:
    return tmp_path / "firefox"
