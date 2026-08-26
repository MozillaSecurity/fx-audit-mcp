import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


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
