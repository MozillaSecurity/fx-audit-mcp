from pathlib import Path

import pytest


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def js_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "js"
    binary.touch()
    return binary


@pytest.fixture
def firefox_dir(tmp_path: Path) -> Path:
    return tmp_path / "firefox"
