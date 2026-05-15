"""Tests for build_nss tool."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.build_nss import build_nss


def _layout(tmp_path: Path) -> Path:
    """Build a fake firefox tree with nsprpub and security/nss subdirectories."""
    firefox = tmp_path / "firefox"
    (firefox / "nsprpub").mkdir(parents=True)
    (firefox / "security" / "nss").mkdir(parents=True)
    return firefox


def _mock_proc(
    mocker: MockerFixture, returncode: int, stdout: bytes, stderr: bytes
) -> MagicMock:
    proc: MagicMock = mocker.AsyncMock()
    proc.returncode = returncode
    proc.communicate = AsyncMock(return_value=(stdout, stderr))
    mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
    return proc


@pytest.mark.anyio
async def test_successful_build(mocker: MockerFixture, tmp_path: Path) -> None:
    firefox = _layout(tmp_path)
    _mock_proc(mocker, 0, b"compiled\n", b"")

    result = await build_nss(firefox)

    assert result.success is True
    assert result.message == "NSS build completed successfully"
    assert result.build_dir == str(
        firefox / "security" / "nss" / ".." / "dist" / "Debug"
    )
    assert result.stdout == "compiled\n"


@pytest.mark.anyio
async def test_failed_build_surfaces_exit_code(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    firefox = _layout(tmp_path)
    _mock_proc(mocker, 2, b"", b"link error\n")

    result = await build_nss(firefox)

    assert result.success is False
    assert "exit code 2" in result.message
    assert result.stderr == "link error\n"


@pytest.mark.anyio
async def test_missing_firefox_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    result = await build_nss(tmp_path / "no_firefox")
    assert result.success is False
    assert "Firefox directory not found" in result.message
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_missing_nspr_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    firefox = tmp_path / "firefox"
    (firefox / "security" / "nss").mkdir(parents=True)
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    result = await build_nss(firefox)
    assert result.success is False
    assert "NSPR directory not found" in result.message
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_missing_nss_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    firefox = tmp_path / "firefox"
    (firefox / "nsprpub").mkdir(parents=True)
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    result = await build_nss(firefox)
    assert result.success is False
    assert "NSS directory not found" in result.message
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_creates_nspr_symlink_for_nss_build(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    firefox = _layout(tmp_path)
    nspr_dir = firefox / "nsprpub"
    nss_symlink = firefox / "security" / "nspr"
    _mock_proc(mocker, 0, b"", b"")

    assert not nss_symlink.exists()
    await build_nss(firefox)
    assert nss_symlink.is_symlink()
    assert nss_symlink.resolve() == nspr_dir.resolve()


@pytest.mark.anyio
async def test_subprocess_exception_returns_failure(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    firefox = _layout(tmp_path)
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )
    result = await build_nss(firefox)
    assert result.success is False
    assert "OSError" in result.message
    assert "Permission denied" in result.message
