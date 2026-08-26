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
    assert Path(result.logs.stdout[0]).read_bytes() == b"compiled\n"


@pytest.mark.anyio
async def test_failed_build_surfaces_exit_code(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    firefox = _layout(tmp_path)
    _mock_proc(mocker, 2, b"", b"link error\n")

    result = await build_nss(firefox)

    assert result.success is False
    assert "exit code 2" in result.message
    assert Path(result.logs.stderr[0]).read_bytes() == b"link error\n"


@pytest.mark.anyio
async def test_missing_firefox_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    with pytest.raises(FileNotFoundError, match="Firefox directory not found"):
        await build_nss(tmp_path / "no_firefox")
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_missing_nspr_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    firefox = tmp_path / "firefox"
    (firefox / "security" / "nss").mkdir(parents=True)
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    with pytest.raises(FileNotFoundError, match="NSPR directory not found"):
        await build_nss(firefox)
    spawn.assert_not_called()


@pytest.mark.anyio
async def test_missing_nss_directory(mocker: MockerFixture, tmp_path: Path) -> None:
    firefox = tmp_path / "firefox"
    (firefox / "nsprpub").mkdir(parents=True)
    spawn = mocker.patch("asyncio.create_subprocess_exec")
    with pytest.raises(FileNotFoundError, match="NSS directory not found"):
        await build_nss(firefox)
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
async def test_subprocess_exception_propagates(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Verify that a spawn failure reaches the caller instead of a false result."""
    firefox = _layout(tmp_path)
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )
    with pytest.raises(OSError, match="Permission denied"):
        await build_nss(firefox)
