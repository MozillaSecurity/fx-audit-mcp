"""Tests for build_firefox tool."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp.build_firefox import (
    _get_build_dir,
    _parse_args,
    _windows_build_env,
    build_firefox,
    main,
)

bf_module = sys.modules["fx_audit_mcp.build_firefox"]

_DUMMY_OBJDIR = "/tmp/firefox/obj-asan"


@pytest.fixture(autouse=True)
def _mock_get_build_dir(mocker: MockerFixture) -> None:
    mocker.patch(
        "fx_audit_mcp.build_firefox._get_build_dir",
        return_value=_DUMMY_OBJDIR,
    )


class TestGetBuildDir:
    @pytest.mark.anyio
    async def test_returns_topobjdir_from_mach_output(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Parses topobjdir from mach environment JSON output."""
        payload = json.dumps({"topobjdir": "/some/obj"}).encode()
        proc = mocker.AsyncMock()
        proc.communicate = mocker.AsyncMock(return_value=(payload, None))
        mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
        result = await _get_build_dir("python3", tmp_path, {})
        assert result == "/some/obj"

    @pytest.mark.anyio
    async def test_raises_on_subprocess_failure(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Raises if mach environment cannot be launched."""
        mocker.patch("asyncio.create_subprocess_exec", side_effect=OSError("not found"))
        with pytest.raises(OSError):
            await _get_build_dir("python3", tmp_path, {})

    @pytest.mark.anyio
    async def test_raises_on_invalid_json(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Raises if mach environment output is not valid JSON."""
        proc = mocker.AsyncMock()
        proc.communicate = mocker.AsyncMock(return_value=(b"not json", None))
        mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
        with pytest.raises(json.JSONDecodeError):
            await _get_build_dir("python3", tmp_path, {})

    @pytest.mark.anyio
    async def test_raises_if_topobjdir_missing(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Raises RuntimeError if topobjdir key is absent from mach output."""
        payload = json.dumps({"topsrcdir": "/src"}).encode()
        proc = mocker.AsyncMock()
        proc.communicate = mocker.AsyncMock(return_value=(payload, None))
        mocker.patch("asyncio.create_subprocess_exec", return_value=proc)
        with pytest.raises(RuntimeError, match="topobjdir"):
            await _get_build_dir("python3", tmp_path, {})


@pytest.mark.anyio
async def test_successful_build(mocker: MockerFixture, tmp_path: Path) -> None:
    """A successful build returns success=True with build_dir from mach environment."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mocker.AsyncMock(
        return_value=(b"Build succeeded\n", b"Warning: something\n")
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is True
    assert result.build_dir == _DUMMY_OBJDIR
    assert result.message == "Firefox build completed successfully"
    assert result.stdout is not None and "Build succeeded" in result.stdout
    assert result.stderr is not None and "Warning: something" in result.stderr


@pytest.mark.anyio
async def test_failed_build(mocker: MockerFixture, tmp_path: Path) -> None:
    """A failed build returns success=False with stdout/stderr."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 1
    mock_process.communicate = mocker.AsyncMock(
        return_value=(b"Build output\n", b"Error: build failed\n")
    )
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert "failed with exit code 1" in result.message
    assert result.stdout is not None and "Build output" in result.stdout
    assert result.stderr is not None and "Error: build failed" in result.stderr


@pytest.mark.anyio
async def test_missing_firefox_directory(tmp_path: Path) -> None:
    """Missing Firefox directory returns error without calling subprocess."""
    firefox_dir = tmp_path / "nonexistent"
    mozconfig = tmp_path / "mozconfig"
    mozconfig.touch()

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert "Firefox directory not found" in result.message
    assert str(firefox_dir) in result.message


@pytest.mark.anyio
async def test_missing_mozconfig(tmp_path: Path) -> None:
    """Missing MOZCONFIG file returns error without calling subprocess."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "nonexistent_mozconfig"
    firefox_dir.mkdir()

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert "MOZCONFIG file not found" in result.message
    assert str(mozconfig) in result.message


class TestWindowsBuildEnv:
    def test_no_paths_present_leaves_path_unchanged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With none of the Windows toolchain dirs present, PATH is not modified."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake_home")
        env = {"PATH": "/usr/bin"}
        result = _windows_build_env(env)
        assert result["PATH"] == "/usr/bin"

    def test_prepends_cargo_when_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An existing ~/.cargo/bin is prepended onto PATH."""
        home = tmp_path / "home"
        cargo = home / ".cargo" / "bin"
        cargo.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        env = {"PATH": "C:/Windows/System32"}
        result = _windows_build_env(env)
        assert result["PATH"].startswith(str(cargo))
        assert "C:/Windows/System32" in result["PATH"]

    def test_prepends_mozilla_build_paths_when_present(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An existing mozilla-build root adds python3 + msys2/usr/bin to PATH."""
        mb_root = tmp_path / "mozilla-build"
        msys2_bin = mb_root / "msys2" / "usr" / "bin"
        msys2_bin.mkdir(parents=True)
        monkeypatch.setattr(bf_module, "MOZILLA_BUILD_ROOT", mb_root)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake_home")
        env = {"PATH": ""}
        result = _windows_build_env(env)
        assert str(mb_root / "python3") in result["PATH"]
        assert str(msys2_bin) in result["PATH"]

    def test_mozilla_build_without_msys2_skips_msys2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When msys2/usr/bin is absent, only python3 is added; no error."""
        mb_root = tmp_path / "mozilla-build"
        mb_root.mkdir()
        monkeypatch.setattr(bf_module, "MOZILLA_BUILD_ROOT", mb_root)
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fake_home")
        env = {"PATH": ""}
        result = _windows_build_env(env)
        assert str(mb_root / "python3") in result["PATH"]
        assert "msys2" not in result["PATH"]

    def test_prepends_clang_asan_runtime_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The clang ASAN runtime directory is added when present."""
        home = tmp_path / "home"
        asan_dir = (
            home / ".mozbuild" / "clang" / "lib" / "clang" / "18" / "lib" / "windows"
        )
        asan_dir.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        env = {"PATH": ""}
        result = _windows_build_env(env)
        assert str(asan_dir) in result["PATH"]


class TestParseArgs:
    def test_defaults(self) -> None:
        """No arguments leaves mozconfig unset."""
        args = _parse_args([])
        assert args.mozconfig is None

    def test_overrides(self) -> None:
        """Explicit --firefox-dir and --mozconfig override the defaults."""
        args = _parse_args(["--firefox-dir", "/tmp/ff", "--mozconfig", "/tmp/mc"])
        assert args.firefox_dir == Path("/tmp/ff")
        assert args.mozconfig == Path("/tmp/mc")

    def test_firefox_dir_defaults_from_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """FIREFOX_SOURCE_ROOT env var sets the default --firefox-dir."""
        monkeypatch.setenv("FIREFOX_SOURCE_ROOT", "/env/firefox")
        args = _parse_args([])
        assert args.firefox_dir == Path("/env/firefox")


class TestMain:
    def test_missing_mozconfig_exits_nonzero(
        self,
        mocker: MockerFixture,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """main() exits 1 when --mozconfig is not provided."""
        mocker.patch("sys.argv", ["fx-audit-build-firefox"])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        assert "--mozconfig" in capsys.readouterr().err

    def test_exits_nonzero_on_build_failure(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """main() propagates a failed build to a nonzero exit."""
        mc = tmp_path / "mc"
        mc.touch()
        mocker.patch(
            "sys.argv",
            [
                "fx-audit-build-firefox",
                "--firefox-dir",
                str(tmp_path),
                "--mozconfig",
                str(mc),
            ],
        )
        result_obj: MagicMock = mocker.MagicMock(
            success=False, build_dir=None, stdout="out", stderr="err", message="failed"
        )

        async def _fake_build(*_args: object, **_kwargs: object) -> MagicMock:
            return result_obj

        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox", side_effect=_fake_build
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_exits_zero_on_success(self, mocker: MockerFixture, tmp_path: Path) -> None:
        """main() exits 0 when build succeeds."""
        mc = tmp_path / "mc"
        mc.touch()
        mocker.patch(
            "sys.argv",
            [
                "fx-audit-build-firefox",
                "--firefox-dir",
                str(tmp_path),
                "--mozconfig",
                str(mc),
            ],
        )
        result_obj: MagicMock = mocker.MagicMock(
            success=True,
            build_dir="/path/to/obj",
            stdout=None,
            stderr=None,
            message="ok",
        )

        async def _fake_build(*_args: object, **_kwargs: object) -> MagicMock:
            return result_obj

        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox", side_effect=_fake_build
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0


@pytest.mark.anyio
async def test_strips_taskcluster_env(
    mocker: MockerFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """TASKCLUSTER_* env vars are stripped from the build env."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"
    mocker.patch("pathlib.Path.exists", return_value=True)
    monkeypatch.setenv("TASKCLUSTER_ROOT_URL", "https://example.com")
    monkeypatch.setenv("TASKCLUSTER_PROXY_URL", "http://taskcluster")
    monkeypatch.setenv("KEEP_ME", "yes")

    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mocker.AsyncMock(return_value=(b"", b""))
    create = mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    await build_firefox(firefox_dir, mozconfig)

    passed_env = create.call_args.kwargs["env"]
    assert not any(k.startswith("TASKCLUSTER_") for k in passed_env)
    assert passed_env["KEEP_ME"] == "yes"


@pytest.mark.anyio
async def test_calls_windows_build_env_on_win32(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """The Windows PATH-augmentation helper runs only when sys.platform=='win32'."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"
    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch("sys.platform", "win32")
    helper: MagicMock = mocker.patch("fx_audit_mcp.build_firefox._windows_build_env")
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.communicate = mocker.AsyncMock(return_value=(b"", b""))
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    await build_firefox(firefox_dir, mozconfig)
    helper.assert_called_once()


@pytest.mark.anyio
async def test_mach_build_exception_returns_failure(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Exception from mach build is caught and returned as failure."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert "Error building Firefox" in result.message
    assert "OSError" in result.message
    assert "Permission denied" in result.message


@pytest.mark.anyio
async def test_mach_environment_failure_returns_failure(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Failure from mach environment is surfaced as a build failure."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch(
        "fx_audit_mcp.build_firefox._get_build_dir",
        side_effect=RuntimeError("mach environment output missing topobjdir"),
    )

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert "Error building Firefox" in result.message
