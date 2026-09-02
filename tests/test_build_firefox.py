"""Tests for build_firefox tool."""

import asyncio
import json
import os
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
from fx_audit_mcp.process_output import STREAM_CHUNK_SIZE

bf_module = sys.modules["fx_audit_mcp.build_firefox"]

_DUMMY_OBJDIR = "/tmp/firefox/obj-asan"


class _FakeStream:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)

    async def read(self, _size: int) -> bytes:
        return next(self._chunks, b"")


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
    mock_process.returncode = None

    async def _wait() -> int:
        mock_process.returncode = 0
        return 0

    mock_process.wait = _wait
    mock_process.stdout = _FakeStream([b"Build succeeded\n"])
    mock_process.stderr = _FakeStream([b"Warning: something\n"])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is True
    assert result.build_dir == _DUMMY_OBJDIR
    assert result.exit_code == 0
    assert Path(result.logs.stdout[0]).read_bytes() == b"Build succeeded\n"
    assert Path(result.logs.stderr[0]).read_bytes() == b"Warning: something\n"


@pytest.mark.anyio
async def test_failed_build(mocker: MockerFixture, tmp_path: Path) -> None:
    """A failed build returns success=False with stdout/stderr."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 1
    mock_process.stdout = _FakeStream([b"Build output\n"])
    mock_process.stderr = _FakeStream([b"Error: build failed\n"])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(firefox_dir, mozconfig)

    assert result.success is False
    assert result.exit_code == 1
    assert Path(result.logs.stdout[0]).read_bytes() == b"Build output\n"
    assert Path(result.logs.stderr[0]).read_bytes() == b"Error: build failed\n"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "error", [BrokenPipeError(), UnicodeEncodeError("utf-8", "x", 0, 1, "test")]
)
async def test_cli_output_error_does_not_abort_build(
    mocker: MockerFixture, tmp_path: Path, error: Exception
) -> None:
    """A CLI output error does not terminate an otherwise healthy build."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.stdout = _FakeStream([b"out line\n", b"more\n"])
    mock_process.stderr = _FakeStream([])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)
    output = mocker.Mock()
    output.write.side_effect = error
    mocker.patch.object(bf_module.sys, "stdout", output)

    result = await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig")

    assert result.success is True


@pytest.mark.anyio
async def test_missing_firefox_directory(tmp_path: Path) -> None:
    """Missing Firefox directory raises without calling subprocess."""
    firefox_dir = tmp_path / "nonexistent"
    mozconfig = tmp_path / "mozconfig"
    mozconfig.touch()

    with pytest.raises(FileNotFoundError, match="Firefox directory not found") as exc:
        await build_firefox(firefox_dir, mozconfig)

    assert str(firefox_dir) in str(exc.value)


@pytest.mark.anyio
async def test_missing_mozconfig(tmp_path: Path) -> None:
    """Missing MOZCONFIG file raises without calling subprocess."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "nonexistent_mozconfig"
    firefox_dir.mkdir()

    with pytest.raises(FileNotFoundError, match="MOZCONFIG file not found") as exc:
        await build_firefox(firefox_dir, mozconfig)

    assert str(mozconfig) in str(exc.value)


@pytest.mark.parametrize("environ", [{"PATH": "/nowhere"}, {}])
@pytest.mark.anyio
async def test_missing_python3(
    mocker: MockerFixture, tmp_path: Path, environ: dict[str, str]
) -> None:
    """An unusable PATH raises rather than tripping an assertion."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"
    firefox_dir.mkdir()
    mozconfig.touch()
    mocker.patch.dict(os.environ, environ, clear=True)
    which = mocker.patch("fx_audit_mcp.build_firefox.which", return_value=None)

    with pytest.raises(FileNotFoundError, match="python3"):
        await build_firefox(firefox_dir, mozconfig)

    assert which.call_args.kwargs["path"] == environ.get("PATH", os.defpath)


@pytest.mark.anyio
async def test_long_output_line_is_streamed(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Output longer than the asyncio pipe limit is retained and streamed."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    output = b"x" * (STREAM_CHUNK_SIZE * 2)
    mock_process.stdout = _FakeStream([output])
    mock_process.stderr = _FakeStream([])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig")

    assert result.success is True
    assert Path(result.logs.stdout[0]).read_bytes() == output


@pytest.mark.anyio
async def test_streams_output_to_context_and_cli(
    mocker: MockerFixture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Streams output through MCP context without writing to MCP stdout."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.stdout = _FakeStream([b"out line\n"])
    mock_process.stderr = _FakeStream([b"err line\n"])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)
    ctx = mocker.Mock()
    ctx.info = mocker.AsyncMock()

    result = await build_firefox(firefox_dir, mozconfig, ctx=ctx)

    assert result.success is True
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert ctx.info.await_count == 2
    ctx.info.assert_any_await("out line\n", logger_name="mach.stdout")
    ctx.info.assert_any_await("err line\n", logger_name="mach.stderr")


@pytest.mark.anyio
async def test_context_failure_disables_notifications(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """A notification failure does not terminate an otherwise healthy build."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.stdout = _FakeStream([b"out line\n", b"more\n"])
    mock_process.stderr = _FakeStream([])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)
    ctx = mocker.Mock()
    ctx.info = mocker.AsyncMock(side_effect=RuntimeError("client disconnected"))

    result = await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig", ctx=ctx)

    assert result.success is True
    assert Path(result.logs.stdout[0]).read_bytes() == b"out line\nmore\n"
    ctx.info.assert_awaited_once()
    mock_process.terminate.assert_not_called()


@pytest.mark.anyio
async def test_context_cancellation_terminates_build(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Cancellation from a notification aborts and waits for mach build."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = None
    mock_process.stdout = _FakeStream([b"out line\n"])
    mock_process.stderr = _FakeStream([])
    mock_process.terminate = mocker.Mock()
    mock_process.wait = mocker.AsyncMock()
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)
    ctx = mocker.Mock()
    ctx.info = mocker.AsyncMock(side_effect=asyncio.CancelledError)

    with pytest.raises(asyncio.CancelledError):
        await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig", ctx=ctx)

    mock_process.terminate.assert_called_once_with()
    mock_process.wait.assert_awaited_once_with()


@pytest.mark.anyio
async def test_context_cancellation_kills_stuck_build(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """A stuck process is killed after termination times out."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch("fx_audit_mcp.build_firefox.PROCESS_TERMINATION_TIMEOUT", 0.001)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = None
    mock_process.stdout = _FakeStream([b"out line\n"])
    mock_process.stderr = _FakeStream([])
    mock_process.terminate = mocker.Mock()
    mock_process.kill = mocker.Mock()

    async def _stuck_wait() -> None:
        await asyncio.sleep(3600)

    mock_process.wait = _stuck_wait
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)
    ctx = mocker.Mock()
    ctx.info = mocker.AsyncMock(side_effect=asyncio.CancelledError)

    with pytest.raises(asyncio.CancelledError):
        await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig", ctx=ctx)

    mock_process.terminate.assert_called_once_with()
    mock_process.kill.assert_called_once_with()


@pytest.mark.anyio
async def test_direct_call_prints_output(
    mocker: MockerFixture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Direct calls stream output to the process streams."""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.stdout = _FakeStream([b"out line\n"])
    mock_process.stderr = _FakeStream([b"err line\n"])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    result = await build_firefox(tmp_path / "firefox", tmp_path / "mozconfig")

    assert result.success is True
    captured = capsys.readouterr()
    assert captured.out == "out line\n"
    assert captured.err == "err line\n"


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

    @pytest.mark.parametrize(
        "error",
        [
            FileNotFoundError("MOZCONFIG file not found at /nope"),
            NotADirectoryError("Not a directory: '/nope/firefox'"),
            RuntimeError("mach environment output missing topobjdir"),
            json.JSONDecodeError("Expecting value", "", 0),
        ],
    )
    def test_build_error_is_reported_without_a_traceback(
        self,
        mocker: MockerFixture,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        error: Exception,
    ) -> None:
        """main() prints the message for a bad invocation rather than raising."""
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
        mocker.patch("fx_audit_mcp.build_firefox.build_firefox", side_effect=error)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1
        assert str(error) in capsys.readouterr().err

    def test_interrupt_exits_without_a_traceback(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Ctrl-C during a build exits 130 rather than raising."""
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
        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox", side_effect=KeyboardInterrupt
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 130

    def test_unexpected_error_keeps_its_traceback(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """main() lets an error that isn't a bad invocation propagate."""
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
        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox",
            side_effect=ValueError("bug in the tool"),
        )
        with pytest.raises(ValueError, match="bug in the tool"):
            main()

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
            success=False, build_dir=None, exit_code=1
        )

        async def _fake_build(*_args: object, **_kwargs: object) -> MagicMock:
            return result_obj

        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox", side_effect=_fake_build
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 1

    def test_exits_zero_on_success(
        self, mocker: MockerFixture, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
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
            exit_code=0,
        )

        async def _fake_build(*_args: object, **_kwargs: object) -> MagicMock:
            return result_obj

        mocker.patch(
            "fx_audit_mcp.build_firefox.build_firefox", side_effect=_fake_build
        )
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0
        output = capsys.readouterr().out
        assert "--- stdout ---" not in output
        assert "--- stderr ---" not in output


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
    mock_process.stdout = _FakeStream([])
    mock_process.stderr = _FakeStream([])
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
    # sys.platform is faked, so which() would take shutil's Windows branch and
    # reach _winapi, which does not exist on the host running these tests.
    mocker.patch("fx_audit_mcp.build_firefox.which", return_value="python3")
    mocker.patch("fx_audit_mcp.build_firefox._get_build_dir", return_value="/objdir")
    mock_process = mocker.AsyncMock()
    mock_process.returncode = 0
    mock_process.stdout = _FakeStream([])
    mock_process.stderr = _FakeStream([])
    mocker.patch("asyncio.create_subprocess_exec", return_value=mock_process)

    await build_firefox(firefox_dir, mozconfig)
    helper.assert_called_once()


@pytest.mark.anyio
async def test_mach_build_exception_propagates(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Verify that a spawn failure reaches the caller instead of a false result."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch(
        "asyncio.create_subprocess_exec",
        side_effect=OSError("Permission denied"),
    )

    with pytest.raises(OSError, match="Permission denied"):
        await build_firefox(firefox_dir, mozconfig)


@pytest.mark.anyio
async def test_mach_environment_failure_propagates(
    mocker: MockerFixture, tmp_path: Path
) -> None:
    """Verify that an objdir lookup failure reaches the caller."""
    firefox_dir = tmp_path / "firefox"
    mozconfig = tmp_path / "mozconfig"

    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch(
        "fx_audit_mcp.build_firefox._get_build_dir",
        side_effect=RuntimeError("mach environment output missing topobjdir"),
    )

    with pytest.raises(RuntimeError, match="missing topobjdir"):
        await build_firefox(firefox_dir, mozconfig)
