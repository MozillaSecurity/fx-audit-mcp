"""Tests for android_browser_evaluator.py."""

import hashlib
import importlib
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fxpoppet.adb_session import ADBSession, ADBSessionError
from fxpoppet.adb_wrapper import ADBResult
from grizzly.target import TargetLaunchError
from pytest_mock import MockerFixture

from fx_audit_mcp.android_browser_evaluator import (
    ANDROID_SERIAL_ENV,
    APK_ENV,
    APK_HASH_FILE,
    SYMBOLS_DIR_ENV,
    DeviceBusyError,
    _categorize_logs,
    _device_lock,
    _ensure_installed,
    _select_serial,
    _symbolizer,
    android_browser_evaluator,
)

abe_module = sys.modules["fx_audit_mcp.android_browser_evaluator"]
FIXTURES = Path(__file__).parent / "fixtures"
SYMBOLS = FIXTURES / "symbols"
REPORT = FIXTURES / "android_asan_report.txt"
# ++PROCESS records as the parent writes them to logcat (prefix stripped by
# fxpoppet), attributing pid 6599 of the report fixture to a content process.
STDERR = (
    "[Parent 6500: IPC I/O Parent]: I/ChildProcessLifecycle ++PROCESS [pid = 6598]"
    " [childID = 1] [type = gpu]\n"
    "[Parent 6500: IPC I/O Parent]: I/ChildProcessLifecycle ++PROCESS [pid = 6599]"
    " [childID = 2] [type = tab]\n"
)


class TestSelectSerial:
    def test_argument_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An explicit serial beats ANDROID_SERIAL."""
        monkeypatch.setenv(ANDROID_SERIAL_ENV, "emulator-5554")
        assert _select_serial("emulator-5556") == "emulator-5556"

    def test_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ANDROID_SERIAL selects the device, as it does for adb itself."""
        monkeypatch.setenv(ANDROID_SERIAL_ENV, "emulator-5554")
        assert _select_serial(None) == "emulator-5554"

    def test_single_connected_device(
        self, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """With nothing configured, the only connected device is used."""
        monkeypatch.delenv(ANDROID_SERIAL_ENV, raising=False)
        mocker.patch.object(
            abe_module.ADBWrapper, "devices", return_value={"emulator-5554": "device"}
        )
        assert _select_serial(None) == "emulator-5554"

    @pytest.mark.parametrize(
        ("devices", "match"),
        [
            ({}, "No Android device"),
            ({"emulator-5554": "device", "emulator-5556": "device"}, "Several"),
        ],
    )
    def test_ambiguous_or_missing(
        self,
        monkeypatch: pytest.MonkeyPatch,
        mocker: MockerFixture,
        devices: dict[str, str],
        match: str,
    ) -> None:
        """No device, or several without a selection, is an error."""
        monkeypatch.delenv(ANDROID_SERIAL_ENV, raising=False)
        mocker.patch.object(abe_module.ADBWrapper, "devices", return_value=devices)
        with pytest.raises(RuntimeError, match=match):
            _select_serial(None)


def test_device_lock_is_exclusive() -> None:
    """A second evaluator cannot take a device another one holds."""
    with _device_lock("emulator-5554"):
        with (
            pytest.raises(DeviceBusyError, match="emulator-5554"),
            _device_lock("emulator-5554"),
        ):
            pass
        # Another device is unaffected.
        with _device_lock("emulator-5556"):
            pass
    # Released on exit.
    with _device_lock("emulator-5554"):
        pass


class TestEnsureInstalled:
    @pytest.fixture
    def apk(self, tmp_path: Path) -> Path:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"not really an apk")
        return apk

    def test_skips_install_when_hash_matches(
        self, apk: Path, mocker: MockerFixture
    ) -> None:
        """The same bytes already on the device are not pushed again."""
        mocker.patch.object(
            abe_module.ADBSession, "get_package_name", return_value="org.mozilla.gve"
        )
        session = MagicMock()
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        session.device.shell.return_value = ADBResult(0, digest + "\n")
        session.is_installed.return_value = True

        assert _ensure_installed(session, apk) == "org.mozilla.gve"
        session.install.assert_not_called()

    @pytest.mark.parametrize("installed", [True, False])
    def test_installs_when_hash_differs_or_package_missing(
        self, apk: Path, mocker: MockerFixture, installed: bool
    ) -> None:
        """A changed APK, or a wiped device, triggers an install and stores the hash."""
        mocker.patch.object(
            abe_module.ADBSession, "get_package_name", return_value="org.mozilla.gve"
        )
        session = MagicMock()
        session.device.shell.return_value = ADBResult(0, "stale\n" if installed else "")
        session.is_installed.return_value = installed
        session.install.return_value = "org.mozilla.gve"

        assert _ensure_installed(session, apk) == "org.mozilla.gve"
        session.install.assert_called_once_with(apk)
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        assert session.device.shell.call_args.args[0] == (
            "sh",
            "-c",
            f"echo {digest} > {APK_HASH_FILE}",
        )

    def test_unreadable_package_name(self, apk: Path, mocker: MockerFixture) -> None:
        """A package name aapt cannot read is a clear error, not a crash later."""
        mocker.patch.object(
            abe_module.ADBSession, "get_package_name", return_value=None
        )
        with pytest.raises(RuntimeError, match="aapt"):
            _ensure_installed(MagicMock(), apk)


def test_categorize_logs_routes_fxpoppet_files(tmp_path: Path) -> None:
    """Raw logcat goes with stdout; only diagnostics land in crashdata."""
    for name in (
        "log_stderr.txt",
        "log_stdout.txt",
        "log_logcat.txt",
        "log_asan.txt",
        "log_minidump_00.txt",
    ):
        (tmp_path / name).write_text(name)
    paths = _categorize_logs(tmp_path)
    assert [Path(p).name for p in paths.stderr] == ["log_stderr.txt"]
    assert [Path(p).name for p in paths.stdout] == ["log_logcat.txt", "log_stdout.txt"]
    assert [Path(p).name for p in paths.crashdata] == [
        "log_asan.txt",
        "log_minidump_00.txt",
    ]


class TestSymbolizerSelection:
    def test_symbols_next_to_apk(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A symbols/ directory beside the APK (fuzzfetch layout) is picked up."""
        monkeypatch.delenv(SYMBOLS_DIR_ENV, raising=False)
        (tmp_path / "symbols").mkdir()
        assert (
            _symbolizer(tmp_path / "app.apk", None).symbols_dir == tmp_path / "symbols"
        )

    def test_environment_overrides_layout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ANDROID_SYMBOLS_DIR wins over the directory beside the APK."""
        monkeypatch.setenv(SYMBOLS_DIR_ENV, str(SYMBOLS))
        (tmp_path / "symbols").mkdir()
        assert _symbolizer(tmp_path / "app.apk", None).symbols_dir == SYMBOLS

    def test_argument_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An explicit symbols_dir beats everything else."""
        monkeypatch.setenv(SYMBOLS_DIR_ENV, str(tmp_path))
        assert _symbolizer(tmp_path / "app.apk", SYMBOLS).symbols_dir == SYMBOLS


class TestAndroidBrowserEvaluator:
    @pytest.fixture
    def apk(self, tmp_path: Path) -> Path:
        apk = tmp_path / "geckoview_example.apk"
        apk.write_bytes(b"apk")
        return apk

    @pytest.fixture
    def testcase_file(self, tmp_path: Path) -> Path:
        html = tmp_path / "test.html"
        html.write_text("<html></html>")
        return html

    def _mock_device(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> MagicMock:
        monkeypatch.setenv(ANDROID_SERIAL_ENV, "emulator-5554")
        session = mocker.MagicMock()
        session.device.shell.return_value = ADBResult(
            0, "package:/system/framework/framework-res.apk\n"
        )
        mocker.patch.object(abe_module.ADBSession, "connect", return_value=session)
        mocker.patch.object(
            abe_module, "_ensure_installed", return_value="org.mozilla.gve"
        )
        target = mocker.MagicMock()
        target.launch_timeout_report = None
        target.hang_detected = False
        target.parent_pid = 6500
        mocker.patch.object(abe_module, "_FxAuditFenixTarget", return_value=target)
        mocker.patch.object(abe_module, "Sapphire")
        return target

    def _mock_replay(
        self,
        mocker: MockerFixture,
        tmp_path: Path,
        report_files: dict[str, str],
        is_hang: bool = False,
    ) -> None:
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        for name, content in report_files.items():
            (report_dir / name).write_text(content)
        result = mocker.MagicMock()
        result.report.path = report_dir
        result.report.is_hang = is_hang
        replay = mocker.patch.object(abe_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.return_value = [result]

    @pytest.mark.anyio
    async def test_missing_apk(self, tmp_path: Path, testcase_file: Path) -> None:
        """A missing APK is rejected before touching any device."""
        with pytest.raises(FileNotFoundError, match="APK not found"):
            await android_browser_evaluator(
                file_paths={"test.html": testcase_file},
                entry_point="test.html",
                apk=tmp_path / "nope.apk",
            )

    @pytest.mark.anyio
    async def test_apk_required_from_argument_or_environment(
        self, testcase_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without an APK argument, FIREFOX_APK must name one."""
        monkeypatch.delenv(APK_ENV, raising=False)
        with pytest.raises(ValueError, match=APK_ENV):
            await android_browser_evaluator(
                file_paths={"test.html": testcase_file}, entry_point="test.html"
            )

    @pytest.mark.anyio
    async def test_clean_run(
        self,
        apk: Path,
        testcase_file: Path,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No result from replay is a clean run on the selected device."""
        target = self._mock_device(mocker, monkeypatch)
        replay = mocker.patch.object(abe_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.return_value = []
        target.save_logs.side_effect = lambda dst: (dst / "log_stderr.txt").write_text(
            "ok"
        )

        result = await android_browser_evaluator(
            file_paths={"test.html": testcase_file}, entry_point="test.html", apk=apk
        )

        assert result.crashed is False
        assert result.timed_out is False
        assert result.device_serial == "emulator-5554"
        assert result.crashed_content is None
        assert Path(result.logs.stderr[0]).read_text() == "ok"
        # The selected device is what FenixTarget is built against.
        assert abe_module.ADBSession.connect.call_args.args[0] == "emulator-5554"  # type: ignore[attr-defined]

    @pytest.mark.anyio
    async def test_crash_is_attributed_and_symbolized(
        self,
        apk: Path,
        testcase_file: Path,
        tmp_path: Path,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An ASan report from a content process is a crash with symbolized frames."""
        self._mock_device(mocker, monkeypatch)
        self._mock_replay(
            mocker,
            tmp_path,
            {"log_asan.txt": REPORT.read_text(), "log_stderr.txt": STDERR},
        )

        result = await android_browser_evaluator(
            file_paths={"test.html": testcase_file},
            entry_point="test.html",
            apk=apk,
            symbols_dir=SYMBOLS,
        )

        assert result.crashed is True
        assert result.timed_out is False
        assert result.crashed_content is True
        assert result.crashed_parent is False
        assert result.crashed_gpu is False
        asan_log = Path(result.logs.crashdata[0])
        assert asan_log.name == "log_asan.txt"
        assert "in CrashChannel::OpenContentStream" in asan_log.read_text()

    @pytest.mark.anyio
    async def test_hang_is_a_timeout(
        self,
        apk: Path,
        testcase_file: Path,
        tmp_path: Path,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A report grizzly flags as a hang is reported as timed out, not crashed."""
        self._mock_device(mocker, monkeypatch)
        self._mock_replay(mocker, tmp_path, {"log_stderr.txt": "busy"}, is_hang=True)

        result = await android_browser_evaluator(
            file_paths={"test.html": testcase_file}, entry_point="test.html", apk=apk
        )

        assert result.timed_out is True
        assert result.crashed is False

    @pytest.mark.anyio
    async def test_launch_failure_surfaces_logs(
        self,
        apk: Path,
        testcase_file: Path,
        tmp_path: Path,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """fxpoppet launch failures become an error naming the device and the logs."""
        self._mock_device(mocker, monkeypatch)
        report_dir = tmp_path / "launch_report"
        report_dir.mkdir()
        (report_dir / "log_logcat.txt").write_text("am start failed")
        report = mocker.MagicMock()
        report.path = report_dir
        replay = mocker.patch.object(abe_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.side_effect = TargetLaunchError(
            "boom", report
        )

        with pytest.raises(RuntimeError, match="emulator-5554") as exc_info:
            await android_browser_evaluator(
                file_paths={"test.html": testcase_file},
                entry_point="test.html",
                apk=apk,
            )
        log_dir = Path(str(exc_info.value).rsplit(" ", 1)[-1])
        assert (log_dir / "log_logcat.txt").read_text() == "am start failed"
        shutil.rmtree(log_dir)
        report.cleanup.assert_called_once()

    @pytest.mark.anyio
    async def test_launch_failure_with_asan_report_is_a_crash(
        self,
        apk: Path,
        testcase_file: Path,
        tmp_path: Path,
        mocker: MockerFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A child dying under ASan during startup is a crash, not a launch error."""
        self._mock_device(mocker, monkeypatch)
        report_dir = tmp_path / "launch_report"
        report_dir.mkdir()
        (report_dir / "log_asan.txt").write_text(REPORT.read_text())
        report = mocker.MagicMock()
        report.path = report_dir
        replay = mocker.patch.object(abe_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.side_effect = TargetLaunchError(
            "boom", report
        )

        result = await android_browser_evaluator(
            file_paths={"test.html": testcase_file}, entry_point="test.html", apk=apk
        )

        assert result.crashed is True
        # No launch records were captured, so the crashing pid is not the
        # parent but cannot be attributed to a child type either.
        assert result.crashed_parent is False
        assert result.crashed_content is None


class TestInstallRetry:
    """A stale install (other debug keystore) is replaced instead of failing."""

    @pytest.fixture
    def apk(self, tmp_path: Path) -> Path:
        apk = tmp_path / "app.apk"
        apk.write_bytes(b"PK\x03\x04stale-vs-fresh")
        return apk

    def _session(self, mocker: MockerFixture, installed: bool) -> MagicMock:
        session = mocker.MagicMock()
        session.device.shell.return_value = SimpleNamespace(exit_code=1, output="")
        session.is_installed.return_value = installed
        return session

    def test_uninstalls_and_retries_when_upgrade_rejected(
        self, apk: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ADBSession, "get_package_name", lambda _apk: "org.pkg")
        session = self._session(mocker, installed=True)
        session.install.side_effect = [ADBSessionError("Failed to install"), "org.pkg"]
        assert _ensure_installed(session, apk) == "org.pkg"
        assert session.install.call_count == 2
        assert (
            mocker.call(("pm", "uninstall", "org.pkg"))
            in session.device.shell.call_args_list
        )

    def test_install_failure_without_stale_package_propagates(
        self, apk: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(ADBSession, "get_package_name", lambda _apk: "org.pkg")
        session = self._session(mocker, installed=False)
        session.install.side_effect = ADBSessionError("Failed to install")
        with pytest.raises(ADBSessionError):
            _ensure_installed(session, apk)
        assert session.install.call_count == 1


class TestAutoRestart:
    """A vanished emulator is rebooted and the connection retried once, only
    when ANDROID_AUTOSTART_EMULATOR is set."""

    def test_reboots_and_retries_when_enabled(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")

        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        mocker.patch.object(abe, "_adb_state", return_value=None)
        session = _session_with_package_service(mocker, alive=True)
        connect = mocker.patch.object(
            ADBSession, "connect", side_effect=[ADBSessionError("gone"), session]
        )
        boot = mocker.patch.object(abe, "boot_serial", return_value=True)
        assert abe._connect("emulator-5556") is session
        boot.assert_called_once_with("emulator-5556")
        assert connect.call_count == 2

    def test_failure_propagates_when_disabled(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")

        monkeypatch.delenv(abe.AUTOSTART_ENV, raising=False)
        mocker.patch.object(ADBSession, "connect", side_effect=ADBSessionError("gone"))
        boot = mocker.patch.object(abe, "boot_serial", return_value=True)
        with pytest.raises(ADBSessionError):
            abe._connect("emulator-5556")
        boot.assert_not_called()

    def test_failed_boot_propagates(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")

        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        mocker.patch.object(abe, "_adb_state", return_value=None)
        mocker.patch.object(ADBSession, "connect", side_effect=ADBSessionError("gone"))
        mocker.patch.object(abe, "boot_serial", return_value=False)
        with pytest.raises(ADBSessionError):
            abe._connect("emulator-5556")

    def test_wedged_but_listed_device_is_replaced_not_rebooted(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A guest that still reports "device" but times out on connect is
        wedged; boot_serial() would call it already up, so it must be replaced."""
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")

        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        mocker.patch.object(abe, "_adb_state", return_value="device")
        fresh = _session_with_package_service(mocker, alive=True)
        connect = mocker.patch.object(
            ADBSession,
            "connect",
            side_effect=[ADBSessionError("Device boot timeout exceeded"), fresh],
        )
        restart = mocker.patch.object(abe, "restart_serial", return_value=True)
        boot = mocker.patch.object(abe, "boot_serial", return_value=True)
        assert abe._connect("emulator-5554") is fresh
        restart.assert_called_once_with("emulator-5554")
        boot.assert_not_called()
        assert connect.call_count == 2


def _session_with_package_service(mocker: MockerFixture, alive: bool) -> MagicMock:
    session = mocker.MagicMock()
    result = mocker.MagicMock()
    result.exit_code = 0 if alive else 20
    result.output = (
        "package:/system/framework/framework-res.apk"
        if alive
        else "cmd: Can't find service: package"
    )
    session.device.shell.return_value = result
    return session


class TestWedgedPackageService:
    """An emulator that still answers adb but whose package service died is
    replaced (not merely re-booted) when ANDROID_AUTOSTART_EMULATOR is set."""

    def test_healthy_device_is_returned_as_is(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")
        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        session = _session_with_package_service(mocker, alive=True)
        mocker.patch.object(ADBSession, "connect", return_value=session)
        restart = mocker.patch.object(abe, "restart_serial", return_value=True)
        assert abe._connect("emulator-5556") is session
        restart.assert_not_called()
        session.device.shell.assert_called_once_with(
            ("pm", "path", "android"), timeout=30
        )

    def test_wedged_device_is_replaced(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")
        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        wedged = _session_with_package_service(mocker, alive=False)
        fresh = _session_with_package_service(mocker, alive=True)
        connect = mocker.patch.object(
            ADBSession, "connect", side_effect=[wedged, fresh]
        )
        restart = mocker.patch.object(abe, "restart_serial", return_value=True)
        boot = mocker.patch.object(abe, "boot_serial", return_value=True)
        assert abe._connect("emulator-5556") is fresh
        restart.assert_called_once_with("emulator-5556")
        boot.assert_not_called()
        assert connect.call_count == 2

    def test_wedged_device_fails_when_autostart_disabled(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")
        monkeypatch.delenv(abe.AUTOSTART_ENV, raising=False)
        wedged = _session_with_package_service(mocker, alive=False)
        mocker.patch.object(ADBSession, "connect", return_value=wedged)
        restart = mocker.patch.object(abe, "restart_serial", return_value=True)
        with pytest.raises(ADBSessionError, match="package service"):
            abe._connect("emulator-5556")
        restart.assert_not_called()

    def test_failed_replacement_propagates(
        self, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        abe = importlib.import_module("fx_audit_mcp.android_browser_evaluator")
        monkeypatch.setenv(abe.AUTOSTART_ENV, "1")
        wedged = _session_with_package_service(mocker, alive=False)
        mocker.patch.object(ADBSession, "connect", return_value=wedged)
        mocker.patch.object(abe, "restart_serial", return_value=False)
        with pytest.raises(ADBSessionError, match="could not be replaced"):
            abe._connect("emulator-5556")
