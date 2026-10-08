"""Tests for android_emulator.py."""

import sys
from pathlib import Path, PurePosixPath
from subprocess import TimeoutExpired
from unittest.mock import MagicMock

import pytest
from fxpoppet.adb_session import ADBSessionError
from fxpoppet.emulator.android import AndroidEmulatorError
from pytest_mock import MockerFixture

from fx_audit_mcp.android_emulator import (
    _PREP_SETTINGS,
    LAUNCH_ATTEMPTS,
    SERIAL_ENV,
    _EmulatorManager,
    emulator_manager,
)

ae_module = sys.modules["fx_audit_mcp.android_emulator"]


@pytest.fixture(autouse=True)
def _isolated(mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep managers off the real atexit hook and away from attached devices."""
    mocker.patch.object(ae_module.atexit, "register")
    monkeypatch.delenv(SERIAL_ENV, raising=False)
    emulator_manager.cache_clear()


@pytest.fixture(name="emulator_cls")
def _emulator_cls(mocker: MockerFixture) -> MagicMock:
    """AndroidEmulator whose instances are running emulators on port 5554."""
    cls: MagicMock = mocker.patch.object(ae_module, "AndroidEmulator")
    cls.search_free_ports.return_value = 5554
    cls.return_value.port = 5554
    cls.return_value.poll.return_value = None
    return cls


@pytest.fixture(name="session_cls")
def _session_cls(mocker: MockerFixture) -> MagicMock:
    """ADBSession connecting to a device that has the package installed."""
    cls: MagicMock = mocker.patch.object(ae_module, "ADBSession")
    cls.get_package_name.return_value = "org.mozilla.fenix"
    cls.connect.return_value.is_installed.return_value = True
    return cls


@pytest.fixture(name="apk")
def _apk(tmp_path: Path) -> Path:
    path = tmp_path / "target.apk"
    path.write_bytes(b"apk")
    return path


def _use(manager: _EmulatorManager, apk_path: Path) -> str:
    with manager.device(apk_path) as serial:
        return serial


def test_boots_prepares_and_installs_once(
    emulator_cls: MagicMock, session_cls: MagicMock, apk: Path
) -> None:
    """The first call boots a prepared emulator; later calls reuse it as-is."""
    manager = _EmulatorManager()

    assert _use(manager, apk) == "emulator-5554"
    assert _use(manager, apk) == "emulator-5554"

    emulator_cls.install.assert_called_once_with()
    emulator_cls.create_avd.assert_called_once_with("x86.5554")
    assert emulator_cls.call_args.kwargs["xvfb"] is True
    session = session_cls.connect.return_value
    assert session.airplane_mode is True
    session.install.assert_called_once_with(apk)
    session.uninstall.assert_called_once_with("org.mozilla.fenix")


@pytest.mark.parametrize("failure", ["exited", "unresponsive"])
def test_relaunches_a_dead_emulator(
    emulator_cls: MagicMock, session_cls: MagicMock, apk: Path, failure: str
) -> None:
    """A crashed or unresponsive emulator is replaced and the APK reinstalled."""
    first, second = MagicMock(port=5554), MagicMock(port=5556)
    first.poll.return_value = None
    second.poll.return_value = None
    emulator_cls.side_effect = [first, second]
    emulator_cls.search_free_ports.side_effect = [5554, 5556]
    manager = _EmulatorManager()
    _use(manager, apk)

    session = session_cls.connect.return_value
    if failure == "exited":
        first.poll.return_value = -9
        assert manager.emulator_exited() is True
    else:
        session_cls.connect.side_effect = [ADBSessionError("gone"), session]

    assert _use(manager, apk) == "emulator-5556"
    first.terminate.assert_called_once_with()
    first.cleanup.assert_called_once_with()
    emulator_cls.install.assert_called_once_with()
    assert session.install.call_count == 2
    assert manager.emulator_exited() is False


@pytest.mark.usefixtures("session_cls")
@pytest.mark.parametrize("exits_on_kill", [True, False])
def test_kills_an_emulator_that_ignores_terminate(
    emulator_cls: MagicMock, apk: Path, exits_on_kill: bool
) -> None:
    """An emulator that ignores terminate is killed; cleanup runs even if it hangs."""
    emulator = emulator_cls.return_value
    timeout = TimeoutExpired("emulator", 30)
    emulator.wait.side_effect = [timeout, 0 if exits_on_kill else timeout]
    manager = _EmulatorManager()
    _use(manager, apk)

    manager.shutdown()

    emulator.emu.kill.assert_called_once_with()
    emulator.cleanup.assert_called_once_with()


@pytest.mark.usefixtures("session_cls")
def test_unexpected_boot_failure_removes_avd(
    emulator_cls: MagicMock, apk: Path
) -> None:
    """A boot failure other than AndroidEmulatorError still removes its AVD."""
    emulator_cls.side_effect = TimeoutExpired("Xvfb", 5)

    with pytest.raises(TimeoutExpired):
        _use(_EmulatorManager(), apk)

    emulator_cls.remove_avd.assert_called_once_with("x86.5554")


def test_failed_setup_is_retried_on_the_same_emulator(
    emulator_cls: MagicMock, session_cls: MagicMock, apk: Path
) -> None:
    """A setup step that fails after boot is redone next call, without a reboot."""
    shell = session_cls.connect.return_value.device.shell
    shell.side_effect = [OSError("adb hiccup"), *[None] * 20]
    manager = _EmulatorManager()
    with pytest.raises(OSError, match="adb hiccup"):
        _use(manager, apk)

    _use(manager, apk)

    emulator_cls.assert_called_once()
    settings = [c for c in shell.call_args_list if c.args[0][0] == "settings"]
    # The failed first attempt, then a full pass of every setting.
    assert len(settings) == 1 + len(_PREP_SETTINGS)


def test_launch_gives_up_after_repeated_failures(
    emulator_cls: MagicMock, session_cls: MagicMock, apk: Path
) -> None:
    """Each failed boot removes its AVD; the last failure is raised."""
    emulator_cls.side_effect = AndroidEmulatorError("Failed to launch emulator.")
    manager = _EmulatorManager()

    with pytest.raises(AndroidEmulatorError):
        _use(manager, apk)

    assert emulator_cls.remove_avd.call_count == LAUNCH_ATTEMPTS
    session_cls.connect.assert_not_called()


@pytest.mark.usefixtures("emulator_cls")
@pytest.mark.parametrize("change", ["modified", "missing_on_device"])
def test_reinstalls_when_apk_or_device_changes(
    session_cls: MagicMock, apk: Path, change: str
) -> None:
    """A rebuilt APK, or one gone from the device, is installed again."""
    manager = _EmulatorManager()
    _use(manager, apk)
    session = session_cls.connect.return_value

    if change == "modified":
        apk.write_bytes(b"rebuilt apk")
    else:
        session.is_installed.return_value = False
    _use(manager, apk)

    assert session.install.call_count == 2


@pytest.mark.usefixtures("emulator_cls")
@pytest.mark.parametrize("present", [True, False])
def test_installs_llvm_symbolizer_when_present(
    session_cls: MagicMock, apk: Path, present: bool
) -> None:
    """llvm-symbolizer beside the APK is pushed for on-device ASAN symbolization."""
    symbolizer = apk.parent / "llvm-symbolizer"
    if present:
        symbolizer.touch()

    _use(_EmulatorManager(), apk)

    install_file = session_cls.connect.return_value.install_file
    if present:
        install_file.assert_called_once_with(
            symbolizer, ae_module.DEVICE_TMP, mode="777"
        )
    else:
        install_file.assert_not_called()


@pytest.mark.usefixtures("emulator_cls")
@pytest.mark.parametrize(
    ("change", "pushes"),
    [("none", 1), ("missing_on_device", 2), ("rebuilt", 2)],
)
def test_symbolizer_repushed_when_missing_or_changed(
    session_cls: MagicMock, apk: Path, change: str, pushes: int
) -> None:
    """With the APK cached, the symbolizer is pushed again only if it is needed."""
    symbolizer = apk.parent / "llvm-symbolizer"
    symbolizer.write_bytes(b"sym")
    session = session_cls.connect.return_value
    session.listdir.return_value = [PurePosixPath("llvm-symbolizer")]
    manager = _EmulatorManager()
    _use(manager, apk)

    if change == "missing_on_device":
        session.listdir.return_value = []
    elif change == "rebuilt":
        symbolizer.write_bytes(b"rebuilt sym")
    _use(manager, apk)

    session.install.assert_called_once_with(apk)
    assert session.install_file.call_count == pushes


@pytest.mark.usefixtures("emulator_cls")
def test_unreadable_package_name_raises(session_cls: MagicMock, apk: Path) -> None:
    """An APK aapt cannot read a package name from is rejected before install."""
    session_cls.get_package_name.return_value = None

    with pytest.raises(ValueError, match="package name"):
        _use(_EmulatorManager(), apk)

    session_cls.connect.return_value.install.assert_not_called()


def test_serial_env_uses_existing_device(
    emulator_cls: MagicMock,
    session_cls: MagicMock,
    apk: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With ANDROID_SERIAL set, that device is used and no emulator is managed."""
    monkeypatch.setenv(SERIAL_ENV, "R5CT1234")
    manager = _EmulatorManager()

    assert _use(manager, apk) == "R5CT1234"
    manager.shutdown()

    session_cls.connect.assert_called_once_with(
        "R5CT1234", as_root=True, boot_timeout=10
    )
    emulator_cls.install.assert_not_called()
    emulator_cls.assert_not_called()
    assert manager.emulator_exited() is False


def test_serial_env_device_unreachable(
    emulator_cls: MagicMock,
    session_cls: MagicMock,
    apk: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreachable ANDROID_SERIAL device is an error, not a cue to boot one."""
    monkeypatch.setenv(SERIAL_ENV, "R5CT1234")
    session_cls.connect.side_effect = ADBSessionError("offline")

    with pytest.raises(RuntimeError, match="R5CT1234"):
        _use(_EmulatorManager(), apk)

    emulator_cls.assert_not_called()


def test_manager_is_shared_and_stopped_at_exit() -> None:
    """One manager serves the process, and its shutdown runs at exit."""
    manager = emulator_manager()

    assert emulator_manager() is manager
    ae_module.atexit.register.assert_called_once_with(manager.shutdown)
