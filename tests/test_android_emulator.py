"""Tests for android_emulator.py."""

import importlib
import socket
import subprocess
from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp import android_emulator
from fx_audit_mcp.android_emulator import (
    CONSOLE_PORT_MAX,
    SDK_ROOT_ENV,
    emulator_args,
    free_console_ports,
    main,
    parse_args,
)


@pytest.fixture
def fake_sdk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An SDK layout with executable stand-ins for emulator and adb."""
    for rel in ("emulator/emulator", "platform-tools/adb"):
        tool = tmp_path / rel
        tool.parent.mkdir(parents=True, exist_ok=True)
        tool.write_text("#!/bin/sh\nexit 0\n")
        tool.chmod(0o755)
    monkeypatch.setenv(SDK_ROOT_ENV, str(tmp_path))
    return tmp_path


class TestEmulatorArgs:
    def test_shares_the_avd_read_only_on_its_own_port(self, fake_sdk: Path) -> None:
        """Every instance is read-only and bound to the requested console port."""
        args = emulator_args("myavd", 5558, 8192, 4, accelerated=True)
        assert args[0] == str(fake_sdk / "emulator" / "emulator")
        assert "-read-only" in args
        assert args[args.index("-port") + 1] == "5558"
        assert args[args.index("-memory") + 1] == "8192"
        assert args[args.index("-cores") + 1] == "4"
        assert args[args.index("-accel") + 1] == "on"
        assert "-no-window" in args
        assert "-no-snapshot" in args

    @pytest.mark.usefixtures("fake_sdk")
    def test_software_mode_is_explicit(self) -> None:
        """Without acceleration the emulator is told so rather than left to guess."""
        args = emulator_args("myavd", 5554, 4096, 2, accelerated=False)
        assert args[args.index("-accel") + 1] == "off"


class TestFreeConsolePorts:
    def test_even_ports_skipping_busy_ones(self) -> None:
        """Ports are even, start at the requested one and skip occupied ports."""
        first = CONSOLE_PORT_MAX - 4
        with socket.socket() as busy:
            busy.bind(("127.0.0.1", first))
            assert free_console_ports(1, first) == [first + 2]

    def test_odd_start_rounds_up(self) -> None:
        """An odd starting port is rounded up to the next even one."""
        first = CONSOLE_PORT_MAX - 3
        assert free_console_ports(1, first) == [first + 1]

    def test_not_enough_ports(self) -> None:
        """Running out of the console port range is an error."""
        with pytest.raises(RuntimeError, match="free emulator console ports"):
            free_console_ports(2, CONSOLE_PORT_MAX)


class TestParseArgs:
    @pytest.mark.usefixtures("fake_sdk")
    def test_count_must_be_positive(self) -> None:
        """--count 0 is rejected."""
        with pytest.raises(SystemExit):
            parse_args(["start", "--count", "0"])

    def test_missing_emulator(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """start needs the emulator binary under the SDK root."""
        monkeypatch.setenv(SDK_ROOT_ENV, str(tmp_path / "nope"))
        with pytest.raises(SystemExit):
            parse_args(["start"])

    @pytest.mark.usefixtures("fake_sdk")
    def test_stop_and_list_need_no_sdk_check(self) -> None:
        """stop/list parse without touching the emulator binary."""
        assert parse_args(["stop", "emulator-5554"]).serials == ["emulator-5554"]
        assert parse_args(["list"]).command == "list"


class TestStart:
    @pytest.mark.usefixtures("fake_sdk")
    def test_refuses_software_emulation(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """Without KVM, start exits non-zero instead of booting a useless device."""
        mocker.patch.object(
            android_emulator, "_acceleration_available", return_value=False
        )
        popen = mocker.patch.object(subprocess, "Popen")
        assert main(["start", "--log-dir", str(tmp_path / "logs")]) == 1
        popen.assert_not_called()

    @pytest.mark.usefixtures("fake_sdk")
    def test_boots_requested_instances(
        self,
        mocker: MockerFixture,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Each instance gets its own port, log file and AVD home, and is awaited."""
        monkeypatch.delenv("ANDROID_AVD_HOME", raising=False)
        mocker.patch.object(
            android_emulator, "_acceleration_available", return_value=True
        )
        mocker.patch.object(
            android_emulator, "free_console_ports", return_value=[5560, 5562]
        )
        mocker.patch.object(android_emulator, "_wait_for_boot", return_value=True)
        popen = mocker.patch.object(subprocess, "Popen")
        avd_home = tmp_path / "avd"
        avd_home.mkdir()
        mocker.patch.object(android_emulator, "DEFAULT_AVD_HOME", avd_home)

        assert main(["start", "--count", "2", "--log-dir", str(tmp_path / "logs")]) == 0

        assert popen.call_count == 2
        ports = [
            call.args[0][call.args[0].index("-port") + 1]
            for call in popen.call_args_list
        ]
        assert ports == ["5560", "5562"]
        assert popen.call_args.kwargs["env"]["ANDROID_AVD_HOME"] == str(avd_home)
        assert (tmp_path / "logs" / "emulator-5560.log").exists()

    @pytest.mark.usefixtures("fake_sdk")
    def test_boot_failure_is_reported(
        self, mocker: MockerFixture, tmp_path: Path
    ) -> None:
        """An instance that never reports boot_completed makes start fail."""
        mocker.patch.object(
            android_emulator, "_acceleration_available", return_value=True
        )
        mocker.patch.object(android_emulator, "free_console_ports", return_value=[5560])
        mocker.patch.object(android_emulator, "_wait_for_boot", return_value=False)
        mocker.patch.object(subprocess, "Popen")
        assert main(["start", "--log-dir", str(tmp_path / "logs")]) == 1


def test_stop_kills_every_running_emulator(
    fake_sdk: Path, mocker: MockerFixture
) -> None:
    """stop without serials shuts down each emulator adb lists."""
    mocker.patch.object(
        android_emulator,
        "_emulator_serials",
        return_value=["emulator-5554", "emulator-5556"],
    )
    adb = mocker.patch.object(android_emulator, "_adb", return_value="")
    assert main(["stop"]) == 0
    assert [call.args[0] for call in adb.call_args_list] == [
        "emulator-5554",
        "emulator-5556",
    ]
    assert all(call.args[1:] == ("emu", "kill") for call in adb.call_args_list)


class TestBootSerial:
    def test_boots_read_only_on_the_serials_port(
        self, mocker: MockerFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fx_audit_mcp import android_emulator as em

        monkeypatch.setattr(em, "BOOT_LOCK", tmp_path / "boot.lock")
        mocker.patch.object(em, "_acceleration_available", return_value=True)
        mocker.patch.object(em, "_adb", return_value=None)  # device not up
        popen = mocker.patch.object(em.subprocess, "Popen")
        mocker.patch.object(em, "_wait_for_boot", return_value=True)
        mocker.patch.object(em, "emulator_path", return_value=tmp_path / "emulator")
        assert em.boot_serial("emulator-5556", log_dir=tmp_path) is True
        argv = popen.call_args.args[0]
        assert "-read-only" in argv and argv[argv.index("-port") + 1] == "5556"
        assert (tmp_path / "emulator-5556.log").exists()

    def test_skips_boot_when_device_already_up(
        self, mocker: MockerFixture, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from fx_audit_mcp import android_emulator as em

        monkeypatch.setattr(em, "BOOT_LOCK", tmp_path / "boot.lock")
        mocker.patch.object(em, "_acceleration_available", return_value=True)
        mocker.patch.object(em, "_adb", return_value="device")
        popen = mocker.patch.object(em.subprocess, "Popen")
        assert em.boot_serial("emulator-5556", log_dir=tmp_path) is True
        popen.assert_not_called()

    def test_rejects_non_emulator_serial(self) -> None:
        from fx_audit_mcp import android_emulator as em

        with pytest.raises(ValueError):
            em.boot_serial("0123456789ABCDEF")


class TestRestartSerial:
    def test_kills_then_boots(self, mocker, tmp_path) -> None:
        em = importlib.import_module("fx_audit_mcp.android_emulator")
        states = iter(["device", "device", None, None])

        def fake_adb(serial, *args, timeout=30):
            if args == ("emu", "kill"):
                return ""
            if args == ("get-state",):
                return next(states, None)
            return None

        mocker.patch.object(em, "_adb", side_effect=fake_adb)
        mocker.patch.object(em.time, "sleep")
        kill = mocker.patch.object(em, "_kill_port_processes")
        boot = mocker.patch.object(em, "boot_serial", return_value=True)
        assert em.restart_serial("emulator-5556", log_dir=tmp_path) is True
        kill.assert_not_called()
        boot.assert_called_once_with(
            "emulator-5556",
            avd=em.DEFAULT_AVD,
            timeout=em.BOOT_TIMEOUT,
            log_dir=tmp_path,
        )

    def test_falls_back_to_sigkill_when_console_kill_is_ignored(
        self, mocker, tmp_path
    ) -> None:
        em = importlib.import_module("fx_audit_mcp.android_emulator")
        states = {"n": 0}

        def fake_adb(serial, *args, timeout=30):
            if args == ("get-state",):
                states["n"] += 1
                return "device" if states["n"] < 40 else None
            return ""

        mocker.patch.object(em, "_adb", side_effect=fake_adb)
        mocker.patch.object(em.time, "sleep")
        clock = iter(range(0, 10_000, 10))
        mocker.patch.object(em.time, "monotonic", side_effect=lambda: next(clock))

        def kill(port):
            states["n"] = 100

        kill_mock = mocker.patch.object(em, "_kill_port_processes", side_effect=kill)
        boot = mocker.patch.object(em, "boot_serial", return_value=True)
        assert em.restart_serial("emulator-5556", log_dir=tmp_path) is True
        kill_mock.assert_called_once_with(5556)
        boot.assert_called_once()

    def test_rejects_non_emulator_serial(self) -> None:
        em = importlib.import_module("fx_audit_mcp.android_emulator")
        with pytest.raises(ValueError):
            em.restart_serial("0123456789ABCDEF")
