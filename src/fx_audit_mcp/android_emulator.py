"""Provide an Android device, booting and maintaining an emulator on demand."""

from __future__ import annotations

import atexit
import functools
import os
import threading
from contextlib import contextmanager
from logging import getLogger
from pathlib import PurePosixPath
from subprocess import TimeoutExpired
from typing import TYPE_CHECKING

from fxpoppet.adb_session import DEVICE_TMP, ADBSession, ADBSessionError
from fxpoppet.emulator.android import AndroidEmulator, AndroidEmulatorError

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

BOOT_TIMEOUT = 300
LAUNCH_ATTEMPTS = 3
SERIAL_ENV = "ANDROID_SERIAL"

_LOG = getLogger(__name__)

# Device settings applied to each fresh emulator, matching `fxpoppet --prep`:
# animations off, and nothing throttling or killing the browser in the background.
_PREP_SETTINGS = (
    ("animator_duration_scale", "0"),
    ("transition_animation_scale", "0"),
    ("window_animation_scale", "0"),
    ("device_idle_enabled", "0"),
    ("low_power", "0"),
    ("background_process_limit", "0"),
)


class _EmulatorManager:
    """Own the process's Android emulator and the APK installed on it.

    One emulator is booted on first use and reused by later calls; it is
    relaunched whenever it is found dead (crashed, OOM-killed) or unresponsive,
    and shut down at interpreter exit. Setting ``ANDROID_SERIAL`` bypasses the
    emulator entirely: that device is used as-is and never launched or killed.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._emulator: AndroidEmulator | None = None
        # (serial, resolved APK path, mtime_ns, size) of the last install, so an
        # unchanged APK is not reinstalled on every call.
        self._installed: tuple[str, str, int, int] | None = None
        # (serial, mtime_ns, size) of the llvm-symbolizer last pushed.
        self._symbolizer: tuple[str, int, int] | None = None
        # Whether the managed emulator has had _prepare() applied. Tracked apart
        # from the boot so a failed setup step is retried on the next call
        # instead of leaving a live but unprepared emulator.
        self._prepared = False
        self._sdk_ready = False
        atexit.register(self.shutdown)

    def _connect(self) -> tuple[str, ADBSession]:
        """Return a session on a healthy, prepared emulator, booting if needed."""
        session: ADBSession | None = None
        if self._emulator is not None and self._emulator.poll() is None:
            serial = f"emulator-{self._emulator.port}"
            try:
                session = ADBSession.connect(serial, as_root=True, boot_timeout=10)
            except ADBSessionError:
                _LOG.warning("Android emulator %s is unresponsive", serial)
        elif self._emulator is not None:
            _LOG.warning("Android emulator exited; relaunching")
        if session is None:
            self._stop_emulator()
            serial = self._launch_emulator()
            session = ADBSession.connect(serial, as_root=True, boot_timeout=10)
        if not self._prepared:
            self._prepare(session)
            self._prepared = True
        return serial, session

    def _install(self, serial: str, session: ADBSession, apk: Path) -> None:
        """Install *apk* and its symbolizer unless already on the device."""
        package = ADBSession.get_package_name(apk)
        if package is None:
            raise ValueError(f"Could not read the package name from {apk}")
        stat = apk.stat()
        record = (serial, str(apk.resolve()), stat.st_mtime_ns, stat.st_size)
        if record != self._installed or not session.is_installed(package):
            self._installed = None
            # Uninstall first: `adb install -r` refuses an APK signed differently.
            session.uninstall(package)
            session.install(apk)
            self._installed = record
        self._push_symbolizer(serial, session, apk)

    def _launch_emulator(self) -> str:
        """Boot a new emulator (installing the SDK if needed); return its serial."""
        if not self._sdk_ready:
            # Downloads the emulator, system image and tools on first use, and
            # otherwise just checks they are current.
            AndroidEmulator.install()
            self._sdk_ready = True

        attempt = 1
        while True:
            port = AndroidEmulator.search_free_ports()
            avd_name = f"x86.{port:d}"
            AndroidEmulator.create_avd(avd_name)
            try:
                self._emulator = AndroidEmulator(
                    avd_name=avd_name,
                    port=port,
                    boot_timeout=BOOT_TIMEOUT,
                    xvfb=True,
                )
            except AndroidEmulatorError:
                AndroidEmulator.remove_avd(avd_name)
                if attempt == LAUNCH_ATTEMPTS:
                    raise
                _LOG.warning("Android emulator launch failed (attempt %d)", attempt)
                attempt += 1
                continue
            except BaseException:
                # The emulator cleans up its own process and Xvfb on a failed
                # boot, but not the AVD (and its sdcard image) made for it.
                AndroidEmulator.remove_avd(avd_name)
                raise
            return f"emulator-{port}"

    @staticmethod
    def _prepare(session: ADBSession) -> None:
        """Apply the device settings runs depend on."""
        for name, value in _PREP_SETTINGS:
            session.device.shell(["settings", "put", "global", name, value])
        session.device.shell(["dumpsys", "deviceidle", "disable"])
        # Testcases are served over `adb reverse`, which airplane mode leaves up.
        session.airplane_mode = True

    def _push_symbolizer(self, serial: str, session: ADBSession, apk: Path) -> None:
        """Push the llvm-symbolizer next to *apk*, if any, unless already there."""
        symbolizer = apk.parent / "llvm-symbolizer"
        if not symbolizer.is_file():
            return
        stat = symbolizer.stat()
        record = (serial, stat.st_mtime_ns, stat.st_size)
        # Check the device too: /data/local/tmp can be wiped (e.g. a reboot of an
        # ANDROID_SERIAL device) while the package stays installed.
        if record == self._symbolizer and PurePosixPath(
            symbolizer.name
        ) in session.listdir(DEVICE_TMP):
            return
        # ASAN_OPTIONS on the device point external_symbolizer_path here.
        session.install_file(symbolizer, DEVICE_TMP, mode="777")
        self._symbolizer = record

    def _stop_emulator(self) -> None:
        emulator, self._emulator = self._emulator, None
        if emulator is None:
            return
        self._installed = None
        self._symbolizer = None
        self._prepared = False
        try:
            emulator.terminate()
            emulator.wait(30)
        except TimeoutExpired:
            emulator.emu.kill()
            try:
                emulator.wait(30)
            except TimeoutExpired:
                # Wedged (e.g. in uninterruptible I/O): give up on it rather
                # than fail the relaunch or the exit handler.
                _LOG.warning("Android emulator pid %d ignored SIGKILL", emulator.pid)
        finally:
            emulator.cleanup()

    @contextmanager
    def device(self, apk: Path) -> Iterator[str]:
        """Hold a ready device with *apk* installed for the duration of a run.

        Runs are serialized: the device is held exclusively until the block
        exits.

        Args:
            apk: APK that must be installed on the device.

        Yields:
            The device's ADB serial.
        """
        with self._lock:
            serial = os.environ.get(SERIAL_ENV)
            if serial is None:
                serial, session = self._connect()
            else:
                try:
                    session = ADBSession.connect(serial, as_root=True, boot_timeout=10)
                except ADBSessionError as exc:
                    raise RuntimeError(
                        f"Cannot connect to {SERIAL_ENV} device {serial}: {exc}"
                    ) from None
            self._install(serial, session, apk)
            yield serial

    def emulator_exited(self) -> bool:
        """Whether the managed emulator has died; False for an external device."""
        return self._emulator is not None and self._emulator.poll() is not None

    def shutdown(self) -> None:
        """Stop the managed emulator, if one is running."""
        with self._lock:
            self._stop_emulator()


@functools.cache
def emulator_manager() -> _EmulatorManager:
    """Return the process-wide emulator manager."""
    return _EmulatorManager()
