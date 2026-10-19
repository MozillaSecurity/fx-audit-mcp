"""Evaluate testcase tool for testing vulnerabilities in Firefox on Android.

The Android counterpart of :mod:`browser_evaluator`: the same grizzly replay
loop, driving GeckoView (geckoview_example or Fenix) on an emulator or device
through fxpoppet's ``FenixTarget`` instead of ffpuppet. The emulator must
already be running; one evaluator owns one device at a time, so several
clauditors share a machine by each pointing ``ANDROID_SERIAL`` at their own
emulator (see ``fx-audit-android-emulator``).
"""

from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import re
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from logging import ERROR, getLogger
from pathlib import Path, PurePosixPath
from shutil import copytree
from typing import TYPE_CHECKING, Any

from fxpoppet.adb_session import ADBSession, ADBSessionError
from fxpoppet.adb_wrapper import ADBWrapper
from grizzly.replay.replay import ReplayManager
from grizzly.target import TargetLaunchError, TargetLaunchTimeout
from grizzly.target.fenix_target import FenixTarget
from prefpicker import PrefPicker
from sapphire import Sapphire

from .android_emulator import AUTOSTART_ENV, adb_path, boot_serial, restart_serial
from .asan_symbolize import Symbolizer
from .browser_evaluator import (
    _IDLE_THRESHOLD,
    ProcessFlags,
    _build_testcase,
    _check_pref_blocklist,
    _crashed_process_fields,
    _load_ignored_signatures,
    _load_pref_blocklist,
)
from .logs import LOG_DIR_PREFIX
from .models import BrowserCrashInfo, CrashLogPaths

if TYPE_CHECKING:
    from collections.abc import Iterator

    from grizzly.common.report import Report

LOG = logging.getLogger(__name__)

ANDROID_SERIAL_ENV = "ANDROID_SERIAL"
APK_ENV = "FIREFOX_APK"
SYMBOLS_DIR_ENV = "ANDROID_SYMBOLS_DIR"
LIB_DIR_ENV = "ANDROID_UNSTRIPPED_LIB_DIR"
# sha256 of the APK installed last, kept on the device so an unchanged APK is
# not pushed again on every evaluation (an ASan APK is a few hundred MB).
APK_HASH_FILE = PurePosixPath("/data/local/tmp/fx-audit-apk.sha256")
DEFAULT_TIMEOUT = 60
# ASan GeckoView takes 10-20 s to reach a page on an emulator; the adb side of
# the launch (am start -W) is counted too.
LAUNCH_TIMEOUT = 120
BOOT_TIMEOUT = 60

_LOCK_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")
# FenixTarget picks its device from ANDROID_SERIAL; constructing two targets
# for different devices in one process must not interleave that.
_TARGET_LOCK = threading.Lock()

getLogger("grizzly").setLevel(ERROR)
getLogger("fxpoppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)


class DeviceBusyError(RuntimeError):
    """Another evaluator holds the selected device."""


class _FxAuditFenixTarget(FenixTarget):
    """FenixTarget that records the parent PID and hang/launch-timeout state."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        super().__init__(*args, **kwargs)
        self.parent_pid: int | None = None
        # Set when launch() catches TargetLaunchTimeout; caller is responsible
        # for reading the report's path and calling its cleanup().
        self.launch_timeout_report: Report | None = None
        self.hang_detected = False

    def handle_hang(
        self, ignore_idle: bool = True, ignore_timeout: bool = False
    ) -> bool:
        was_idle = super().handle_hang(
            ignore_idle=ignore_idle, ignore_timeout=ignore_timeout
        )
        self.hang_detected = not was_idle
        return was_idle

    def launch(self, location: str) -> None:  # pragma: no cover
        try:
            super().launch(location)
        except TargetLaunchTimeout:
            self.launch_timeout_report = self.create_report(is_hang=True)
            raise
        # The app's main process; child processes show up as "<package>:tab..."
        assert self._package is not None
        self.parent_pid = self._session.get_pid(self._package)


def _select_serial(device_serial: str | None) -> str:
    """Pick the device to use: the argument, ANDROID_SERIAL, or the only device."""
    serial = device_serial or os.environ.get(ANDROID_SERIAL_ENV)
    if serial:
        return serial
    devices = ADBWrapper.devices(any_state=False)
    if len(devices) == 1:
        return next(iter(devices))
    if not devices:
        raise RuntimeError(
            "No Android device is connected; start an emulator first "
            "(fx-audit-android-emulator start)"
        )
    raise RuntimeError(
        f"Several Android devices are connected ({', '.join(sorted(devices))}); "
        f"set {ANDROID_SERIAL_ENV} or pass device_serial so each evaluator "
        "uses its own"
    )


@contextmanager
def _device_lock(serial: str) -> Iterator[None]:
    """Hold an exclusive lock on the device for the duration of an evaluation.

    Two clauditors must never drive the same emulator: both would install
    APKs, clear logcat and read each other's crashes. The lock is a flock on a
    per-serial file, so it works across processes and is released by the
    kernel if the holder dies.
    """
    lock_dir = Path(tempfile.gettempdir()) / "fx-audit-mcp-android"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{_LOCK_NAME_RE.sub('_', serial)}.lock"
    with lock_path.open("a") as lock_file:
        try:
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeviceBusyError(
                f"Android device {serial} is in use by another evaluator; run one "
                f"clauditor per emulator and point {ANDROID_SERIAL_ENV} at it"
            ) from None
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _connect(serial: str) -> ADBSession:
    """Connect to *serial*, rebooting it first if it is gone and allowed.

    The emulator can die under a long run (qemu hangs have been observed after
    many hours). With ``ANDROID_AUTOSTART_EMULATOR`` set, a connection failure
    boots a fresh read-only instance on the same console port and retries
    once; otherwise the failure propagates as before.
    """
    autostart = os.environ.get(AUTOSTART_ENV, "").lower() in ("1", "true", "yes")
    try:
        session = ADBSession.connect(serial, as_root=True, boot_timeout=BOOT_TIMEOUT)
    except ADBSessionError:
        if not autostart:
            raise
        # A guest that still answers "device" but cannot complete a connection is
        # wedged, not gone: boot_serial() would see it as already up and change
        # nothing (seen 2026-10-19: "Device boot timeout exceeded" three times in a
        # row). Replace it instead.
        if _adb_state(serial) == "device":
            LOG.warning(
                "device %s wedged; replacing it (%s set)", serial, AUTOSTART_ENV
            )
            if not restart_serial(serial):
                raise
        else:
            LOG.warning(
                "device %s unavailable; booting it (%s set)", serial, AUTOSTART_ENV
            )
            if not boot_serial(serial):
                raise
        session = ADBSession.connect(serial, as_root=True, boot_timeout=BOOT_TIMEOUT)
    if _package_service_alive(session):
        return session
    # The guest answers adb but system_server's package service is gone, so
    # every install would fail ("Can't find service: package"). Only a fresh
    # instance fixes that.
    if not autostart:
        raise ADBSessionError(
            f"device {serial} has no working package service; restart the emulator"
        )
    LOG.warning(
        "device %s has no package service; replacing it (%s set)", serial, AUTOSTART_ENV
    )
    if not restart_serial(serial):
        raise ADBSessionError(f"device {serial} could not be replaced")
    session = ADBSession.connect(serial, as_root=True, boot_timeout=BOOT_TIMEOUT)
    if not _package_service_alive(session):
        raise ADBSessionError(
            f"device {serial} still has no package service after a restart"
        )
    return session


def _adb_state(serial: str) -> str | None:
    """``adb get-state`` for *serial*, None when adb has no such device."""
    try:
        result = subprocess.run(
            [str(adb_path()), "-s", serial, "get-state"],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def _package_service_alive(session: ADBSession) -> bool:
    result = session.device.shell(("pm", "path", "android"), timeout=30)
    return result is not None and result.exit_code == 0 and "package:" in result.output


def _ensure_installed(session: ADBSession, apk: Path) -> str:
    """Install the APK unless the same bytes are already on the device.

    Returns:
        The APK's package name.
    """
    package = ADBSession.get_package_name(apk)
    if package is None:
        raise RuntimeError(
            f"Could not read the package name from {apk}; is aapt (Android SDK "
            "build-tools) on PATH?"
        )
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    recorded = session.device.shell(("cat", str(APK_HASH_FILE)))
    if (
        recorded is not None
        and recorded.exit_code == 0
        and recorded.output.strip() == digest
        and session.is_installed(package)
    ):
        return package
    try:
        installed = session.install(apk)
    except ADBSessionError:
        if not session.is_installed(package):
            raise
        # An existing install signed with another debug keystore (a build from
        # a different machine or sandbox) rejects the upgrade; replace it.
        session.device.shell(("pm", "uninstall", package))
        installed = session.install(apk)
    session.device.shell(("sh", "-c", f"echo {digest} > {APK_HASH_FILE}"))
    return installed


def _categorize_logs(log_dir: Path) -> CrashLogPaths:
    """Categorize fxpoppet's log_*.txt files into stderr/stdout/crashdata.

    fxpoppet splits logcat into ``log_stderr.txt``/``log_stdout.txt`` (the
    app's lines) and keeps the whole ``log_logcat.txt``; the ASan report, when
    there is one, is broken out into ``log_asan.txt`` and minidumps into
    ``log_minidump_NN.txt``. The raw logcat goes with stdout so that only
    crash diagnostics land in crashdata.
    """
    paths: dict[str, list[str]] = {"stderr": [], "stdout": [], "crashdata": []}
    for path in sorted(log_dir.glob("log_*.txt")):
        log_name = path.name.lower()
        if "stderr" in log_name:
            paths["stderr"].append(str(path))
        elif "stdout" in log_name or log_name == "log_logcat.txt":
            paths["stdout"].append(str(path))
        else:
            paths["crashdata"].append(str(path))
    return CrashLogPaths(**paths)


def _symbolizer(apk: Path, symbols_dir: Path | None) -> Symbolizer:
    """Build the symbolizer for this APK from the argument, environment or layout."""
    if symbols_dir is None:
        env_dir = os.environ.get(SYMBOLS_DIR_ENV)
        if env_dir:
            symbols_dir = Path(env_dir)
        elif (apk.parent / "symbols").is_dir():
            # fuzzfetch unpacks crashreporter-symbols next to the build.
            symbols_dir = apk.parent / "symbols"
    lib_dir_env = os.environ.get(LIB_DIR_ENV)
    return Symbolizer(
        symbols_dir=symbols_dir, lib_dir=Path(lib_dir_env) if lib_dir_env else None
    )


async def android_browser_evaluator(
    file_paths: dict[str, Path],
    entry_point: str,
    apk: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    prefs: dict[str, str | int | bool] | None = None,
    device_serial: str | None = None,
    symbols_dir: Path | None = None,
) -> BrowserCrashInfo:
    """Reproduce a Firefox for Android crash by running an HTML/JS testcase in
    an ASAN-instrumented GeckoView app on a running Android emulator or device
    and reporting any crash detected.

    Testcases are served over HTTP from the host; the device reaches the
    server through ``adb reverse``. The emulator must already be booted.
    The APK is installed on first use and whenever its bytes change.

    The following environment variables are always set on the app:
    - MOZ_LOG=console:5,PageMessages:5,ChildProcessLifecycle:5

    Prefs are merged on top of the prefpicker browser-fuzzing template and
    checked against ``FIREFOX_PREF_BLOCKLIST`` exactly as for browser_evaluator.
    Ignored-signature matches are filtered out before this returns.

    ASAN frames from the device name only a library and offset, so the report
    in crashdata is symbolized on the host before it is returned, from the
    Breakpad symbols (``symbols_dir``, ``ANDROID_SYMBOLS_DIR``, or a
    ``symbols/`` directory next to the APK) or from unstripped libraries
    (``ANDROID_UNSTRIPPED_LIB_DIR``, e.g. an objdir's ``dist/bin``).

    Logs are written to a temporary directory. The caller is responsible for
    cleanup.

    Args:
        file_paths: Testcase files, as a mapping of the name each file should
            have in the testcase to its path on disk. Use forward slashes for
            subdirectories (e.g. ``sub/frame.html``). Source files are copied,
            not moved. Binary files (images, fonts, media) are supported.
        entry_point: Filename within ``file_paths`` that the app loads first;
            must be present in ``file_paths``.
        apk: The GeckoView app to test (geckoview_example or Fenix, debuggable,
            ASAN-instrumented). Defaults to ``FIREFOX_APK`` from the environment.
        timeout: Run window in seconds; the app is closed when it expires.
            ASAN GeckoView on an emulator is several times slower than desktop
            Firefox, so raise it for testcases that do real work.
        prefs: Optional custom Firefox prefs to layer on top of the prefpicker
            template.
        device_serial: adb serial of the device to use (e.g. ``emulator-5556``).
            Defaults to ``ANDROID_SERIAL``, or the only connected device.
        symbols_dir: Unpacked crashreporter-symbols directory for symbolizing
            the ASAN report.

    Returns:
        BrowserCrashInfo with:
        - crashed: Boolean indicating if the testcase triggered a crash.
        - timed_out: Boolean indicating if the testcase timed out.
        - crashed_parent, crashed_content, crashed_gpu, crashed_rdd,
          crashed_gmp, crashed_socket, crashed_utility: which process type the
          crash was attributed to; None when attribution was unavailable.
        - device_serial: the device the testcase ran on.
        - logs: Paths to the run's stderr/stdout/crashdata log files; the
          symbolized ASAN report is ``log_asan.txt`` in crashdata.
    """
    if apk is None:
        apk_env = os.environ.get(APK_ENV)
        if not apk_env:
            raise ValueError(f"No APK given and {APK_ENV} is not set")
        apk = Path(apk_env)
    if not apk.is_file():
        raise FileNotFoundError(f"APK not found at {apk}")

    serial = _select_serial(device_serial)
    symbolizer = _symbolizer(apk, symbols_dir)

    with _device_lock(serial):
        try:
            session = _connect(serial)
        except ADBSessionError as exc:
            raise RuntimeError(
                f"Could not connect to Android device {serial}: {exc}"
            ) from exc
        try:
            _ensure_installed(session, apk)
        except ADBSessionError as exc:
            raise RuntimeError(f"Could not install {apk} on {serial}: {exc}") from exc

        testcase = _build_testcase(file_paths, entry_point)

        with _TARGET_LOCK:
            previous = os.environ.get(ANDROID_SERIAL_ENV)
            os.environ[ANDROID_SERIAL_ENV] = serial
            try:
                target = _FxAuditFenixTarget(
                    binary=apk,
                    launch_timeout=LAUNCH_TIMEOUT,
                    log_limit=0,
                    memory_limit=0,
                    report_size_limit=0,
                )
            finally:
                if previous is None:
                    del os.environ[ANDROID_SERIAL_ENV]
                else:
                    os.environ[ANDROID_SERIAL_ENV] = previous

        # Child process launch records are what attributes a crash to a
        # process type; on Android MOZ_LOG output reaches logcat.
        target.environ["MOZ_LOG"] = "console:5,PageMessages:5,ChildProcessLifecycle:5"

        with tempfile.TemporaryDirectory(prefix="fx_audit_prefs_") as prefs_dir:
            prefs_path = Path(prefs_dir) / "prefs.js"
            template = PrefPicker.lookup_template("browser-fuzzing.yml")
            assert template is not None
            PrefPicker.load_template(template).create_prefsjs(
                prefs_path,
                variant="code-review",
                additional_prefs=prefs,
            )
            _check_pref_blocklist(prefs_path, _load_pref_blocklist())
            target.asset_mgr.add("prefs", prefs_path)
        target.process_assets()

        # Removed below only if it ends up empty - otherwise the caller owns it.
        log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))

        def finish(crashed: bool, timed_out: bool, attribute: bool) -> BrowserCrashInfo:
            log_paths = _categorize_logs(log_dir)
            for path in log_paths.crashdata:
                symbolizer.symbolize_file(Path(path))
            fields: ProcessFlags = (
                _crashed_process_fields(log_paths, target.parent_pid)
                if attribute
                else {}
            )
            return BrowserCrashInfo(
                crashed=crashed,
                timed_out=timed_out,
                device_serial=serial,
                logs=log_paths,
                **fields,
            )

        results = []
        try:
            with Sapphire(auto_close=1, timeout=timeout) as server:
                target.reverse(server.port, server.port)
                with ReplayManager(
                    ignore=frozenset(),
                    server=server,
                    target=target,
                    ignore_signatures=_load_ignored_signatures(),
                    use_harness=False,
                ) as replay:
                    try:
                        results = replay.run(
                            testcases=[testcase],
                            time_limit=timeout,
                            expect_hang=False,
                            idle_threshold=_IDLE_THRESHOLD,
                            # See browser_evaluator: polling before the time
                            # limit would end a run that is still waiting to
                            # reach its bug.
                            idle_delay=timeout,
                        )
                    except TargetLaunchTimeout:
                        if target.launch_timeout_report is None:
                            raise TimeoutError(
                                "GeckoView failed to launch within the timeout"
                            ) from None
                        copytree(
                            target.launch_timeout_report.path,
                            log_dir,
                            dirs_exist_ok=True,
                        )
                        if any(
                            Path(path).stat().st_size
                            for path in _categorize_logs(log_dir).crashdata
                        ):
                            return finish(crashed=True, timed_out=False, attribute=True)
                        raise TimeoutError(
                            "GeckoView failed to launch within the timeout; "
                            f"launch logs are in {log_dir}"
                        ) from None
                    except TargetLaunchError as exc:
                        # fxpoppet reports every launch failure (device gone,
                        # am start rejected, bootstrap not reached) this way.
                        copytree(exc.report.path, log_dir, dirs_exist_ok=True)
                        exc.report.cleanup()
                        if any(
                            Path(path).stat().st_size
                            for path in _categorize_logs(log_dir).crashdata
                        ):
                            return finish(crashed=True, timed_out=False, attribute=True)
                        raise RuntimeError(
                            f"GeckoView failed to launch on {serial}: {exc}; "
                            f"launch logs are in {log_dir}"
                        ) from None

            if not results:
                target.save_logs(log_dir)
                return finish(
                    crashed=False, timed_out=target.hang_detected, attribute=False
                )

            result_obj = results[0]
            copytree(result_obj.report.path, log_dir, dirs_exist_ok=True)
            if result_obj.report.is_hang:
                return finish(crashed=False, timed_out=True, attribute=False)
            return finish(crashed=True, timed_out=False, attribute=True)

        finally:
            testcase.cleanup()
            if target.launch_timeout_report is not None:
                target.launch_timeout_report.cleanup()
            target.cleanup()
            for result_obj in results:
                result_obj.report.cleanup()
            if not any(log_dir.iterdir()):
                log_dir.rmdir()
