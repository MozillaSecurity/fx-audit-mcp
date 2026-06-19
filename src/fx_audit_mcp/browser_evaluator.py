"""Evaluate testcase tool for testing vulnerabilities in Firefox."""

from __future__ import annotations

import re
import sys
import tempfile
import threading
from contextlib import suppress
from functools import partial
from logging import ERROR, getLogger
from pathlib import Path
from typing import TYPE_CHECKING, Any

import psutil
from FTB.Signatures.CrashSignature import CrashSignature
from grizzly.common.storage import TestCase
from grizzly.replay.replay import ReplayManager
from grizzly.target import TargetLaunchTimeout
from grizzly.target.firefox_target import FirefoxTarget
from prefpicker import PrefPicker
from sapphire import Sapphire

from .models import BrowserCrashInfo, Logs

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from grizzly.common.report import Report

MAX_LOG_SIZE = 1_048_576  # bytes; logs are tail-truncated to this limit
IGNORED_SIGNATURES_DIR = Path(__file__).parent / "ignored_signatures"

# Firefox child process-type token (trailing cmdline arg of a "-contentproc"
# process) -> the BrowserCrashInfo field that flags a crash in that process.
# The parent process has no "-contentproc" arg and is matched by PID instead.
_PROCESS_TYPE_FIELDS: dict[str, str] = {
    "tab": "crashed_content",
    "gpu": "crashed_gpu",
    "rdd": "crashed_rdd",
    "gmplugin": "crashed_gmp",
    "socket": "crashed_socket",
    "utility": "crashed_utility",
}

# Every per-process crash flag on BrowserCrashInfo, parent first.
_ALL_CRASH_FIELDS: tuple[str, ...] = ("crashed_parent", *_PROCESS_TYPE_FIELDS.values())

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)

# Baseline prefs written to every profile launched by browser_evaluator.
# Quiets log spam and prevents network calls that slow down or noise up runs.
_BASELINE_PREFS: dict[str, str | int | bool] = {
    # Disable Experiments / Normandy
    "app.normandy.enabled": False,
    "app.shield.optoutstudies.enabled": False,
    # Disable application updates
    "app.update.disabledForTesting": True,
    # Disable BackupService (errors about Documents directory)
    "browser.backup.enabled": False,
    # Prevent activity stream feeds from initializing (CDN errors)
    "browser.newtabpage.enabled": False,
    "browser.newtabpage.activity-stream.testing.shouldInitializeFeeds": False,
    # Disable region detection network fetch
    "browser.region.network.url": "",
    "browser.region.update.enabled": False,
    # Disable safe browsing list updates
    "browser.safebrowsing.downloads.enabled": False,
    # Disable translations (downloads Bergamot ML language models over the network)
    "browser.translations.enable": False,
    # Disable Merino/URLBar suggestion fetches
    "browser.urlbar.merino.endpointURL": "",
    "browser.urlbar.quicksuggest.enabled": False,
    # Select theme to prevent log spam
    "extensions.activeThemeID": "default-theme@mozilla.org",
    "browser.theme.content-theme": 2,
    "browser.theme.toolbar-theme": 2,
    # Disable system addon and addon repository updates
    "extensions.blocklist.enabled": False,
    "extensions.systemAddon.update.enabled": False,
    "extensions.update.enabled": False,
    # Disable built-in WebExtensions to avoid "context not found" spam
    "extensions.formautofill.addresses.enabled": False,
    "extensions.formautofill.creditCards.enabled": False,
    "extensions.getAddons.cache.enabled": False,
    "extensions.installDistroAddons": False,
    "extensions.webcompat.enabled": False,
    # Disable Firefox Accounts
    "identity.fxaccounts.enabled": False,
    # Disable health report
    "datareporting.healthreport.service.enabled": False,
    # Disable Geolocation
    "geo.enabled": False,
    # Disable GMP plugin downloads (OpenH264, Widevine)
    "media.gmp-manager.updateEnabled": False,
    # Quiet remote settings logging and prevent network hits
    "messaging-system.log": "off",
    # Disable captive portal / connectivity network probes
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
    # Disable Nimbus
    "nimbus.rollouts.enabled": False,
    # Disable tracking-list updates
    "privacy.trackingprotection.enabled": False,
    # Disable Remote Settings
    "services.settings.loglevel": "off",
    "services.settings.server": "data:,#remote-settings-dummy/v1",
    # Disable Sync addons
    "services.sync.engine.addons": False,
    # Disable telemetry
    "toolkit.telemetry.enabled": False,
}


class _FxAuditFirefoxTarget(FirefoxTarget):
    """Firefox target that records the parent PID at launch time."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        super().__init__(*args, **kwargs)
        self.parent_pid: int | None = None
        # Set when launch() catches TargetLaunchTimeout; caller is responsible
        # for reading the report's path and calling its cleanup().
        self.launch_timeout_report: Report | None = None

    def launch(self, location: str) -> None:  # pragma: no cover
        """Override to capture parent PID right after Firefox launches."""
        try:
            super().launch(location)
        except TargetLaunchTimeout:
            # Save logs so caller can surface them; grizzly's launch path
            # discards logs for timeouts (unlike TargetLaunchError).
            self.launch_timeout_report = self.create_report(is_hang=True)
            raise
        # Capture parent PID immediately after launch
        if hasattr(self, "_puppet"):
            self.parent_pid = self._puppet.get_pid()


class _ProcessTreeSampler:
    """Accumulate a ``{pid: process_type}`` map from a live Firefox tree.

    Child processes (content/GPU/RDD/...) spawn during a run and are gone by
    the time the crash report is read, and ASAN builds write no minidump
    ``ProcessType`` annotation. So a background thread periodically walks the
    live tree and records each child's type from its command line. A crashing
    process was alive on earlier ticks, so accumulating (never evicting) lets
    us classify it even if the final sample is missed.
    """

    def __init__(
        self,
        list_procs: Callable[[], Iterable[tuple[int, list[str]]]],
        interval: float = 0.1,
    ) -> None:
        self._list_procs = list_procs
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._pid_types: dict[int, str] = {}

    def _run(self) -> None:  # pragma: no cover
        while not self._stop.is_set():
            _record_process_types(self._pid_types, self._list_procs())
            self._stop.wait(self._interval)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def pid_types(self) -> dict[int, str]:
        """A snapshot copy of the accumulated ``{pid: process_type}`` map."""
        return dict(self._pid_types)


def _list_target_processes(
    target: _FxAuditFirefoxTarget,
) -> Iterable[tuple[int, list[str]]]:
    """Yield ``(pid, cmdline)`` for the target's parent and its descendants.

    Yields nothing until the browser has launched (``parent_pid`` is set).
    Processes that vanish mid-walk are skipped.
    """
    parent_pid = target.parent_pid
    if parent_pid is None:
        return
    try:
        parent = psutil.Process(parent_pid)
        procs = [parent, *parent.children(recursive=True)]
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return
    for proc in procs:
        with suppress(psutil.NoSuchProcess, psutil.AccessDenied):
            yield proc.pid, proc.cmdline()


def _record_process_types(
    pid_types: dict[int, str],
    procs: Iterable[tuple[int, list[str]]],
) -> None:
    """Record the process type of every child in *procs* into *pid_types*.

    Entries accumulate and are never evicted, so a process that has since left
    the tree stays classified.
    """
    for pid, cmdline in procs:
        process_type = _cmdline_process_type(cmdline)
        if process_type is not None:
            pid_types[pid] = process_type


def _cmdline_process_type(cmdline: list[str]) -> str | None:
    """Return the Firefox child process type token from a command line.

    Child processes carry a ``-contentproc`` arg and the process-type token
    (e.g. ``tab``, ``gpu``, ``rdd``) as the trailing argument. The token is
    validated against the known set rather than trusting position blindly.
    Returns None for the parent process or any unrecognized child.
    """
    if "-contentproc" not in cmdline:
        return None
    for token in reversed(cmdline):
        if token in _PROCESS_TYPE_FIELDS:
            return token
    return None


def _extract_crash_pid(crashdata: str) -> int | None:
    """Extract the crashing process PID from ASAN output.

    Args:
        crashdata: ASAN crash output.

    Returns:
        PID of the crashing process, or None if no ASAN PID marker is present.
    """
    # ASAN format: ==PID==ERROR: AddressSanitizer: ...
    match = re.search(r"==(\d+)==ERROR:", crashdata)
    if match:
        return int(match.group(1))
    return None


def _classify_crash(
    parent_pid: int | None,
    pid_types: dict[int, str],
    crashdata: str,
) -> dict[str, bool]:
    """Map the ASAN crash PID to the per-process crash flags.

    A crash happens in exactly one process, so at most one returned flag is
    True. When the crashing PID can't be determined (no ASAN marker) or its
    process type was never sampled, every flag is False: the crash is real but
    we can't attribute it to a process.

    Args:
        parent_pid: PID of the Firefox parent process, if known.
        pid_types: Accumulated ``{pid: process_type}`` map from the run.
        crashdata: ASAN crash output.

    Returns:
        Mapping of every BrowserCrashInfo per-process flag to a bool.
    """
    result = dict.fromkeys(_ALL_CRASH_FIELDS, False)
    crash_pid = _extract_crash_pid(crashdata)
    if crash_pid is None:
        return result
    if parent_pid is not None and crash_pid == parent_pid:
        result["crashed_parent"] = True
        return result
    process_type = pid_types.get(crash_pid)
    field = _PROCESS_TYPE_FIELDS.get(process_type) if process_type else None
    if field is not None:
        result[field] = True
    return result


def _collect_dump_files(dump_dir: Path) -> dict[str, str]:
    """Read all files under *dump_dir* into a relative-path → contents dict.

    Paths in the returned mapping use forward slashes regardless of platform
    so downstream consumers (LLM agents, packaged testcases) see portable
    keys.

    Args:
        dump_dir: Directory containing files dumped by grizzly's testcase.dump().

    Returns:
        Mapping of file path (POSIX-style, relative to *dump_dir*) to file
        contents, decoded as UTF-8 with replacement for invalid sequences.
    """
    files: dict[str, str] = {}
    for file_path in dump_dir.rglob("*"):
        if file_path.is_file():
            relative_name = file_path.relative_to(dump_dir)
            with file_path.open(encoding="utf-8", errors="replace") as f:
                files[relative_name.as_posix()] = f.read()
    return files


def _load_ignored_signatures() -> list[CrashSignature]:
    """Load FuzzManager crash signatures from the ignored_signatures directory.

    Returns:
        List of CrashSignature instances loaded from each ``*.json`` file in
        IGNORED_SIGNATURES_DIR (empty if the directory does not exist).
    """
    if not IGNORED_SIGNATURES_DIR.is_dir():
        return []
    return [
        CrashSignature.fromFile(p)
        for p in sorted(IGNORED_SIGNATURES_DIR.glob("*.json"))
    ]


def read_grizzly_logs(log_dir: Path) -> Logs:
    """Categorize log_*.txt files in *log_dir* into stderr/stdout/crashdata.

    Files larger than MAX_LOG_SIZE are tail-truncated.

    Args:
        log_dir: Directory containing log_*.txt files emitted by grizzly.

    Returns:
        Logs with stderr, stdout, and crashdata populated from matched files.
    """
    logs: dict[str, str] = {"stderr": "", "stdout": "", "crashdata": ""}

    for log_path in log_dir.glob("log_*.txt"):
        with log_path.open(encoding="utf-8", errors="replace") as f:
            size = log_path.stat().st_size
            if size > MAX_LOG_SIZE:
                f.seek(size - MAX_LOG_SIZE)
            log_content = f.read()
            log_name = log_path.name.lower()
            if "stderr" in log_name:
                logs["stderr"] += log_content
            elif "stdout" in log_name:
                logs["stdout"] += log_content
            else:
                logs["crashdata"] += log_content

    return Logs(**logs)


async def package_testcase(
    testcase_path: Path,
    entry_point: str,
    prefs: dict[str, str | int | bool] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Bundle a Firefox crash reproducer directory (HTML/JS files plus prefs
    and env) into a replayable grizzly TestCase suitable for browser_evaluator
    or the standalone grizzly replay tool.

    Custom prefs are merged on top of the prefpicker browser-fuzzing template
    and the baseline prefs; the emitted prefs.js holds the full effective set.

    Args:
        testcase_path: Path to a directory containing all files in the testcase
            (e.g. ``/tmp/my-testcase``).
        entry_point: Filename within ``testcase_path`` that the browser loads
            first; must exist in ``testcase_path`` (e.g. ``test.html``).
        prefs: Optional custom Firefox preferences to layer on top of the
            baseline (e.g. ``{"dom.workers.enabled": False}``).
        env: Optional environment variables to record on the bundled testcase
            (e.g. ``{"MOZ_LOG": "ConsoleAPI:5"}``).

    Returns:
        Path to the bundled grizzly testcase directory.
    """
    testcase = TestCase(
        entry_point=entry_point,
        adapter_name="fx-audit",
        input_fname=entry_point,
    )

    try:
        for file_path in testcase_path.rglob("*"):
            if not file_path.is_file():
                continue
            relative_name = file_path.relative_to(testcase_path).as_posix()
            is_entry = relative_name == entry_point
            testcase.add_from_file(
                file_path,
                file_name=relative_name,
                required=is_entry,
            )

        merged_prefs: dict[str, str | int | bool] = dict(_BASELINE_PREFS)
        if prefs:
            merged_prefs.update(prefs)

        assets_dir = Path(tempfile.mkdtemp(prefix="fx_audit_assets_"))
        prefs_path = assets_dir / "prefs.js"
        template = PrefPicker.lookup_template("browser-fuzzing.yml")
        assert template is not None
        PrefPicker.load_template(template).create_prefsjs(
            prefs_path,
            additional_prefs=merged_prefs,
        )
        testcase.assets = {"prefs": "prefs.js"}
        testcase.assets_path = assets_dir

        if env:
            testcase.env_vars = dict(env)

        output_dir = Path(tempfile.mkdtemp(prefix="fx_audit_pkg_"))
        testcase.dump(output_dir, include_details=True)
    finally:
        testcase.cleanup()

    return str(output_dir)


async def browser_evaluator(  # pragma: no cover
    content: str,
    filename: str,
    firefox_binary: Path,
    timeout: int = 30,
    prefs: dict[str, str | int | bool] | None = None,
) -> BrowserCrashInfo:
    """Reproduce a Firefox crash by running an HTML/JS testcase under
    ASAN-instrumented Firefox and reporting any crash detected.

    Testcases are served over HTTP.

    On Linux, Firefox uses Xvfb (virtual framebuffer X server) as its display.
    On other platforms, the OS default display is used (visible window).

    The following environment variables are always set on the browser process:
    - MOZ_LOG=console:5,PageMessages:5

    The ``prefs`` argument is merged on top of a hardened baseline of Firefox
    prefs; caller-supplied values override the baseline.

    Ignored-signature matches (loaded from ``ignored_signatures/``) are
    filtered out before this returns. Captured logs are tail-truncated to
    MAX_LOG_SIZE. On crash, the dumped testcase directory contents are
    returned alongside the logs.

    Args:
        content: Testcase file contents as a string, not a path on disk.
        filename: Filename to give the testcase when written to disk; controls
            the extension Firefox uses to dispatch the file.
        firefox_binary: Absolute path to the Firefox binary.
        timeout: Per-run timeout in seconds before closing the browser.
        prefs: Optional custom Firefox prefs to layer on top of the baseline.
    """
    if not firefox_binary.exists():
        raise FileNotFoundError(f"Firefox binary not found at {firefox_binary}")

    testcase = TestCase(
        entry_point=filename,
        adapter_name="fx-audit",
        input_fname=filename,
    )

    # Add testcase content from bytes (creates temp file internally)
    testcase.add_from_bytes(content.encode("utf-8"), filename, required=True)

    # Use our custom target to capture parent PID
    # xvfb is only available on Linux; use default display mode on other platforms
    display_mode = "xvfb" if sys.platform == "linux" else "default"
    target = _FxAuditFirefoxTarget(
        binary=firefox_binary,
        display_mode=display_mode,
        launch_timeout=30,
        log_limit=0,
        memory_limit=0,
    )

    # Enable verbose logging
    target.environ["MOZ_LOG"] = "console:5,PageMessages:5"

    # Minimize log spam from mesa
    target.environ["EGL_LOG_LEVEL"] = "fatal"

    # Always generate prefs.js from prefpicker template with hardcoded
    # baseline prefs, plus any user-supplied custom prefs on top.
    # These are set on the target profile (not the testcase) so they
    # don't appear in testcase dump output.
    merged_prefs = {**_BASELINE_PREFS, **prefs} if prefs else _BASELINE_PREFS
    with tempfile.TemporaryDirectory(prefix="fx_audit_prefs_") as prefs_dir:
        prefs_path = Path(prefs_dir) / "prefs.js"
        template = PrefPicker.lookup_template("browser-fuzzing.yml")
        assert template is not None
        PrefPicker.load_template(template).create_prefsjs(
            prefs_path,
            additional_prefs=merged_prefs,
        )
        target.asset_mgr.add("prefs", prefs_path)

    # Process assets (prefs, etc.) - required for Firefox to launch properly
    target.process_assets()

    # Sample the live process tree throughout the run so we can attribute a
    # crash to its process type (parent vs. content/GPU/RDD/...).
    sampler = _ProcessTreeSampler(partial(_list_target_processes, target))

    results = []
    try:
        sampler.start()
        with Sapphire(auto_close=1) as server:
            target.reverse(server.port, server.port)
            with ReplayManager(
                ignore=frozenset(["timeout"]),
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
                    )
                except TargetLaunchTimeout:
                    if target.launch_timeout_report is None:
                        raise
                    logs = read_grizzly_logs(target.launch_timeout_report.path)
                    # A child process (content/GPU/etc.) can crash with ASAN
                    # while the parent stays alive and the bootstrap times out.
                    if logs.crashdata:
                        return BrowserCrashInfo(
                            crashed=True,
                            **_classify_crash(
                                target.parent_pid,
                                sampler.pid_types,
                                logs.crashdata,
                            ),
                            files={},
                            logs=logs,
                            message="Crash detected",
                        )
                    return BrowserCrashInfo(
                        crashed=False,
                        message=(
                            "Firefox failed to launch within the timeout - "
                            "check logs for the underlying cause"
                        ),
                        logs=logs,
                    )

        if not results:
            with tempfile.TemporaryDirectory(prefix="fx_audit_logs_") as log_dir_str:
                log_dir = Path(log_dir_str)
                target.save_logs(log_dir)
                return BrowserCrashInfo(
                    crashed=False,
                    message=(
                        "No crash detected - check logs for clues "
                        "about why the testcase didn't trigger the vulnerability"
                    ),
                    logs=read_grizzly_logs(log_dir),
                )

        result_obj = results[0]
        report = result_obj.report
        with tempfile.TemporaryDirectory(prefix="fx_audit_dump_") as dump_dir_str:
            dump_dir = Path(dump_dir_str)
            testcase.dump(dump_dir, include_details=True)
            logs = read_grizzly_logs(report.path)
            return BrowserCrashInfo(
                crashed=True,
                **_classify_crash(target.parent_pid, sampler.pid_types, logs.crashdata),
                files=_collect_dump_files(dump_dir),
                logs=logs,
                message="Crash detected",
            )

    finally:
        sampler.stop()
        testcase.cleanup()
        if target.launch_timeout_report is not None:
            target.launch_timeout_report.cleanup()
        target.cleanup()
        for result_obj in results:
            result_obj.report.cleanup()
