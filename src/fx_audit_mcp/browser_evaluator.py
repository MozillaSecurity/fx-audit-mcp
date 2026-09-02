"""Evaluate testcase tool for testing vulnerabilities in Firefox."""

from __future__ import annotations

import os
import re
import sys
import tempfile
from logging import ERROR, getLogger
from pathlib import Path
from shutil import copytree
from typing import TYPE_CHECKING, Any

from FTB.Signatures.CrashSignature import CrashSignature
from grizzly.common.storage import TestCase
from grizzly.replay.replay import ReplayManager
from grizzly.target import TargetLaunchTimeout
from grizzly.target.firefox_target import FirefoxTarget
from prefpicker import PrefPicker
from sapphire import Sapphire

from .logs import LOG_DIR_PREFIX
from .models import BrowserCrashInfo, CrashLogPaths

if TYPE_CHECKING:
    from collections.abc import Iterator

    from grizzly.common.report import Report


IGNORED_SIGNATURES_DIR = Path(__file__).parent / "ignored_signatures"
PREF_BLOCKLIST_ENV = "FIREFOX_PREF_BLOCKLIST"

# Idle detection is what separates a finished run from a hang once the time
# limit expires: a browser under this CPU threshold stopped requesting files
# because it was done, anything above it is still working. The value is
# grizzly's own, what FirefoxTarget.handle_hang tests against.
_IDLE_THRESHOLD = 15

_USER_PREF_RE = re.compile(r'user_pref\(\s*"([^"]+)"')
_ASAN_PID_RE = re.compile(r"==(\d+)==ERROR:")
_CHILD_LAUNCH_RE = re.compile(
    r"\+\+PROCESS \[pid = (\d+)\] \[childID = \d+\] \[type = (.*)\]"
)
_PTYPE_TO_FIELD_MAP: dict[str, str] = {
    "tab": "crashed_content",
    "gpu": "crashed_gpu",
    "rdd": "crashed_rdd",
    "gmplugin": "crashed_gmp",
    "socket": "crashed_socket",
    "utility": "crashed_utility",
}

# Suppress grizzly's verbose logging (but allow CRITICAL and ERROR)
getLogger("grizzly").setLevel(ERROR)
getLogger("ffpuppet").setLevel(ERROR)
getLogger("sapphire").setLevel(ERROR)


class _FxAuditFirefoxTarget(FirefoxTarget):
    """Firefox target that records the parent PID at launch time."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover
        super().__init__(*args, **kwargs)
        self.parent_pid: int | None = None
        # Set when launch() catches TargetLaunchTimeout; caller is responsible
        # for reading the report's path and calling its cleanup().
        self.launch_timeout_report: Report | None = None
        # Grizzly calls handle_hang() only when a run hits its time limit, but
        # produces a hang report solely for busy hangs on Linux (elsewhere, and
        # for idle hangs, the browser is just closed), so this flag is then the
        # only record that the browser was still busy when the limit expired.
        self.hang_detected = False

    def handle_hang(
        self, ignore_idle: bool = True, ignore_timeout: bool = False
    ) -> bool:
        was_idle = super().handle_hang(
            ignore_idle=ignore_idle, ignore_timeout=ignore_timeout
        )
        # Only a browser still burning CPU at the time limit is a hang; an idle
        # one finished its work and simply stopped requesting files, which is a
        # clean run and must not be reported as a timeout.
        self.hang_detected = not was_idle
        return was_idle

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


def _scan_lines(log_paths: list[str]) -> Iterator[str]:
    """Yield every line of each file in *log_paths*, in path order.

    Logs are untruncated and can be arbitrarily large, so they are streamed a
    line at a time and never held in memory whole. Scanning at line granularity
    loses nothing: both patterns matched against these lines
    (``==<pid>==ERROR:`` and the ``++PROCESS`` launch record) are emitted on a
    single line, so no match can straddle a line boundary.

    Args:
        log_paths: Paths of the log files to read, in the order to read them.

    Yields:
        Each line of each file, decoded as UTF-8 with replacement for invalid
        sequences.
    """
    for path in log_paths:
        with Path(path).open(encoding="utf-8", errors="replace") as log_file:
            yield from log_file


def _extract_crash_pids(log_paths: list[str]) -> list[int]:
    """Extract the PIDs of all crashing processes from ASAN output.

    Args:
        log_paths: Paths of the crashdata logs holding the ASAN output.

    Returns:
        PIDs of the crashing processes, in report order. Empty if no ASAN PID
        marker is present.
    """
    return [
        int(match.group(1))
        for line in _scan_lines(log_paths)
        for match in _ASAN_PID_RE.finditer(line)
    ]


def _extract_child_ptypes(log_paths: list[str]) -> dict[int, str]:
    """Map each launched child PID to its GeckoProcessType.

    Reads the ChildProcessLifecycle log the parent writes to stderr (enabled
    via the MOZ_LOG modules set by browser_evaluator). A PID that carries no
    launch record is absent from the mapping - the parent is never launched as
    a child, and a record is missing when the parent died before flushing it.

    Args:
        log_paths: Paths of the stderr logs captured during the run.

    Returns:
        Mapping of child PID to process type (e.g. "tab", "gpu"). A PID can be
        reused, so the last launch wins.
    """
    return {
        int(match.group(1)): match.group(2)
        for line in _scan_lines(log_paths)
        for match in _CHILD_LAUNCH_RE.finditer(line)
    }


def _crashed_process_fields(
    log_paths: CrashLogPaths, parent_pid: int | None
) -> dict[str, bool | None]:
    """Determine which process a crash occurred in.

    Args:
        log_paths: Log files captured for the crash. The ASAN PIDs are read
            from the crashdata logs and resolved against the
            ChildProcessLifecycle records in the stderr logs.
        parent_pid: PID of the Firefox parent process, or None if unknown.

    Returns:
        The BrowserCrashInfo process flags. Multiple processes can crash in a
        single run, so more than one flag can be True. A parent-only crash
        reports every child process flag as False. Child flags are only False
        once every crashing PID has been attributed: any PID that is neither
        the parent nor carries a launch record in stderr leaves the
        unidentified child flags None, so an unresolved crash is not reported
        as having happened in none of these processes. When crashdata carries
        no ASAN PID marker at all, every flag is None.
    """
    crash_pids = _extract_crash_pids(log_paths.crashdata)
    if not crash_pids:
        return dict.fromkeys(("crashed_parent", *_PTYPE_TO_FIELD_MAP.values()), None)

    pfields: dict[str, bool | None] = dict.fromkeys(
        ("crashed_parent", *_PTYPE_TO_FIELD_MAP.values()), False
    )
    if parent_pid is None:
        pfields["crashed_parent"] = None

    child_ptypes = _extract_child_ptypes(log_paths.stderr)
    for crash_pid in crash_pids:
        if crash_pid == parent_pid:
            pfields["crashed_parent"] = True
            continue

        crash_ptype = child_ptypes.get(crash_pid)
        if pfield_name := _PTYPE_TO_FIELD_MAP.get(crash_ptype or ""):
            pfields[pfield_name] = True
            continue

        # Resolved type without a flag of its own (e.g. "vr", "forkserver"):
        # not reportable, but it still rules the tracked types out.
        if crash_ptype:
            continue

        # Unattributable PID: keep what was positively identified, but reset
        # the other child flags to None rather than ruling them out.
        for pfield_name in _PTYPE_TO_FIELD_MAP.values():
            pfields[pfield_name] = pfields[pfield_name] or None

    return pfields


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


def _check_pref_blocklist(prefs_path: Path, pref_blocklist: list[str]) -> None:
    """Raise if any blocklisted pref name appears in the generated prefs.js.

    Matching is by pref name only (value-independent). All matched prefs are
    named in the raised error message.

    Args:
        prefs_path: Path to the generated prefs.js to inspect.
        pref_blocklist: Pref names that must not appear in prefs.js.

    Raises:
        ValueError: If one or more blocklisted pref names are present.
    """
    blocked = set(pref_blocklist)
    present = {
        m.group(1)
        for line in prefs_path.read_text(encoding="utf-8").splitlines()
        for m in (_USER_PREF_RE.match(line.strip()),)
        if m
    }
    matched = sorted(present & blocked)
    if matched:
        message = f"Blocked prefs detected: {', '.join(matched)}"
        raise ValueError(message)


def _load_pref_blocklist() -> list[str]:
    """Load blocked pref names from the file named by PREF_BLOCKLIST_ENV.

    Blank lines and lines starting with ``#`` are ignored.

    Returns:
        Blocked pref names in file order, or an empty list when the env var is
        unset.

    Raises:
        FileNotFoundError: If the env var is set but the file does not exist.
    """
    path_str = os.environ.get(PREF_BLOCKLIST_ENV)
    if not path_str:
        return []
    path = Path(path_str)
    if not path.is_file():
        raise FileNotFoundError(
            f"Pref blocklist file not found at {path} (from ${PREF_BLOCKLIST_ENV})"
        )
    return [
        stripped
        for line in path.read_text(encoding="utf-8").splitlines()
        if (stripped := line.strip()) and not stripped.startswith("#")
    ]


def _build_testcase(file_paths: dict[str, Path], entry_point: str) -> TestCase:
    """Build a grizzly TestCase from files on disk.

    Args:
        file_paths: Mapping of the name a file should have in the testcase
            (relative to the testcase root, forward slashes for
            subdirectories) to the source file's path on disk.
        entry_point: Name of the file in *file_paths* the browser loads first.

    Returns:
        TestCase containing every file, with the entry point marked required.
    """
    testcase = TestCase(
        entry_point=entry_point,
        adapter_name="fx-audit",
        input_fname=entry_point,
    )
    try:
        for name, src in file_paths.items():
            # Compare sanitized paths: grizzly normalizes both, so a caller
            # passing "/test.html" still matches the "test.html" key.
            is_entry = TestCase.sanitize_path(name) == testcase.entry_point
            # copy: grizzly moves by default, which would consume the
            # caller's source files.
            testcase.add_from_file(src, file_name=name, required=is_entry, copy=True)
        if testcase.entry_point not in testcase:
            raise ValueError(
                f"entry_point '{entry_point}' not found in file_paths: "
                f"{sorted(file_paths)}"
            )
    except Exception:
        # TestCase allocates a temp directory on creation; drop it before the
        # rejected input propagates to the caller.
        testcase.cleanup()
        raise
    return testcase


def _categorize_logs(log_dir: Path) -> CrashLogPaths:
    """Categorize the log_*.txt files in *log_dir* into stderr/stdout/crashdata.

    Args:
        log_dir: Directory containing log_*.txt files emitted by grizzly.

    Returns:
        CrashLogPaths holding the absolute path of every matched file, sorted
        within each category. Categories with no matching file are empty.
    """
    paths: dict[str, list[str]] = {"stderr": [], "stdout": [], "crashdata": []}

    for path in sorted(log_dir.glob("log_*.txt")):
        log_name = path.name.lower()
        if "stderr" in log_name:
            paths["stderr"].append(str(path))
        elif "stdout" in log_name:
            paths["stdout"].append(str(path))
        else:
            paths["crashdata"].append(str(path))

    return CrashLogPaths(**paths)


async def package_testcase(
    testcase_path: Path,
    entry_point: str,
    prefs: dict[str, str | int | bool] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    """Bundle a Firefox crash reproducer directory (HTML/JS files plus prefs
    and env) into a replayable grizzly TestCase suitable for browser_evaluator
    or the standalone grizzly replay tool.

    Custom prefs are merged on top of the prefpicker browser-fuzzing template;
    the emitted prefs.js holds the full effective set.

    Args:
        testcase_path: Path to a directory containing all files in the testcase
            (e.g. ``/tmp/my-testcase``).
        entry_point: Filename within ``testcase_path`` that the browser loads
            first; must exist in ``testcase_path`` (e.g. ``test.html``).
        prefs: Optional custom Firefox preferences to layer on top of the
            prefpicker template (e.g. ``{"dom.workers.enabled": False}``).
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

        assets_dir = Path(tempfile.mkdtemp(prefix="fx_audit_assets_"))
        prefs_path = assets_dir / "prefs.js"
        template = PrefPicker.lookup_template("browser-fuzzing.yml")
        assert template is not None
        PrefPicker.load_template(template).create_prefsjs(
            prefs_path,
            variant="code-review",
            additional_prefs=prefs,
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
    file_paths: dict[str, Path],
    entry_point: str,
    firefox_binary: Path,
    timeout: int = 30,
    prefs: dict[str, str | int | bool] | None = None,
    enable_sandbox: bool = False,
) -> BrowserCrashInfo:
    """Reproduce a Firefox crash by running an HTML/JS testcase under
    ASAN-instrumented Firefox and reporting any crash detected.

    Testcases are served over HTTP.

    On Linux, Firefox uses Xvfb (virtual framebuffer X server) as its display.
    On other platforms, the OS default display is used (visible window).

    The following environment variables are always set on the browser process:
    - MOZ_LOG=console:5,PageMessages:5,ChildProcessLifecycle:5

    By default the browser sandbox is disabled via the MOZ_DISABLE_*_SANDBOX
    environment variables (content, GMP, GPU, RDD, socket process, utility and
    VR). Setting ``enable_sandbox`` removes those variables so the sandbox
    stays enabled.

    The ``prefs`` argument is merged on top of the prefpicker browser-fuzzing
    template; caller-supplied values override the template.

    When the ``FIREFOX_PREF_BLOCKLIST`` environment variable names a file, the
    generated prefs.js is checked against the blocked pref names it lists (one
    per line); a match raises ValueError before Firefox launches. This guard
    cannot be disabled by the caller.

    Ignored-signature matches (loaded from ``ignored_signatures/``) are
    filtered out before this returns.

    Logs are written to a temporary directory. The caller is responsible for
    cleanup.

    Args:
        file_paths: Testcase files, as a mapping of the name each file should
            have in the testcase to its path on disk. Use forward slashes for
            subdirectories (e.g. ``sub/frame.html``). Source files are copied,
            not moved. Binary files (images, fonts, media) are supported. A
            name escaping the testcase root raises ValueError; a missing
            source file raises FileNotFoundError.
        entry_point: Filename within ``file_paths`` that the browser loads
            first; must be present in ``file_paths``, and its extension
            controls how Firefox dispatches the file.
        firefox_binary: Absolute path to the Firefox binary.
        timeout: Run window in seconds; the browser is closed when it expires.
            Raise it for testcases that need more time to reach the
            vulnerable code.
        prefs: Optional custom Firefox prefs to layer on top of the prefpicker
            template.
        enable_sandbox: Leave the Firefox sandbox enabled. Off by default, which
            disables sandboxing so the browser behaves like other fuzzing and
            replay runs. Enabling the sandbox can interfere with crash log
            creation, so crashes may be missed.

    Returns:
        BrowserCrashInfo with:
        - crashed: Boolean indicating if the testcase triggered a crash.
        - timed_out: Boolean indicating if the testcase timed out.
        - crashed_parent, crashed_content, crashed_gpu, crashed_rdd,
          crashed_gmp, crashed_socket, crashed_utility: which process type the
          crash was attributed to; None when attribution was unavailable.
        - logs: Paths to the run's stderr/stdout/crashdata log files.
    """
    if not firefox_binary.exists():
        raise FileNotFoundError(f"Firefox binary not found at {firefox_binary}")

    testcase = _build_testcase(file_paths, entry_point)

    # Use our custom target to capture parent PID
    # xvfb is only available on Linux; use default display mode on other platforms
    display_mode = "xvfb" if sys.platform == "linux" else "default"
    target = _FxAuditFirefoxTarget(
        binary=firefox_binary,
        disable_sandboxing=not enable_sandbox,
        display_mode=display_mode,
        launch_timeout=30,
        log_limit=0,
        memory_limit=0,
        report_size_limit=0,
    )

    # Enable verbose logging
    target.environ["MOZ_LOG"] = "console:5,PageMessages:5,ChildProcessLifecycle:5"

    # Minimize log spam from mesa
    target.environ["EGL_LOG_LEVEL"] = "fatal"

    # Always generate prefs.js from the prefpicker template, plus any
    # user-supplied custom prefs on top. These are set on the target profile
    # (not the testcase) so they don't appear in testcase dump output.
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

    # Process assets (prefs, etc.) - required for Firefox to launch properly
    target.process_assets()

    # Removed below only if it ends up empty - otherwise the caller owns it.
    log_dir = Path(tempfile.mkdtemp(prefix=LOG_DIR_PREFIX))

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
                        # Hold the first idle poll until the time limit is up.
                        # Sapphire tests the idle callback before the deadline,
                        # so polling any sooner ends the run at that poll
                        # instead: a testcase that waits before triggering its
                        # bug (a timer, a slow load) would be closed as a clean
                        # run having never reached it, whatever the timeout.
                        idle_delay=timeout,
                    )
                except TargetLaunchTimeout:
                    if target.launch_timeout_report is None:
                        raise TimeoutError(
                            "Firefox failed to launch within the timeout"
                        ) from None
                    copytree(
                        target.launch_timeout_report.path,
                        log_dir,
                        dirs_exist_ok=True,
                    )
                    log_paths = _categorize_logs(log_dir)
                    # A child process (content/GPU/etc.) can crash with ASAN
                    # while the parent stays alive and the bootstrap times out.
                    # Test file size rather than the crash PIDs: UBSAN reports
                    # carry no ==pid==ERROR: marker, so a PID scan would miss
                    # them here.
                    if any(Path(path).stat().st_size for path in log_paths.crashdata):
                        return BrowserCrashInfo(
                            crashed=True,
                            timed_out=False,
                            **_crashed_process_fields(log_paths, target.parent_pid),
                            logs=log_paths,
                        )
                    # The copied launch logs are the only diagnostics for this
                    # failure; hand the caller their location, as with any
                    # returned log dir, rather than stranding the directory.
                    raise TimeoutError(
                        "Firefox failed to launch within the timeout; "
                        f"launch logs are in {log_dir}"
                    ) from None

        if not results:
            target.save_logs(log_dir)
            return BrowserCrashInfo(
                crashed=False,
                # A hang that produced no report (idle hang, or any hang on
                # non-Linux) still timed out; only the flag records it.
                timed_out=target.hang_detected,
                logs=_categorize_logs(log_dir),
            )

        result_obj = results[0]
        # Copy before the finally block rmtree()s the report dir.
        copytree(result_obj.report.path, log_dir, dirs_exist_ok=True)
        log_paths = _categorize_logs(log_dir)
        if result_obj.report.is_hang:
            return BrowserCrashInfo(
                crashed=False,
                timed_out=True,
                logs=log_paths,
            )
        return BrowserCrashInfo(
            crashed=True,
            timed_out=False,
            **_crashed_process_fields(log_paths, target.parent_pid),
            logs=log_paths,
        )

    finally:
        testcase.cleanup()
        if target.launch_timeout_report is not None:
            target.launch_timeout_report.cleanup()
        target.cleanup()
        for result_obj in results:
            result_obj.report.cleanup()
        if not any(log_dir.iterdir()):
            log_dir.rmdir()
