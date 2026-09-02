"""Tests for browser_evaluator.py."""

import asyncio
import inspect
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from grizzly.common import storage as grizzly_storage
from grizzly.common import utils as grizzly_utils
from grizzly.target import TargetLaunchTimeout
from grizzly.target.firefox_target import FirefoxTarget
from pytest_mock import MockerFixture

from fx_audit_mcp.browser_evaluator import (
    PREF_BLOCKLIST_ENV,
    _build_testcase,
    _categorize_logs,
    _check_pref_blocklist,
    _crashed_process_fields,
    _extract_child_ptypes,
    _extract_crash_pids,
    _load_ignored_signatures,
    _load_pref_blocklist,
    browser_evaluator,
    package_testcase,
)
from fx_audit_mcp.logs import LOG_DIR_PREFIX
from fx_audit_mcp.models import CrashLogPaths

be_module = sys.modules["fx_audit_mcp.browser_evaluator"]


def _write_grizzly_logs(
    log_dir: Path, stderr: str = "", crashdata: str = ""
) -> CrashLogPaths:
    """Lay out log text as grizzly log files and return their categorized paths.

    Routes through _categorize_logs() rather than building a CrashLogPaths by hand so
    the tests exercise the real filename routing. An empty string writes no
    file, which is how a run with no such log is expressed.
    """
    if stderr:
        (log_dir / "log_stderr.txt").write_text(stderr)
    if crashdata:
        (log_dir / "log_ffp_asan_0.txt").write_text(crashdata)
    return _categorize_logs(log_dir)


class TestExtractCrashPids:
    def test_standard_asan_format(self, tmp_path: Path) -> None:
        """Parse a PID from a standard ASAN error header."""
        crashdata = "==12345==ERROR: AddressSanitizer: heap-use-after-free"
        log_paths = _write_grizzly_logs(tmp_path, crashdata=crashdata)
        assert _extract_crash_pids(log_paths.crashdata) == [12345]

    def test_returns_empty_when_no_match(self, tmp_path: Path) -> None:
        """Return an empty list when the input contains no ASAN PID marker."""
        log_paths = _write_grizzly_logs(tmp_path, crashdata="no pid here")
        assert not _extract_crash_pids(log_paths.crashdata)

    def test_extracts_all_matches_in_order(self, tmp_path: Path) -> None:
        """Return every crashing PID in the order the reports appear."""
        crashdata = "==111==ERROR: AddressSanitizer: ...\n==222==ERROR: something\n"
        log_paths = _write_grizzly_logs(tmp_path, crashdata=crashdata)
        assert _extract_crash_pids(log_paths.crashdata) == [111, 222]

    def test_reads_across_multiple_files_in_path_order(self, tmp_path: Path) -> None:
        """One asan log per crashing process: every file is scanned."""
        (tmp_path / "log_ffp_asan_111.txt").write_text("==111==ERROR: ASan: SEGV\n")
        (tmp_path / "log_ffp_asan_222.txt").write_text("==222==ERROR: ASan: SEGV\n")
        assert _extract_crash_pids(_categorize_logs(tmp_path).crashdata) == [111, 222]

    def test_marker_past_old_truncation_limit_is_found(self, tmp_path: Path) -> None:
        """A report beyond the old 1 MiB cap is still scanned, not truncated."""
        crashdata = "x" * 1_048_576 + "\n==777==ERROR: AddressSanitizer: SEGV\n"
        log_paths = _write_grizzly_logs(tmp_path, crashdata=crashdata)
        assert _extract_crash_pids(log_paths.crashdata) == [777]


class TestCategorizeLogs:
    def test_empty_directory(self, tmp_path: Path) -> None:
        """Every category is empty when the directory holds no log files."""
        assert _categorize_logs(tmp_path) == CrashLogPaths(
            stderr=[], stdout=[], crashdata=[]
        )

    def test_routes_by_filename(self, tmp_path: Path) -> None:
        """Route log files to stderr, stdout, or crashdata based on filename."""
        for name in ("log_stderr.txt", "log_stdout.txt", "log_asan.txt"):
            (tmp_path / name).write_text(name)
        assert _categorize_logs(tmp_path) == CrashLogPaths(
            stderr=[str(tmp_path / "log_stderr.txt")],
            stdout=[str(tmp_path / "log_stdout.txt")],
            crashdata=[str(tmp_path / "log_asan.txt")],
        )

    def test_multiple_files_in_one_category_sorted(self, tmp_path: Path) -> None:
        """One asan log per crashing process, listed in sorted path order."""
        for name in ("log_ffp_asan_222.txt", "log_ffp_asan_111.txt"):
            (tmp_path / name).write_text(name)
        assert _categorize_logs(tmp_path).crashdata == [
            str(tmp_path / "log_ffp_asan_111.txt"),
            str(tmp_path / "log_ffp_asan_222.txt"),
        ]

    def test_ignores_non_log_entries(self, tmp_path: Path) -> None:
        """Only log_*.txt files are reported; other entries are skipped."""
        (tmp_path / "log_stderr.txt").write_text("err")
        (tmp_path / "prefs.js").write_text("user_pref()")
        (tmp_path / "minidumps").mkdir()
        result = _categorize_logs(tmp_path)
        assert result.stderr == [str(tmp_path / "log_stderr.txt")]
        assert not result.stdout
        assert not result.crashdata


def test_target_supports_report_size_limit() -> None:
    """The grizzly pin exposes the knob that disables report log tailing.

    FirefoxTarget swallows unknown keywords via **kwds, so on an older grizzly
    report_size_limit=0 is discarded silently and logs are tailed to 1 MiB
    again with nothing to signal it.
    """
    params = inspect.signature(FirefoxTarget.__init__).parameters
    assert "report_size_limit" in params


class TestCheckPrefBlocklist:
    @staticmethod
    def _write_prefs(tmp_path: Path, names: list[str]) -> Path:
        prefs_path = tmp_path / "prefs.js"
        lines = ["// Generated with PrefPicker"]
        lines += [f'user_pref("{name}", false);' for name in names]
        prefs_path.write_text("\n".join(lines) + "\n")
        return prefs_path

    def test_no_match_returns_none(self, tmp_path: Path) -> None:
        """No exception when no blocklisted pref is present."""
        prefs_path = self._write_prefs(tmp_path, ["dom.workers.enabled"])
        assert _check_pref_blocklist(prefs_path, ["security.foo"]) is None

    def test_single_match_raises(self, tmp_path: Path) -> None:
        """A present blocklisted pref raises ValueError naming it."""
        prefs_path = self._write_prefs(tmp_path, ["dom.workers.enabled"])
        with pytest.raises(ValueError, match="Blocked prefs detected"):
            _check_pref_blocklist(prefs_path, ["dom.workers.enabled"])

    def test_multiple_matches_report_each(self, tmp_path: Path) -> None:
        """Every matched pref is named in the raised message."""
        prefs_path = self._write_prefs(
            tmp_path, ["dom.workers.enabled", "geo.enabled", "media.gmp.enabled"]
        )
        with pytest.raises(ValueError) as exc_info:
            _check_pref_blocklist(prefs_path, ["dom.workers.enabled", "geo.enabled"])
        message = str(exc_info.value)
        assert "dom.workers.enabled" in message
        assert "geo.enabled" in message
        assert "media.gmp.enabled" not in message


class TestLoadPrefBlocklist:
    def test_env_unset_returns_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No blocklist file configured means an empty list."""
        monkeypatch.delenv(PREF_BLOCKLIST_ENV, raising=False)
        assert _load_pref_blocklist() == []

    def test_parses_names_ignoring_blanks_and_comments(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blank lines and '#' comments are skipped; names keep file order."""
        blocklist = tmp_path / "blocklist.txt"
        blocklist.write_text(
            "# blocked prefs\ndom.workers.enabled\n\n  geo.enabled  \n"
        )
        monkeypatch.setenv(PREF_BLOCKLIST_ENV, str(blocklist))
        assert _load_pref_blocklist() == ["dom.workers.enabled", "geo.enabled"]

    def test_missing_file_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A configured but absent blocklist file raises FileNotFoundError."""
        monkeypatch.setenv(PREF_BLOCKLIST_ENV, str(tmp_path / "missing.txt"))
        with pytest.raises(FileNotFoundError, match="Pref blocklist file not found"):
            _load_pref_blocklist()


class TestBuildTestcase:
    @staticmethod
    def _write(directory: Path, name: str, data: bytes) -> Path:
        """Write *data* to *name* under *directory* and return the path."""
        path = directory / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_single_file(self, tmp_path: Path) -> None:
        """A lone entry point file is added and marked required."""
        src = self._write(tmp_path, "test.html", b"<html></html>")
        testcase = _build_testcase({"test.html": src}, "test.html")
        try:
            assert list(testcase.required) == ["test.html"]
            assert not list(testcase.optional)
        finally:
            testcase.cleanup()

    def test_entry_point_required_others_optional(self, tmp_path: Path) -> None:
        """The entry point is required; every other file is optional."""
        testcase = _build_testcase(
            {
                "test.html": self._write(tmp_path, "test.html", b"<html></html>"),
                "worker.js": self._write(tmp_path, "worker.js", b"postMessage(1)"),
                "style.css": self._write(tmp_path, "style.css", b"body{}"),
            },
            "test.html",
        )
        out = tmp_path / "dump"
        try:
            assert list(testcase.required) == ["test.html"]
            assert sorted(testcase.optional) == ["style.css", "worker.js"]
            testcase.dump(out)
        finally:
            testcase.cleanup()

        assert (out / "worker.js").read_bytes() == b"postMessage(1)"
        assert (out / "style.css").read_bytes() == b"body{}"

    def test_binary_file_is_preserved(self, tmp_path: Path) -> None:
        """A non-UTF-8 source file round-trips byte-exact into the testcase."""
        blob = b"\x89PNG\r\n\x1a\n\xff\xfe\x00"
        testcase = _build_testcase(
            {
                "test.html": self._write(tmp_path, "test.html", b"<img src='x.png'>"),
                "x.png": self._write(tmp_path, "x.png", blob),
            },
            "test.html",
        )
        out = tmp_path / "dump"
        try:
            testcase.dump(out)
        finally:
            testcase.cleanup()

        assert (out / "x.png").read_bytes() == blob

    def test_source_files_are_not_consumed(self, tmp_path: Path) -> None:
        """Source files are copied, so the caller's originals survive."""
        html = self._write(tmp_path, "test.html", b"<html></html>")
        png = self._write(tmp_path, "x.png", b"\x89PNG")
        testcase = _build_testcase({"test.html": html, "x.png": png}, "test.html")
        testcase.cleanup()

        assert html.read_bytes() == b"<html></html>"
        assert png.read_bytes() == b"\x89PNG"

    def test_nested_name_creates_subdirectory(self, tmp_path: Path) -> None:
        """A forward-slash testcase name is written into a subdirectory."""
        testcase = _build_testcase(
            {
                "test.html": self._write(tmp_path, "test.html", b"<html></html>"),
                "sub/frame.html": self._write(tmp_path, "frame.html", b"<h1>f</h1>"),
            },
            "test.html",
        )
        out = tmp_path / "dump"
        try:
            testcase.dump(out)
        finally:
            testcase.cleanup()

        assert (out / "sub" / "frame.html").read_bytes() == b"<h1>f</h1>"

    def test_missing_source_file_raises(self, tmp_path: Path) -> None:
        """A source path that does not exist is reported."""
        with pytest.raises(FileNotFoundError):
            _build_testcase({"test.html": tmp_path / "absent.html"}, "test.html")

    def test_missing_entry_point_raises(self, tmp_path: Path) -> None:
        """An entry point absent from file_paths is rejected."""
        src = self._write(tmp_path, "other.js", b"x")
        with pytest.raises(ValueError, match=r"'test\.html' not found in file_paths"):
            _build_testcase({"other.js": src}, "test.html")

    def test_empty_mapping_raises(self) -> None:
        """An empty mapping cannot satisfy the entry point."""
        with pytest.raises(ValueError, match="not found in file_paths"):
            _build_testcase({}, "test.html")

    def test_entry_point_is_sanitized_before_matching(self, tmp_path: Path) -> None:
        """An absolute-looking entry point still matches its relative name."""
        src = self._write(tmp_path, "test.html", b"<html></html>")
        testcase = _build_testcase({"test.html": src}, "/test.html")
        try:
            assert list(testcase.required) == ["test.html"]
        finally:
            testcase.cleanup()

    def test_colliding_names_raise(self, tmp_path: Path) -> None:
        """Two testcase names that normalize to the same path are rejected."""
        with pytest.raises(grizzly_storage.TestFileExists, match=r"'a\.js' exists"):
            _build_testcase(
                {
                    "test.html": self._write(tmp_path, "test.html", b"<html>"),
                    "a.js": self._write(tmp_path, "a.js", b"x"),
                    "./a.js": self._write(tmp_path, "b.js", b"y"),
                },
                "test.html",
            )

    @pytest.mark.parametrize(
        "name",
        [
            "../evil.js",  # escapes the testcase root
            "a/../../b.js",  # escapes after normalization
            "sub/",  # missing filename
            "C:\\evil.js",  # drive letter
        ],
    )
    def test_invalid_name_raises(self, name: str, tmp_path: Path) -> None:
        """Testcase names that escape the root or are malformed are rejected."""
        src = self._write(tmp_path, "src.js", b"x")
        with pytest.raises(ValueError, match="invalid path"):
            _build_testcase(
                {"test.html": self._write(tmp_path, "test.html", b"<html>"), name: src},
                "test.html",
            )

    def test_rejected_input_leaves_no_temp_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Rejected input does not leak the testcase temp directory."""
        # TestCase roots are created under grizzly's own GRZ_TMP, not tmp_path;
        # redirect it so the check is isolated from other grizzly processes.
        storage = tmp_path / "grz"
        monkeypatch.setattr(grizzly_utils, "GRZ_TMP", storage)
        src = self._write(tmp_path, "other.js", b"x")
        with pytest.raises(ValueError, match="not found in file_paths"):
            _build_testcase({"other.js": src}, "test.html")
        assert not list((storage / "storage").iterdir())

    def test_leading_slash_is_stripped(self, tmp_path: Path) -> None:
        """An absolute-looking testcase name is normalized to a relative path."""
        testcase = _build_testcase(
            {
                "test.html": self._write(tmp_path, "test.html", b"<html></html>"),
                "/a.js": self._write(tmp_path, "a.js", b"x"),
            },
            "test.html",
        )
        out = tmp_path / "dump"
        try:
            assert list(testcase.optional) == ["a.js"]
            testcase.dump(out)
        finally:
            testcase.cleanup()

        assert (out / "a.js").read_bytes() == b"x"


class TestPackageTestcase:
    def test_packages_files_prefs_and_env(self, tmp_path: Path) -> None:
        """Package a multi-file testcase with custom prefs and env vars."""
        tc_dir = tmp_path / "testcase"
        tc_dir.mkdir()
        (tc_dir / "test.html").write_text("<html><body>exploit</body></html>")
        js_dir = tc_dir / "js"
        js_dir.mkdir()
        (js_dir / "helper.js").write_text("alert(1);")

        custom_prefs: dict[str, str | int | bool] = {"dom.workers.enabled": False}
        env = {"MOZ_LOG": "all:5"}

        output = asyncio.run(
            package_testcase(tc_dir, "test.html", prefs=custom_prefs, env=env)
        )
        output_path = Path(output)

        assert output_path.is_dir()
        content = (output_path / "test.html").read_text()
        assert content == "<html><body>exploit</body></html>"
        assert (output_path / "js/helper.js").read_text() == "alert(1);"

        info = json.loads((output_path / "test_info.json").read_text())
        assert info["target"] == "test.html"
        assert info["adapter"] == "fx-audit"
        assert info["env"] == env
        assert info["assets"] == {"prefs": "prefs.js"}

        prefs_content = (output_path / "_assets_" / "prefs.js").read_text()
        assert "dom.workers.enabled" in prefs_content
        assert "browser.backup.enabled" in prefs_content

    def test_template_prefs_without_custom(self, tmp_path: Path) -> None:
        """Template prefs are included even when no custom prefs are given."""
        tc_dir = tmp_path / "testcase"
        tc_dir.mkdir()
        (tc_dir / "test.html").write_text("<html></html>")

        output = asyncio.run(package_testcase(tc_dir, "test.html"))
        output_path = Path(output)

        prefs_content = (output_path / "_assets_" / "prefs.js").read_text()
        assert "browser.backup.enabled" in prefs_content


class TestBrowserEvaluator:
    @pytest.mark.anyio
    async def test_missing_firefox_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A missing firefox binary raises before any log directory is made."""
        temp_root = tmp_path / "tmp"
        temp_root.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        with pytest.raises(FileNotFoundError, match="Firefox binary not found"):
            await browser_evaluator(
                file_paths={"test.html": tmp_path / "test.html"},
                entry_point="test.html",
                firefox_binary=tmp_path / "no_firefox",
            )
        # The binary check must stay ahead of the mkdtemp() call, or every
        # missing-binary call strands an empty directory.
        assert not list(temp_root.iterdir())

    @pytest.mark.anyio
    async def test_launch_timeout_removes_empty_log_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """A launch timeout with no report leaves no empty log directory behind."""
        firefox_binary = tmp_path / "firefox"
        firefox_binary.touch()
        testcase_file = tmp_path / "test.html"
        testcase_file.write_text("<html></html>")

        target = mocker.MagicMock()
        target.launch_timeout_report = None
        mocker.patch.object(be_module, "_FxAuditFirefoxTarget", return_value=target)
        mocker.patch.object(be_module, "Sapphire")
        replay = mocker.patch.object(be_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.side_effect = TargetLaunchTimeout

        temp_root = tmp_path / "tmp"
        temp_root.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        with pytest.raises(TimeoutError, match="failed to launch"):
            await browser_evaluator(
                file_paths={"test.html": testcase_file},
                entry_point="test.html",
                firefox_binary=firefox_binary,
            )
        assert not list(temp_root.glob(f"{LOG_DIR_PREFIX}*"))

    @pytest.mark.anyio
    async def test_launch_timeout_with_report_names_log_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mocker: MockerFixture
    ) -> None:
        """A launch timeout with logs but no crashdata keeps and names the log dir."""
        firefox_binary = tmp_path / "firefox"
        firefox_binary.touch()
        testcase_file = tmp_path / "test.html"
        testcase_file.write_text("<html></html>")

        report_dir = tmp_path / "report"
        report_dir.mkdir()
        (report_dir / "log_stderr.txt").write_text("launch diagnostics")
        (report_dir / "log_asan_blank.txt").write_text("")

        target = mocker.MagicMock()
        target.launch_timeout_report.path = report_dir
        mocker.patch.object(be_module, "_FxAuditFirefoxTarget", return_value=target)
        mocker.patch.object(be_module, "Sapphire")
        replay = mocker.patch.object(be_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.side_effect = TargetLaunchTimeout

        temp_root = tmp_path / "tmp"
        temp_root.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp_root))
        with pytest.raises(TimeoutError, match="failed to launch") as excinfo:
            await browser_evaluator(
                file_paths={"test.html": testcase_file},
                entry_point="test.html",
                firefox_binary=firefox_binary,
            )
        (log_dir,) = temp_root.glob(f"{LOG_DIR_PREFIX}*")
        assert str(log_dir) in str(excinfo.value)
        assert (log_dir / "log_stderr.txt").read_text() == "launch diagnostics"

    @staticmethod
    def _mock_replay(
        mocker: MockerFixture,
        tmp_path: Path,
        *,
        is_hang: bool,
        report_files: dict[str, str],
    ) -> MagicMock:
        """Stub grizzly so replay yields one result with the given report files."""
        target = mocker.MagicMock()
        target.launch_timeout_report = None
        target.parent_pid = 1234
        mocker.patch.object(be_module, "_FxAuditFirefoxTarget", return_value=target)
        mocker.patch.object(be_module, "Sapphire")
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        for name, content in report_files.items():
            (report_dir / name).write_text(content)
        result = mocker.MagicMock()
        result.report.path = report_dir
        result.report.is_hang = is_hang
        replay = mocker.patch.object(be_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.return_value = [result]
        return target

    @pytest.mark.anyio
    async def test_hang_result_reports_timed_out_not_crashed(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        """A run grizzly flags as a hang is a timeout result, never a crash."""
        firefox_binary = tmp_path / "firefox"
        firefox_binary.touch()
        testcase_file = tmp_path / "test.html"
        testcase_file.write_text("<html></html>")
        self._mock_replay(
            mocker,
            tmp_path,
            is_hang=True,
            report_files={"log_stderr.txt": "still busy\n"},
        )

        result = await browser_evaluator(
            file_paths={"test.html": testcase_file},
            entry_point="test.html",
            firefox_binary=firefox_binary,
        )

        assert result.timed_out is True
        assert result.crashed is False
        assert result.crashed_parent is None
        assert Path(result.logs.stderr[0]).read_text(encoding="utf-8") == "still busy\n"

    @pytest.mark.anyio
    @pytest.mark.parametrize("hang_detected", [True, False])
    async def test_empty_results_reports_hang_flag_as_timed_out(
        self, tmp_path: Path, mocker: MockerFixture, hang_detected: bool
    ) -> None:
        """With no replay results, timed_out mirrors the target's hang flag."""
        firefox_binary = tmp_path / "firefox"
        firefox_binary.touch()
        testcase_file = tmp_path / "test.html"
        testcase_file.write_text("<html></html>")

        target = mocker.MagicMock()
        target.launch_timeout_report = None
        target.hang_detected = hang_detected
        mocker.patch.object(be_module, "_FxAuditFirefoxTarget", return_value=target)
        mocker.patch.object(be_module, "Sapphire")
        replay = mocker.patch.object(be_module, "ReplayManager").return_value
        replay.__enter__.return_value.run.return_value = []

        result = await browser_evaluator(
            file_paths={"test.html": testcase_file},
            entry_point="test.html",
            firefox_binary=firefox_binary,
        )

        assert result.timed_out is hang_detected
        assert result.crashed is False

    @pytest.mark.anyio
    async def test_crash_result_reports_attributed_crash(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        """A non-hang replay result is a crash, attributed via its report logs."""
        firefox_binary = tmp_path / "firefox"
        firefox_binary.touch()
        testcase_file = tmp_path / "test.html"
        testcase_file.write_text("<html></html>")
        self._mock_replay(
            mocker,
            tmp_path,
            is_hang=False,
            report_files={
                "log_stderr.txt": "gecko noise\n",
                # The PID matches the mocked target.parent_pid.
                "log_ffp_asan_1234.txt": (
                    "==1234==ERROR: AddressSanitizer: heap-use-after-free\n"
                ),
            },
        )

        result = await browser_evaluator(
            file_paths={"test.html": testcase_file},
            entry_point="test.html",
            firefox_binary=firefox_binary,
        )

        assert result.crashed is True
        assert result.timed_out is False
        assert result.crashed_parent is True
        assert result.logs.crashdata
        assert "asan" in Path(result.logs.crashdata[0]).name


class TestExtractChildPtypes:
    _PREFIX = "[Parent 100: Main Thread]: I/ChildProcessLifecycle "
    _LIFECYCLE_LOG = (
        f"{_PREFIX}++PROCESS [pid = 4242] [childID = 1] [type = tab]\n"
        f"{_PREFIX}++PROCESS [pid = 4243] [childID = 2] [type = gpu]\n"
        f"{_PREFIX}++PROCESS [pid = 4244] [childID = 3] [type = utility]\n"
        f"{_PREFIX}++PROCESS [pid = 4245] [childID = 4] [type = rdd]\n"
        f"{_PREFIX}--PROCESS [pid = 4245] [childID = 4] [type = rdd]\n"
        f"{_PREFIX}++PROCESS [pid = 4245] [childID = 5] [type = socket]\n"
    )

    @pytest.mark.parametrize(
        ("stderr", "expected"),
        [
            (
                _LIFECYCLE_LOG,
                {
                    4242: "tab",
                    4243: "gpu",
                    4244: "utility",
                    # PID reused after the rdd process exited: last launch wins.
                    4245: "socket",
                },
            ),
            # Nothing to map: no launch records, e.g. the parent died before
            # flushing them. The parent (pid 100) is never launched as a
            # child, so it never appears.
            ("[Parent 100: Main Thread]: I/console some unrelated output\n", {}),
        ],
    )
    def test_maps_pids_to_types(
        self, stderr: str, expected: dict[int, str], tmp_path: Path
    ) -> None:
        """Map launched child PIDs to their ChildProcessLifecycle types."""
        log_paths = _write_grizzly_logs(tmp_path, stderr=stderr)
        assert _extract_child_ptypes(log_paths.stderr) == expected

    def test_reads_across_multiple_files(self, tmp_path: Path) -> None:
        """Launch records are picked up from every stderr log, not just one."""
        (tmp_path / "log_stderr_0.txt").write_text(
            f"{self._PREFIX}++PROCESS [pid = 1] [childID = 1] [type = tab]\n"
        )
        (tmp_path / "log_stderr_1.txt").write_text(
            f"{self._PREFIX}++PROCESS [pid = 2] [childID = 2] [type = gpu]\n"
        )
        log_paths = _categorize_logs(tmp_path)
        assert _extract_child_ptypes(log_paths.stderr) == {1: "tab", 2: "gpu"}


class TestCrashedProcessFields:
    _PARENT_PID = 100
    _PARENT_CRASH_LOG = "==100==ERROR: AddressSanitizer: heap-use-after-free\n"
    _TAB_LAUNCH_LOG = (
        "[Parent 100: Main Thread]: I/ChildProcessLifecycle "
        "++PROCESS [pid = 4242] [childID = 1] [type = tab]\n"
    )
    _TAB_CRASH_LOG = "==4242==ERROR: AddressSanitizer: heap-use-after-free\n"
    _GPU_LAUNCH_LOG = (
        "[Parent 100: Main Thread]: I/ChildProcessLifecycle "
        "++PROCESS [pid = 4243] [childID = 2] [type = gpu]\n"
    )
    _GPU_CRASH_LOG = "==4243==ERROR: AddressSanitizer: heap-use-after-free\n"
    _SECOND_TAB_LAUNCH_LOG = (
        "[Parent 100: Main Thread]: I/ChildProcessLifecycle "
        "++PROCESS [pid = 4244] [childID = 3] [type = tab]\n"
    )
    _SECOND_TAB_CRASH_LOG = "==4244==ERROR: AddressSanitizer: heap-use-after-free\n"

    @pytest.mark.parametrize(
        ("stderr", "crashdata", "parent_pid", "expected"),
        [
            # Child identified from its launch record; other types ruled out.
            (
                _GPU_LAUNCH_LOG,
                _GPU_CRASH_LOG,
                _PARENT_PID,
                {
                    "crashed_parent": False,
                    "crashed_gpu": True,
                    "crashed_content": False,
                },
            ),
            # Parent identified by PID; it has no launch record to type it from.
            (
                _GPU_LAUNCH_LOG,
                _PARENT_CRASH_LOG,
                _PARENT_PID,
                {"crashed_parent": True},
            ),
            # Several processes crashed in one run: every one of them is flagged.
            (
                _GPU_LAUNCH_LOG + _TAB_LAUNCH_LOG,
                _GPU_CRASH_LOG + _TAB_CRASH_LOG + _PARENT_CRASH_LOG,
                _PARENT_PID,
                {
                    "crashed_parent": True,
                    "crashed_gpu": True,
                    "crashed_content": True,
                    "crashed_rdd": False,
                },
            ),
            # No launch record for the crashing PID, e.g. never written.
            (
                "",
                _GPU_CRASH_LOG,
                _PARENT_PID,
                {"crashed_parent": False, "crashed_gpu": None},
            ),
            # An unattributable PID alongside the parent still rules nothing out.
            (
                _GPU_LAUNCH_LOG,
                _PARENT_CRASH_LOG + "==9999==ERROR: AddressSanitizer: SEGV\n",
                _PARENT_PID,
                {"crashed_parent": True, "crashed_gpu": None},
            ),
            # Two crashes of the same type collapse into one flag, not into None.
            (
                _TAB_LAUNCH_LOG + _SECOND_TAB_LAUNCH_LOG,
                _TAB_CRASH_LOG + _SECOND_TAB_CRASH_LOG,
                _PARENT_PID,
                {
                    "crashed_parent": False,
                    "crashed_content": True,
                    "crashed_gpu": False,
                },
            ),
            # No ASAN PID marker at all.
            (
                _GPU_LAUNCH_LOG,
                "Segmentation fault",
                _PARENT_PID,
                {"crashed_parent": None, "crashed_gpu": None},
            ),
            # Parent PID unknown, e.g. a crash during launch.
            (
                _GPU_LAUNCH_LOG,
                _GPU_CRASH_LOG,
                None,
                {"crashed_parent": None, "crashed_gpu": True},
            ),
        ],
    )
    def test_flags_each_crashed_process(
        self,
        stderr: str,
        crashdata: str,
        parent_pid: int | None,
        expected: dict[str, bool | None],
        tmp_path: Path,
    ) -> None:
        """Flag every crashed process; report an unidentified one as None."""
        log_paths = _write_grizzly_logs(tmp_path, stderr=stderr, crashdata=crashdata)
        fields = _crashed_process_fields(log_paths, parent_pid)
        assert {key: fields[key] for key in expected} == expected


class TestIgnoredSignatures:
    def test_missing_directory_returns_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No signatures are loaded when the configured directory is absent."""
        monkeypatch.setattr(
            be_module,
            "IGNORED_SIGNATURES_DIR",
            tmp_path / "missing",
        )
        assert _load_ignored_signatures() == []

    def test_only_json_files_loaded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Non-.json files in the directory are skipped."""
        sig_dir = tmp_path / "sigs"
        sig_dir.mkdir()
        (sig_dir / "real.json").write_text(
            '{"symptoms": [{"type": "output", "src": "stderr", "value": "x"}]}'
        )
        (sig_dir / "ignore.txt").write_text("not a signature")
        monkeypatch.setattr(be_module, "IGNORED_SIGNATURES_DIR", sig_dir)
        sigs = _load_ignored_signatures()
        assert len(sigs) == 1
