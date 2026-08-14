"""Tests for browser_evaluator.py."""

import asyncio
import json
import sys
from pathlib import Path

import pytest

from fx_audit_mcp.browser_evaluator import (
    MAX_LOG_SIZE,
    PREF_BLOCKLIST_ENV,
    _check_pref_blocklist,
    _collect_dump_files,
    _crashed_process_fields,
    _extract_child_ptypes,
    _extract_crash_pids,
    _load_ignored_signatures,
    _load_pref_blocklist,
    browser_evaluator,
    package_testcase,
    read_grizzly_logs,
)
from fx_audit_mcp.models import Logs

be_module = sys.modules["fx_audit_mcp.browser_evaluator"]


class TestExtractCrashPids:
    def test_standard_asan_format(self) -> None:
        """Parse a PID from a standard ASAN error header."""
        crashdata = "==12345==ERROR: AddressSanitizer: heap-use-after-free"
        assert _extract_crash_pids(crashdata) == [12345]

    def test_returns_empty_when_no_match(self) -> None:
        """Return an empty list when the input contains no ASAN PID marker."""
        assert not _extract_crash_pids("no pid here")

    def test_extracts_all_matches_in_order(self) -> None:
        """Return every crashing PID in the order the reports appear."""
        crashdata = "==111==ERROR: AddressSanitizer: ...\n==222==ERROR: something\n"
        assert _extract_crash_pids(crashdata) == [111, 222]


class TestReadGrizzlyLogs:
    def test_empty_directory(self, tmp_path: Path) -> None:
        """Return empty strings for all categories when no log files are present."""
        assert read_grizzly_logs(tmp_path) == Logs(stderr="", stdout="", crashdata="")

    def test_routes_by_filename(self, tmp_path: Path) -> None:
        """Route log files to stderr, stdout, or crashdata based on filename."""
        (tmp_path / "log_stderr.txt").write_text("err")
        (tmp_path / "log_stdout.txt").write_text("out")
        (tmp_path / "log_asan.txt").write_text("crash")
        assert read_grizzly_logs(tmp_path) == Logs(
            stderr="err", stdout="out", crashdata="crash"
        )

    def test_multiple_files_concatenated(self, tmp_path: Path) -> None:
        """Concatenate multiple files that map to the same category."""
        (tmp_path / "log_stderr_0.txt").write_text("first")
        (tmp_path / "log_stderr_1.txt").write_text("second")
        result = read_grizzly_logs(tmp_path)
        assert "first" in result.stderr
        assert "second" in result.stderr

    def test_large_log_tail_truncated(self, tmp_path: Path) -> None:
        """Tail-truncate logs exceeding MAX_LOG_SIZE to exactly MAX_LOG_SIZE bytes."""
        content = "x" * (MAX_LOG_SIZE + 100)
        (tmp_path / "log_stderr.txt").write_text(content)
        result = read_grizzly_logs(tmp_path)
        assert len(result.stderr) == MAX_LOG_SIZE
        assert result.stderr == content[-MAX_LOG_SIZE:]


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
    async def test_missing_firefox_binary(self, tmp_path: Path) -> None:
        """Verify that a missing firefox binary raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError, match="Firefox binary not found"):
            await browser_evaluator(
                content="<html></html>",
                filename="test.html",
                firefox_binary=tmp_path / "no_firefox",
            )


class TestCollectDumpFiles:
    def test_empty_dir_returns_empty(self, tmp_path: Path) -> None:
        """No files under the dump dir → empty mapping."""
        assert not _collect_dump_files(tmp_path)

    def test_relative_paths_preserved(self, tmp_path: Path) -> None:
        """File paths are returned relative to the dump dir, not absolute."""
        (tmp_path / "test.html").write_text("<html>x</html>")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "nested.js").write_text("var y = 1;")
        files = _collect_dump_files(tmp_path)
        assert files == {
            "test.html": "<html>x</html>",
            "sub/nested.js": "var y = 1;",
        }

    def test_invalid_utf8_uses_replacement(self, tmp_path: Path) -> None:
        """Files with non-UTF-8 bytes are read with errors='replace'."""
        (tmp_path / "binary.bin").write_bytes(b"\xff\xfe\x80\x00ok")
        files = _collect_dump_files(tmp_path)
        # Replacement character (U+FFFD) appears at each invalid byte; the
        # trailing valid bytes survive.
        assert "ok" in files["binary.bin"]
        assert "�" in files["binary.bin"]


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
            # Nothing to map: no launch records, e.g. tail-truncated stderr. The
            # parent (pid 100) is never launched as a child, so it never appears.
            ("[Parent 100: Main Thread]: I/console some unrelated output\n", {}),
        ],
    )
    def test_maps_pids_to_types(self, stderr: str, expected: dict[int, str]) -> None:
        """Map launched child PIDs to their ChildProcessLifecycle types."""
        assert _extract_child_ptypes(stderr) == expected


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
            # No launch record for the crashing PID, e.g. tail-truncated stderr.
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
    ) -> None:
        """Flag every crashed process; report an unidentified one as None."""
        logs = Logs(stderr=stderr, stdout="", crashdata=crashdata)
        fields = _crashed_process_fields(logs, parent_pid)
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
