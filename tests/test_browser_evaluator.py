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
    _crashed_parent,
    _extract_crash_pid,
    _load_ignored_signatures,
    _load_pref_blocklist,
    browser_evaluator,
    package_testcase,
    read_grizzly_logs,
)
from fx_audit_mcp.models import Logs

be_module = sys.modules["fx_audit_mcp.browser_evaluator"]


class TestExtractCrashPid:
    def test_standard_asan_format(self) -> None:
        """Parse a PID from a standard ASAN error header."""
        crashdata = "==12345==ERROR: AddressSanitizer: heap-use-after-free"
        assert _extract_crash_pid(crashdata) == 12345

    def test_returns_none_when_no_match(self) -> None:
        """Return None when the input contains no ASAN PID marker."""
        assert _extract_crash_pid("no pid here") is None

    def test_extracts_first_match(self) -> None:
        """Return the PID from the first ASAN marker when multiple are present."""
        crashdata = "==111==ERROR: AddressSanitizer: ...\n==222==ERROR: something"
        assert _extract_crash_pid(crashdata) == 111


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


_ASAN_CRASHDATA = "==4242==ERROR: AddressSanitizer: x"


@pytest.mark.parametrize(
    ("parent_pid", "crashdata", "expected"),
    [
        (4242, _ASAN_CRASHDATA, True),
        (9999, _ASAN_CRASHDATA, False),
        (None, _ASAN_CRASHDATA, False),
        (4242, "Segmentation fault (core dumped)", False),
    ],
)
def test_crashed_parent(parent_pid: int | None, crashdata: str, expected: bool) -> None:
    """Verify that _crashed_parent returns True only when PIDs are known and match."""
    assert _crashed_parent(parent_pid, crashdata) is expected


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
