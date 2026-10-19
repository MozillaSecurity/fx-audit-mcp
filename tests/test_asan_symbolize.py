"""Tests for asan_symbolize.py."""

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pytest_mock import MockerFixture

from fx_audit_mcp import asan_symbolize
from fx_audit_mcp.asan_symbolize import (
    BreakpadModule,
    Resolved,
    Symbolizer,
    debug_id_from_build_id,
    find_sym_file,
    main,
    parse_args,
)

FIXTURES = Path(__file__).parent / "fixtures"
SYMBOLS = FIXTURES / "symbols"
REPORT = FIXTURES / "android_asan_report.txt"
# The BuildId in the report fixture and the Breakpad id of its libxul.so.sym.
BUILD_ID = "a1d6ad6afa1ef4eedbe2970b48932be0"
DEBUG_ID = "6AADD6A11EFAEEF4DBE2970B48932BE00"


@pytest.mark.parametrize(
    ("build_id", "debug_id"),
    [
        (BUILD_ID, DEBUG_ID),
        # Longer build ids (sha1 notes) only contribute their first 16 bytes.
        (BUILD_ID + "deadbeef", DEBUG_ID),
        # Shorter ones are zero padded.
        ("a1d6ad6afa1ef4ee", "6AADD6A11EFAEEF400000000000000000"),
    ],
)
def test_debug_id_from_build_id(build_id: str, debug_id: str) -> None:
    """The ELF build id maps to Breakpad's byte-swapped GUID plus age 0."""
    assert debug_id_from_build_id(build_id) == debug_id


class TestFindSymFile:
    def test_matching_build_id(self) -> None:
        """The .sym under the frame's debug id is chosen."""
        sym = find_sym_file(SYMBOLS, "libxul.so", BUILD_ID)
        assert sym == SYMBOLS / "libxul.so" / DEBUG_ID / "libxul.so.sym"

    def test_mismatching_build_id_is_not_guessed(self) -> None:
        """A build id with no matching .sym yields None rather than another build."""
        assert find_sym_file(SYMBOLS, "libxul.so", "00" * 16) is None

    def test_without_build_id_uses_single_candidate(self) -> None:
        """With no build id the archive's only copy of the library is used."""
        assert find_sym_file(SYMBOLS, "libxul.so", None) is not None

    def test_without_build_id_ambiguous(self, tmp_path: Path) -> None:
        """Several copies and no build id to pick one is unresolvable."""
        for debug_id in ("A" * 33, "B" * 33):
            sym = tmp_path / "libfoo.so" / debug_id / "libfoo.so.sym"
            sym.parent.mkdir(parents=True)
            sym.write_text("MODULE Linux x86_64 X libfoo.so\n")
        assert find_sym_file(tmp_path, "libfoo.so", None) is None

    def test_unknown_library(self) -> None:
        """A library absent from the archive yields None."""
        assert find_sym_file(SYMBOLS, "libnope.so", BUILD_ID) is None


class TestBreakpadModule:
    def test_func_range(self) -> None:
        """An offset inside a FUNC range resolves to that function."""
        module = BreakpadModule(find_sym_file(SYMBOLS, "libxul.so", BUILD_ID))
        assert module.debug_id == DEBUG_ID
        resolved = module.resolve(0x15F2203E)
        assert resolved == Resolved(
            "CrashChannel::OpenContentStream(bool, nsIInputStream**, nsIChannel**)"
        )

    def test_func_with_multiple_marker(self) -> None:
        """The optional 'm' field of FUNC records is skipped."""
        module = BreakpadModule(find_sym_file(SYMBOLS, "libxul.so", BUILD_ID))
        resolved = module.resolve(0x86169DE)
        assert resolved is not None
        assert resolved.function == "nsBaseChannel::BeginPumpingData()"

    def test_public_fallback(self) -> None:
        """Outside every FUNC range, the nearest preceding PUBLIC symbol is used."""
        module = BreakpadModule(find_sym_file(SYMBOLS, "libxul.so", BUILD_ID))
        resolved = module.resolve(0xA61DA4E)
        assert resolved is not None
        assert resolved.function.startswith("nsURILoader::OpenURI(")
        assert resolved.location is None

    def test_offset_before_any_symbol(self) -> None:
        """An offset below every record is unresolved."""
        module = BreakpadModule(find_sym_file(SYMBOLS, "libxul.so", BUILD_ID))
        assert module.resolve(0x10) is None

    def test_line_records_opt_in(self) -> None:
        """Line records give file:line only when requested."""
        sym = find_sym_file(SYMBOLS, "libxul.so", BUILD_ID)
        assert BreakpadModule(sym).resolve(0x15F2203E).location is None  # type: ignore[union-attr]
        with_lines = BreakpadModule(sym, with_lines=True).resolve(0x15F2203E)
        assert with_lines is not None
        assert with_lines.location == "netwerk/base/CrashChannel.cpp:42"


class TestSymbolizer:
    def test_frames_rewritten_in_asan_layout(self) -> None:
        """Resolved frames become '#N 0xADDR in FUNCTION lib+0xoffset'."""
        output = Symbolizer(symbols_dir=SYMBOLS).symbolize_text(REPORT.read_text())
        lines = output.splitlines()
        assert lines[1].split() == [
            "#0",
            "0x6d1c0f1ab03e",
            "in",
            "CrashChannel::OpenContentStream(bool,",
            "nsIInputStream**,",
            "nsIChannel**)",
            "libxul.so+0x15f2203e",
        ]
        # The BuildId suffix is dropped once the frame is resolved.
        assert "BuildId" not in lines[1]
        assert lines[2].endswith(
            "in nsBaseChannel::BeginPumpingData() libxul.so+0x86169de"
        )

    def test_unresolvable_frame_untouched(self) -> None:
        """A frame in a library without symbols keeps its module+offset and BuildId."""
        output = Symbolizer(symbols_dir=SYMBOLS).symbolize_text(REPORT.read_text())
        libart = next(line for line in output.splitlines() if "libart.so" in line)
        assert "(/apex/com.android.art/lib64/libart.so+0x85458e) (BuildId: " in libart
        assert " in " not in libart

    def test_summary_rewritten(self) -> None:
        """The SUMMARY line follows ASan's 'LOCATION in FUNCTION' form."""
        output = Symbolizer(symbols_dir=SYMBOLS).symbolize_text(REPORT.read_text())
        assert output.splitlines()[-1] == (
            "SUMMARY: AddressSanitizer: SEGV libxul.so+0x15f2203e in "
            "CrashChannel::OpenContentStream(bool, nsIInputStream**, nsIChannel**)"
        )

    def test_with_lines_uses_source_location(self) -> None:
        """When line records are loaded the location is file:line."""
        output = Symbolizer(symbols_dir=SYMBOLS, with_lines=True).symbolize_text(
            REPORT.read_text()
        )
        assert (
            "nsIChannel**) netwerk/base/CrashChannel.cpp:42" in output.splitlines()[1]
        )

    def test_unconfigured_is_identity(self) -> None:
        """Without any symbol source the text is returned as is."""
        text = REPORT.read_text()
        assert Symbolizer().symbolize_text(text) == text

    def test_symbolize_file_in_place(self, tmp_path: Path) -> None:
        """symbolize_file rewrites the file and reports whether anything changed."""
        report = tmp_path / "log_asan.txt"
        report.write_text(REPORT.read_text())
        symbolizer = Symbolizer(symbols_dir=SYMBOLS)
        assert symbolizer.symbolize_file(report) is True
        assert "in nsBaseChannel::AsyncOpen" in report.read_text()
        assert symbolizer.symbolize_file(report) is False

    def test_llvm_symbolizer_fallback(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        """Unstripped libraries are resolved through llvm-symbolizer."""
        (tmp_path / "libxul.so").write_bytes(b"\x7fELF")
        run = mocker.patch.object(
            subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="mozilla::Foo()\n/src/foo.cpp:12:3\n", stderr=""
            ),
        )
        symbolizer = Symbolizer(lib_dir=tmp_path, llvm_symbolizer=Path("/bin/llvm-sym"))
        assert symbolizer.resolve("libxul.so", 0x1234, None) == Resolved(
            "mozilla::Foo()", "/src/foo.cpp", 12
        )
        assert run.call_args.args[0][:2] == [
            "/bin/llvm-sym",
            f"--obj={tmp_path / 'libxul.so'}",
        ]
        # Results are cached per (library, offset).
        symbolizer.resolve("libxul.so", 0x1234, None)
        assert run.call_count == 1

    def test_llvm_symbolizer_unknown_location(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        """'??:0:0' from llvm-symbolizer leaves the source position unset."""
        (tmp_path / "libxul.so").write_bytes(b"\x7fELF")
        mocker.patch.object(
            subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="mozilla::Foo()\n??:0:0\n", stderr=""
            ),
        )
        symbolizer = Symbolizer(lib_dir=tmp_path, llvm_symbolizer=Path("/bin/llvm-sym"))
        assert symbolizer.resolve("libxul.so", 0x1234, None) == Resolved(
            "mozilla::Foo()"
        )

    def test_breakpad_preferred_over_llvm(
        self, tmp_path: Path, mocker: MockerFixture
    ) -> None:
        """With both sources configured the Breakpad symbols are used."""
        run = mocker.patch.object(subprocess, "run")
        symbolizer = Symbolizer(symbols_dir=SYMBOLS, lib_dir=tmp_path)
        resolved = symbolizer.resolve("libxul.so", 0x15F2203E, BUILD_ID)
        assert resolved is not None
        run.assert_not_called()


class TestCli:
    def test_requires_a_symbol_source(self) -> None:
        """Neither --symbols nor --lib-dir is an error."""
        with pytest.raises(SystemExit):
            parse_args([str(REPORT)])

    def test_missing_symbols_dir(self, tmp_path: Path) -> None:
        """A nonexistent --symbols directory is rejected."""
        with pytest.raises(SystemExit):
            parse_args(["--symbols", str(tmp_path / "nope"), str(REPORT)])

    def test_main_prints_symbolized_report(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """main() writes the symbolized text to stdout by default."""
        assert main(["--symbols", str(SYMBOLS), str(REPORT)]) == 0
        assert "in CrashChannel::OpenContentStream" in capsys.readouterr().out

    def test_main_in_place(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """--in-place rewrites the file and prints nothing."""
        report = tmp_path / "report.txt"
        report.write_text(REPORT.read_text())
        assert main(["--symbols", str(SYMBOLS), "--in-place", str(report)]) == 0
        assert capsys.readouterr().out == ""
        assert "in nsBaseChannel::BeginPumpingData()" in report.read_text()


class TestLlvmBatching:
    """llvm-symbolizer is invoked once per library, not once per frame."""

    REPORT = (
        "    #0 0x7f00 (/data/app/x/lib/x86_64/libxul.so+0x1000) (BuildId: aa)\n"
        "    #1 0x7f01 (/data/app/x/lib/x86_64/libxul.so+0x2000) (BuildId: aa)\n"
        "    #2 0x7f02 (/data/app/x/lib/x86_64/libxul.so+0x3000) (BuildId: aa)\n"
        "SUMMARY: AddressSanitizer: heap-use-after-free "
        "(/data/app/x/lib/x86_64/libxul.so+0x1000) (BuildId: aa)\n"
    )

    def test_one_invocation_per_library(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "libxul.so").write_bytes(b"\x7fELF")
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **_: object) -> SimpleNamespace:
            calls.append(cmd)
            addrs = [a for a in cmd if a.startswith("0x")]
            out = "".join(
                f"fn_{a}\n/src/f.cpp:{int(a, 16) // 0x1000}:1\n\n" for a in addrs
            )
            return SimpleNamespace(returncode=0, stdout=out)

        monkeypatch.setattr(asan_symbolize.subprocess, "run", fake_run)
        sym = Symbolizer(
            symbols_dir=None, lib_dir=tmp_path, llvm_symbolizer=Path("/bin/true")
        )
        out = sym.symbolize_text(self.REPORT)
        assert len(calls) == 1, "expected a single llvm-symbolizer call"
        assert {a for a in calls[0] if a.startswith("0x")} == {
            "0x1000",
            "0x2000",
            "0x3000",
        }
        assert "#0 0x7f00 in fn_0x1000 /src/f.cpp:1" in out
        assert "#2 0x7f02 in fn_0x3000 /src/f.cpp:3" in out
        assert out.rstrip().endswith("/src/f.cpp:1 in fn_0x1000")

    def test_unknown_addresses_stay_unsymbolized(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "libxul.so").write_bytes(b"\x7fELF")
        monkeypatch.setattr(
            asan_symbolize.subprocess,
            "run",
            lambda _cmd, **_: SimpleNamespace(
                returncode=0, stdout="??\n??:0:0\n\n" * 3
            ),
        )
        sym = Symbolizer(
            symbols_dir=None, lib_dir=tmp_path, llvm_symbolizer=Path("/bin/true")
        )
        assert sym.symbolize_text(self.REPORT) == self.REPORT
