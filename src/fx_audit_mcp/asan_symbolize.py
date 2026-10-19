"""Symbolize AddressSanitizer reports from Android on the host.

On Android the sanitizer runtime has no symbolizer to call, so a report only
names each frame's module and offset::

    #0 0x6d1c0f1ab03e  (/data/app/.../libxul.so+0x15f2203e) (BuildId: a1d6ad6a...)

The packaged libraries are stripped, so frames are resolved here instead,
either from the build's Breakpad symbol files (``target.crashreporter-symbols.zip``
unpacked as ``<dir>/<lib>/<debug id>/<lib>.sym``; the file whose debug id
matches the frame's BuildId is used, so an archive holding several builds of
one library resolves correctly) or from unstripped copies of the libraries
through llvm-symbolizer.

Symbolized frames follow ASan's own layout, ``#N 0xADDR in FUNCTION LOCATION``,
with the location a ``file:line`` when known and ``lib+0xoffset`` otherwise, so
FuzzManager and grizzly parse them like a desktop report.
"""

from __future__ import annotations

import bisect
import os
import re
import shutil
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = [
    "BreakpadModule",
    "Resolved",
    "Symbolizer",
    "debug_id_from_build_id",
    "find_sym_file",
    "main",
]

# Stack frames: "#0 0x6d1c0f1ab03e  (/data/app/.../libxul.so+0x15f2203e) (BuildId: ...)"
FRAME_RE = re.compile(
    r"(?P<frame>#\d+ 0x[0-9a-fA-F]+) +"
    r"\((?P<path>[^()\s]*?)(?P<lib>[^/()\s]+)\+0x(?P<offset>[0-9a-fA-F]+)\)"
    r"(?P<build> \(BuildId: (?P<build_id>[0-9a-fA-F]+)\))?"
)
# "SUMMARY: AddressSanitizer: SEGV (/data/app/.../libxul.so+0x15f2203e) (BuildId: ...)"
SUMMARY_RE = re.compile(
    r"(?P<head>SUMMARY: \w+Sanitizer: \S+) "
    r"\((?P<path>[^()\s]*?)(?P<lib>[^/()\s]+)\+0x(?P<offset>[0-9a-fA-F]+)\)"
    r"(?P<build> \(BuildId: (?P<build_id>[0-9a-fA-F]+)\))?"
)
LLVM_SYMBOLIZER_ENV = "LLVM_SYMBOLIZER"
_LLVM_LOCATION_RE = re.compile(r"^(?P<file>.*):(?P<line>\d+):(?P<column>\d+)$")


@dataclass(frozen=True)
class Resolved:
    """Where an offset in a library lands."""

    function: str
    file: str | None = None
    line: int | None = None

    @property
    def location(self) -> str | None:
        """``file:line`` when the source position is known."""
        if self.file is None or self.line is None:
            return None
        return f"{self.file}:{self.line}"


def debug_id_from_build_id(build_id: str) -> str:
    """Convert an ELF build id into the Breakpad debug id used in symbol paths.

    Breakpad treats the first 16 bytes of the build id as a GUID, with its
    first three fields byte-swapped, and appends an age of 0. A build id
    shorter than 16 bytes is zero-padded.

    Args:
        build_id: Hex ELF build id, as printed in a sanitizer frame.

    Returns:
        33 hex digit upper-case debug id.
    """
    raw = bytes.fromhex(build_id[:32].ljust(32, "0"))
    return (raw[3::-1] + raw[5:3:-1] + raw[7:5:-1] + raw[8:16]).hex().upper() + "0"


def find_sym_file(symbols_dir: Path, lib: str, build_id: str | None) -> Path | None:
    """Locate the Breakpad symbol file for a library.

    Args:
        symbols_dir: Root of an unpacked crashreporter-symbols archive.
        lib: Library file name (e.g. ``libxul.so``).
        build_id: ELF build id from the frame, when the report carries one.

    Returns:
        The ``<lib>.sym`` whose debug id matches ``build_id``. Without a build
        id the archive's single copy of the library is used; several copies
        are ambiguous and yield None rather than a guess.
    """
    lib_dir = symbols_dir / lib
    if not lib_dir.is_dir():
        return None
    if build_id:
        sym = lib_dir / debug_id_from_build_id(build_id) / f"{lib}.sym"
        return sym if sym.is_file() else None
    candidates = sorted(lib_dir.glob(f"*/{lib}.sym"))
    return candidates[0] if len(candidates) == 1 else None


class BreakpadModule:
    """Function (and optionally line) records of one Breakpad symbol file.

    Only the record types needed to name a frame are kept: ``FUNC`` and
    ``PUBLIC`` always, the per-address line records when ``with_lines`` is
    set. Line records multiply the memory needed for a libxul-sized file by an
    order of magnitude, which is why they are opt-in.
    """

    def __init__(self, sym_path: Path, with_lines: bool = False) -> None:
        self.path = sym_path
        self.debug_id: str | None = None
        self._funcs: list[tuple[int, int, str]] = []
        self._publics: list[tuple[int, str]] = []
        self._lines: list[tuple[int, int, int, int]] = []
        self._files: dict[int, str] = {}
        self._parse(with_lines)

    def _parse(self, with_lines: bool) -> None:
        with self.path.open(encoding="utf-8", errors="replace") as sym:
            for raw in sym:
                fields = raw.rstrip("\n").split(" ")
                kind = fields[0]
                if kind == "FUNC":
                    # FUNC [m] address size parameter_size name
                    if fields[1] == "m":
                        del fields[1]
                    self._funcs.append(
                        (int(fields[1], 16), int(fields[2], 16), " ".join(fields[4:]))
                    )
                elif kind == "PUBLIC":
                    # PUBLIC [m] address parameter_size name
                    if fields[1] == "m":
                        del fields[1]
                    self._publics.append((int(fields[1], 16), " ".join(fields[3:])))
                elif kind == "MODULE":
                    # MODULE os arch debug_id name
                    self.debug_id = fields[3]
                elif with_lines:
                    if kind == "FILE":
                        # FILE number path
                        self._files[int(fields[1])] = " ".join(fields[2:])
                    elif len(fields) == 4 and kind[:1] in "0123456789abcdef":
                        # address size line file_number
                        self._lines.append(
                            (
                                int(fields[0], 16),
                                int(fields[1], 16),
                                int(fields[2]),
                                int(fields[3]),
                            )
                        )
        self._funcs.sort()
        self._publics.sort()
        self._lines.sort()

    def resolve(self, offset: int) -> Resolved | None:
        """Name the function containing ``offset`` (a module-relative address).

        ``FUNC`` records are exact ranges and win; ``PUBLIC`` records only
        mark where an exported symbol starts, so the nearest preceding one is
        used when no function range covers the offset.
        """
        index = bisect.bisect_right(self._funcs, (offset, sys.maxsize, "")) - 1
        if index >= 0:
            address, size, name = self._funcs[index]
            if offset < address + size:
                return Resolved(name, *self._source(offset))
        index = bisect.bisect_right(self._publics, (offset, "")) - 1
        if index >= 0:
            return Resolved(self._publics[index][1])
        return None

    def _source(self, offset: int) -> tuple[str | None, int | None]:
        if not self._lines:
            return None, None
        index = bisect.bisect_right(self._lines, (offset, sys.maxsize, 0, 0)) - 1
        if index < 0:
            return None, None
        address, size, line, file_number = self._lines[index]
        if offset >= address + size:
            return None, None
        return self._files.get(file_number), line


class Symbolizer:
    """Resolve ``(lib+0xoffset)`` frames from Breakpad symbols or unstripped libraries.

    Breakpad symbols are preferred when both are configured: they are what CI
    publishes for the stripped APKs. Unstripped libraries (a local objdir's
    ``dist/bin``) are resolved with llvm-symbolizer and give inline-accurate
    source positions, but cannot be checked against the frame's BuildId, so
    they must come from the build that produced the APK.
    """

    def __init__(
        self,
        symbols_dir: Path | None = None,
        lib_dir: Path | None = None,
        with_lines: bool = False,
        llvm_symbolizer: Path | None = None,
    ) -> None:
        self.symbols_dir = symbols_dir
        self.lib_dir = lib_dir
        self.with_lines = with_lines
        self.llvm_symbolizer = llvm_symbolizer
        self._modules: dict[tuple[str, str | None], BreakpadModule | None] = {}
        self._llvm_cache: dict[tuple[str, int], Resolved | None] = {}

    @property
    def configured(self) -> bool:
        """True when at least one symbol source is available."""
        return self.symbols_dir is not None or self.lib_dir is not None

    def resolve(self, lib: str, offset: int, build_id: str | None) -> Resolved | None:
        """Resolve one frame.

        Args:
            lib: Library file name from the frame.
            offset: Module-relative offset from the frame.
            build_id: ELF build id from the frame, if present.

        Returns:
            The function (and source position when available), or None when no
            configured source knows the library.
        """
        if self.symbols_dir is not None:
            key = (lib, build_id)
            if key not in self._modules:
                sym = find_sym_file(self.symbols_dir, lib, build_id)
                self._modules[key] = (
                    BreakpadModule(sym, self.with_lines) if sym else None
                )
            module = self._modules[key]
            if module is not None:
                resolved = module.resolve(offset)
                if resolved is not None:
                    return resolved
        if self.lib_dir is not None:
            return self._resolve_llvm(lib, offset)
        return None

    def _resolve_llvm(self, lib: str, offset: int) -> Resolved | None:
        key = (lib, offset)
        if key not in self._llvm_cache:
            self._resolve_llvm_batch(lib, [offset])
        return self._llvm_cache[key]

    def _resolve_llvm_batch(self, lib: str, offsets: list[int]) -> None:
        """Resolve ``offsets`` in ``lib`` with one llvm-symbolizer invocation.

        Each invocation re-reads the library's debug info, which for an ASan
        libxul.so is gigabytes, so a report's frames are resolved per library
        rather than per address. Results (including misses) land in the cache.
        """
        assert self.lib_dir is not None
        library = self.lib_dir / lib
        tool = self.llvm_symbolizer or _default_llvm_symbolizer()
        blocks: list[str] = []
        if offsets and library.is_file() and tool is not None:
            result = subprocess.run(
                [
                    str(tool),
                    f"--obj={library}",
                    "--functions=linkage",
                    "--inlining=false",
                    "--demangle",
                    *(f"0x{offset:x}" for offset in offsets),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
            )
            # Per address: the function, then "file:line:column" ("??" /
            # "??:0:0" when unknown), blank-line separated.
            if result.returncode == 0 and result.stdout.strip():
                blocks = result.stdout.strip("\n").split("\n\n")
        for index, offset in enumerate(offsets):
            resolved: Resolved | None = None
            lines = blocks[index].splitlines() if index < len(blocks) else []
            if lines and lines[0] not in ("", "??"):
                file: str | None = None
                line: int | None = None
                if len(lines) > 1:
                    location = _LLVM_LOCATION_RE.match(lines[1])
                    if location and location.group("file") != "??":
                        file = location.group("file")
                        line = int(location.group("line"))
                resolved = Resolved(lines[0], file, line)
            self._llvm_cache[(lib, offset)] = resolved

    def _prime_llvm_cache(self, text: str) -> None:
        """Batch-resolve every frame Breakpad cannot answer, per library."""
        if self.lib_dir is None:
            return
        wanted: dict[str, set[int]] = {}
        for match in (*FRAME_RE.finditer(text), *SUMMARY_RE.finditer(text)):
            lib, offset = match.group("lib"), int(match.group("offset"), 16)
            if (lib, offset) in self._llvm_cache:
                continue
            if self.symbols_dir is not None and find_sym_file(
                self.symbols_dir, lib, match.group("build_id")
            ):
                continue
            wanted.setdefault(lib, set()).add(offset)
        for lib, offsets in wanted.items():
            self._resolve_llvm_batch(lib, sorted(offsets))

    def symbolize_text(self, text: str) -> str:
        """Rewrite every resolvable frame and SUMMARY line in ``text``."""
        if not self.configured:
            return text
        self._prime_llvm_cache(text)

        def resolve_match(match: re.Match[str]) -> tuple[Resolved, str] | None:
            lib, offset = match.group("lib"), match.group("offset")
            resolved = self.resolve(lib, int(offset, 16), match.group("build_id"))
            if resolved is None:
                return None
            return resolved, resolved.location or f"{lib}+0x{offset}"

        def frame(match: re.Match[str]) -> str:
            hit = resolve_match(match)
            if hit is None:
                return match.group(0)
            resolved, location = hit
            return f"{match.group('frame')} in {resolved.function} {location}"

        def summary(match: re.Match[str]) -> str:
            hit = resolve_match(match)
            if hit is None:
                return match.group(0)
            resolved, location = hit
            return f"{match.group('head')} {location} in {resolved.function}"

        return SUMMARY_RE.sub(summary, FRAME_RE.sub(frame, text))

    def symbolize_file(self, src: Path, dst: Path | None = None) -> bool:
        """Symbolize a report file, in place unless ``dst`` is given.

        Returns:
            True if any frame was rewritten.
        """
        text = src.read_text(encoding="utf-8", errors="replace")
        output = self.symbolize_text(text)
        if output != text or dst is not None:
            (dst or src).write_text(output, encoding="utf-8")
        return output != text


def _default_llvm_symbolizer() -> Path | None:
    configured = os.environ.get(LLVM_SYMBOLIZER_ENV)
    if configured:
        return Path(configured)
    found = shutil.which("llvm-symbolizer")
    return Path(found) if found else None


def parse_args(argv: Sequence[str] | None = None) -> Namespace:
    """Argument parsing for the ``fx-audit-asan-symbolize`` CLI."""
    parser = ArgumentParser(
        description="Symbolize Android AddressSanitizer reports on the host."
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="Report or logcat files to symbolize ('-' reads stdin, writes stdout).",
    )
    parser.add_argument(
        "--symbols",
        type=Path,
        help="Unpacked crashreporter-symbols directory (<lib>/<debug id>/<lib>.sym).",
    )
    parser.add_argument(
        "--lib-dir",
        type=Path,
        help="Directory of unstripped libraries matching the APK, for llvm-symbolizer.",
    )
    parser.add_argument(
        "--lines",
        action="store_true",
        help="Also load Breakpad line records for file:line positions (slow, large).",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Rewrite the files instead of printing the symbolized text.",
    )
    args = parser.parse_args(argv)
    if args.symbols is None and args.lib_dir is None:
        parser.error("one of --symbols or --lib-dir is required")
    if args.symbols is not None and not args.symbols.is_dir():
        parser.error(f"--symbols directory not found: {args.symbols}")
    if args.lib_dir is not None and not args.lib_dir.is_dir():
        parser.error(f"--lib-dir directory not found: {args.lib_dir}")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for ``fx-audit-asan-symbolize``."""
    args = parse_args(argv)
    symbolizer = Symbolizer(
        symbols_dir=args.symbols, lib_dir=args.lib_dir, with_lines=args.lines
    )
    for path in args.files:
        if str(path) == "-":
            sys.stdout.write(symbolizer.symbolize_text(sys.stdin.read()))
            continue
        if args.in_place:
            symbolizer.symbolize_file(path)
        else:
            sys.stdout.write(
                symbolizer.symbolize_text(
                    path.read_text(encoding="utf-8", errors="replace")
                )
            )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
