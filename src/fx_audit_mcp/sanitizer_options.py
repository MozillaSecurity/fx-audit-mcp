"""Caller-supplied sanitizer runtime options for the evaluators.

``ASAN_OPTIONS`` shapes two different things: how the allocator behaves under
a testcase (whether a freed chunk can be reclaimed, what fresh memory holds,
how wide the redzones are) and what counts as a crash and where the report
goes. A caller proving that a defect allows more than the first fault the
sanitizer caught needs the former — a use-after-free cannot be turned into a
fault at a chosen address while the quarantine keeps the chunk unreachable —
and must never be able to touch the latter. The evaluators therefore accept
only the options named in :data:`ALLOWED_ASAN_OPTIONS` and merge them over
whatever the process environment already set, with the caller's values
winning for the keys they name.

``UBSAN_OPTIONS`` gets the same treatment for a build whose only sanitizer
runtime is UBSan's, such as a libFuzzer build without ASan: that runtime
reports nothing but fatal signals, and the single option in
:data:`ALLOWED_UBSAN_OPTIONS` decides how the stack of such a report is
walked, not whether there is one.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ffpuppet.sanitizer_util import SanitizerOptions

if TYPE_CHECKING:
    from collections.abc import Mapping

# Options that only change the allocator's behaviour under the testcase.
# Everything that decides whether an error is reported, how the process ends,
# or where the report is written stays out of reach: ffpuppet owns log_path,
# the harness owns the exit and abort behaviour, and halting on the first
# error is what makes a report mean what it says.
ALLOWED_ASAN_OPTIONS = frozenset(
    {
        "quarantine_size_mb",
        "thread_local_quarantine_size_kb",
        "malloc_fill_byte",
        "free_fill_byte",
        "max_malloc_fill_size",
        "max_free_fill_size",
        "detect_stack_use_after_return",
        "redzone",
        "max_redzone",
    }
)

# How the stack of a fatal-signal report is unwound. The default unwinder can
# fault while walking back from a program counter that is not mapped, which
# ends the report after its header line; the frame-pointer unwinder prints
# the frames. Either way the header, and with it the verdict, is the same.
ALLOWED_UBSAN_OPTIONS = frozenset({"fast_unwind_on_fatal"})

# A value is a bare number, a bool, or a short token: never a path, a colon
# or a space, which the option syntax would misparse.
_VALUE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def _merged_options(
    name: str,
    allowed: frozenset[str],
    options: Mapping[str, str | int | bool] | None,
    existing: str | None,
) -> str | None:
    """Return the option string that applies *options* over *existing*.

    Args:
        name: The sanitizer the options belong to, for error messages.
        allowed: The option names a caller may set.
        options: Caller-supplied options. Booleans become ``1``/``0``.
        existing: The option string already in force, kept for every key the
            caller does not name.

    Returns:
        The merged option string, or None when *options* is empty.

    Raises:
        ValueError: An option is not allowed or its value is malformed.
    """
    if not options:
        return None
    rejected = sorted(set(options) - allowed)
    if rejected:
        raise ValueError(
            f"{name} options not allowed: {', '.join(rejected)}"
            f" (allowed: {', '.join(sorted(allowed))})"
        )
    merged = SanitizerOptions(existing)
    for key, value in options.items():
        text = str(int(value)) if isinstance(value, bool) else str(value)
        if not _VALUE_RE.match(text):
            raise ValueError(f"{name} option {key} has a malformed value: {text!r}")
        merged.add(key, text, overwrite=True)
    return str(merged)


def asan_options_env(
    options: Mapping[str, str | int | bool] | None,
    existing: str | None = None,
) -> str | None:
    """Return the ``ASAN_OPTIONS`` value that applies *options* over *existing*.

    Args:
        options: Caller-supplied options, each key in
            :data:`ALLOWED_ASAN_OPTIONS`. Booleans become ``1``/``0``.
        existing: The ``ASAN_OPTIONS`` already in force (from the
            environment), kept for every key the caller does not name.

    Returns:
        The merged option string, or None when *options* is empty so the
        caller leaves the environment untouched.

    Raises:
        ValueError: An option is not allowed or its value is malformed.
    """
    return _merged_options("ASAN", ALLOWED_ASAN_OPTIONS, options, existing)


def ubsan_options_env(
    options: Mapping[str, str | int | bool] | None,
    existing: str | None = None,
) -> str | None:
    """Return the ``UBSAN_OPTIONS`` value that applies *options* over *existing*.

    Args:
        options: Caller-supplied options, each key in
            :data:`ALLOWED_UBSAN_OPTIONS`. Booleans become ``1``/``0``.
        existing: The ``UBSAN_OPTIONS`` already in force (from the
            environment), kept for every key the caller does not name.

    Returns:
        The merged option string, or None when *options* is empty so the
        caller leaves the environment untouched.

    Raises:
        ValueError: An option is not allowed or its value is malformed.
    """
    return _merged_options("UBSAN", ALLOWED_UBSAN_OPTIONS, options, existing)
