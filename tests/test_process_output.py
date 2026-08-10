"""Tests for shared subprocess output streaming helpers."""

import asyncio

import pytest

from fx_audit_mcp.process_output import stream_process_output


class _Stream:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = iter(chunks)

    async def read(self, _size: int) -> bytes:
        return next(self._chunks, b"")


class _BlockingStream:
    def __init__(self) -> None:
        self.cancelled = False
        self._event = asyncio.Event()

    async def read(self, _size: int) -> bytes:
        try:
            await self._event.wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return b""


@pytest.mark.anyio
async def test_flushes_incomplete_utf8_at_eof() -> None:
    """Emits replacement text when UTF-8 ends mid-character."""
    output: list[tuple[str, str]] = []

    async def on_output(text: str, stream_name: str) -> None:
        output.append((text, stream_name))

    stdout, stderr = await stream_process_output(
        _Stream([b"partial \xf0"]), _Stream([]), on_output
    )

    assert stdout == "partial �"
    assert stderr == ""
    assert output[-1] == ("�", "stdout")


@pytest.mark.anyio
async def test_callback_failure_cancels_sibling_reader() -> None:
    """Cancels the other reader when output notification fails."""
    sibling = _BlockingStream()

    async def on_output(_text: str, _stream_name: str) -> None:
        raise RuntimeError("notification failed")

    with pytest.raises(RuntimeError, match="notification failed"):
        await stream_process_output(_Stream([b"output"]), sibling, on_output)

    assert sibling.cancelled is True
