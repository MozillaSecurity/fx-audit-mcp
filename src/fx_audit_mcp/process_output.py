"""Shared helpers for streaming subprocess output."""

import asyncio
import codecs
from collections.abc import Awaitable, Callable

STREAM_CHUNK_SIZE = 64 * 1024
OutputCallback = Callable[[str, str], Awaitable[None]]


async def stream_process_output(
    stdout: asyncio.StreamReader,
    stderr: asyncio.StreamReader,
    on_output: OutputCallback,
) -> tuple[str, str]:
    """Drain two subprocess streams concurrently and report decoded chunks.

    Args:
        stdout: Subprocess stdout stream.
        stderr: Subprocess stderr stream.
        on_output: Async callback receiving each decoded chunk and stream name
            (``"stdout"`` or ``"stderr"``).

    Returns:
        Complete UTF-8-decoded stdout and stderr contents.

    Raises:
        BaseException: Propagates callback or stream failures after cancelling
            and awaiting the sibling reader.
    """

    async def read_stream(stream: asyncio.StreamReader, stream_name: str) -> str:
        captured = bytearray()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while chunk := await stream.read(STREAM_CHUNK_SIZE):
            captured.extend(chunk)
            text = decoder.decode(chunk)
            if text:
                await on_output(text, stream_name)
        text = decoder.decode(b"", final=True)
        if text:
            await on_output(text, stream_name)
        return captured.decode("utf-8", errors="replace")

    output_tasks = (
        asyncio.create_task(read_stream(stdout, "stdout")),
        asyncio.create_task(read_stream(stderr, "stderr")),
    )
    try:
        return await asyncio.gather(*output_tasks)
    except BaseException:
        for task in output_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*output_tasks, return_exceptions=True)
        raise
