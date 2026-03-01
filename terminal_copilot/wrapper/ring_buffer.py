"""Fixed-size ring buffers for output lines and raw tail."""
from __future__ import annotations


class RingBuffer:
    def __init__(self, max_lines: int = 100, max_bytes: int = 4096):
        self._lines: list[str] = []
        self._max_lines = max_lines
        self._tail_chunks: list[bytes] = []
        self._tail_size = 0
        self._max_bytes = max_bytes

    def append_line(self, line: str) -> None:
        self._lines.append(line)
        if len(self._lines) > self._max_lines:
            self._lines.pop(0)

    def append_bytes(self, data: bytes) -> None:
        self._tail_chunks.append(data)
        self._tail_size += len(data)
        while self._tail_size > self._max_bytes and self._tail_chunks:
            old = self._tail_chunks.pop(0)
            self._tail_size -= len(old)

    def get_lines(self) -> list[str]:
        return self._lines.copy()

    def get_tail(self) -> str:
        raw = b"".join(self._tail_chunks)
        return raw.decode("utf-8", errors="replace")[-self._max_bytes:]
