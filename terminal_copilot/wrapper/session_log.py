"""
Opt-in session transcript logging for terminal-copilot.

Writes newline-delimited JSON (NDJSON) events that can be replayed or
analyzed by downstream tools (including LLM copilots).
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


_REDACTION_PATTERNS = [
    # Common API key patterns and bearer tokens.
    re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    re.compile(r"\b(Bearer\s+[A-Za-z0-9._\-]{20,})\b", re.I),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _default_log_path(session_id: str) -> str:
    root = Path.home() / ".terminal-copilot" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return str(root / f"session-{stamp}-{session_id}.ndjson")


def _redact_text(text: str) -> str:
    out = text
    for pat in _REDACTION_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


@dataclass
class SessionRecorder:
    """Append-only NDJSON session recorder."""

    host_os: str
    shell: str
    file_path: str | None = None
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    _fh: object | None = field(default=None, init=False, repr=False)

    def open(self) -> str:
        path = self.file_path or _default_log_path(self.session_id)
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        self._fh = p.open("a", encoding="utf-8")
        self.file_path = str(p)
        self._write(
            {
                "event": "session_start",
                "host": {
                    "os": self.host_os,
                },
                "shell": os.path.basename(self.shell),
            }
        )
        return self.file_path

    def close(self, *, exit_code: int | None = None) -> None:
        if not self._fh:
            return
        self._write({"event": "session_end", "exit_code": exit_code})
        try:
            self._fh.close()
        finally:
            self._fh = None

    def record_output(self, text: str, *, source: str = "shell") -> None:
        if not text:
            return
        self._write(
            {
                "event": "output",
                "direction": "out",
                "source": source,
                "raw": _redact_text(text),
            }
        )

    def record_input(self, command: str, *, source: str = "tty") -> None:
        cmd = command.strip()
        if not cmd:
            return
        self._write(
            {
                "event": "input",
                "direction": "in",
                "source": source,
                "command": _redact_text(cmd),
            }
        )

    def record_note(self, message: str) -> None:
        msg = message.strip()
        if not msg:
            return
        self._write(
            {
                "event": "note",
                "direction": "meta",
                "message": msg,
            }
        )

    def _write(self, payload: dict) -> None:
        if not self._fh:
            return
        event = {
            "ts": _utc_now(),
            "session_id": self.session_id,
        }
        event.update(payload)
        try:
            self._fh.write(json.dumps(event, ensure_ascii=True) + "\n")
            self._fh.flush()
        except OSError:
            # Best effort logging should never break the terminal session.
            pass
