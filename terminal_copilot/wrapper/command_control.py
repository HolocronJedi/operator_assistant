"""
Parse terminal-copilot control commands typed inside the wrapped shell.
"""
from __future__ import annotations

import shlex
from typing import NamedTuple


class SessionInvocation(NamedTuple):
    recognized: bool
    action: str | None
    path: str | None
    parse_error: str | None


def parse_session_invocation(line: str) -> SessionInvocation:
    raw = line.strip()
    if not raw:
        return SessionInvocation(False, None, None, None)

    try:
        parts = shlex.split(raw)
    except ValueError as e:
        if raw.startswith("tc session"):
            return SessionInvocation(True, None, None, str(e))
        return SessionInvocation(False, None, None, None)

    if len(parts) < 3 or parts[0] != "tc" or parts[1] != "session":
        return SessionInvocation(False, None, None, None)

    action = parts[2].lower()
    if action not in ("start", "stop", "path"):
        return SessionInvocation(
            True,
            None,
            None,
            "expected one of: start, stop, path",
        )

    if action in ("stop", "path") and len(parts) != 3:
        return SessionInvocation(True, None, None, f"'{action}' does not accept extra arguments")

    if action == "start":
        if len(parts) == 3:
            return SessionInvocation(True, "start", None, None)
        return SessionInvocation(True, "start", " ".join(parts[3:]), None)

    return SessionInvocation(True, action, None, None)
