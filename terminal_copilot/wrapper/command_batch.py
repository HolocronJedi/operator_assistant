"""
Utilities for loading and executing newline-separated command batches from
local files.
"""
from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import NamedTuple


_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class BatchInvocation(NamedTuple):
    recognized: bool
    inline_path: str | None
    parse_error: str | None


def _normalize_terminal_input(text: str) -> str:
    # Remove bracketed-paste wrappers and common ANSI CSI sequences.
    cleaned = text.replace("\x1b[200~", "").replace("\x1b[201~", "")
    cleaned = _CSI_RE.sub("", cleaned)
    return cleaned


def first_nonempty_line(text: str) -> str:
    cleaned = _normalize_terminal_input(text)
    for line in cleaned.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def parse_batch_invocation(line: str) -> BatchInvocation:
    """
    Parse `tc runfile` / `tc runlist` invocations.

    Examples:
      tc runfile
      tc runfile ~/commands.txt
      tc runlist "/tmp/my commands.txt"
    """
    raw = first_nonempty_line(line)
    if not raw:
        return BatchInvocation(False, None, None)
    try:
        parts = shlex.split(raw)
    except ValueError as e:
        if raw.startswith("tc runfile") or raw.startswith("tc runlist"):
            return BatchInvocation(True, None, str(e))
        return BatchInvocation(False, None, None)

    if len(parts) < 2 or parts[0] != "tc" or parts[1] not in ("runfile", "runlist"):
        return BatchInvocation(False, None, None)
    if len(parts) == 2:
        return BatchInvocation(True, None, None)
    return BatchInvocation(True, " ".join(parts[2:]), None)


def load_commands_from_file(path_text: str) -> tuple[str, list[str]]:
    """
    Read newline-separated commands from a local text file.
    Blank lines and comment lines beginning with '#' are ignored.
    """
    path = Path(path_text).expanduser()
    display = str(path)
    content = path.read_text(encoding="utf-8")

    commands: list[str] = []
    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        commands.append(line.rstrip())
    return display, commands


def encode_commands(commands: list[str]) -> bytes:
    if not commands:
        return b""
    return ("\n".join(commands) + "\n").encode("utf-8")
