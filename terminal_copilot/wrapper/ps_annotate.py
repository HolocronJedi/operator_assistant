"""
Annotate arbitrary `ps` command output with terminal-copilot categories.

Reads ps output from stdin and prints normal process list lines with a
category prefix on the far left.
"""
from __future__ import annotations

import re
import sys

from ..monitor.process_monitor import _iter_processes


COLOUR = {
    "safe": "\033[32m",
    "installed_app": "\033[34m",
    "potentially_malicious": "\033[33m",
    "malicious": "\033[31m",
    "unknown": "\033[90m",
}

FLAG = {
    "safe": "[safe]",
    "installed_app": "[installed_app]",
    "potentially_malicious": "[potentially_malicious]",
    "malicious": "[malicious]",
    "unknown": "[unknown]",
}

RESET = "\033[0m"
PREFIX_WIDTH = max(len(v) for v in FLAG.values())


def _category_by_pid() -> dict[int, str]:
    out: dict[int, str] = {}
    for p in _iter_processes():
        out[p.pid] = p.category or "unknown"
    return out


def _format_prefix(category: str) -> str:
    category = category if category in FLAG else "unknown"
    colour = COLOUR.get(category, "")
    flag = FLAG[category].ljust(PREFIX_WIDTH)
    if not colour:
        return flag
    return f"{colour}{flag}{RESET}"


def _annotate_lines(raw: str) -> list[str]:
    pid_map = _category_by_pid()
    lines = raw.splitlines()
    if not lines:
        return []

    # Try to locate PID column from a header line.
    pid_col = None
    header_idx = None
    for idx, line in enumerate(lines):
        parts = line.split()
        if not parts:
            continue
        upper = [p.upper() for p in parts]
        if "PID" in upper:
            pid_col = upper.index("PID")
            header_idx = idx
            break

    out_lines: list[str] = []

    for idx, line in enumerate(lines):
        if not line.strip():
            out_lines.append(line)
            continue

        if header_idx is not None and idx == header_idx:
            out_lines.append(f"{'CATEGORY'.ljust(PREFIX_WIDTH)} {line}")
            continue

        pid = None
        parts = line.split()
        if pid_col is not None and pid_col < len(parts) and parts[pid_col].isdigit():
            pid = int(parts[pid_col])
        else:
            m = re.search(r"\b(\d+)\b", line)
            if m:
                pid = int(m.group(1))

        category = pid_map.get(pid, "unknown") if pid is not None else "unknown"
        prefix = _format_prefix(category)
        annotated = f"{prefix} {line}"
        out_lines.append(annotated)

    return out_lines


def annotate_ps_output(raw: str) -> str:
    annotated = _annotate_lines(raw)
    if not annotated:
        return ""
    return "\n".join(annotated).rstrip() + "\n"


def main() -> int:
    raw = sys.stdin.read()
    sys.stdout.write(annotate_ps_output(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
