"""
Annotate `ss`/`netstat` command output with terminal-copilot categories.

Reads command output from stdin and prints original rows with a category
prefix on the left.
"""
from __future__ import annotations

import argparse
import re
import sys

from ..monitor.process_monitor import _iter_processes, _rules


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

_SEVERITY = {
    "unknown": 0,
    "safe": 1,
    "installed_app": 2,
    "potentially_malicious": 3,
    "malicious": 4,
}


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


def _extract_pid(line: str) -> int | None:
    m = re.search(r"pid=(\d+)", line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None

    # netstat often uses "PID/Program name" as final column.
    m = re.search(r"\s(\d+)/[^\s]+\s*$", line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None

    # PowerShell Get-Net* outputs often end with OwningProcess integer.
    m = re.search(r"\s(\d{1,10})\s*$", line)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            return None
    return None


def _extract_ports(line: str) -> list[int]:
    out: list[int] = []
    # Support both Linux-style host:port and macOS netstat host.port forms.
    for tok in line.split():
        token = tok.strip(",")
        m = re.search(r"[.:](\d{1,5})$", token)
        if not m:
            continue
        try:
            p = int(m.group(1))
        except ValueError:
            continue
        if 0 <= p <= 65535:
            out.append(p)
    return out


def _is_data_row(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if stripped.startswith("Netid "):
        return False
    if stripped.startswith("Proto "):
        return False
    if stripped.startswith("Active "):
        return False
    if stripped.startswith("State "):
        return False
    if "OwningProcess" in stripped and "LocalAddress" in stripped:
        return False
    if stripped.startswith("LocalAddress "):
        return False
    if stripped.startswith("LocalPort "):
        return False
    return True


def _line_state_upper(line: str) -> str:
    up = line.upper()
    if "LISTEN" in up:
        return "LISTEN"
    return up


def _classify_line(
    line: str,
    *,
    pid_map: dict[int, str],
    suspicious_ports: set[int],
) -> str:
    pid = _extract_pid(line)
    category = pid_map.get(pid, "unknown") if pid is not None else "unknown"

    ports = _extract_ports(line)
    bad_ports = [p for p in ports if p in suspicious_ports]
    if not bad_ports:
        return category

    state = _line_state_upper(line)
    if "LISTEN" in state:
        bumped = "potentially_malicious"
    else:
        bumped = "potentially_malicious"

    if _SEVERITY[bumped] > _SEVERITY.get(category, 0):
        category = bumped

    if category == "potentially_malicious" and pid is not None:
        # If process context already looked suspicious and this row also has
        # suspicious ports, escalate.
        proc_cat = pid_map.get(pid, "unknown")
        if proc_cat in ("potentially_malicious", "malicious"):
            category = "malicious"

    return category


def _annotate_lines(raw: str) -> list[str]:
    pid_map = _category_by_pid()
    suspicious_ports = {int(p) for p in _rules().get("network_suspicious_ports", [])}

    lines = raw.splitlines()
    if not lines:
        return []

    out_lines: list[str] = []
    for line in lines:
        if not line.strip():
            out_lines.append(line)
            continue

        stripped = line.strip()
        if stripped.startswith("Netid ") or stripped.startswith("Proto "):
            out_lines.append(f"{'CATEGORY'.ljust(PREFIX_WIDTH)} {line}")
            continue

        if not _is_data_row(line):
            out_lines.append(line)
            continue

        category = _classify_line(line, pid_map=pid_map, suspicious_ports=suspicious_ports)
        out_lines.append(f"{_format_prefix(category)} {line}")

    return out_lines


def annotate_network_output(raw: str) -> str:
    annotated = _annotate_lines(raw)
    if not annotated:
        return ""
    return "\n".join(annotated).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", default="", help="calling command (ss or netstat)")
    parser.parse_args()

    raw = sys.stdin.read()
    sys.stdout.write(annotate_network_output(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
