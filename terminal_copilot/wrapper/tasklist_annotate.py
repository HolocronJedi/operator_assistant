"""
Annotate Windows process-list output with terminal-copilot categories.

Supports:
- tasklist (table/csv/list formats, with or without headers)
- PowerShell Get-Process (table output)
- wmic process outputs (common table/csv forms)
"""
from __future__ import annotations

import argparse
import csv
import io
import re
import sys
from pathlib import Path
from typing import Iterable, NamedTuple


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


class WinProcRow(NamedTuple):
    name: str
    pid: int | None
    meta: str
    raw_line: str


def _load_rules() -> dict:
    path = Path(__file__).resolve().parents[2] / "collector" / "detectors" / "rules.json"
    if not path.exists():
        return {}
    try:
        import json

        return json.load(path.open())
    except Exception:
        return {}


def _format_prefix(category: str) -> str:
    category = category if category in FLAG else "unknown"
    colour = COLOUR.get(category, "")
    flag = FLAG[category].ljust(PREFIX_WIDTH)
    if not colour:
        return flag
    return f"{colour}{flag}{RESET}"


def _normalize_name(name: str) -> str:
    return name.strip().strip('"').lower()


def _categorize_name(name: str, rules: dict) -> str:
    lower = _normalize_name(name)
    safe_windows = {str(n).lower() for n in rules.get("safe_windows_names", [])}
    lolbins = {str(n).lower() for n in rules.get("lolbin_windows", [])}
    if lower and not lower.endswith(".exe"):
        if f"{lower}.exe" in safe_windows:
            return "safe"
        if f"{lower}.exe" in lolbins:
            return "potentially_malicious"
    if lower in safe_windows:
        return "safe"
    if lower in lolbins:
        return "potentially_malicious"
    return "unknown"


def _categorize_row(name: str, raw_line: str, rules: dict) -> str:
    """
    Score-accumulation classification for a process row.
    """
    base = _categorize_name(name, rules)
    text = f"{name} {raw_line}".lower()
    score = 0

    if base == "safe":
        score -= 30
    elif base == "potentially_malicious":
        score += 20

    for pat in rules.get("windows_safe_row_patterns", []):
        try:
            if re.search(str(pat), text, re.I):
                score -= 20
        except re.error:
            if str(pat).lower() in text:
                score -= 20

    for pat in rules.get("windows_suspicious_row_patterns", []):
        try:
            if re.search(str(pat), text, re.I):
                score += 20
        except re.error:
            if str(pat).lower() in text:
                score += 20

    for pat in rules.get("windows_malicious_row_patterns", []):
        try:
            if re.search(str(pat), text, re.I):
                score += 100
        except re.error:
            if str(pat).lower() in text:
                score += 100

    for pat in rules.get("suspicious_cmdline_patterns", []):
        try:
            if re.search(str(pat), text, re.I):
                score += 20
        except re.error:
            if str(pat).lower() in text:
                score += 20
    for pat in rules.get("malicious_cmdline_patterns", []):
        try:
            if re.search(str(pat), text, re.I):
                score += 100
        except re.error:
            if str(pat).lower() in text:
                score += 100

    if score >= 100:
        return "malicious"
    if score >= 20:
        return "potentially_malicious"
    if score <= -20:
        return "safe"

    if base in _SEVERITY:
        return base
    return "unknown"


def _looks_like_prompt(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    # Common remote/local prompt endings.
    return (
        stripped.endswith(">")
        or stripped.endswith("$")
        or stripped.startswith("*Evil-WinRM*")
        or stripped.startswith("[tc]")
    )


def _extract_name_from_tasklist_row(stripped: str) -> str | None:
    # tasklist table row: first token is image name, then pid column.
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s+(\d+)\s+", stripped)
    if m:
        return m.group(1)
    return None


def _extract_name_from_get_process_row(stripped: str) -> str | None:
    # Get-Process table row commonly ends with ProcessName and includes numeric Id.
    parts = stripped.split()
    if len(parts) < 2:
        return None
    if not any(p.isdigit() for p in parts):
        return None
    tail = parts[-1]
    if re.match(r"^[A-Za-z][A-Za-z0-9_.-]*$", tail):
        return tail
    return None


def _extract_name_from_wmic_row(stripped: str) -> str | None:
    # wmic table often starts with Name then ProcessId somewhere to the right.
    m = re.match(r"^([A-Za-z0-9_.-]+)\s+.*\b(\d+)\b", stripped)
    if m:
        return m.group(1)
    return None


def _iter_windows_rows(raw: str) -> Iterable[WinProcRow]:
    """
    Yield normalized rows from Windows process-list output.
    """
    lines = [ln.rstrip("\r") for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return []

    # tasklist /fo list style: key/value blocks.
    list_rows: list[WinProcRow] = []
    current: dict[str, str] = {}
    saw_list_keys = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _looks_like_prompt(line):
            continue
        if ":" not in stripped:
            continue
        left, right = stripped.split(":", 1)
        key = left.strip().lower()
        value = right.strip()
        if key in {"image name", "name", "caption"}:
            saw_list_keys = True
            if current.get("name"):
                list_rows.append(
                    WinProcRow(
                        name=current.get("name", ""),
                        pid=int(current["pid"]) if current.get("pid", "").isdigit() else None,
                        meta=" ".join(
                            p for p in [
                                f"session={current.get('session name')}" if current.get("session name") else "",
                                f"mem={current.get('mem usage')}" if current.get("mem usage") else "",
                            ] if p
                        ),
                        raw_line=f"Image Name: {current.get('name', '')}",
                    )
                )
                current = {}
            current["name"] = value
        elif saw_list_keys:
            current[key] = value
    if saw_list_keys and current.get("name"):
        list_rows.append(
            WinProcRow(
                name=current.get("name", ""),
                pid=int(current["pid"]) if current.get("pid", "").isdigit() else None,
                meta=" ".join(
                    p for p in [
                        f"session={current.get('session name')}" if current.get("session name") else "",
                        f"mem={current.get('mem usage')}" if current.get("mem usage") else "",
                    ] if p
                ),
                raw_line=f"Image Name: {current.get('name', '')}",
            )
        )
    if list_rows:
        return list_rows

    # CSV mode rows (tasklist /fo csv, wmic csv).
    csv_rows: list[WinProcRow] = []
    if any(ln.lstrip().startswith('"') for ln in lines):
        for line in lines:
            if _looks_like_prompt(line):
                continue
            if not line.lstrip().startswith('"'):
                continue
            try:
                parsed = next(csv.reader(io.StringIO(line)))
            except Exception:
                continue
            if not parsed:
                continue
            first = parsed[0].strip()
            # Skip header-like csv rows.
            if first.lower() in {"imagename", "name", "caption"}:
                continue
            pid: int | None = None
            if len(parsed) > 1:
                pid_text = parsed[1].strip().strip('"')
                if pid_text.isdigit():
                    pid = int(pid_text)
            meta = ""
            if len(parsed) > 2:
                rest = [p.strip().strip('"') for p in parsed[2:] if p.strip()]
                meta = " ".join(rest[:2]) if rest else ""
            csv_rows.append(WinProcRow(name=first, pid=pid, meta=meta, raw_line=line))
    if csv_rows:
        return csv_rows

    # Default table / get-process / wmic text mode.
    rows: list[WinProcRow] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if _looks_like_prompt(line):
            continue

        upper = stripped.upper()
        if upper.startswith("IMAGE NAME"):
            continue
        if upper.startswith("HANDLES ") and "PROCESSNAME" in upper:
            # Get-Process header line
            continue
        if upper.startswith("NAME ") and "PROCESSID" in upper:
            # wmic table header line
            continue
        if set(stripped).issubset({"=", " "}):
            continue

        # tasklist default table.
        m_task = re.match(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s+(\d+)\s+(.*)$", stripped)
        if m_task:
            rows.append(
                WinProcRow(
                    name=m_task.group(1),
                    pid=int(m_task.group(2)),
                    meta=m_task.group(3).strip(),
                    raw_line=line,
                )
            )
            continue

        # Get-Process table rows: tail usually "... <Id> <SI> <ProcessName>".
        m_gp = re.match(
            r"^.*\s(\d+)\s+\d+\s+([A-Za-z_][A-Za-z0-9_.-]*)$",
            stripped,
        )
        if m_gp:
            rows.append(
                WinProcRow(
                    name=m_gp.group(2),
                    pid=int(m_gp.group(1)),
                    meta="",
                    raw_line=line,
                )
            )
            continue

        # wmic table-ish fallback.
        name = (
            _extract_name_from_tasklist_row(stripped)
            or _extract_name_from_get_process_row(stripped)
            or _extract_name_from_wmic_row(stripped)
        )
        if not name:
            # Generic fallback for table-ish outputs from other tools:
            # first token looks like process name + some numeric token (pid).
            m_generic = re.match(r'^"?([A-Za-z_][A-Za-z0-9_.-]*)"?\s+.*\b(\d{1,8})\b', stripped)
            if m_generic:
                name = m_generic.group(1)
        if name:
            pid_match = re.search(r"\b(\d+)\b", stripped)
            pid = int(pid_match.group(1)) if pid_match else None
            rows.append(WinProcRow(name=name, pid=pid, meta="", raw_line=line))
    return rows


def annotate_windows_process_output(raw: str) -> tuple[str, str]:
    """
    Return (annotated_output, worst_level).
    worst_level is one of info|warning|danger based on categories present.
    """
    rules = _load_rules()
    rows = list(_iter_windows_rows(raw))
    if not rows:
        return "", "info"

    annotated: list[str] = []
    categories_present: set[str] = set()
    for row in rows:
        category = _categorize_row(row.name, row.raw_line, rules)
        categories_present.add(category)
        annotated.append(f"{_format_prefix(category)} {row.raw_line}")

    level = "info"
    if "malicious" in categories_present:
        level = "danger"
    elif "potentially_malicious" in categories_present:
        level = "warning"

    return "\n".join(annotated), level


def annotate_tasklist_output(raw: str) -> tuple[str, str]:
    # Backward-compatible alias.
    return annotate_windows_process_output(raw)


def annotate_tasklist_text(raw: str) -> str:
    body, _ = annotate_windows_process_output(raw)
    if not body:
        return ""
    return body.rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", default="", help="source command label")
    parser.parse_args()
    raw = sys.stdin.read()
    sys.stdout.write(annotate_tasklist_text(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
