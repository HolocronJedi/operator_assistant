"""
Insight providers: given terminal context, return a list of Insight objects.
Includes rule-based (local heuristics) and an optional AI-backed provider.
"""
from __future__ import annotations

import json
import os
import re
import hashlib
from pathlib import Path

from .insights import Insight
from .pty_runner import TerminalContext
from .net_annotate import annotate_network_output
from .tasklist_annotate import annotate_windows_process_output
from ..monitor.process_monitor import (
    scan_processes_and_connections,
    classify_ps_output,
)


def _load_rules() -> dict:
    path = Path(__file__).resolve().parent.parent.parent / "collector" / "detectors" / "rules.json"
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


# Compiled patterns from rules (suspicious command line)
_suspicious_cmdline_patterns: list[re.Pattern] | None = None
_last_windows_proc_digest: str | None = None
_last_windows_proc_input_len: int = -1
_last_network_digest: str | None = None
_last_network_input_len: int = -1


def _get_suspicious_patterns() -> list[re.Pattern]:
    global _suspicious_cmdline_patterns
    if _suspicious_cmdline_patterns is not None:
        return _suspicious_cmdline_patterns
    rules = _load_rules()
    raw = rules.get("suspicious_cmdline_patterns", [])

    compiled: list[re.Pattern] = []
    for p in raw:
        # Treat rules like "curl | sh" as loose patterns: allow arbitrary
        # arguments between tokens instead of requiring an exact literal match.
        escaped = re.escape(p)
        # Any whitespace in the rule becomes "\s+.*" in the regex, so
        # "curl | sh" matches "curl http://x | sh", etc.
        pattern = re.sub(r"\\\s+", r"\\s+.*", escaped)
        compiled.append(re.compile(pattern, re.I))

    _suspicious_cmdline_patterns = compiled
    return _suspicious_cmdline_patterns


def _extract_ps_block(ctx: TerminalContext) -> str:
    """
    Heuristically extract the most recent ps output block from the buffered
    terminal output.

    We walk backwards from the end of output_lines looking for a header line
    typical of ps (starts with USER/UID/PID), then take that line and all
    following non-empty lines as the ps block.
    """
    lines = ctx.output_lines
    if not lines:
        return ""

    header_idx = None
    for i in range(len(lines) - 1, -1, -1):
        up = lines[i].lstrip().upper()
        if up.startswith("USER ") or up.startswith("UID ") or up.startswith("PID "):
            header_idx = i
            break
    if header_idx is None:
        return ""

    block: list[str] = []
    for line in lines[header_idx:]:
        if not line.strip():
            break
        block.append(line)
    return "\n".join(block)


def _extract_tasklist_block(ctx: TerminalContext) -> str:
    """
    Best-effort extraction of the most recent tasklist output block from
    terminal lines. Handles both table and csv output.
    """
    lines = ctx.output_lines
    if not lines:
        return ""

    start = None
    for i in range(len(lines) - 1, -1, -1):
        up = lines[i].strip().upper()
        if up.startswith("IMAGE NAME"):
            start = i
            break
        if lines[i].lstrip().startswith('"'):
            # CSV /fo csv lines.
            start = i
            # Walk upward while previous lines are csv rows too.
            while start > 0 and lines[start - 1].lstrip().startswith('"'):
                start -= 1
            break
    if start is None:
        return ""

    block: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            if block:
                break
            continue
        # Stop when prompt-like line appears after we've captured rows.
        if block and (
            stripped.endswith("$")
            or stripped.endswith(">")
            or stripped.startswith("[tc]")
        ):
            break
        block.append(line)
    return "\n".join(block)


def _extract_windows_process_block(ctx: TerminalContext) -> str:
    """
    Extract the latest Windows process-list block from context. Supports:
    tasklist (table/csv/list), Get-Process, and wmic process outputs.
    """
    lines = ctx.output_lines
    if not lines:
        return ""

    # Preferred anchor: find the most recent echoed command line for the
    # command user just ran (e.g. tasklist/Get-Process/wmic process), then
    # take lines until the next prompt-like line.
    last_cmd = (ctx.last_command() or "").strip().lower()
    if last_cmd:
        anchor = None
        for i in range(len(lines) - 1, -1, -1):
            low = lines[i].lower()
            if last_cmd in low and (
                "*evil-winrm*" in low or low.rstrip().endswith("$ " + last_cmd)
            ):
                anchor = i
                break
        if anchor is not None:
            block: list[str] = []
            for line in lines[anchor + 1 :]:
                stripped = line.strip()
                if not stripped:
                    if block:
                        break
                    continue
                if (
                    stripped.startswith("[tc]")
                    or stripped.startswith("[safe]")
                    or stripped.startswith("[unknown]")
                    or stripped.startswith("[potentially_malicious]")
                    or stripped.startswith("[malicious]")
                ):
                    break
                if stripped.startswith("*Evil-WinRM*") and ">" in stripped:
                    break
                if stripped.endswith("$"):
                    break
                block.append(line)
            if block:
                return "\n".join(block)

    start = None
    for i in range(len(lines) - 1, -1, -1):
        stripped = lines[i].strip()
        up = stripped.upper()
        if (
            up.startswith("IMAGE NAME")
            or up.startswith("HANDLES ") and "PROCESSNAME" in up
            or up.startswith("NAME ") and "PROCESSID" in up
            or up.startswith("IMAGE NAME:")
            or (lines[i].lstrip().startswith('"'))
        ):
            start = i
            # For contiguous CSV rows, walk up to first quoted line.
            if lines[i].lstrip().startswith('"'):
                while start > 0 and lines[start - 1].lstrip().startswith('"'):
                    start -= 1
            break
    if start is None:
        # Fallback for long outputs where the header scrolled out of the
        # ring buffer: still try classifying recent rows.
        tail = lines[-120:] if len(lines) > 120 else lines
        filtered = [
            ln for ln in tail
            if ln.strip()
            and not ln.strip().startswith("[tc]")
            and not ln.strip().startswith("[safe]")
            and not ln.strip().startswith("[unknown]")
            and not ln.strip().startswith("[potentially_malicious]")
            and not ln.strip().startswith("[malicious]")
        ]
        return "\n".join(filtered)

    block: list[str] = []
    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            if block:
                break
            continue
        if block and (
            stripped.endswith("$")
            or stripped.endswith(">")
            or stripped.startswith("[tc]")
            or stripped.startswith("*Evil-WinRM*")
        ):
            break
        block.append(line)
    return "\n".join(block)


def _extract_windows_process_block_for_last_cmd(
    ctx: TerminalContext, last_cmd: str
) -> tuple[str, bool]:
    """
    Extract output block for the most recent Windows process command echo.
    Returns (block, complete), where complete indicates we observed the next
    prompt after the block (command fully finished).
    """
    lines = ctx.output_lines
    if not lines or not last_cmd:
        return "", False

    cmd_l = last_cmd.strip().lower()
    anchor = None
    for i in range(len(lines) - 1, -1, -1):
        low = lines[i].lower()
        if cmd_l in low and (
            "*evil-winrm*" in low
            or low.rstrip().endswith("> " + cmd_l)
            or low.rstrip().endswith("$ " + cmd_l)
        ):
            anchor = i
            break
    if anchor is None:
        return "", False

    block: list[str] = []
    complete = False
    for line in lines[anchor + 1 :]:
        stripped = line.strip()
        if not stripped:
            if block:
                break
            continue
        # Next prompt means command completed.
        if (
            stripped.startswith("*Evil-WinRM*")
            and ">" in stripped
        ) or stripped.endswith("$") or stripped.endswith(">"):
            complete = True
            break
        if (
            stripped.startswith("[tc]")
            or stripped.startswith("[safe]")
            or stripped.startswith("[unknown]")
            or stripped.startswith("[potentially_malicious]")
            or stripped.startswith("[malicious]")
        ):
            continue
        block.append(line)

    return "\n".join(block), complete


def _extract_command_block_for_last_cmd(
    ctx: TerminalContext, last_cmd: str
) -> tuple[str, bool]:
    """
    Extract output block for the most recent command echo in local/remote shells.
    Returns (block, complete).
    """
    lines = ctx.output_lines
    if not lines or not last_cmd:
        return "", False

    cmd_l = last_cmd.strip().lower()
    anchor = None
    for i in range(len(lines) - 1, -1, -1):
        low = lines[i].lower().rstrip()
        if cmd_l in low and (
            "*evil-winrm*" in low
            or low.endswith("> " + cmd_l)
            or low.endswith("$ " + cmd_l)
            or low.endswith("# " + cmd_l)
        ):
            anchor = i
            break
    if anchor is None:
        return "", False

    block: list[str] = []
    complete = False
    for line in lines[anchor + 1 :]:
        stripped = line.strip()
        if not stripped:
            if block:
                break
            continue
        if (
            (stripped.startswith("*Evil-WinRM*") and ">" in stripped)
            or stripped.endswith("$")
            or stripped.endswith(">")
            or stripped.startswith("[tc]")
        ):
            complete = True
            break
        if (
            stripped.startswith("[safe]")
            or stripped.startswith("[unknown]")
            or stripped.startswith("[potentially_malicious]")
            or stripped.startswith("[malicious]")
        ):
            continue
        block.append(line)

    return "\n".join(block), complete


def _is_windows_remote_session(ctx: TerminalContext) -> bool:
    for line in ctx.output_lines[-40:]:
        stripped = line.strip()
        if "*EVIL-WINRM*" in stripped.upper():
            return True
        if re.search(r"[A-Za-z]:\\", stripped):
            return True
    return False


def _tail_has_shell_prompt(ctx: TerminalContext) -> bool:
    """
    Heuristic: command output is complete only when a prompt-like line is seen
    in the recent tail.
    """
    tail = ctx.output_lines[-20:] if len(ctx.output_lines) > 20 else ctx.output_lines
    for line in tail:
        s = line.strip()
        if not s:
            continue
        if s.startswith("[tc]"):
            continue
        if s.startswith("*Evil-WinRM*"):
            return True
        if s.endswith("$") or s.endswith(">"):
            return True
    return False


def rule_based_insights(ctx: TerminalContext) -> list[Insight]:
    """
    Local heuristics using collector/detectors/rules.json, focused on what you
    just asked to see via a ps command.

    Behaviour:
    - If the last command was not some form of `ps ...`, do nothing.
    - If it was, parse the most recent terminal output as ps text,
      classify each process, enrich with network data, and then print
      a coloured summary *after* the normal ps output.
    """
    insights: list[Insight] = []

    # Only react when the last command the user typed was some form of ps
    # or tasklist.
    last_cmd = (ctx.last_command() or "").strip()
    if not last_cmd:
        return insights
    # Split on whitespace and pipes so patterns like `ps aux | grep foo` match.
    tokens = [t.lower() for t in re.split(r"[|\s]+", last_cmd) if t]
    is_windows_proc_cmd = (
        ("tasklist" in tokens)
        or ("get-process" in tokens)
        or ("gps" in tokens)
        or ("wmic" in tokens and "process" in tokens)
        or ("ps" in tokens and _is_windows_remote_session(ctx))
    )
    is_net_cmd = "netstat" in tokens or "ss" in tokens

    if is_windows_proc_cmd:
        global _last_windows_proc_input_len
        if len(ctx.input_lines) == _last_windows_proc_input_len:
            return insights
        proc_snapshot, complete = _extract_windows_process_block_for_last_cmd(
            ctx, last_cmd
        )
        if not complete:
            return insights
        if not proc_snapshot:
            proc_snapshot = _extract_windows_process_block(ctx)
        if not proc_snapshot:
            return insights
        global _last_windows_proc_digest
        digest = hashlib.sha256(proc_snapshot.encode("utf-8", errors="replace")).hexdigest()
        if digest == _last_windows_proc_digest:
            return insights
        _last_windows_proc_digest = digest
        _last_windows_proc_input_len = len(ctx.input_lines)
        body, level = annotate_windows_process_output(proc_snapshot)
        if not body:
            return insights
        insights.append(
            Insight(
                level=level,
                title="Windows process classification",
                body=body,
                commands=[],
            )
        )
        return insights

    if is_net_cmd:
        if os.environ.get("TC_NET_WRAPPED") == "1":
            # netstat/ss output already rewritten inline by shell wrapper.
            return insights
        global _last_network_input_len
        if len(ctx.input_lines) == _last_network_input_len:
            return insights
        net_snapshot, complete = _extract_command_block_for_last_cmd(ctx, last_cmd)
        if not complete:
            return insights
        if not net_snapshot:
            return insights
        global _last_network_digest
        digest = hashlib.sha256(net_snapshot.encode("utf-8", errors="replace")).hexdigest()
        if digest == _last_network_digest:
            return insights
        _last_network_digest = digest
        _last_network_input_len = len(ctx.input_lines)
        body = annotate_network_output(net_snapshot).rstrip()
        if not body:
            return insights
        insights.append(
            Insight(
                level="info",
                title="Network connection classification",
                body=body,
                commands=[],
            )
        )
        return insights

    if "ps" in tokens:
        if os.environ.get("TC_PS_WRAPPED") == "1":
            # ps output is already rewritten inline by shell wrapper integration.
            return insights

        ps_snapshot = _extract_ps_block(ctx)
        if not ps_snapshot:
            return insights

        procs = classify_ps_output(ps_snapshot)
        if not procs:
            return insights

        # Enrich with live network/connection heuristics, but only for PIDs
        # that appeared in the ps output.
        live = {p.pid: p for p in scan_processes_and_connections()}
        merged: list[dict] = []
        for p in procs:
            lp = live.get(p.pid)
            category = p.category
            reason = p.reason
            if lp:
                # Prefer the more severe category between ps-based and live.
                order = {
                    "unknown": 0,
                    "safe": 0,
                    "installed_app": 1,
                    "potentially_malicious": 2,
                    "malicious": 3,
                }
                if order.get(lp.category, 0) > order.get(category, 0):
                    category = lp.category
                reason = "; ".join(
                    r
                    for r in [p.reason, lp.reason]
                    if r
                )
            merged.append(
                {
                    "pid": p.pid,
                    "user": p.user,
                    "name": p.name,
                    "cmdline": p.cmdline,
                    "category": category,
                    "reason": reason,
                }
            )

        # Build annotated process list with flags on the left.
        cat_to_colour = {
            "safe": "\033[32m",                 # green
            "installed_app": "\033[34m",        # blue
            "potentially_malicious": "\033[33m",  # yellow
            "malicious": "\033[31m",            # red
            "unknown": "",
        }
        flag_for_cat = {
            "safe": "[safe]",
            "installed_app": "[installed_app]",
            "potentially_malicious": "[potentially_malicious]",
            "malicious": "[malicious]",
            "unknown": "[unknown]",
        }
        reset = "\033[0m"
        lines: list[str] = []
        for info in merged:
            cat = info.get("category") or "unknown"
            colour = cat_to_colour.get(cat, "")
            flag = flag_for_cat.get(cat, "[unknown]")
            if colour:
                prefix = f"{colour}{flag}{reset}"
            else:
                prefix = flag
            lines.append(f"{prefix} {info['user']} {info['pid']} {info['cmdline']}")

        body = "\n".join(lines).rstrip()

        # Overall level is based on the worst category present.
        level = "info"
        categories_present = {info.get("category") or "unknown" for info in merged}
        if "malicious" in categories_present:
            level = "danger"
        elif "potentially_malicious" in categories_present:
            level = "warning"

        insights.append(
            Insight(
                level=level,
                title="Process classification for last ps output",
                body=body,
                commands=[],
            )
        )

    return insights


def ai_insights(ctx: TerminalContext) -> list[Insight]:
    """
    Optional AI-backed insights. Set OPENAI_API_KEY (or ANTHROPIC_API_KEY) to enable.
    Falls back to rule-based only if no key or request fails.
    """
    try:
        from .ai_provider import query_ai_insights
        return query_ai_insights(ctx)
    except Exception:
        return []


def combined_insights(ctx: TerminalContext) -> list[Insight]:
    """Run rule-based first, then AI if configured. Dedupe by title."""
    seen_titles: set[str] = set()
    out: list[Insight] = []
    for insight in rule_based_insights(ctx) + ai_insights(ctx):
        if insight.title not in seen_titles:
            seen_titles.add(insight.title)
            out.append(insight)
    return out
