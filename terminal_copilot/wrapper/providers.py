"""
Insight providers: given terminal context, return a list of Insight objects.
Includes rule-based (local heuristics) and an optional AI-backed provider.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .insights import Insight
from .pty_runner import TerminalContext
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
    # (ps, ps -ef, sudo ps aux, etc.). This avoids triggering on commands
    # like `id` that print similar-looking columns.
    last_cmd = (ctx.last_command() or "").strip()
    if not last_cmd:
        return insights
    # Split on whitespace and pipes so patterns like `ps aux | grep foo` match.
    tokens = re.split(r"[|\s]+", last_cmd)
    if "ps" not in tokens:
        return insights
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
