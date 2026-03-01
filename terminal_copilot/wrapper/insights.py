"""
Insight types and notification delivery (desktop notify and/or stderr banner).
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field


@dataclass
class Insight:
    """A single insight to show to the user (warning, vulnerability, suggestion)."""
    level: str  # "info" | "warning" | "danger"
    title: str
    body: str = ""
    commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "title": self.title,
            "body": self.body,
            "commands": self.commands,
        }


def notify_insight(insight: Insight) -> None:
    """Show the insight via desktop notification (if available) and a stderr banner."""
    # Desktop notification (Linux: notify-send)
    summary = f"[{insight.level.upper()}] {insight.title}"
    body = insight.body
    if insight.commands:
        body = (body + "\n\nSuggested:\n" + "\n".join(f"  $ {c}" for c in insight.commands)).strip()
    try:
        subprocess.run(
            ["notify-send", "--urgency=normal", summary, body[:500]],
            capture_output=True,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    # Stderr banner so it works in headless or when notify isn't available
    prefix = {"info": "\033[36m[tc]\033[0m", "warning": "\033[33m[tc]\033[0m", "danger": "\033[31m[tc]\033[0m"}.get(
        insight.level, "\033[36m[tc]\033[0m"
    )
    if insight.title in {
        "Windows process classification",
        "Network connection classification",
    } and insight.body:
        # Render categorized rows directly for better terminal readability.
        sys.stderr.write("\r\n" + insight.body.rstrip() + "\r\n")
        sys.stderr.flush()
        return

    banner = f"\r\n{prefix} {insight.title}"
    if insight.body:
        banner += f"\r\n     {insight.body}"
    for cmd in insight.commands:
        banner += f"\r\n     \033[32m$ {cmd}\033[0m"
    banner += "\r\n"
    sys.stderr.write(banner)
    sys.stderr.flush()
