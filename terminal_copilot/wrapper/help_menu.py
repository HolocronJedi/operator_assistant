"""
Help menu generation for the interactive terminal-copilot shell context.
"""
from __future__ import annotations

import os
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _iter_custom_locations() -> list[Path]:
    roots: list[Path] = []

    env_paths = os.environ.get("TC_MODULE_PATHS", "").strip()
    if env_paths:
        for raw in env_paths.split(os.pathsep):
            p = Path(raw).expanduser()
            if p.exists() and p.is_dir():
                roots.append(p.resolve())

    for candidate in (
        Path.cwd() / "modules",
        Path.cwd() / "scripts",
        _project_root() / "modules",
        _project_root() / "scripts",
    ):
        if candidate.exists() and candidate.is_dir():
            rp = candidate.resolve()
            if rp not in roots:
                roots.append(rp)
    return roots


def _discover_custom_entries() -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for root in _iter_custom_locations():
        for child in sorted(root.iterdir(), key=lambda p: p.name.lower()):
            if child.name.startswith(".") or child.name.startswith("_"):
                continue
            if child.is_file() and child.suffix == ".py":
                entries.append(("python-module", child.stem, str(child)))
                continue
            if child.is_file() and os.access(child, os.X_OK):
                entries.append(("script", child.name, str(child)))
    return entries


def render_help_menu() -> str:
    builtins = [
        ("combined_insights", "Rule-based + optional AI insights"),
        ("rule_based_insights", "Local process/rule heuristic insights"),
        ("ai_insights", "AI-backed insights (when API keys are set)"),
    ]
    custom = _discover_custom_entries()

    lines: list[str] = []
    lines.append("[tc] terminal-copilot help")
    lines.append("")
    lines.append("Built-in modules:")
    for name, desc in builtins:
        lines.append(f"  - {name}: {desc}")

    lines.append("")
    lines.append("Custom modules/scripts:")
    if custom:
        for kind, name, path in custom:
            lines.append(f"  - {name} ({kind}) -> {path}")
    else:
        lines.append("  - none found")

    lines.append("")
    lines.append("Discovery locations:")
    lines.append("  - $TC_MODULE_PATHS (os.pathsep-separated)")
    lines.append("  - ./modules, ./scripts")
    lines.append("")
    lines.append("Batch command execution:")
    lines.append('  - tc runfile')
    lines.append('    Prompts for a local file path, then executes newline-separated commands')
    lines.append("    in the current shell context (including active SSH/remote sessions).")
    lines.append('  - tc runfile /path/to/commands.txt')
    lines.append("    Same behavior with inline path.")
    lines.append("  - Confirmation per command: [y]es / [N]o (default skip) / [x] exit")
    lines.append("  - tc session start [path]")
    lines.append("    Start session logging while already inside the wrapped shell.")
    lines.append("  - tc session stop")
    lines.append("    Stop session logging for the current shell.")
    lines.append("  - tc session path")
    lines.append("    Print active session transcript path.")
    lines.append("")
    lines.append("Session recording (opt-in):")
    lines.append("  - Start wrapper with --record-session to persist this session as NDJSON.")
    lines.append("  - Optional --session-log /path/to/file.ndjson to choose output path.")
    lines.append("  - Default path: ~/.terminal-copilot/sessions/")
    lines.append("")
    lines.append("Windows remote support:")
    lines.append("  - `tasklist`, `Get-Process`, and `wmic process` output is classified")
    lines.append("    from terminal context (works via SSH/evil-winrm).")
    lines.append("  - On Windows tc shells, `tasklist`, `Get-Process`/`gps`, and")
    lines.append("    `wmic process ...` are wrapped inline with category prefixes.")
    lines.append("  - On Windows tc shells, `netstat`, `Get-NetTCPConnection`, and")
    lines.append("    `Get-NetUDPEndpoint` are wrapped inline with connection categories.")
    lines.append("  - On Windows host shells, selected remote command output is rewritten")
    lines.append("    inline before display for tasklist/Get-Process/wmic process and")
    lines.append("    ss/netstat flows.")
    lines.append("  - Local Windows shells (`powershell.exe` / `cmd.exe`) are supported.")
    lines.append("  - `netstat` output is annotated with the same categories.")
    lines.append("  - Remote shell prompts may not include `[tc]`, but tc monitoring remains active.")
    lines.append("")
    lines.append('Type "help" any time in this wrapped shell to see this menu again.')
    return "\n".join(lines)
