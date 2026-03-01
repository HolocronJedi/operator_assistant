"""
Process and network monitor for the terminal wrapper.

On each check:
- Reads the current process list via `ps`.
- Reads current TCP/UDP connections via `ss` (if available).
- Classifies processes into:
  - safe (green)
  - installed_app (blue)
  - potentially_malicious (yellow)
  - malicious (red)
- Returns only *new* non-green processes since the last check so the user
  isn't spammed every time.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass
class ProcInfo:
    pid: int
    user: str
    name: str
    cmdline: str
    category: str  # unknown | safe | installed_app | potentially_malicious | malicious
    reason: str


def _load_rules() -> dict:
    # Repo root is two levels above the package directory:
    #   <repo>/terminal_copilot/monitor/process_monitor.py
    #   parents[0] = monitor/, parents[1] = terminal_copilot/, parents[2] = <repo>
    path = Path(__file__).resolve().parents[2] / "collector" / "detectors" / "rules.json"
    if not path.exists():
        return {}
    try:
        import json

        return json.load(path.open())
    except Exception:
        return {}


_rules_cache: dict | None = None
_last_reported_keys: set[str] = set()


def _rules() -> dict:
    global _rules_cache
    if _rules_cache is None:
        _rules_cache = _load_rules()
    return _rules_cache


def _host_safe_names(rules: dict) -> set[str]:
    host = platform.system().lower()
    base = {str(n).lower() for n in rules.get("safe_linux_names", [])}
    if host == "darwin":
        base.update(str(n).lower() for n in rules.get("safe_macos_names", []))
    return base


def _iter_processes() -> Iterable[ProcInfo]:
    """Yield ProcInfo for current processes using ps."""
    out = ""
    ps_bin = shutil.which("ps") or "/bin/ps"
    try:
        # Try portable variants first; macOS does not support GNU --no-headers.
        ps_cmds = [
            [ps_bin, "-axo", "pid=,user=,comm=,command="],
            [ps_bin, "-eo", "pid=,user=,comm=,args="],
            [ps_bin, "-eo", "pid,user,comm,args", "--no-headers"],
            ["/bin/ps", "-axo", "pid=,user=,comm=,command="],
            ["/bin/ps", "-eo", "pid=,user=,comm=,args="],
        ]
        for cmd in ps_cmds:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0 and res.stdout.strip():
                out = res.stdout
                break
    except Exception:
        return []
    if not out:
        return []

    rules = _rules()
    safe_names = _host_safe_names(rules)
    installed_prefixes = rules.get("installed_app_paths_prefix", [])
    suspicious_cmd_patterns = [
        re.compile(p, re.I)
        for p in rules.get("suspicious_cmdline_patterns", [])
    ]
    malicious_cmd_patterns = [
        re.compile(p, re.I)
        for p in rules.get("malicious_cmdline_patterns", [])
    ]
    safe_cmd_patterns = [
        re.compile(p, re.I)
        for p in rules.get("safe_cmdline_patterns", [])
    ]

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=3)
        if len(parts) < 3:
            continue
        pid_s, user, name = parts[:3]
        cmdline = parts[3] if len(parts) == 4 else name
        try:
            pid = int(pid_s)
        except ValueError:
            continue

        category = "unknown"
        reasons: list[str] = []
        name_l = name.lower()

        if name_l in safe_names:
            category = "safe"
            reasons.append("known safe process name")
        elif any(p.search(name) or p.search(cmdline) for p in safe_cmd_patterns):
            category = "safe"
            reasons.append("safe cmdline pattern")
        else:
            # Installed applications: rough heuristic based on path prefixes.
            for pref in installed_prefixes:
                if pref and cmdline.startswith(pref):
                    category = "installed_app"
                    reasons.append(f"installed path prefix: {pref}")
                    break

            # Malicious patterns first.
            for pat in malicious_cmd_patterns:
                if pat.search(cmdline):
                    category = "malicious"
                    reasons.append(f"malicious cmdline pattern: {pat.pattern}")
                    break
            else:
                # Suspicious command line patterns bump category.
                for pat in suspicious_cmd_patterns:
                    if pat.search(cmdline):
                        if category in ("unknown", "safe", "installed_app"):
                            category = "potentially_malicious"
                        reasons.append(f"cmdline pattern: {pat.pattern}")
                        break

        yield ProcInfo(
            pid=pid,
            user=user,
            name=name,
            cmdline=cmdline,
            category=category,
            reason="; ".join(reasons) if reasons else "",
        )


def _iter_suspicious_connections() -> dict[int, list[str]]:
    """
    Map pid -> list of reasons based on network ports using `ss`.
    """
    rules = _rules()
    suspicious_ports = set(rules.get("network_suspicious_ports", []))
    if not suspicious_ports:
        return {}

    try:
        out = subprocess.run(
            ["ss", "-tunp"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
    except Exception:
        return {}

    by_pid: dict[int, list[str]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid"):
            continue
        # Extract pid first so we only attribute ports to known processes.
        m_pid = re.search(r"pid=(\d+)", line)
        if not m_pid:
            continue
        try:
            pid = int(m_pid.group(1))
        except ValueError:
            continue
        # Now look for any port numbers on this line; let the rule list
        # decide which ones are interesting. This is more tolerant of
        # different `ss` output formats (LISTEN, ESTAB, v6, etc.).
        for m_port in re.finditer(r":(\d{1,5})\\b", line):
            try:
                port = int(m_port.group(1))
            except ValueError:
                continue
            if port not in suspicious_ports:
                continue
            by_pid.setdefault(pid, []).append(
                f"connection on suspicious port {port}"
            )
    return by_pid


def classify_ps_output(text: str) -> list[ProcInfo]:
    """
    Best-effort classifier for arbitrary `ps` output (ps, ps aux, ps -ef, etc.).

    We only need pid, user, name/cmdline; everything else is ignored. This lets
    the user run whatever ps flags they like and still get categorization.
    """
    rules = _rules()
    safe_names = _host_safe_names(rules)
    installed_prefixes = rules.get("installed_app_paths_prefix", [])
    suspicious_cmd_patterns = [
        re.compile(p, re.I) for p in rules.get("suspicious_cmdline_patterns", [])
    ]
    malicious_cmd_patterns = [
        re.compile(p, re.I) for p in rules.get("malicious_cmdline_patterns", [])
    ]
    safe_cmd_patterns = [
        re.compile(p, re.I) for p in rules.get("safe_cmdline_patterns", [])
    ]

    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return []

    # Drop header if present (starts with USER or PID usually).
    if lines and (
        lines[0].upper().startswith("USER ")
        or lines[0].upper().startswith("UID ")
        or lines[0].upper().startswith("PID ")
    ):
        lines = lines[1:]

    out: list[ProcInfo] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue

        user = parts[0]
        # Heuristics for common ps formats.
        pid_idx = 1
        cmd_start_idx = 1
        if "COMMAND" in line or "CMD" in line:
            # ps aux: USER PID ... COMMAND
            # ps -ef: UID PID PPID ... CMD
            # Heuristic based on field count.
            if len(parts) >= 11:
                # Likely ps aux: user pid ... 10th=COMMAND start
                pid_idx = 1
                cmd_start_idx = 10
            elif len(parts) >= 8:
                # Likely ps -ef: uid pid ppid c stime tty time cmd
                pid_idx = 1
                cmd_start_idx = 7
        else:
            # Fallback: treat second field as PID, command from third onward.
            pid_idx = 1
            cmd_start_idx = 2 if len(parts) > 2 else 1

        try:
            pid = int(parts[pid_idx])
        except (ValueError, IndexError):
            continue

        cmdline = " ".join(parts[cmd_start_idx:]) if cmd_start_idx < len(parts) else ""
        name = cmdline.split()[0] if cmdline else parts[pid_idx]

        category = "unknown"
        reasons: list[str] = []
        name_l = name.lower()

        if name_l in safe_names:
            category = "safe"
            reasons.append("known safe process name")
        elif any(p.search(name) or p.search(cmdline) for p in safe_cmd_patterns):
            category = "safe"
            reasons.append("safe cmdline pattern")
        else:
            for pref in installed_prefixes:
                if pref and cmdline.startswith(pref):
                    category = "installed_app"
                    reasons.append(f"installed path prefix: {pref}")
                    break

            # Malicious patterns first.
            for pat in malicious_cmd_patterns:
                if pat.search(cmdline):
                    category = "malicious"
                    reasons.append(f"malicious cmdline pattern: {pat.pattern}")
                    break
            else:
                for pat in suspicious_cmd_patterns:
                    if pat.search(cmdline):
                        if category in ("unknown", "safe", "installed_app"):
                            category = "potentially_malicious"
                        reasons.append(f"cmdline pattern: {pat.pattern}")
                        break

        out.append(
            ProcInfo(
                pid=pid,
                user=user,
                name=name,
                cmdline=cmdline or name,
                category=category,
                reason="; ".join(reasons) if reasons else "",
            )
        )

    return out


def scan_processes_and_connections() -> list[ProcInfo]:
    """
    Scan processes+network, classify, and return only *new* non-safe/non-unknown entries
    since the last call.
    """
    suspicious_conns = _iter_suspicious_connections()
    results: list[ProcInfo] = []

    global _last_reported_keys

    for p in _iter_processes():
        reasons = [p.reason] if p.reason else []
        conn_reasons = suspicious_conns.get(p.pid, [])
        if conn_reasons:
            reasons.extend(conn_reasons)
            if p.category in ("unknown", "safe", "installed_app"):
                p.category = "potentially_malicious"
        if not reasons and p.category == "safe":
            continue
        # Escalate category if we have both suspicious cmd and ports.
        if conn_reasons and "cmdline pattern" in (p.reason or ""):
            p.category = "malicious"

        p.reason = "; ".join(r for r in reasons if r)
        if p.category in ("safe", "unknown"):
            continue

        key = f"{p.pid}:{p.category}:{p.reason}"
        if key in _last_reported_keys:
            continue
        _last_reported_keys.add(key)
        results.append(p)

    return results
