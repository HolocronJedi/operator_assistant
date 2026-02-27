"""
PTY-based terminal wrapper: runs a shell in a pseudo-terminal, forwards all I/O,
and captures commands + output for insight providers (e.g. AI or rule-based).
"""
from __future__ import annotations

import os
import pty
import shutil
import sys
from dataclasses import dataclass, field
from typing import Callable

from .help_menu import render_help_menu
from .ring_buffer import RingBuffer


@dataclass
class TerminalContext:
    """Recent terminal activity for insight providers."""
    # Last N lines of output (from shell)
    output_lines: list[str] = field(default_factory=list)
    # Last N user input lines (commands)
    input_lines: list[str] = field(default_factory=list)
    # Full raw tail of output (e.g. last 4KB) for AI
    output_tail: str = ""

    def last_command(self) -> str | None:
        if not self.input_lines:
            return None
        return self.input_lines[-1].strip() or None

    def recent_output(self) -> str:
        return "\n".join(self.output_lines) if self.output_lines else self.output_tail


def _find_shell() -> str:
    shell = os.environ.get("SHELL", "sh")
    path = shutil.which(shell)
    return path or shell


def _is_help_command(data: bytes) -> bool:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return False
    return text.strip() == "help"


def _ensure_bashrc_tc_prompt() -> None:
    """
    Ensure the user's ~/.bashrc contains a small TC_CONTEXT-aware prompt
    snippet. This lets terminal-copilot mark the inner shell prompt with
    [tc] transparently, without the user having to edit their config.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot prompt integration"
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + '  PS1="[tc] $PS1"\n'
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            return
        with open(bashrc, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write("\n" + snippet + "\n")
    except OSError:
        # If we can't write to .bashrc, just skip; the wrapper still works,
        # but the prompt won't be auto-prefixed.
        return


def _ensure_bashrc_tc_help() -> None:
    """
    Ensure the user's ~/.bashrc contains a TC_CONTEXT-aware help override.
    With no args, `help` shows terminal-copilot menu; with args, it falls
    back to bash builtin help.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot help integration"
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + "  help() {\n"
        + "    if [[ $# -eq 0 ]]; then\n"
        + '      printf "%s\\n" "$TC_HELP_MENU"\n'
        + "      return 0\n"
        + "    fi\n"
        + '    builtin help "$@"\n'
        + "  }\n"
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            return
        with open(bashrc, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write("\n" + snippet + "\n")
    except OSError:
        return


def _ensure_bashrc_tc_ps() -> None:
    """
    Ensure ~/.bashrc contains a TC_CONTEXT-aware ps wrapper.
    The wrapper preserves normal ps output while adding category prefixes.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot ps integration"
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + "  ps() {\n"
        + '    local _tc_out _tc_status _tc_py="${TC_PYTHON_BIN:-python3}"\n'
        + '    _tc_out="$(command ps "$@")"\n'
        + "    _tc_status=$?\n"
        + "    if [[ $_tc_status -ne 0 ]]; then\n"
        + '      [[ -n "$_tc_out" ]] && printf "%s\\n" "$_tc_out"\n'
        + "      return $_tc_status\n"
        + "    fi\n"
        + '    if [[ -z "$TC_HOME" ]]; then\n'
        + '      printf "%s\\n" "$_tc_out"\n'
        + "      return 0\n"
        + "    fi\n"
        + '    printf "%s\\n" "$_tc_out" | PYTHONPATH="$TC_HOME${PYTHONPATH:+:$PYTHONPATH}" "$_tc_py" -m terminal_copilot.wrapper.ps_annotate\n'
        + "  }\n"
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            return
        with open(bashrc, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write("\n" + snippet + "\n")
    except OSError:
        return


def _ensure_bashrc_tc_network() -> None:
    """
    Ensure ~/.bashrc contains TC_CONTEXT-aware ss/netstat wrappers.
    The wrappers preserve normal output while adding category prefixes.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot network integration"
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + "  ss() {\n"
        + '    local _tc_out _tc_status _tc_py="${TC_PYTHON_BIN:-python3}"\n'
        + '    _tc_out="$(command ss "$@")"\n'
        + "    _tc_status=$?\n"
        + "    if [[ $_tc_status -ne 0 ]]; then\n"
        + '      [[ -n "$_tc_out" ]] && printf "%s\\n" "$_tc_out"\n'
        + "      return $_tc_status\n"
        + "    fi\n"
        + '    if [[ -z "$TC_HOME" ]]; then\n'
        + '      printf "%s\\n" "$_tc_out"\n'
        + "      return 0\n"
        + "    fi\n"
        + '    printf "%s\\n" "$_tc_out" | PYTHONPATH="$TC_HOME${PYTHONPATH:+:$PYTHONPATH}" "$_tc_py" -m terminal_copilot.wrapper.net_annotate --source ss\n'
        + "  }\n"
        + "  netstat() {\n"
        + '    local _tc_out _tc_status _tc_py="${TC_PYTHON_BIN:-python3}"\n'
        + '    _tc_out="$(command netstat \"$@\")"\n'
        + "    _tc_status=$?\n"
        + "    if [[ $_tc_status -ne 0 ]]; then\n"
        + '      [[ -n "$_tc_out" ]] && printf "%s\\n" "$_tc_out"\n'
        + "      return $_tc_status\n"
        + "    fi\n"
        + '    if [[ -z "$TC_HOME" ]]; then\n'
        + '      printf "%s\\n" "$_tc_out"\n'
        + "      return 0\n"
        + "    fi\n"
        + '    printf "%s\\n" "$_tc_out" | PYTHONPATH="$TC_HOME${PYTHONPATH:+:$PYTHONPATH}" "$_tc_py" -m terminal_copilot.wrapper.net_annotate --source netstat\n'
        + "  }\n"
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            return
        with open(bashrc, "a", encoding="utf-8") as f:
            if content and not content.endswith("\n"):
                f.write("\n")
            f.write("\n" + snippet + "\n")
    except OSError:
        return


def run_wrapped_shell(
    *,
    shell: str | None = None,
    on_context: Callable[[TerminalContext], list] | None = None,
    output_line_limit: int = 100,
    output_tail_bytes: int = 4096,
    debounce_seconds: float = 0.5,
) -> int:
    """
    Run an interactive shell in a PTY with full passthrough. Optionally call
    `on_context(context)` with recent input/output; any returned insights
    are surfaced (e.g. notifications). Returns shell exit code.
    """
    shell = shell or _find_shell()

    # Best-effort: make sure the user's bashrc has a TC_CONTEXT-aware prompt
    # snippet so we can show [tc] in the inner shell prompt automatically.
    _ensure_bashrc_tc_prompt()
    _ensure_bashrc_tc_help()
    _ensure_bashrc_tc_ps()
    _ensure_bashrc_tc_network()
    buf_out = RingBuffer(max_lines=output_line_limit, max_bytes=output_tail_bytes)
    buf_in: list[str] = []
    last_insight_check = 0.0
    import time

    def make_context() -> TerminalContext:
        return TerminalContext(
            output_lines=buf_out.get_lines(),
            input_lines=buf_in[-50:] if len(buf_in) > 50 else buf_in.copy(),
            output_tail=buf_out.get_tail(),
        )

    def maybe_run_insights() -> None:
        nonlocal last_insight_check
        if not on_context:
            return
        ctx = make_context()
        last_cmd = (ctx.last_command() or "").strip()
        ps_tokens = set(last_cmd.replace("|", " ").split())
        is_ps_flow = "ps" in ps_tokens
        now = time.monotonic()
        # For ps output classification, run checks eagerly so short-lived
        # command output is not skipped by debounce timing.
        if (not is_ps_flow) and (now - last_insight_check < debounce_seconds):
            return
        last_insight_check = now
        try:
            insights = on_context(ctx)
            for insight in insights or []:
                from .insights import notify_insight
                notify_insight(insight)
        except Exception as e:
            # Don't break the terminal; log to stderr
            print(f"\r\n[tc] insight error: {e}\n", file=sys.stderr, flush=True)

    def master_read(fd: int) -> bytes:
        """Read from child PTY, buffer, maybe run insights, and pass through."""
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        # Buffer output for context
        buf_out.append_bytes(data)
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            if line.strip():
                buf_out.append_line(line)

        maybe_run_insights()
        return data

    def stdin_read(fd: int) -> bytes:
        """Read from our stdin, track commands, and pass through."""
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        if _is_help_command(data):
            buf_in.append("help")
            print("\r\n" + render_help_menu() + "\r\n", file=sys.stderr, flush=True)
            return b"\n"

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if line and not line.isspace():
                buf_in.append(line)
        return data

    # Mark this PTY as a terminal-copilot context so shell config (e.g. ~/.bashrc)
    # can adjust the prompt (PS1) accordingly.
    orig_tc = os.environ.get("TC_CONTEXT")
    orig_help = os.environ.get("TC_HELP_MENU")
    orig_home = os.environ.get("TC_HOME")
    orig_ps_wrapped = os.environ.get("TC_PS_WRAPPED")
    orig_py = os.environ.get("TC_PYTHON_BIN")
    os.environ["TC_CONTEXT"] = "1"
    os.environ["TC_HELP_MENU"] = render_help_menu()
    os.environ["TC_HOME"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    os.environ["TC_PS_WRAPPED"] = "1"
    os.environ["TC_PYTHON_BIN"] = sys.executable or "python3"

    # Optional one-time header so it's obvious when you enter the wrapped shell.
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or "?"
    host = os.uname().nodename
    cwd = os.getcwd()
    print(f"[tc] Dropping into terminal-copilot shell... 🚀", file=sys.stderr, flush=True)

    # Use pty.spawn to handle PTY setup, line discipline, and job control.
    argv = [shell, "-i"]
    try:
        status = pty.spawn(argv, master_read=master_read, stdin_read=stdin_read)
    except OSError as e:
        print(f"terminal-copilot: pty.spawn failed: {e}", file=sys.stderr)
        return 127
    finally:
        # Restore TC_CONTEXT in the parent environment.
        if orig_tc is None:
            os.environ.pop("TC_CONTEXT", None)
        else:
            os.environ["TC_CONTEXT"] = orig_tc
        if orig_help is None:
            os.environ.pop("TC_HELP_MENU", None)
        else:
            os.environ["TC_HELP_MENU"] = orig_help
        if orig_home is None:
            os.environ.pop("TC_HOME", None)
        else:
            os.environ["TC_HOME"] = orig_home
        if orig_ps_wrapped is None:
            os.environ.pop("TC_PS_WRAPPED", None)
        else:
            os.environ["TC_PS_WRAPPED"] = orig_ps_wrapped
        if orig_py is None:
            os.environ.pop("TC_PYTHON_BIN", None)
        else:
            os.environ["TC_PYTHON_BIN"] = orig_py

    # pty.spawn returns wait status from os.waitpid; convert to exit code.
    try:
        return os.waitstatus_to_exitcode(status)
    except Exception:
        return 0
