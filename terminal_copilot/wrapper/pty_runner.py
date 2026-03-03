"""
PTY-based terminal wrapper: runs a shell in a pseudo-terminal, forwards all I/O,
and captures commands + output for insight providers (e.g. AI or rule-based).
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import ctypes
from dataclasses import dataclass, field
from typing import Callable

try:
    import pty
except ImportError:
    pty = None

from .command_batch import (
    encode_commands,
    load_commands_from_file,
    parse_batch_invocation,
)
from .command_control import parse_session_invocation
from .help_menu import render_help_menu
from .output_middleware import OutputPipeline, RemoteCommandRewriteMiddleware
from .ring_buffer import RingBuffer
from .session_log import SessionRecorder


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
    if os.name == "nt":
        detected_parent = _detect_windows_parent_shell()
        candidates = [
            os.environ.get("TC_WINDOWS_SHELL", "").strip(),
            detected_parent,
            os.environ.get("SHELL", "").strip(),
            os.environ.get("COMSPEC", "").strip(),
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
        ]
        for candidate in candidates:
            if not candidate:
                continue
            path = shutil.which(candidate)
            if path:
                return path
            if os.path.exists(candidate):
                return candidate
        return "cmd.exe"

    shell = os.environ.get("SHELL", "sh")
    path = shutil.which(shell)
    return path or shell


def _detect_windows_parent_shell() -> str:
    """Best-effort detection of parent shell executable on Windows."""
    if os.name != "nt":
        return ""

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.c_ulong),
            ("cntUsage", ctypes.c_ulong),
            ("th32ProcessID", ctypes.c_ulong),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", ctypes.c_ulong),
            ("cntThreads", ctypes.c_ulong),
            ("th32ParentProcessID", ctypes.c_ulong),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.c_ulong),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    kernel32 = ctypes.windll.kernel32

    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        return ""

    try:
        proc_map: dict[int, tuple[int, str]] = {}
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            pid = int(entry.th32ProcessID)
            ppid = int(entry.th32ParentProcessID)
            exe = (entry.szExeFile or "").strip().lower()
            proc_map[pid] = (ppid, exe)
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))

        pid = os.getpid()
        visited: set[int] = set()
        while pid and pid not in visited:
            visited.add(pid)
            parent = proc_map.get(pid)
            if not parent:
                break
            ppid, exe = parent
            if exe in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
                return exe
            pid = ppid
    finally:
        kernel32.CloseHandle(snapshot)

    return ""


def _windows_shell_argv(shell: str) -> list[str]:
    """Build shell argv with tc context + process-list wrappers."""
    name = os.path.basename(shell).lower()
    if "powershell" in name or name in ("pwsh.exe", "pwsh"):
        script = (
            'function global:prompt { "[tc] PS $($executionContext.SessionState.Path.CurrentLocation)> " }; '
            'function global:help { '
            'param([Parameter(ValueFromRemainingArguments=$true)][string[]]$tcArgs); '
            'if ($tcArgs.Count -eq 0) { if ($env:TC_HELP_MENU) { $env:TC_HELP_MENU -split "`n" | ForEach-Object { $_ } }; return }; '
            'Microsoft.PowerShell.Core\\Get-Help @tcArgs '
            '}; '
            '$tcPy = if ($env:TC_PYTHON_BIN) { $env:TC_PYTHON_BIN } else { "python" }; '
            'function global:tasklist { & tasklist.exe @args | & $tcPy -m terminal_copilot.wrapper.tasklist_pipe --source tasklist }; '
            'function global:Get-Process { Microsoft.PowerShell.Management\\Get-Process @args | Out-String -Width 4096 | & $tcPy -m terminal_copilot.wrapper.tasklist_pipe --source get-process }; '
            'function global:wmic { if ($args.Count -gt 0 -and $args[0].ToString().ToLower() -eq "process") { & wmic.exe @args | & $tcPy -m terminal_copilot.wrapper.tasklist_pipe --source wmic } else { & wmic.exe @args } }; '
            'function global:netstat { & netstat.exe @args | & $tcPy -m terminal_copilot.wrapper.net_pipe --source netstat }; '
            'function global:Get-NetTCPConnection { NetTCPIP\\Get-NetTCPConnection @args | Out-String -Width 4096 | & $tcPy -m terminal_copilot.wrapper.net_pipe --source get-nettcpconnection }; '
            'function global:Get-NetUDPEndpoint { NetTCPIP\\Get-NetUDPEndpoint @args | Out-String -Width 4096 | & $tcPy -m terminal_copilot.wrapper.net_pipe --source get-netudpendpoint }'
        )
        return [shell, "-NoLogo", "-NoExit", "-Command", script]
    if name in ("cmd.exe", "cmd"):
        cmd_init = (
            "prompt [tc] $P$G"
            " & doskey help=python -m terminal_copilot.wrapper.print_help_menu"
            " & doskey tasklist=tasklist.exe $* ^| python -m terminal_copilot.wrapper.tasklist_pipe --source tasklist"
            " & doskey wmic=wmic.exe $* ^| python -m terminal_copilot.wrapper.tasklist_pipe --source wmic"
            " & doskey netstat=netstat.exe $* ^| python -m terminal_copilot.wrapper.net_pipe --source netstat"
        )
        return [shell, "/Q", "/K", cmd_init]
    return [shell]


def _host_os_name() -> str:
    name = platform.system().lower()
    if "windows" in name:
        return "windows"
    if "darwin" in name:
        return "macos"
    if "linux" in name:
        return "linux"
    return name or "unknown"


def _is_help_command(data: bytes) -> bool:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return False
    return text.strip() == "help"


def _print_tc_message(message: str) -> None:
    sys.stderr.write(f"\r\n[tc] {message}\r\n")
    sys.stderr.flush()


def _ensure_bashrc_tc_prompt() -> None:
    """
    Ensure the user's ~/.bashrc contains a small TC_CONTEXT-aware prompt
    snippet. This lets terminal-copilot mark the inner shell prompt with
    [tc] transparently, without the user having to edit their config.
    """
    bashrc = os.path.expanduser("~/.bashrc")
    snippet_tag = "# terminal-copilot prompt integration"
    prompt_value = (
        '[tc] \\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:'
        '\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '
    )
    snippet = (
        snippet_tag
        + "\n"
        + 'if [[ -n "$TC_CONTEXT" ]]; then\n'
        + f'  PS1="{prompt_value}"\n'
        + "fi\n"
    )
    try:
        try:
            with open(bashrc, "r", encoding="utf-8") as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        if snippet_tag in content:
            # Migrate older prompt snippet to safe fixed PS1 form.
            replacements = {
                'PS1="[tc] $PS1"': f'PS1="{prompt_value}"',
                'PS1="[tc] \\u@\\h:\\w\\$ "': f'PS1="{prompt_value}"',
            }
            changed = False
            for old, new in replacements.items():
                if old in content:
                    content = content.replace(old, new)
                    changed = True
            if changed:
                with open(bashrc, "w", encoding="utf-8") as f:
                    f.write(content)
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


def _run_wrapped_shell_windows(
    *,
    shell: str,
    on_context: Callable[[TerminalContext], list] | None,
    output_line_limit: int,
    output_tail_bytes: int,
    debounce_seconds: float,
    recorder: SessionRecorder | None,
    pipeline: OutputPipeline | None,
) -> int:
    """Simple Windows fallback: spawn shell attached to current console."""
    _ = on_context
    _ = output_line_limit
    _ = output_tail_bytes
    _ = debounce_seconds
    _ = pipeline

    if recorder:
        recorder.record_note(
            "Windows basic mode active: transcript captures metadata only; raw shell I/O is not piped through tc."
        )

    orig_env = {
        "TC_CONTEXT": os.environ.get("TC_CONTEXT"),
        "TC_HELP_MENU": os.environ.get("TC_HELP_MENU"),
        "TC_HOME": os.environ.get("TC_HOME"),
        "TC_PS_WRAPPED": os.environ.get("TC_PS_WRAPPED"),
        "TC_TASKLIST_WRAPPED": os.environ.get("TC_TASKLIST_WRAPPED"),
        "TC_NET_WRAPPED": os.environ.get("TC_NET_WRAPPED"),
        "TC_PYTHON_BIN": os.environ.get("TC_PYTHON_BIN"),
        "TC_HOST_OS": os.environ.get("TC_HOST_OS"),
    }
    os.environ["TC_CONTEXT"] = "1"
    os.environ["TC_HELP_MENU"] = render_help_menu()
    os.environ["TC_HOME"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    os.environ["TC_PS_WRAPPED"] = "0"
    os.environ["TC_TASKLIST_WRAPPED"] = "1"
    os.environ["TC_NET_WRAPPED"] = "1"
    os.environ["TC_PYTHON_BIN"] = sys.executable or "python"
    os.environ["TC_HOST_OS"] = _host_os_name()

    _print_tc_message(
        f"Dropping into terminal-copilot shell ({_host_os_name()} via {os.path.basename(shell)})..."
    )

    try:
        argv = _windows_shell_argv(shell)
        proc = subprocess.Popen(
            argv,
            env=os.environ.copy(),
        )
    except OSError as e:
        print(f"terminal-copilot: failed to start shell '{shell}': {e}", file=sys.stderr)
        return 127

    try:
        return proc.wait()
    except KeyboardInterrupt:
        return 130
    finally:
        for key, value in orig_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def run_wrapped_shell(
    *,
    shell: str | None = None,
    on_context: Callable[[TerminalContext], list] | None = None,
    output_line_limit: int = 100,
    output_tail_bytes: int = 4096,
    debounce_seconds: float = 0.5,
    record_session: bool = False,
    session_log_path: str | None = None,
) -> int:
    """
    Run an interactive shell in a PTY with full passthrough. Optionally call
    `on_context(context)` with recent input/output; any returned insights
    are surfaced (e.g. notifications). Returns shell exit code.
    """
    shell = shell or _find_shell()
    recorder: SessionRecorder | None = None
    if record_session:
        recorder = SessionRecorder(
            host_os=_host_os_name(),
            shell=shell,
            file_path=session_log_path,
        )
        try:
            log_path = recorder.open()
            _print_tc_message(f"Session logging enabled: {log_path}")
        except OSError as e:
            _print_tc_message(f"Unable to start session logging: {e}")
            recorder = None

    pipeline = OutputPipeline(middlewares=[RemoteCommandRewriteMiddleware()])

    if os.name == "nt" or pty is None:
        code = _run_wrapped_shell_windows(
            shell=shell,
            on_context=on_context,
            output_line_limit=output_line_limit,
            output_tail_bytes=output_tail_bytes,
            debounce_seconds=debounce_seconds,
            recorder=recorder,
            pipeline=pipeline,
        )
        if recorder:
            recorder.close(exit_code=code)
        return code

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
    awaiting_batch_path = False
    pending_batch_commands: list[str] = []
    pending_batch_source = ""
    typed_line = ""
    in_escape_sequence = False

    def _prompt_next_batch_command() -> None:
        if not pending_batch_commands:
            _print_tc_message("Command batch finished.")
            return
        total = len(pending_batch_commands)
        cmd = pending_batch_commands[0]
        sys.stderr.write(
            f"\r\n[tc] Next command from '{pending_batch_source}' ({total} remaining):"
            f"\r\n[tc] $ {cmd}"
            "\r\n[tc] Run it? [y]es / [N]o / [x] exit: "
        )
        sys.stderr.flush()

    def _start_session_recording(path_text: str | None = None) -> None:
        nonlocal recorder
        if recorder:
            _print_tc_message(f"Session logging already enabled: {recorder.file_path}")
            return
        rec = SessionRecorder(
            host_os=_host_os_name(),
            shell=shell,
            file_path=path_text,
        )
        try:
            path = rec.open()
        except OSError as e:
            _print_tc_message(f"Unable to start session logging: {e}")
            return
        recorder = rec
        _print_tc_message(f"Session logging enabled: {path}")

    def _stop_session_recording() -> None:
        nonlocal recorder
        if not recorder:
            _print_tc_message("Session logging is not active.")
            return
        path = recorder.file_path
        recorder.close(exit_code=None)
        recorder = None
        _print_tc_message(f"Session logging stopped: {path}")

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
        cmd_tokens = {t.lower() for t in last_cmd.replace("|", " ").split()}
        is_ps_flow = "ps" in cmd_tokens
        is_windows_proc_flow = (
            "tasklist" in cmd_tokens
            or "get-process" in cmd_tokens
            or "gps" in cmd_tokens
            or ("wmic" in cmd_tokens and "process" in cmd_tokens)
        )
        now = time.monotonic()
        # Keep eager checks for ps and Windows process commands. The provider
        # itself waits for prompt-return for Windows flows to avoid interleaving.
        if (not is_ps_flow) and (not is_windows_proc_flow) and (now - last_insight_check < debounce_seconds):
            return
        last_insight_check = now
        try:
            insights = on_context(ctx)
            for insight in insights or []:
                from .insights import notify_insight
                notify_insight(insight)
        except Exception as e:
            # Don't break the terminal; log to stderr
            sys.stderr.write(f"\r\n[tc] insight error: {e}\r\n")
            sys.stderr.flush()

    def master_read(fd: int) -> bytes:
        """Read from child PTY, buffer, maybe run insights, and pass through."""
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        if recorder:
            try:
                recorder.record_output(data.decode("utf-8", errors="replace"))
            except Exception:
                pass

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
        # Keep raw PTY bytes unchanged on Unix to avoid prompt/display issues.
        # Remote inline rewriting currently runs in the Windows pipe wrapper.
        return data

    def stdin_read(fd: int) -> bytes:
        """Read from our stdin, track commands, and pass through."""
        nonlocal awaiting_batch_path, typed_line, in_escape_sequence
        try:
            data = os.read(fd, 4096)
        except OSError:
            return b""
        if not data:
            return b""

        if _is_help_command(data):
            buf_in.append("help")
            sys.stderr.write(f"\r\n{render_help_menu()}\r\n")
            sys.stderr.flush()
            return b"\n"

        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = ""

        def handle_submitted_line(line: str) -> bytes | None:
            nonlocal awaiting_batch_path, pending_batch_source
            if awaiting_batch_path:
                local_path = line.strip()
                if not local_path:
                    _print_tc_message("Path is empty. Enter local command file path:")
                    return b""
                try:
                    resolved_path, commands = load_commands_from_file(local_path)
                except OSError as e:
                    _print_tc_message(f"Unable to read local file '{local_path}': {e}")
                    _print_tc_message("Enter local command file path:")
                    return b""
                awaiting_batch_path = False
                if not commands:
                    _print_tc_message(f"No commands found in '{resolved_path}'.")
                    return b""
                pending_batch_source = resolved_path
                pending_batch_commands.clear()
                pending_batch_commands.extend(commands)
                _print_tc_message(
                    f"Loaded {len(commands)} command(s) from '{resolved_path}'."
                )
                _prompt_next_batch_command()
                return b""

            if pending_batch_commands:
                response = line.strip().lower()
                if response in ("x", "exit"):
                    pending_batch_commands.clear()
                    _print_tc_message("Stopped remaining commands and returned to prompt.")
                    return b""
                if response in ("y", "yes"):
                    command = pending_batch_commands.pop(0)
                    buf_in.append(command)
                    if pending_batch_commands:
                        _prompt_next_batch_command()
                    return encode_commands([command])

                # Default to No when blank or unrecognized input.
                skipped = pending_batch_commands.pop(0)
                _print_tc_message(f"Skipped: {skipped}")
                if pending_batch_commands:
                    _prompt_next_batch_command()
                else:
                    _print_tc_message("No remaining commands in batch.")
                return b""

            sess = parse_session_invocation(line)
            if sess.recognized:
                if sess.parse_error:
                    _print_tc_message(f"Invalid tc session syntax: {sess.parse_error}")
                    return b""
                if sess.action == "start":
                    _start_session_recording(sess.path)
                elif sess.action == "stop":
                    _stop_session_recording()
                elif sess.action == "path":
                    if recorder and recorder.file_path:
                        _print_tc_message(f"Session log path: {recorder.file_path}")
                    else:
                        _print_tc_message("Session logging is not active.")
                return b""

            invocation = parse_batch_invocation(line)
            if not invocation.recognized:
                return None
            if invocation.parse_error:
                _print_tc_message(
                    f"Invalid tc runfile syntax: {invocation.parse_error}"
                )
                return b""
            if invocation.inline_path is None:
                awaiting_batch_path = True
                _print_tc_message("Enter local command file path:")
                return b""
            try:
                resolved_path, commands = load_commands_from_file(invocation.inline_path)
            except OSError as e:
                _print_tc_message(
                    f"Unable to read local file '{invocation.inline_path}': {e}"
                )
                return b""
            if not commands:
                _print_tc_message(f"No commands found in '{resolved_path}'.")
                return b""
            pending_batch_source = resolved_path
            pending_batch_commands.clear()
            pending_batch_commands.extend(commands)
            _print_tc_message(
                f"Loaded {len(commands)} command(s) from '{resolved_path}'."
            )
            _prompt_next_batch_command()
            return b""

        passthrough = bytearray()
        injected = bytearray()
        current_line_start = 0
        for b in data:
            passthrough.append(b)

            if in_escape_sequence:
                if 0x40 <= b <= 0x7E:
                    in_escape_sequence = False
                continue
            if b == 0x1B:
                in_escape_sequence = True
                continue

            if b in (0x0A, 0x0D):
                submitted = typed_line
                typed_line = ""
                action = handle_submitted_line(submitted)
                if action is not None:
                    # Intercepted line: do not pass the typed line (or newline)
                    # through to the shell.
                    del passthrough[current_line_start:]
                    injected.extend(b"\x15")
                    injected.extend(action)
                    if recorder:
                        try:
                            injected_text = action.decode("utf-8", errors="replace")
                        except Exception:
                            injected_text = ""
                        for cmd in injected_text.splitlines():
                            if cmd.strip():
                                recorder.record_input(cmd.strip(), source="injected")
                    try:
                        injected_text = action.decode("utf-8", errors="replace")
                    except Exception:
                        injected_text = ""
                    for cmd in injected_text.splitlines():
                        if cmd.strip():
                            pipeline.on_input_line(cmd.strip())
                    current_line_start = len(passthrough)
                else:
                    line = submitted.strip()
                    if line and not line.isspace():
                        buf_in.append(line)
                        if recorder:
                            recorder.record_input(line, source="tty")
                        pipeline.on_input_line(line)
                    current_line_start = len(passthrough)
                continue

            if b in (0x08, 0x7F):
                typed_line = typed_line[:-1]
                continue
            if 32 <= b <= 126:
                typed_line += chr(b)

        if injected:
            return bytes(passthrough) + bytes(injected)
        return bytes(passthrough)

    # Mark this PTY as a terminal-copilot context so shell config (e.g. ~/.bashrc)
    # can adjust the prompt (PS1) accordingly.
    orig_tc = os.environ.get("TC_CONTEXT")
    orig_help = os.environ.get("TC_HELP_MENU")
    orig_home = os.environ.get("TC_HOME")
    orig_ps_wrapped = os.environ.get("TC_PS_WRAPPED")
    orig_net_wrapped = os.environ.get("TC_NET_WRAPPED")
    orig_py = os.environ.get("TC_PYTHON_BIN")
    orig_host_os = os.environ.get("TC_HOST_OS")
    orig_columns = os.environ.get("COLUMNS")
    orig_lines = os.environ.get("LINES")
    os.environ["TC_CONTEXT"] = "1"
    os.environ["TC_HELP_MENU"] = render_help_menu()
    os.environ["TC_HOME"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    os.environ["TC_PS_WRAPPED"] = "1"
    os.environ["TC_NET_WRAPPED"] = "1"
    os.environ["TC_PYTHON_BIN"] = sys.executable or "python3"
    os.environ["TC_HOST_OS"] = _host_os_name()
    try:
        term_size = os.get_terminal_size(sys.stdin.fileno())
        os.environ["COLUMNS"] = str(term_size.columns)
        os.environ["LINES"] = str(term_size.lines)
    except OSError:
        pass

    # Optional one-time header so it's obvious when you enter the wrapped shell.
    _print_tc_message(
        f"Dropping into terminal-copilot shell ({_host_os_name()} via {os.path.basename(shell)})..."
    )

    # Use pty.spawn to handle PTY setup, line discipline, and job control.
    argv = [shell, "-i"]
    try:
        spawn = getattr(pty, "spawn")
        status = spawn(argv, master_read=master_read, stdin_read=stdin_read)
    except OSError as e:
        print(f"terminal-copilot: pty.spawn failed: {e}", file=sys.stderr)
        if recorder:
            recorder.close(exit_code=127)
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
        if orig_net_wrapped is None:
            os.environ.pop("TC_NET_WRAPPED", None)
        else:
            os.environ["TC_NET_WRAPPED"] = orig_net_wrapped
        if orig_py is None:
            os.environ.pop("TC_PYTHON_BIN", None)
        else:
            os.environ["TC_PYTHON_BIN"] = orig_py
        if orig_host_os is None:
            os.environ.pop("TC_HOST_OS", None)
        else:
            os.environ["TC_HOST_OS"] = orig_host_os
        if orig_columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = orig_columns
        if orig_lines is None:
            os.environ.pop("LINES", None)
        else:
            os.environ["LINES"] = orig_lines

    # pty.spawn returns wait status from os.waitpid; convert to exit code.
    exit_code = 0
    try:
        exit_code = os.waitstatus_to_exitcode(status)
    except Exception:
        exit_code = 0
    if recorder:
        recorder.close(exit_code=exit_code)
    return exit_code
