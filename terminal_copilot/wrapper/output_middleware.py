"""
Pluggable output middleware pipeline.

Middlewares can inspect/transform terminal output before it is presented.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .net_annotate import annotate_network_output
from .tasklist_annotate import annotate_windows_process_output


class OutputMiddleware:
    def on_input_line(self, line: str) -> None:
        return

    def process_output(self, text: str) -> str:
        return text

    def flush(self) -> str:
        return ""


@dataclass
class OutputPipeline:
    middlewares: list[OutputMiddleware] = field(default_factory=list)

    def on_input_line(self, line: str) -> None:
        for mw in self.middlewares:
            mw.on_input_line(line)

    def process_output(self, text: str) -> str:
        out = text
        for mw in self.middlewares:
            out = mw.process_output(out)
        return out

    def flush(self) -> str:
        chunks: list[str] = []
        for mw in self.middlewares:
            tail = mw.flush()
            if tail:
                chunks.append(tail)
        return "".join(chunks)


class RemoteCommandRewriteMiddleware(OutputMiddleware):
    """
    Rewrites selected remote command output blocks inline before display.

    Current command kinds:
    - Windows process listings (tasklist/Get-Process/wmic process)
    - Network listings (ss/netstat)
    """

    _MAX_CAPTURE_BYTES = 256 * 1024

    def __init__(self) -> None:
        self._remote_mode = False
        self._active_kind: str | None = None
        self._capture: list[str] = []
        self._capture_size = 0
        self._partial = ""

    def on_input_line(self, line: str) -> None:
        text = line.strip()
        if not text:
            return

        low = text.lower()
        if low.startswith(("ssh ", "evil-winrm", "smbclient ")):
            self._remote_mode = True

        if low in ("exit", "logout", "quit") and not self._active_kind:
            self._remote_mode = False

        if not self._remote_mode or self._active_kind:
            return

        tokens = {t.lower() for t in low.replace("|", " ").split()}
        is_windows_proc_cmd = (
            "tasklist" in tokens
            or "get-process" in tokens
            or "gps" in tokens
            or ("wmic" in tokens and "process" in tokens)
        )
        is_net_cmd = "netstat" in tokens or "ss" in tokens
        if is_windows_proc_cmd:
            self._active_kind = "windows_proc"
            self._capture.clear()
            self._capture_size = 0
        elif is_net_cmd:
            self._active_kind = "network"
            self._capture.clear()
            self._capture_size = 0

    def process_output(self, text: str) -> str:
        if not text:
            return text

        combined = self._partial + text
        lines = combined.splitlines(keepends=True)
        if lines and not lines[-1].endswith(("\n", "\r")):
            self._partial = lines.pop()
        else:
            self._partial = ""

        out: list[str] = []
        for line in lines:
            if "*evil-winrm*" in line.lower() or line.strip().startswith("smb:"):
                self._remote_mode = True

            if not self._active_kind:
                out.append(line)
                continue

            if self._looks_like_prompt(line):
                out.append(self._flush_capture_as_annotated())
                out.append(line)
                self._active_kind = None
                continue

            self._capture.append(line)
            self._capture_size += len(line.encode("utf-8", errors="replace"))
            if self._capture_size > self._MAX_CAPTURE_BYTES:
                # Safety valve: stop buffering and pass through.
                out.append("".join(self._capture))
                self._capture.clear()
                self._capture_size = 0
                self._active_kind = None

        return "".join(out)

    def flush(self) -> str:
        tail = ""
        if self._partial:
            if self._active_kind:
                self._capture.append(self._partial)
                self._capture_size += len(self._partial.encode("utf-8", errors="replace"))
            else:
                tail += self._partial
            self._partial = ""
        if self._active_kind and self._capture:
            tail += self._flush_capture_as_annotated()
            self._active_kind = None
        return tail

    def _flush_capture_as_annotated(self) -> str:
        raw = "".join(self._capture)
        self._capture.clear()
        self._capture_size = 0
        if not raw.strip():
            return raw

        if self._active_kind == "windows_proc":
            body, _ = annotate_windows_process_output(raw)
            if body:
                return body.rstrip() + "\n"
            return raw
        if self._active_kind == "network":
            body = annotate_network_output(raw)
            if body:
                return body
            return raw
        return raw

    @staticmethod
    def _looks_like_prompt(line: str) -> bool:
        s = line.strip()
        if not s:
            return False
        if s.startswith("*Evil-WinRM*") and ">" in s:
            return True
        if s.startswith("smb:") and s.endswith("\\>"):
            return True
        return s.endswith("$") or s.endswith(">")
