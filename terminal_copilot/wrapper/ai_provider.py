"""
Optional AI-backed insight provider. Requires OPENAI_API_KEY or ANTHROPIC_API_KEY.
Sends recent command + output snippet to the model and parses structured insights.
"""
from __future__ import annotations

import json
import os
import re

from .insights import Insight
from .pty_runner import TerminalContext


def query_ai_insights(ctx: TerminalContext) -> list[Insight]:
    """
    Call OpenAI or Anthropic with recent context; ask for malicious/vulnerability
    insights and suggested commands. Returns empty list if no key or on error.
    """
    api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return []

    last_cmd = ctx.last_command() or ""
    recent = ctx.recent_output()
    if not last_cmd and not recent.strip():
        return []

    prompt = _build_prompt(last_cmd, recent)
    response_text = _call_api(api_key, prompt)
    if not response_text:
        return []
    return _parse_response(response_text)


def _build_prompt(last_command: str, recent_output: str) -> str:
    return """You are a security-aware terminal assistant. Given the following terminal context, produce a JSON array of insights.

Rules:
- If you see signs of a malicious process, suspicious script, or attack pattern, add an insight with level "danger" or "warning".
- If you notice a vulnerability or misconfiguration that could be exploited, add an insight with level "warning" and optional "commands" to remediate.
- Keep insights short and actionable. "commands" is an optional array of shell commands the user could run.
- If nothing noteworthy, return an empty array: []

Output ONLY a single JSON array of objects, each with: "level" ("info"|"warning"|"danger"), "title", "body", "commands" (array of strings).

Last command:
"""
    + repr(last_command)
    + """

Recent output (excerpt):
"""
    + recent_output[-3000:]
    + """

JSON array:"""


def _call_api(api_key: str, prompt: str) -> str:
    if os.environ.get("OPENAI_API_KEY"):
        return _call_openai(api_key, prompt)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return _call_anthropic(api_key, prompt)
    return ""


def _call_openai(api_key: str, prompt: str) -> str:
    try:
        import urllib.request
        body = {
            "model": os.environ.get("TC_OPENAI_MODEL", "gpt-4o-mini"),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024,
        }
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        return (data.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
    except Exception:
        return ""


def _call_anthropic(api_key: str, prompt: str) -> str:
    try:
        import urllib.request
        body = {
            "model": os.environ.get("TC_ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"),
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=json.dumps(body).encode(),
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
        for block in data.get("content", []):
            if block.get("type") == "text":
                return block.get("text", "") or ""
        return ""
    except Exception:
        return ""


def _parse_response(response_text: str) -> list[Insight]:
    out: list[Insight] = []
    # Extract JSON array (handle markdown code blocks)
    text = response_text.strip()
    m = re.search(r"\[[\s\S]*\]", text)
    if not m:
        return out
    try:
        arr = json.loads(m.group())
    except json.JSONDecodeError:
        return out
    for item in arr if isinstance(arr, list) else []:
        if not isinstance(item, dict):
            continue
        level = (item.get("level") or "info").lower()
        if level not in ("info", "warning", "danger"):
            level = "info"
        title = item.get("title") or "Insight"
        body = item.get("body") or ""
        commands = item.get("commands")
        if not isinstance(commands, list):
            commands = []
        commands = [str(c).strip() for c in commands if c]
        out.append(Insight(level=level, title=title, body=body, commands=commands))
    return out
