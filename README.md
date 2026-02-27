# terminal-copilot

Two modes:

1. **Terminal wrapper** – A PTY passthrough that runs your shell, monitors commands and output, and pushes context to rule-based and optional AI insight providers. You get real-time notifications (e.g. suspicious patterns, suggested remediation commands).
2. **Process triage** – Batch analysis of process lists (see below).

---

## Terminal wrapper (monitor + AI insights)

Run your shell inside a wrapper that watches what you type and what the shell outputs, then surfaces insights (suspicious commands, possible vulnerabilities, suggested fixes).

### Requirements

- Linux (or macOS) with a real TTY (PTY). Not suitable for environments where `openpty()` is unavailable (e.g. some CI/sandboxes).
- Optional: `notify-send` for desktop notifications.
- Optional: `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` for AI-backed insights.

### Usage

```bash
# Rule-based insights only (no API key)
python3 -m terminal_copilot --no-ai

# With AI insights (set OPENAI_API_KEY or ANTHROPIC_API_KEY)
python3 -m terminal_copilot

# Custom shell and debounce
python3 -m terminal_copilot --shell /bin/zsh --debounce 1.0
```

Inside the wrapped shell, type `help` to print the terminal-copilot module menu
(built-in insight modules plus discovered custom scripts/modules).

Inside the wrapped shell, `ps` is wrapped so process rows are prefixed with
categories (`safe`, `installed_app`, `potentially_malicious`, `malicious`,
or `unknown`) and unknown/suspicious rows are grouped at the bottom.

Insights are shown as:

- **Desktop notifications** (if `notify-send` is available).
- **Stderr banners** in the terminal: `[tc]` with level (info/warning/danger), title, body, and optional suggested commands.

### How it works

- Spawns your `$SHELL` (or `sh`) in a pseudo-terminal and forwards all input and output (full passthrough).
- Buffers recent input lines (commands) and output; periodically calls an **insight provider** with this context.
- **Rule-based provider** uses `collector/detectors/rules.json` (suspicious command-line patterns, LOLBins) and requires no API.
- **AI provider** (optional) sends a short excerpt of the last command and recent output to OpenAI or Anthropic and parses structured insights (malicious behavior, vulnerabilities, suggested commands). Enable by setting the corresponding API key.

### Configuration

| Env / flag | Description |
|------------|-------------|
| `SHELL` | Shell to run (default `sh` if unset). |
| `--no-ai` | Disable AI; use only rule-based insights. |
| `--debounce` | Seconds between insight checks (default `0.8`). |
| `OPENAI_API_KEY` | Enable OpenAI-based insights. |
| `ANTHROPIC_API_KEY` | Enable Anthropic-based insights. |
| `TC_OPENAI_MODEL` | OpenAI model (default `gpt-4o-mini`). |
| `TC_ANTHROPIC_MODEL` | Anthropic model (default `claude-3-5-haiku-20241022`). |
| `TC_MODULE_PATHS` | Optional additional module/script directories (separated by `:` on Unix). |

---

## Process triage (batch)

A lightweight process triage tool that ingests Linux or Windows process lists and categorizes each process as:

- **safe** (green)
- **application** / tied to installed software (blue)
- **potentially unsafe** (yellow)
- **unsafe** (red)

This supports quick operator review and can be extended with AI or database-backed lookups.

## Features

- Parses Linux process output (for example `ps -eo pid,comm,args`).
- Parses Windows process output from either:
  - `tasklist /fo csv /nh` (recommended)
  - standard `tasklist` text table
- Classifies using:
  - known-safe process names
  - known installed-application process names
  - known-unsafe process names
  - built-in suspicious command-line heuristics
- Uses ANSI colors for category display.

## Usage

```bash
python process_analyzer.py \
  --platform linux \
  --input ./samples/linux_ps.txt \
  --safe-list ./samples/safe.json \
  --application-list ./samples/apps.json \
  --unsafe-list ./samples/unsafe.json
```

### Input list files

Each list file is JSON array of process names.

`safe.json`
```json
["systemd", "sshd", "explorer.exe"]
```

`apps.json`
```json
["chrome.exe", "teams.exe", "slack"]
```

`unsafe.json`
```json
["evil.exe", "coinminer"]
```

## AI or database integration

`classify_processes(...)` accepts an optional `ai_classifier` callback. You can plug in:

- an LLM risk classifier,
- a malware intelligence database query,
- an internal allow/deny service.

The callback can return one of the categories to override unknown processes.

## Development

- **Wrapper**: Implement a custom insight provider by passing a callable `on_context(ctx) -> list[Insight]` to `run_wrapped_shell(on_context=...)`. `ctx` has `last_command()`, `recent_output()`, `output_lines`, `input_lines`.
- **Process triage**: Run tests with `pytest` (when present).
