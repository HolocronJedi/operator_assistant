# terminal-copilot

## Quick Start

1. Start terminal-copilot:
```bash
python3 -m terminal_copilot --no-ai
```
2. Type `help` in the wrapped shell to see available commands.
3. (Optional) Run commands from a local file:
```bash
tc runfile /tmp/cmds.txt
```
4. Confirm each command when prompted:
   - `y` = run
   - `N` (or Enter) = skip
   - `x` = stop batch and return to prompt

That is enough to start using it immediately.

## Overview

`terminal-copilot` runs your shell inside a PTY wrapper and adds live context-aware insights.
It can:

- Monitor typed commands and shell output.
- Surface rule-based and optional AI insights.
- Wrap `ps`, `ss`, and `netstat` output with quick risk categories.
- Classify Windows `tasklist` output even in remote sessions (for example `evil-winrm`, SSH).
- Detect host OS (`linux`, `windows`, `macos`) for cross-platform behavior.
- Execute newline-separated command batches from a local file with `tc runfile`.
- Optionally record full session transcripts as NDJSON for later analysis.

The wrapped shell works in local and SSH workflows. For `tc runfile`, the file is read locally and only command text is sent to the active terminal session.

## Example Usage

```bash
# Start wrapper with rule-based insights only
python3 -m terminal_copilot --no-ai

# Start wrapper with AI insights (set OPENAI_API_KEY or ANTHROPIC_API_KEY)
python3 -m terminal_copilot

# Start wrapper with custom shell and slower insight checks
python3 -m terminal_copilot --shell /bin/zsh --debounce 1.0

# Opt-in session recording (default output under ~/.terminal-copilot/sessions)
python3 -m terminal_copilot --record-session

# Opt-in session recording to a custom path
python3 -m terminal_copilot --record-session --session-log /tmp/tc-session.ndjson

# Windows examples
python -m terminal_copilot --shell powershell.exe
python -m terminal_copilot --shell cmd.exe
```

Inside the wrapped shell:

```bash
# Show tc help menu
help

# Run a batch from local file (newline-separated commands)
tc runfile
tc runfile /tmp/cmds.txt
```

Command file format:

```text
id
ps -ef
netstat -natu
arp -a
```

Notes:

- Blank lines are ignored.
- Lines beginning with `#` are treated as comments.
- Runfile confirmation options: `y` / `yes`, `N` (default skip), `x` / `exit`.

## Help Menu

### CLI options

```text
python3 -m terminal_copilot [--no-ai] [--shell SHELL] [--debounce SECONDS] [--record-session] [--session-log PATH]
```

- `--no-ai`: Disable AI-backed insights and use rule-based checks only.
- `--shell`: Override shell path (default: Unix=`$SHELL`/`sh`, Windows=`powershell.exe` then `cmd.exe`).
- `--debounce`: Seconds between insight checks (default `0.8`).
- `--record-session`: Opt-in transcript logging for the current wrapped-shell session.
- `--session-log`: Custom transcript path (use with `--record-session`).

### In-shell commands

- `help`: Print terminal-copilot help menu.
- `tc runfile`: Prompt for local command file path and load commands.
- `tc runfile <path>`: Load commands from provided local path.
- `tc runlist`: Alias for `tc runfile`.
- `tc session start [path]`: Start NDJSON transcript logging from inside the wrapped shell.
- `tc session stop`: Stop transcript logging for the current shell session.
- `tc session path`: Print active transcript path.
- `ps`, `ss`, `netstat`: Wrapped output with category prefixes.
- `tasklist`, `Get-Process`, `wmic process ...`: Classified from captured output
  (including remote Windows sessions such as `evil-winrm`/SSH).
- `netstat`: Classified from captured output on Linux/macOS/Windows.

### Help output (example)

```text
[tc] terminal-copilot help

Built-in modules:
  - combined_insights: Rule-based + optional AI insights
  - rule_based_insights: Local process/rule heuristic insights
  - ai_insights: AI-backed insights (when API keys are set)

Custom modules/scripts:
  - none found

Discovery locations:
  - $TC_MODULE_PATHS (os.pathsep-separated)
  - ./modules, ./scripts

Batch command execution:
  - tc runfile
    Prompts for a local file path, then executes newline-separated commands
    in the current shell context (including active SSH/remote sessions).
  - tc runfile /path/to/commands.txt
    Same behavior with inline path.
  - Confirmation per command: [y]es / [N]o (default skip) / [x] exit

Session controls inside wrapped shell:
  - tc session start [path]
    Start transcript logging without restarting terminal-copilot.
  - tc session stop
    Stop transcript logging for this shell.
  - tc session path
    Print active transcript path.

Session recording (opt-in):
  - Start wrapper with --record-session to persist this session as NDJSON.
  - Optional --session-log /path/to/file.ndjson to choose output path.
  - Default path: ~/.terminal-copilot/sessions/
```

## Configuration

| Env / flag | Description |
|---|---|
| `SHELL` | Shell to run (default `sh` if unset). |
| `--no-ai` | Disable AI; use only rule-based insights. |
| `--debounce` | Seconds between insight checks (default `0.8`). |
| `--record-session` | Opt-in NDJSON transcript logging for the current session. |
| `--session-log` | Custom transcript path (used with `--record-session`). |
| `OPENAI_API_KEY` | Enable OpenAI-based insights. |
| `ANTHROPIC_API_KEY` | Enable Anthropic-based insights. |
| `TC_OPENAI_MODEL` | OpenAI model (default `gpt-4o-mini`). |
| `TC_ANTHROPIC_MODEL` | Anthropic model (default `claude-3-5-haiku-20241022`). |
| `TC_MODULE_PATHS` | Additional module/script directories (`:`-separated on Unix). |

## Troubleshooting

- `mcp` or `tc` command not found:
  - `mcp` is not part of this project CLI.
  - Start with `python3 -m terminal_copilot` and use commands inside that wrapped shell.
- `Object "runfile" is unknown, try "tc help"`:
  - You are hitting the system `tc` command instead of terminal-copilot interception.
  - Ensure you are inside the `[tc]` wrapped shell and type `tc runfile` there.
- `tc runfile` cannot read file:
  - Verify the local file exists and path is correct (`ls -l /path/to/file`).
  - Use absolute paths when possible.
- Output formatting looks off:
  - Restart terminal-copilot.
  - Avoid pasting large multiline input directly into confirmation prompts.
- No AI insights appear:
  - Expected with `--no-ai`.
  - Without `--no-ai`, set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`.
- `[tc]` prompt/header seems missing inside `evil-winrm` or SSH-to-Windows:
  - Remote interactive clients render their own prompt, so local bash prompt markers are not shown there.
  - tc monitoring still runs, and `tasklist` classification now comes from captured output context.
- Need inline rewritten remote output for selected commands:
  - On Windows host shells, active remote sessions can rewrite
    `tasklist`/`Get-Process`/`wmic process` and `ss`/`netstat` output locally
    before display using tc middleware.
  - On Unix PTY shells, tc keeps raw terminal passthrough and applies
    context-based classification without rewriting raw PTY bytes.
