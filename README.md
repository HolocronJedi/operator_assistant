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
- Execute newline-separated command batches from a local file with `tc runfile`.

The wrapped shell works in local and SSH workflows. For `tc runfile`, the file is read locally and only command text is sent to the active terminal session.

## Example Usage

```bash
# Start wrapper with rule-based insights only
python3 -m terminal_copilot --no-ai

# Start wrapper with AI insights (set OPENAI_API_KEY or ANTHROPIC_API_KEY)
python3 -m terminal_copilot

# Start wrapper with custom shell and slower insight checks
python3 -m terminal_copilot --shell /bin/zsh --debounce 1.0
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
python3 -m terminal_copilot [--no-ai] [--shell SHELL] [--debounce SECONDS]
```

- `--no-ai`: Disable AI-backed insights and use rule-based checks only.
- `--shell`: Override shell path (default: `$SHELL`, fallback `sh`).
- `--debounce`: Seconds between insight checks (default `0.8`).

### In-shell commands

- `help`: Print terminal-copilot help menu.
- `tc runfile`: Prompt for local command file path and load commands.
- `tc runfile <path>`: Load commands from provided local path.
- `tc runlist`: Alias for `tc runfile`.
- `ps`, `ss`, `netstat`: Wrapped output with category prefixes.

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
```

## Configuration

| Env / flag | Description |
|---|---|
| `SHELL` | Shell to run (default `sh` if unset). |
| `--no-ai` | Disable AI; use only rule-based insights. |
| `--debounce` | Seconds between insight checks (default `0.8`). |
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
