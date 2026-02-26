# terminal-copilot

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

Run tests:

```bash
pytest
```
