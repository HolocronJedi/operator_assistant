"""Print terminal-copilot help menu from environment for shell wrappers."""
from __future__ import annotations

import os
import sys


def main() -> int:
    text = os.environ.get("TC_HELP_MENU", "").rstrip("\n")
    if text:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
