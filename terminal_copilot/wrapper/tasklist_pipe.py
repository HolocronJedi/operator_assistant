"""Pipe-friendly CLI for Windows process-list annotation."""
from __future__ import annotations

import argparse
import sys

from .tasklist_annotate import annotate_tasklist_text


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", default="", help="source command label")
    parser.parse_args()
    raw = sys.stdin.read()
    sys.stdout.write(annotate_tasklist_text(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
