"""Pipe-friendly CLI for network connection annotation."""
from __future__ import annotations

import argparse
import sys

from .net_annotate import annotate_network_output


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source", default="", help="source command label")
    parser.parse_args()
    raw = sys.stdin.read()
    sys.stdout.write(annotate_network_output(raw))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
