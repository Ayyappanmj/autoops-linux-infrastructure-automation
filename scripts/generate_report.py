#!/usr/bin/env python3
"""Thin wrapper: same as 'python -m autoops report ...' (works from any directory)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from autoops.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["report", *sys.argv[1:]]))
