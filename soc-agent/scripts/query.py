#!/usr/bin/env python3
"""Entry point for the investigation-language query tool.

Delegates to soc-agent/scripts/invlang/cli.py.

Usage:
  uv run python soc-agent/scripts/query.py [options]
  uv run python soc-agent/scripts/query.py --help
"""
import sys
from pathlib import Path

# Add scripts/ to path so `invlang` package resolves as a non-relative import
sys.path.insert(0, str(Path(__file__).resolve().parent))

from invlang.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
