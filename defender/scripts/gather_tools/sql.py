#!/usr/bin/env python3
"""`bin/defender-sql`'s command: runs the sql engine (`defender/runtime/sql_engine/sql.py`).

Started by path, so it first puts its own checkout root ahead of anything else on `sys.path`:
a foreign checkout named by `PYTHONPATH` must never answer for this one.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from defender.runtime.sql_engine.sql import main

if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    raise SystemExit(main())
