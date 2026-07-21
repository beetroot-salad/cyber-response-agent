from __future__ import annotations

import sys
from pathlib import Path

_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
EVAL_OUT_DIR = REPO_ROOT / "defender" / "evals" / "results" / "secondary"
WORKTREES_DIR = REPO_ROOT / ".claude" / "worktrees"

from defender.run_common import (  # noqa: E402 — needs REPO_ROOT on sys.path
    HELD_OUT_FIXTURES as FIXTURES_DIR,  # noqa: F401 — re-exported to secondary.py
    resolve_runs_base,
)

DEFAULT_RUNS_BASE = resolve_runs_base()

ELIGIBLE_DISPOSITIONS = {"benign", "inconclusive"}
ESCALATED_DISPOSITION = "malicious"
SKIP_OUTCOME = "skip-passthrough"
CATCH_OUTCOMES = {"caught", "survived", "incoherent", "undecidable"}


class SecondaryError(Exception):
    pass
