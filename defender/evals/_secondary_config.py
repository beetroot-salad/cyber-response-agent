"""Shared constants and base exception for the secondary-metric harness.

Imported by secondary.py, _generation.py, _pipeline.py, and _summary.py.
Lives here (rather than in secondary.py) so the leaf modules can import it
without creating a circular dependency back to secondary.py.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Add evals/ to sys.path so peer evals/_*.py modules can do a plain
# ``import _secondary_config`` regardless of how they are loaded
# (as part of secondary.py, via spec_from_file_location, or directly).
_EVALS_DIR = Path(__file__).resolve().parent
if str(_EVALS_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALS_DIR))

REPO_ROOT = Path(__file__).resolve().parents[2]
# Put the workspace root on sys.path so the on-demand sibling loaders in
# secondary.py (_load_shared / _load_loop exec modules whose imports are
# absolute ``defender.learning.*``) resolve when this harness is run directly.
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
LEARNING_DIR = REPO_ROOT / "defender" / "learning"
EVAL_OUT_DIR = REPO_ROOT / "defender" / "evals" / "results" / "secondary"
WORKTREES_DIR = REPO_ROOT / ".claude" / "worktrees"

# One definition of where the held-out set lives — shared with run_common's
# fail-closed enqueue net and evals/held_out.py's fixture walk.
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
