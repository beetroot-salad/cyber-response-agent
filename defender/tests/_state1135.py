"""Test-side doors onto the learning state handle (#1135).

The handle's root must already exist (nothing creates it lazily), so a fixture that points
`DEFENDER_LEARNING_STATE_DIR` at a path under `tmp_path` has to create the folder too, and a test
that drives a verb taking `state=` opens the handle over whatever root the env names.
"""

from __future__ import annotations

from pathlib import Path

from defender.learning.core.config import loop_paths
from defender.learning.core.state import LearningState

STATE_DIR_ENV = "DEFENDER_LEARNING_STATE_DIR"


def set_state_dir(monkeypatch, root: Path) -> Path:
    """Create `root` and make it the env-named learning state root. Returns `root`."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(STATE_DIR_ENV, str(root))
    return root


def env_state() -> LearningState:
    """A handle over the root the environment currently names (what a launcher entry opens)."""
    return LearningState.open(loop_paths())
