"""Test-side doors onto the learning state handle (#1135).

The handle's root must already exist (nothing creates it lazily), so a fixture that points
`DEFENDER_LEARNING_STATE_DIR` at a path under `tmp_path` has to create the folder too, and a test
that drives a verb taking `state=` opens the handle over whatever root the env names.
"""

from __future__ import annotations

from pathlib import Path

from defender.learning.core.config import loop_paths
from defender.learning.core.state import STATE_DIR_ENV, LearningState


def set_state_dir(monkeypatch, root: Path) -> Path:
    """Create `root` and make it the env-named learning state root. Returns `root`."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(STATE_DIR_ENV, str(root))
    return root


def env_state() -> LearningState:
    """A handle over the root the environment currently names (what a launcher entry opens)."""
    return LearningState.open(loop_paths())


def state_over(root: Path) -> LearningState:
    """Create `root` and open a handle over it, whatever the environment names (a test that
    wants one queue folder of its own, apart from the env-named root)."""
    from defender.learning.core.config import LoopPaths

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return LearningState.open(LoopPaths(repo_root=root, state_dir=root))


def state_for_paths(paths) -> LearningState:
    """Create the root `paths` names (if absent) and open a handle over exactly it — the test
    side of a fixture whose `LoopPaths` points `state_dir` at a not-yet-made tmp folder."""
    paths.state_root.mkdir(parents=True, exist_ok=True)
    return LearningState.open(paths)


def enqueue_case(state: LearningState, case_id: str, run_dir: Path) -> None:
    """File the curation request for `case_id` over `run_dir`, as `run_common.enqueue_curation`
    does (the shape the removed `markers.enqueue_case_for_curation` wrote)."""
    state.enqueue_curation(case_id, {"case_id": case_id, "run_dir": str(Path(run_dir).resolve())})


def enqueue_run(state: LearningState, run_dir: Path) -> None:
    """File a request named for the run itself (the old `markers.enqueue_for_authoring`): the
    one queue is case-keyed now, so the run's own name stands in as the case."""
    enqueue_case(state, Path(run_dir).name, run_dir)
