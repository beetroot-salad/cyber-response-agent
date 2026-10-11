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


# -- curation rows and the runs they name (#1105 PR 2, declared change 8) ----------------------
#
# A curation row is a natural run's address, `{case_id, tenant_id, run_id}`, and the lead-author
# drain rehydrates it by accepting the tenant under the data root it resolves and opening the run
# through that tenant's repository. So a fixture plants the run where a real one lives
# (`<data root>/<T>/runs/<run_id>`, T a real tenant, the runs folder carrying its tenant record),
# and derives the row from that location: a planted run and the row naming it cannot disagree.


def curation_run_dir(run_id: str, *, tenant_id: str | None = None) -> Path:
    """`<data root>/<T>/runs/<run_id>`, made, under the test's own data root (the autouse
    `data_root` fixture's): T (D9's tenant unless named) set up through the real `create_tenant`
    and its runs folder's tenant record ensured, as run setup leaves them."""
    from defender._tenant import ensure_runs_base_record
    from defender.tests._data_root_1078 import D9_TENANT_ID, current_data_root, ensure_d9_tenant

    tenant_id = tenant_id or D9_TENANT_ID
    ensure_d9_tenant(tenant_id)
    runs = current_data_root() / tenant_id / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    ensure_runs_base_record(runs, tenant_id)
    run_dir = runs / run_id
    run_dir.mkdir(exist_ok=True)
    return run_dir


def run_of(run_dir: Path):
    """The `Run` run setup hands run end for the natural run at `run_dir` (planted by
    `curation_run_dir`): its tenant is the folder above its runs folder."""
    from defender.run_repository import Run

    run_dir = Path(run_dir)
    return Run.for_tenant(run_dir.parent.parent.name, run_dir.name, runs_base=run_dir.parent)


def curation_row(case_id: str, run_dir: Path) -> dict:
    """The row `run_common.enqueue_curation` files for the run at `run_dir`: its address, read
    off where the run lives (`<data root>/<T>/runs/<run_id>`)."""
    run_dir = Path(run_dir)
    return {"case_id": case_id, "tenant_id": run_dir.parent.parent.name, "run_id": run_dir.name}


def enqueue_case(state: LearningState, case_id: str, run_dir: Path) -> None:
    """File the curation request for `case_id` over the run at `run_dir`, as
    `run_common.enqueue_curation` does (`curation_row`: the run's address)."""
    state.enqueue_curation(case_id, curation_row(case_id, run_dir))


def enqueue_run(state: LearningState, run_dir: Path) -> None:
    """File a request named for the run itself (the old `markers.enqueue_for_authoring`): the
    one queue is case-keyed now, so the run's own name stands in as the case."""
    enqueue_case(state, Path(run_dir).name, run_dir)
