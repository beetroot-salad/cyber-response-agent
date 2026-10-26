"""Test-side doors onto the learning state handle (#1135).

The handle's root must already exist (nothing creates it lazily), so a fixture that points
`DEFENDER_LEARNING_STATE_DIR` at a path under `tmp_path` has to create the folder too. This is
an explicit test scratch setting used by helpers that inject `state=`; production launchers
ignore the retired variable and select their accepted tenant's learning root.
"""

from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path

from pathlib import Path

from defender.learning.core.config import LoopPaths
from defender.learning.core.state import LearningState

STATE_DIR_ENV = "DEFENDER_LEARNING_STATE_DIR"


def set_state_dir(monkeypatch, root: Path) -> Path:
    """Create `root` and name it for explicit test scratch handles. Returns `root`."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(STATE_DIR_ENV, str(root))
    return root


def env_state() -> LearningState:
    """An explicit scratch handle over the test setting; production launchers ignore it."""
    import os

    root = Path(os.environ[STATE_DIR_ENV])
    return LearningState.open(LoopPaths(repo_root=root, state_dir=root))


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
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return LearningState.open(paths)


# -- curation rows and the runs they name (#1105 PR 2, declared change 8) ----------------------
#
# A curation row is a natural run's address, `{case_id, tenant_id, run_id}`, and the lead-author
# drain rehydrates it by accepting the tenant under the data root it resolves and opening the run
# through that tenant's repository. So a fixture plants the run where a real one lives
# (`<data root>/<T>/runs/<run_id>`, T a real tenant), and derives the row from that location: a
# planted run and the row naming it cannot disagree. #1187: the runs folder holds no
# `_tenant.json` (R1), and the run's id is a uuid4 (`RunId` admits nothing else, declared change
# 1) — a test names its run by a LABEL, and the id is `fixture_uuid(label)`.


def curation_run_dir(label: str, *, tenant_id: str | None = None) -> Path:
    """`<data root>/<T>/runs/<fixture_uuid(label)>`, made, under the test's own data root (the
    autouse `data_root` fixture's): T (D9's tenant unless named) set up through the real
    `create_tenant`, as run setup leaves it. `label` is the test's readable handle for the run;
    the run's id — the folder's name, and the row's `run_id` — is the uuid4 derived from it
    (`_fixture_uuid.fixture_uuid`), so one label names one run in every call."""
    from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID, current_data_root, ensure_d9_tenant
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    tenant_id = tenant_id or D9_TENANT_ID
    ensure_d9_tenant(tenant_id)
    runs = current_data_root() / tenant_id / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    run_dir = runs / fixture_uuid(label)
    run_dir.mkdir(exist_ok=True)
    return run_dir


def run_of(run_dir: Path):
    """The `Run` run setup hands run end for the natural run at `run_dir` (planted by
    `curation_run_dir`): its tenant is the folder above its runs folder (#1187: `Run.under`,
    which reads no record, replaces `Run.for_tenant`)."""
    from defender.records import Run

    run_dir = Path(run_dir)
    return Run.under(fixture_runs_base(run_dir.parent), run_dir.name, tenant_id=run_dir.parent.parent.name)


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
    """File a request named for the run itself (the old authoring-marker enqueue): the
    one queue is case-keyed now, so the run's own name stands in as the case."""
    enqueue_case(state, Path(run_dir).name, run_dir)
