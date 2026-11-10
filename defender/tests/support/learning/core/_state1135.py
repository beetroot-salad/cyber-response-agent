"""Test-side doors onto the learning state handle (#1135).

The handle's root must already exist (nothing creates it lazily), so a fixture that points
the retired learning-state variable at a path under `tmp_path` has to create the folder too. This is
an explicit test scratch setting used by helpers that inject `state=`; production launchers
ignore the retired variable and select their accepted tenant's learning root.

#1278 A1/O10 delete the handle at cutover, so it is imported only inside the openers that use it: a test that needs
only a run's address (`curation_run_dir`, `run_of`, `curation_tenant`) keeps importing, and a test that still opens
the handle fails at that call, where the stale-test census sees it.
"""

from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base, location_path

from pathlib import Path
from typing import TYPE_CHECKING

from defender.learning.core.config import LoopPaths

if TYPE_CHECKING:
    from defender.learning.core.state import LearningState

STATE_DIR_ENV = "DEFENDER_LEARNING_STATE_DIR"  # lint-stale-ref: ok — the retired variable is named here to set or clear it as an ambient decoy


def set_state_dir(monkeypatch, root: Path) -> Path:
    """Create `root` and name it for explicit test scratch handles. Returns `root`."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv(STATE_DIR_ENV, str(root))
    return root


def env_state() -> LearningState:
    """An explicit scratch handle over the test setting; production launchers ignore it."""
    import os

    from defender.learning.core.state import LearningState

    root = Path(os.environ[STATE_DIR_ENV])
    return LearningState.open(LoopPaths(repo_root=root, state_dir=root))


def state_over(root: Path) -> LearningState:
    """Create `root` and open a handle over it, whatever the environment names (a test that
    wants one queue folder of its own, apart from the env-named root)."""
    from defender.learning.core.state import LearningState

    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    return LearningState.open(LoopPaths(repo_root=root, state_dir=root))


def state_for_paths(paths) -> LearningState:
    """Create the root `paths` names (if absent) and open a handle over exactly it — the test
    side of a fixture whose `LoopPaths` points `state_dir` at a not-yet-made tmp folder."""
    from defender.learning.core.state import LearningState

    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return LearningState.open(paths)


# -- curation rows and the runs they name ---------------------------------------------------
#
# A curation row is a natural run's address, `{case_id, tenant_id, run_id}`; the lead-author
# drain opens the run through that tenant's repository. So a fixture plants the run where a
# real one lives (`<data root>/<T>/runs/<uuid4>`) and derives the row from that location: the
# two cannot disagree. A test names its run by a LABEL; the id is `fixture_uuid(label)`.


def curation_run_dir(label: str, *, tenant_id: str | None = None) -> Path:
    """`<data root>/<T>/runs/<fixture_uuid(label)>`, made under the test's own data root, T (D9's
    tenant unless named) set up through the real `create_tenant`. One label names one run in
    every call."""
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
    `curation_run_dir`): its tenant is the folder above its runs folder."""
    from defender.records import Run

    run_dir = Path(run_dir)
    return Run.under(fixture_runs_base(run_dir.parent), run_dir.name, tenant_id=run_dir.parent.parent.name)


def curation_tenant(tenant_id: str | None = None):
    """The accepted `Tenant` whose runs `curation_run_dir` plants (D9's unless named), set up in the test's data
    root: the value a drain's host acceptance hands the drain, for a scene whose claims name that tenant."""
    from defender.tenancy._tenant import data_root_from_path, requested_tenant
    from defender.tests.support.shared.contracts._data_root_1078 import D9_TENANT_ID, current_data_root, ensure_d9_tenant

    tenant_id = tenant_id or D9_TENANT_ID
    ensure_d9_tenant(tenant_id)
    return requested_tenant(data_root_from_path(current_data_root()), tenant_id)


def tenant_of(run_dir: Path):
    """The accepted `Tenant` run end hands `enqueue_curation(..., tenant=)` for the run at `run_dir`: the value of
    run start's host acceptance (r10 O-A5, C7), here accepted raw over the test's data root."""
    from defender.tenancy._tenant import data_root_from_path, requested_tenant

    run_dir = Path(run_dir)
    return requested_tenant(data_root_from_path(run_dir.parents[2]), run_dir.parent.parent.name)


def drained_for(paths: LoopPaths, run_dir: Path) -> LoopPaths:
    """The drain's paths as drain start's host acceptance leaves them for the tenant of the run at `run_dir`: the
    tenant's own learning root, carrying the accepted tenant (r10.1 C1: the drain rehydrates each claim through
    `paths.tenant`, so a drain that serves a claim is handed the tenant that claim names; scratch paths with no
    tenant refuse every claim). Make it BEFORE opening the state: the queue lives under the tenant's learning root."""
    paths = tenant_of(run_dir).learning_paths(LoopPaths, repo_root=paths.repo_root)
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return paths


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
    """File a request named for the run itself: the queue is case-keyed, so the run's own name
    stands in as the case."""
    enqueue_case(state, Path(run_dir).name, run_dir)
