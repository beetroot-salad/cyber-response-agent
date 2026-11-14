"""#1469 D1 (G6): every production road to a box start hands the box check THE data root its entry point resolved.

The check's folder is `<data root>/.box-checks/<random>/`. The data root is handed inward hop by hop (`tenancy.resolve_data_root`
at an entry point, then one keyword per signature), and every hop is a place to hand the wrong folder: the tenant's own folder
under it, a draft root, the host's temporary folder. One caller test per road would miss the next road added, so this is
one scenario over every road found by reading production for `data_root` (`job_host`'s learning boxes, `Batch.box_request`,
`oracle_serving`'s default factory, `preflight_replay`, the branch launcher's `_run_episode` and `run.py`'s world seams), each
run with a fake daemon that records where every check container's folder stood. The operator's `run.py <alert>` road and the
job helper's run box are the contract's own scenes (`test_operator_commands.py`, `test_box_relay_helper.py`).

Interfaces this contract picks: none beyond the other #1469 files'."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

import pytest

from defender import box as box_mod
from defender.tests.e2e._box665 import RecordingDocker
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.learning.oracle.live_contracts.test_preflight_and_outcome import (  # noqa: F401 — the fixture is autouse
    _BASE,
    _by_world,
    _calls,
    _main,
    episodes_root,
)
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn
from defender.tests.support.jobs._job_helper_learning import run_kind
from defender.tests.support.sandbox._box1195 import FakeDaemon
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the helper scene's database
from defender.tests.support.tenancy._host1214 import TEST_TENANT

# The helper scene's fixtures (`_job_helper`'s docs): `process_state` is autouse, `scene` the default helper scene.
process_state = J.process_state
scene = J.scene
from defender.tests.tenancy.tenant_1108_delivery._support import repo  # noqa: E402,F401 — a fixture

pytestmark = [pytest.mark.postgres]

ROAD_NAMES = ["helper-oracle-box", "helper-batch-box", "drain-batch-box-request", "oracle-serving-default-factory",
              "branch-launch-preflight-replay", "sibling-world-seams"]


def _helper_oracle_box(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """The learning job's own box over the helper's socket (`box.start`, kind `oracle`)."""
    scene = request.getfixturevalue("scene")
    job_id = str(uuid.uuid4())

    def job(c: Any) -> int:
        c.request("box.start", kind="oracle", id=job_id)
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, "learning", None, job_id=job_id, docker=docker)
    return [r.folder for r in docker.checks.runs], scene.root


def _helper_batch_box(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """The post-step's drain box over the helper's socket (`batch.start`, then `box.start` of kind `batch`)."""
    scene = request.getfixturevalue("scene")

    def job(c: Any) -> int:
        c.request("box.start", kind="batch", id=c.request("batch.start", lanes=["lessons"])["batch"])
        return 0

    docker = ContainerStandIn(job)
    run_kind(scene, "post-step", None, job_id=None, docker=docker, family_less=True)
    return [r.folder for r in docker.checks.runs], scene.root


def _drain_batch_box_request(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """The tenant's drain: its delivery starts the box of a batch's own `box_request()`."""
    from defender.tests.tenancy.tenant_1108_delivery._support import ForgeHTTP, delivery
    from defender.tests.tenancy.tenant_1108_delivery._support import LANES

    repo_ = request.getfixturevalue("repo")
    d = delivery(repo_, ForgeHTTP())
    batch = d.start_batch("hops1469", lanes=LANES)
    docker = RecordingDocker(daemon_id="daemon-1")
    d.start_box(batch.box_request(), docker=docker)
    return [r.folder for r in docker.checks.runs], Path(location_path(repo_[0].data_root))


def _on_path_daemon(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FakeDaemon:
    daemon = FakeDaemon(tmp_path / "daemon")
    daemon.install(monkeypatch)
    return daemon


def _oracle_serving_default_factory(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """`oracle_serving`'s default box factory, as a world's oracle takes it for its first python turn."""
    from defender.box import stop_oracle_box
    from defender.learning.branch.estate.registry import oracle_serving
    from defender.learning.core.config import oracle_settings_with

    tmp_path, monkeypatch = request.getfixturevalue("tmp_path"), request.getfixturevalue("monkeypatch")
    daemon = _on_path_daemon(tmp_path, monkeypatch)
    root = tmp_path / "serving-root"
    root.mkdir()
    started = oracle_serving(oracle_settings_with(), tenant_id=TEST_TENANT, data_root=root).box()
    stop_oracle_box(started)
    return daemon.check_folders(), root


def _branch_launch_preflight_replay(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """The real branch launcher, over a source run: `_run_episode` hands `preflight_replay` the root, which hands each world's
    `oracle_serving` the root, and each world's oracle takes a python turn, which starts its box."""
    tmp_path, monkeypatch = request.getfixturevalue("tmp_path"), request.getfixturevalue("monkeypatch")
    daemon = _on_path_daemon(tmp_path, monkeypatch)
    est = S.estate(tmp_path)
    oracle = _by_world(*[S.oracle(S.python("print('checked')"), then=S.submit(_BASE, S.EMPTY_CLAIM)) for _ in range(2)])
    _base, src = S.source_run(tmp_path, est, calls=_calls())
    _main(src, est, oracle=oracle, verifier=S.passing_verifier())
    return daemon.check_folders(), Path(os.environ["DEFENDER_DATA_ROOT"])


def _sibling_world_seams(request: pytest.FixtureRequest) -> tuple[list[Path], Path]:
    """`run.py`'s sibling seams: the serving it builds for its world, whose default box factory a python turn takes."""
    from defender import run as run_py
    from defender.box import stop_oracle_box

    tmp_path, monkeypatch = request.getfixturevalue("tmp_path"), request.getfixturevalue("monkeypatch")
    daemon = _on_path_daemon(tmp_path, monkeypatch)
    root = tmp_path / "sibling-root"
    root.mkdir()
    serving = run_py._world_seams(object(), oracle=None, verifier=None, source=None, tenant_id=TEST_TENANT, data_root=root)["serving"]
    stop_oracle_box(serving.box())
    return daemon.check_folders(), root


_ROADS = dict(zip(ROAD_NAMES, [_helper_oracle_box, _helper_batch_box, _drain_batch_box_request,
                                _oracle_serving_default_factory, _branch_launch_preflight_replay, _sibling_world_seams],
                  strict=True))


@pytest.mark.parametrize("road", ROAD_NAMES)
def test_d1_every_road_to_a_sandboxed_box_start_runs_its_check_in_the_data_root_its_entry_point_resolved(
        road, request, monkeypatch):
    """Whichever road a box start comes by, its check folder's parent is exactly `<that road's data root>/.box-checks`: not
    the tenant's folder under it (where drafts and runs live), not a draft root, not the host's temporary folder. The data
    root differs from every one of those by construction in each scene, so a wrong hop cannot hide. (D1, data root)"""
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    folders, root = _ROADS[road](request)
    assert folders, f"premise: the {road} road started no check (no box start reached the daemon)"
    assert {f.parent for f in folders} == {root / ".box-checks"}, (road, sorted(set(f.parent for f in folders)), root)
