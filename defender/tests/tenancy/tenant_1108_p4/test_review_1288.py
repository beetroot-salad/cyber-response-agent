"""#1108 P4, PR #1288 review: the fixes that dissolve a finding by construction, each pinned at the
seam that now carries it.

- a run copy is owned from the instant its folder exists (its building name carries its owner),
  so a publish's sweep, which takes no notice of the building process, never removes it;
- the publish child holds ONE deadline over its network phase and reports, and records, running
  out of it itself;
- the launcher records the outcomes only it sees (a child that crashed or printed nothing).
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


def _status(t) -> dict | None:
    from defender.tenancy._publish_status import read_status

    return read_status(t.tenant)


# --- a run copy is owned while it is built --------------------------------------------------------

def test_a_folder_built_under_an_owned_name_is_alive_before_its_owner_file_exists(tmp_path):
    from defender.tenancy._owner import OWNER_FILE, owned_temporary, owner_alive

    building = tmp_path / owned_temporary(".building-r1")
    building.mkdir()
    assert not (building / OWNER_FILE).exists()
    assert owner_alive(building), "a folder mid-build, its owner this live process, counted dead"


def test_a_folder_whose_name_carries_a_dead_owner_is_dead(tmp_path):
    from defender.tenancy._owner import owned_temporary, owner_alive

    gone = subprocess.Popen([sys.executable, "-c", "pass"])  # noqa: S603 — a process that exits
    gone.wait()
    pid, start = owned_temporary("").split("-")[1:3]
    dead = tmp_path / f".building-r1.owner-{gone.pid}-{start}-0123abcd"
    dead.mkdir()
    assert not owner_alive(dead), "a building folder whose owner has exited counted alive"
    assert owner_alive(tmp_path / f".building-r1.owner-{pid}-{start}-0123abcd"), "control"


def test_a_publish_sweep_keeps_a_run_copy_being_built_and_removes_a_dead_builders(p4_tenant):
    """The finding's race, replayed in order: a run copy's building folder exists with no owner
    file yet (the builder is between making it and writing its record) when a publish sweeps."""
    from defender.learning.author.version_control.exports import sweep_dead_owners
    from defender.tenancy._owner import owned_temporary

    copies = Path(p4_tenant.tenant.run_knowledge)
    copies.mkdir(parents=True, exist_ok=True)
    live = copies / owned_temporary(".building-r-live")
    live.mkdir()
    orphan = copies / ".building-r-orphan-0123abcd"
    orphan.mkdir()
    sweep_dead_owners(p4_tenant.tenant)
    assert live.is_dir(), "the sweep removed a run copy while its owner was building it"
    assert not orphan.exists(), "control: an unowned building folder is swept"


# --- the publish child's one deadline ---------------------------------------------------------------

@pytest.fixture
def child_tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        bind_forge(t)
        yield t


def test_the_child_reports_and_records_running_out_of_its_network_budget(child_tenant, tmp_path):
    """A forge call answers slowly: well within its own 30s bound, but past the child's whole
    budget. The child ends itself at the budget with `stale:transient` and records it, so
    `tenant.py check` names the outage."""
    t = child_tenant
    config = B.write_issuer_config(tmp_path / "operator")
    t.merge(B.MERGE_FILES)

    def slow(_request):
        time.sleep(3.0)

    t.forge.fault = slow
    began = time.monotonic()
    line = B.run_child(t, config, budget=1.0)
    took = time.monotonic() - began
    assert line.startswith("stale:transient "), line
    assert "budget" in line, line
    assert took < 2.5, f"the child took {took:.1f}s over a 1s budget"
    status = _status(t)
    assert status is not None
    assert status.get("kind") == "transient", status
    assert status.get("by") == "launch-time publish", status


def test_the_launcher_hands_the_child_a_budget_inside_its_own(tmp_path):
    from defender.runtime import publish_launch
    from defender.tests.tenancy.tenant_1108_p4.test_publish_child import _RecordingSpawn

    spawn = _RecordingSpawn()
    publish_launch.launch_publish("some-tenant", data_root=tmp_path, budget=60.0, spawn=spawn)
    (argv, _env), = spawn.calls
    budget = float(argv[argv.index("--budget") + 1])
    assert 0 < budget < 60.0, argv


# --- the launcher records what only it sees -----------------------------------------------------------

@pytest.mark.parametrize("child", [
    "import sys; sys.exit(3)",
    "print('not a report')",
])
def test_the_launcher_records_a_child_that_reports_nothing_valid(p4_tenant, child):
    from defender.runtime import publish_launch

    line = publish_launch.launch_publish(
        p4_tenant.tenant_id, data_root=p4_tenant.data_root, budget=30.0,
        command=[sys.executable, "-c", child, "--"])
    assert line.startswith("stale:operator publish child failed:"), line
    status = _status(p4_tenant)
    assert status is not None, "the failed child left no publish status for `check`"
    assert status.get("kind") == "operator", status
    assert status.get("by") == "launch-time publish", status
    assert "publish child failed" in status.get("refused", ""), status


def test_control_a_child_that_reports_validly_is_not_recorded_by_the_launcher(p4_tenant):
    from defender.runtime import publish_launch

    line = publish_launch.launch_publish(
        p4_tenant.tenant_id, data_root=p4_tenant.data_root, budget=30.0,
        command=[sys.executable, "-c", "print('stale:transient the forge is down')", "--"])
    assert line == "stale:transient the forge is down"
    status = _status(p4_tenant)
    assert status is None or "publish child failed" not in status.get("refused", ""), status
