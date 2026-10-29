# ruff: noqa: PT018
"""#1214 smaller mechanisms: the host processes' version check at start, `serve` driving both actors, the by-name sweeps of
`sweep` and `delete_repo` (RC-8), `finish` failing and resuming, the box tenant label (O4) and identity's `all_tenants`
being gone (DC-6, DC-14, O11, F-11).

GAP-Rc-4 (pinned here): `await defender.lifecycle.serve(service, host, *, config, stop)` is `python -m defender.lifecycle
serve`'s loop: one `work()` pass of each actor, then `config.poll_interval`, until `stop()` (called once per round) is true.
Teardown removes the tenant's dev output `<DEFENDER_RUN_VISUALIZATIONS_DIR>/<T>/` (r9 pin, GAP-Rc-5).
NOT asserted, design gaps: failure injection for `teardown` (no seam makes a host removal fail: GAP-Rc-6) and stopping the labelled containers (no docker
seam on the host actor: GAP-Rc-7).
"""
from __future__ import annotations

import datetime as _dt
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.shared._postgres1339 import empty_database  # noqa: E402,F401 — fixture
from defender.tests.support.tenancy._active1214 import DSN_ENV, insert_active_tenant  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._job_cases import openbao_failing  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import REPO_WINDOW, LifecycleWorld  # noqa: E402
from defender.tests.tenancy.lifecycle_1214.test_1214_host_entry import (  # noqa: E402
    TENANT,
    _tenant_placed,  # noqa: F401 — FR-1: the autouse fixture places TENANT complete here too
    _admits,
    _connect,
    _drain_start,
    _has,
    _run_start,
)

DEFENDER = Path(__file__).resolve().parents[3]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


# --- the version check at start (O11) ----------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.parametrize("entry", ["run start", "drain start", "connect command"])
def test_a_host_process_refuses_a_database_behind_naming_both_revisions(entry, empty_database, data_root, tmp_path,  # noqa: F811
                                                                         monkeypatch):
    """Built from the address, each host entry point runs the light version check first: a baseline database is refused
    naming its revision and head; the same database upgraded and holding the tenant is admitted (O11, Flow 4)."""
    from defender.migrations import head, upgrade
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to

    start = {"run start": lambda: _run_start(TENANT, tmp_path), "drain start": lambda: _drain_start(TENANT),
             "connect command": lambda: _connect(["check", TENANT])}[entry]
    _upgrade_to(empty_database, BASELINE)
    monkeypatch.setenv(DSN_ENV, empty_database)
    _has(start(), BASELINE, head())
    upgrade(empty_database)
    insert_active_tenant(empty_database, TENANT, data_root=data_root)
    assert _admits(start())


# --- python -m defender.lifecycle (DC-14) -----------------------------------------------------------

def test_the_lifecycle_command_offers_serve_and_adopt():
    """`python -m defender.lifecycle` has the `serve` and `adopt` subcommands (DC-14)."""
    done = subprocess.run([sys.executable, "-m", "defender.lifecycle", "--help"], cwd=DEFENDER.parent,  # noqa: S603
                          capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert "serve" in done.stdout and "adopt" in done.stdout


def test_serve_runs_both_actors_every_round_until_stopped(world):
    """One process drives the service's and the host's steps alike: a created tenant is made active by `serve` alone,
    which stops when told to (DC-14)."""
    from defender.lifecycle import serve

    tenant = world.create()
    rounds: list[int] = []

    def stop() -> bool:
        rounds.append(1)
        return len(rounds) >= 30
    world.call(serve, world.service_actor, world.host_actor, config=world.config, stop=stop)
    assert len(rounds) == 30
    assert world.item(tenant)["state"] == "active"
    assert world.forge.made("POST", "/api/v1/orgs/tenants/repos"), "control: the service's steps ran"
    assert world.publish.calls, "control: the host's prepare ran"


# --- sweeps (RC-8) -----------------------------------------------------------------------------------

def test_sweep_removes_a_secret_file_no_generation_records_and_keeps_the_recorded_one(world):
    """A stray file in the tenant's secrets directory goes at `sweep`; the installed secret's file stays (RC-8, DC-2)."""
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "sweep")
    [gen] = world.generations(tenant)
    stray = gen.host_secret_file.parent / "stray-accessor"
    stray.write_text("left by a timed-out install\n", encoding="utf-8")
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert not stray.exists()
    assert world.live(tenant).host_secret_file.is_file()


def test_delete_repo_repeats_the_by_name_sweep_once_it_is_due(world):
    """A late effect of a timed-out call (a bot and an AppRole of a destroyed generation) is removed when the repo is
    deleted, not before (RC-8, RC-4)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    world.forge.users.add(gen.bot_login)
    world.openbao.approles[gen.approle] = {}
    world.clock.advance(REPO_WINDOW - _dt.timedelta(seconds=1))
    world.drive()
    assert gen.bot_login in world.forge.users and gen.approle in world.openbao.approles, "control: not yet due"
    world.clock.advance(_dt.timedelta(seconds=2))
    world.drive()
    assert gen.bot_login not in world.forge.users and gen.approle not in world.openbao.approles
    assert world.record(tenant).repo_url is None


# --- finish failing (GAP-B-2) ------------------------------------------------------------------------

def test_a_failing_finish_records_its_restart_point_and_resume_completes_it(world):
    """`finish`'s final by-name sweep failing leaves the tenant `offboarding` with the failure at (finish, service); resume
    finishes: `offboarded`, the stray removed (DC-4, RC-4, Flow 2.4)."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "finish")
    world.openbao.approles[gen.approle] = {}  # a late effect the final sweep has to destroy
    openbao_failing(world, lambda r: r.method == "DELETE" and r.url.path.endswith(f"/auth/approle/role/{gen.approle}"),
                    500, during_step="finish")
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"], item["step_actor"]) == ("offboarding", "finish", "service")
    assert "finish" in item["failure"] and "500" in item["failure"]
    assert world.drive() == 0
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert gen.approle not in world.openbao.approles


@pytest.fixture
def dev_deployment(monkeypatch) -> None:
    """A dev deployment, set before the world (and its config) is built: only dev has dev output (FRR-3)."""
    monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")


def test_offboarding_removes_the_tenants_dev_output_and_keeps_another_tenants(dev_deployment, world, run_visualizations_dir):
    """Teardown deletes `<DEFENDER_RUN_VISUALIZATIONS_DIR>/<T>/`; another tenant's directory beside it stays (O4, Flow 2.3)."""
    tenant, other = world.active_tenant(), world.active_tenant()
    for t in (tenant, other):
        (run_visualizations_dir / t / "runs").mkdir(parents=True)
        (run_visualizations_dir / t / "runs" / "page.html").write_text("page\n", encoding="utf-8")
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (run_visualizations_dir / tenant).exists()
    assert (run_visualizations_dir / other / "runs" / "page.html").read_text(encoding="utf-8") == "page\n"


# --- O4 boxes and DC-6 --------------------------------------------------------------------------------

def _box_argv(tmp_path, **kw) -> list[str]:
    from defender.box import BoxRequest
    from defender.box._lifecycle import _render_argv
    from defender.box._spec import BoxSpec

    request = BoxRequest(name="o4-box", workdir=tmp_path, defender_dir=tmp_path, spec=BoxSpec(rootfs="defender-box:o4"), **kw)
    return _render_argv(request).argv


def test_a_box_of_a_tenant_is_labelled_with_the_tenant_so_teardown_can_stop_it(tmp_path):
    """`BoxRequest.tenant_id` becomes `--label defender.tenant=<T>` on the container; a request without one carries none
    (O4, Flow 2.3)."""
    labelled = _box_argv(tmp_path, tenant_id=TENANT)
    assert ["--label", f"defender.tenant={TENANT}"] in [labelled[i:i + 2] for i in range(len(labelled) - 1)]
    plain = _box_argv(tmp_path)
    assert "--label" in plain, "control: the start-token label is there on the same channel"
    assert not [a for a in plain if a.startswith("defender.tenant=")]


def test_identity_has_no_all_tenants_listing_any_more():
    """The tenant listing and its audit moved to the endpoint; `all_tenants` is gone from the service, the protocol and both
    repositories (DC-6)."""
    from defender.identity import IdentityService, InMemoryIdentityRepository, ports
    from defender.identity.postgres import PostgresIdentityRepository

    holders = [IdentityService, InMemoryIdentityRepository, PostgresIdentityRepository,
               *(c for c in vars(ports).values() if isinstance(c, type) and c.__module__ == ports.__name__)]
    assert [h.__name__ for h in holders if hasattr(h, "all_tenants")] == []
    assert hasattr(InMemoryIdentityRepository, "tenant_exists")  # control: the seam's own method stays
