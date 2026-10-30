# ruff: noqa: F811, PT018
"""#1214 attack-1 on the job model in memory: the exact step order (H-15), a transport failure after the unwrap restarts at
`wrap` (H-9), `serve` waits the poll interval (H-14), the repo deletion is audited after its commit (H-7) (DC-3, DC-4, DC-14, O10)."""
from __future__ import annotations

import asyncio
import datetime as _dt
import time
from typing import Any

import httpx
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._identity1306 import AuditLog  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._atk1 import Raises, watch_commits  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import FORGE_URL, OPENBAO_URL  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import REPO_DELETE, REPO_WINDOW, LifecycleWorld, lifecycle_config  # noqa: E402

CREATE = ["names", "provider", "repo", "bot", "integration", "template", "wrap", "install", "sweep", "prepare", "activate"]
ROTATE = ["names", "provider", "bot", "integration", "wrap", "install", "sweep", "retire", "remove_old_file"]


def _runs(log: list[tuple[Any, Any]], action: str | None = None) -> list[Any]:
    """The committed steps (of `action`), consecutive repeats collapsed: DC-3 pins the order, not the number of commits."""
    steps = [s for a, s in log if action is None or a == action]
    return [s for i, s in enumerate(steps) if i == 0 or steps[i - 1] != s]


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


# --- H-15 --------------------------------------------------------------------------------------------

def test_each_action_runs_its_steps_in_the_order_the_design_lists(world):
    """Every committed step, in order, is DC-3's list for create, rotate, offboard and the repo deletion: a pass runs
    several service steps at once, so the handoffs alone do not show the order (DC-3)."""
    log = watch_commits(world.tenants)
    tenant = world.active_tenant()
    assert _runs(log, "create") == CREATE
    log.clear()
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive()
    assert _runs(log, "rotate") == ROTATE
    log.clear()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert _runs(log) == ["offboard", "teardown", "finish"]
    log.clear()
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.drive()
    assert {a for a, _ in log} == {"delete_repo"} and _runs(log) == ["delete_repo"], log


# --- H-9 ---------------------------------------------------------------------------------------------

def _login(r: httpx.Request) -> bool:
    return r.url.path == "/v1/auth/approle/login"


def _mint(r: httpx.Request) -> bool:
    return r.url.path.startswith("/v1/identity/oidc/token/")


def _repo_read(r: httpx.Request) -> bool:
    return r.method == "GET" and r.url.path.startswith("/api/v1/repos/") and r.url.path.count("/") == 5


def _branch_read(r: httpx.Request) -> bool:
    return r.method == "GET" and r.url.path.endswith("/branches/main")


#: name -> (client, which request fails, the exception raised instead of an answer)
AFTER_UNWRAP = {
    "login": ("openbao", _login, httpx.ConnectError("connection refused")),
    "mint": ("openbao", _mint, httpx.ReadTimeout("timed out")),
    "repo read": ("forge", _repo_read, httpx.ConnectError("connection refused")),
    "branch read": ("forge", _branch_read, OSError("network unreachable")),
}


@pytest.mark.parametrize("name", list(AFTER_UNWRAP))
def test_a_transport_failure_after_the_unwrap_restarts_at_wrap_not_at_the_spent_install(world, name):
    """The wrapper is spent once unwrapped, so install failing after it for any reason, an HTTP answer or not, restarts at
    `wrap` (service); resume makes a fresh secret and the job finishes (DC-4, Flow 1.8)."""
    client, when, error = AFTER_UNWRAP[name]
    if client == "openbao":
        failing = Raises(world.openbao.handle, when, error)
        http = httpx.AsyncClient(transport=httpx.MockTransport(failing), base_url=OPENBAO_URL)
        world.host_actor = world.new_host(world.tenants, openbao_login=http)
    else:
        failing = Raises(world.forge.handle, when, error)
        http = httpx.AsyncClient(transport=httpx.MockTransport(failing), base_url=FORGE_URL)
        world.host_actor = world.new_host(world.tenants, forge=http)
    tenant = world.create()
    world.drive()
    assert failing.hit, "control: the failure was never injected"
    assert len(world.openbao.made("POST", "/v1/sys/wrapping/unwrap")) == 1, "control: the wrapper was spent"
    item = world.item(tenant)
    assert (item["step"], item["step_actor"]) == ("wrap", "service")
    assert item["failure"] and "install" in item["failure"]
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"


# --- H-14 --------------------------------------------------------------------------------------------

def test_serve_waits_the_poll_interval_between_rounds(tmp_path, data_root):
    """Between two rounds of `serve` at least the poll interval passes: it is not a busy loop on the database and the
    forge (DC-14)."""
    from defender.lifecycle import serve

    interval = 0.2
    stamps: list[float] = []

    class Service:
        async def work(self) -> int:
            stamps.append(time.monotonic())
            return 0

    class Host:
        async def work(self) -> int:
            return 0
    rounds: list[int] = []

    def stop() -> bool:
        rounds.append(1)
        return len(rounds) >= 4
    asyncio.run(serve(Service(), Host(), config=lifecycle_config(tmp_path, data_root, poll_interval=interval), stop=stop))
    gaps = [b - a for a, b in zip(stamps, stamps[1:], strict=False)]
    assert len(stamps) >= 2 and min(gaps) >= interval * 0.8, gaps


def test_serve_goes_on_after_a_pass_that_raised(tmp_path, data_root, caplog):
    """The service's first pass raises (the database is unreachable): `serve` logs it, the host still works that round,
    and the next round runs; the process does not end on one failed pass (DC-14)."""
    from defender.lifecycle import serve

    service_rounds: list[int] = []
    host_rounds: list[int] = []

    class Service:
        async def work(self) -> int:
            service_rounds.append(1)
            if len(service_rounds) == 1:
                raise ConnectionError("the database is unreachable")
            return 0

    class Host:
        async def work(self) -> int:
            host_rounds.append(1)
            return 0
    asyncio.run(serve(Service(), Host(), config=lifecycle_config(tmp_path, data_root, poll_interval=0.01),
                      stop=lambda: len(service_rounds) >= 2))
    assert (len(service_rounds), len(host_rounds)) == (2, 2)
    assert "the database is unreachable" in caplog.text


def test_a_tenant_whose_lock_cannot_be_taken_does_not_stop_the_pass_for_the_others(world):
    """Taking the first listed tenant's lock raises (its connection dropped): the pass goes on and the other claimable
    tenant's steps run; once the lock can be taken again the first one is done too (DC-14)."""
    first, second = world.create(), world.create()
    real = world.tenants.lock
    broken: list[str] = []

    def lock(tenant_id: str) -> Any:
        if not broken or broken == [tenant_id]:
            broken[:] = [tenant_id]
            raise ConnectionError("the lock's connection was dropped")
        return real(tenant_id)
    world.tenants.lock = lock
    world.service_pass()
    [skipped] = broken
    [other] = {first, second} - {skipped}
    assert world.item(skipped)["step"] == "names"
    assert world.item(other)["step"] != "names", "the pass ended at the tenant whose lock failed"
    world.tenants.lock = real
    world.drive()
    assert {world.item(t)["state"] for t in (first, second)} == {"active"}


# --- H-7 ---------------------------------------------------------------------------------------------

def _offboarded(world):
    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    return tenant


def test_the_repo_delete_event_is_emitted_only_after_its_commit_landed(world, caplog):
    """When `delete_repo` commits, no `tenant.repo.delete` event exists yet; the event follows, once (O10, K11)."""
    _offboarded(world)
    audit = AuditLog(caplog)
    mark = audit.mark()
    seen: list[list[str]] = []
    watch_commits(world.tenants, before=lambda _record, _kw: seen.append(audit.actions(mark)))
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.drive()
    assert seen == [[]], "the event came before the commit"
    assert audit.actions(mark) == [REPO_DELETE]


def test_a_repo_deletion_whose_commit_misses_its_fence_emits_nothing_and_is_audited_once_when_it_lands(world, caplog):
    """The job moved under `delete_repo` (its commit misses the fence): no event; the next pass finds the repo gone,
    commits and audits it once (O10, P6)."""
    from defender.tenancy import FenceMissed

    _offboarded(world)
    audit = AuditLog(caplog)
    mark = audit.mark()
    missed: list[int] = []

    def miss_once(_record, _kw):
        if not missed:
            missed.append(1)
            raise FenceMissed("the job moved")
    watch_commits(world.tenants, before=miss_once)
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.service_pass()
    assert missed and audit.actions(mark) == [], "an event was emitted for a deletion that did not commit"
    world.service_pass()
    assert audit.actions(mark) == [REPO_DELETE]
    assert world.record(next(t.id for t in world.call(world.tenants.tenants))).repo_url is None
