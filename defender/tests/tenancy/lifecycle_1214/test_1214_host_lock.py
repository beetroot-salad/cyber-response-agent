"""#1214 host lock and registry (P3, RC-5): run start, drain start and the connect command hold T's host lock shared and
record themselves; install holds it shared, prepare exclusive; teardown stops what is recorded.

Black box over real processes: a launcher child enters the real entry point with a directory whose `state()` blocks, so it
sits right after the lock and registry step (Flow 4: lock, then state). The lock lives under the data root the child and the
actor share (`DEFENDER_DATA_ROOT`), keyed by tenant id. Pinned addition (GAP-C-3): `LifecycleConfig.teardown_wait`, the
seconds teardown waits for the exclusive lock after SIGTERM before SIGKILL.

Needs real code, not asserted here: tenant-labelled box containers stopped by teardown (`BoxRequest` has no tenant label; proposal:
`BoxRequest.tenant_id` -> `--label defender.tenant=<T>`); a lock holder SIGKILL cannot free, making teardown fail loudly.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[4]
WAIT = 1.0

LAUNCHER = textwrap.dedent("""
    import os, pathlib, signal, sys, time
    entry, mode, tenant, ready, alert = sys.argv[1:6]
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    from defender.tenancy import TenantDirectory

    class Blocking(TenantDirectory):
        def __init__(self):
            super().__init__(lambda: None)
        def state(self, tenant_id):
            pathlib.Path(ready).write_text(str(os.getpid()))
            time.sleep(600)
        def forge_wiring(self, tenant_id):
            time.sleep(600)
        def admission(self, tenant_id):  # r10 Finding 9: state and wiring in one read
            pathlib.Path(ready).write_text(str(os.getpid()))
            time.sleep(600)

    if entry == "run":
        from defender import run
        run.main([alert, "--tenant", tenant, "--no-learn"], directory=Blocking(),
                 preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                 enqueue=lambda *a, **k: False, publish=lambda *a, **k: "")
    elif entry == "drain":
        from defender.learning.core import cli
        cli.main(["loop.py", "--author-drain", "--tenant", tenant], directory=Blocking())
    elif entry == "workspace_map":
        from defender.cli import workspace_map
        workspace_map.main(["workspace_map.py", "--tenant", tenant, "run-20261028T000000Z-0001"], directory=Blocking())
    else:
        from defender.cli import tenant as connect
        connect.main(["check", tenant], directory=Blocking())
""")


class Holder:
    """One launcher child holding T's shared lock."""

    def __init__(self, tmp_path: Path, tenant: str, entry: str, mode: str, index: int) -> None:
        self.ready = tmp_path / f"ready-{entry}-{index}"
        alert = tmp_path / "alert.json"
        alert.write_text('{"rule": {"id": "r"}, "alert_timestamp": "2026-10-28T00:00:00Z"}', encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
        self.proc = subprocess.Popen([sys.executable, "-c", LAUNCHER, entry, mode, tenant, str(self.ready), str(alert)],  # noqa: S603
                                     env=env, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + 60
        while not self.ready.exists():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.proc.kill()
                raise AssertionError(f"the launcher never reached the state check:\n{self.proc.communicate()}")
            time.sleep(0.05)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        if self.alive():
            self.proc.kill()
        self.proc.communicate()


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=WAIT))
    yield w
    w.close()


@pytest.fixture
def holders(tmp_path):
    made: list[Holder] = []

    def start(tenant: str, entry: str = "run", mode: str = "default") -> Holder:
        made.append(Holder(tmp_path, tenant, entry, mode, len(made)))
        return made[-1]

    yield start
    for holder in made:
        holder.kill()


@pytest.mark.parametrize("entry", ["run", "drain", "connect", "workspace_map"])
def test_teardown_terminates_a_recorded_process_and_completes(world, holders, entry):
    """Teardown SIGTERMs what run start / drain start / the connect command recorded, then removes the folder (P3, O4)."""
    tenant = world.active_tenant()
    holder = holders(tenant, entry)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert holder.proc.wait(timeout=30) == -signal.SIGTERM
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists()


def test_a_process_that_ignores_sigterm_is_killed_after_the_bound(world, holders):
    """No exit within `teardown_wait`: SIGKILL, and teardown still completes (P3)."""
    tenant = world.active_tenant()
    holder = holders(tenant, "run", "ignore-term")
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    started = time.monotonic()
    world.drive()
    assert holder.proc.wait(timeout=30) == -signal.SIGKILL
    assert time.monotonic() - started >= WAIT, "SIGKILL came before the bound"
    assert world.item(tenant)["state"] == "offboarded"


def test_another_tenants_process_is_left_alone(world, holders):
    """Teardown of T stops T's recorded processes only; a holder for T2 keeps running (P3, O7)."""
    first, second = world.active_tenant(), world.active_tenant()
    mine, other = holders(first), holders(second)
    assert world.ops.post(f"/admin/tenants/{first}/offboard").status_code == 202
    world.drive()
    assert mine.proc.wait(timeout=30) == -signal.SIGTERM
    assert other.alive()


def test_the_shared_holders_do_not_exclude_each_other(world, holders):
    """Run, drain and connect hold the lock shared at once: all three get past it (P3)."""
    tenant = world.active_tenant()
    started = [holders(tenant, entry) for entry in ("run", "drain", "connect", "run")]
    assert all(h.alive() for h in started)


def test_install_runs_beside_a_shared_holder_and_prepare_waits_for_it(world, holders):
    """Install (shared) goes ahead while a run holds the lock; prepare (exclusive) does not run until the holder is gone,
    then the job completes (RC-5)."""
    tenant = world.create()
    holder = holders(tenant)
    world.drive(stop=lambda: world.item(tenant)["step"] == "prepare")
    secret_file = world.live(tenant).host_secret_file  # the generation is live from the sweep (DC-5)
    assert secret_file is not None
    assert secret_file.is_file(), "install did not run beside the shared holder"
    assert holder.alive()
    ran = threading.Thread(target=world.host_pass, daemon=True)
    ran.start()
    time.sleep(WAIT + 1.0)
    assert world.publish.calls == [], "prepare published while a shared holder was alive"
    assert not (world.data_root / tenant).exists(), "prepare made the folder under a shared holder"
    holder.kill()
    ran.join(timeout=60)
    assert not ran.is_alive(), "prepare never got the lock once the holder was gone"
    if world.item(tenant)["failure"] is not None:  # waiting out the bound may fail the step; resume is the way on
        assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"
    assert world.publish.calls == [(tenant, world.data_root)]


# --- r10: the hold lasts for the command, nesting reuses it (A2) ---------------------------------

TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"


def _me() -> list:
    from defender.tenancy._owner import process_start

    return [(os.getpid(), process_start(os.getpid()))]


def _recorded(data_root: Path) -> list:
    from defender.tenancy import host_lock

    return [(h.pid, h.start) for h in host_lock.holders(data_root, TENANT)]


def _exclusive_free(data_root: Path) -> bool:
    from defender.tenancy import host_lock

    fd = host_lock.acquire(data_root, TENANT, exclusive=True, timeout=0)
    host_lock.release_lock(fd)
    return fd is not None


def test_a_nested_hold_keeps_the_record_until_the_outer_scope_ends(data_root):
    """Inner exit of a nested shared hold leaves this process recorded and the lock held; the outer exit releases both
    (r10 O-A3, A2; R10-3 probed the inner exit deleting the outer record)."""
    from defender.tenancy import host_lock

    with host_lock.hold_shared(data_root, TENANT):
        with host_lock.hold_shared(data_root, TENANT):
            assert _recorded(data_root) == _me()
        assert _recorded(data_root) == _me(), "the inner exit removed the outer scope's record"
        assert not _exclusive_free(data_root), "the inner exit released the outer scope's lock"
    assert _recorded(data_root) == []
    assert _exclusive_free(data_root)


@pytest.fixture
def placed(data_root) -> Path:
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    place_tenant(data_root, TENANT)
    (data_root / TENANT / "learning").mkdir(exist_ok=True)
    return data_root


def test_the_host_acceptance_holds_for_its_scope_and_a_refusal_releases_what_it_took(placed):
    """An admitted scope records this process and holds the lock until it ends; a refused acceptance (`offboarding`)
    leaves neither record nor lock (r10 O-A2, O-A6)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused
    from defender.tests.support.tenancy._active1214 import active_directory
    from defender.tests.support.tenancy._host1214 import ADMITTED_TENANT, host_tenant

    root = tenancy.resolve_data_root()
    with host_tenant(root, TENANT, directory=active_directory(placed, TENANT)) as admitted:
        assert str(getattr(admitted, ADMITTED_TENANT).id) == TENANT
        assert _recorded(placed) == _me(), "control: an admitted scope is recorded"
        assert not _exclusive_free(placed), "control: an admitted scope holds the lock"
    assert _recorded(placed) == []
    assert _exclusive_free(placed)
    refused = active_directory(placed, TENANT, state="offboarding")
    with pytest.raises(TenantRefused, match="offboarding"), host_tenant(root, TENANT, directory=refused):
        pytest.fail("an offboarding tenant was admitted")
    assert _recorded(placed) == []
    assert _exclusive_free(placed), "the refused acceptance kept the lock"


def test_an_acceptance_blocked_on_the_host_lock_waits_and_says_so_once(placed, capfd):
    """While prepare or teardown holds T's lock exclusive, acceptance waits (no timeout) and prints one line naming
    that it waits for T's host lock; once released it proceeds. A free lock prints no such line (owner ruling, r10)."""
    from defender import tenancy
    from defender.tenancy import host_lock
    from defender.tests.support.tenancy._active1214 import active_directory
    from defender.tests.support.tenancy._host1214 import WAITING_WORDS, host_tenant

    root = tenancy.resolve_data_root()
    directory = active_directory(placed, TENANT)
    with host_tenant(root, TENANT, directory=directory):
        pass
    free = capfd.readouterr()
    assert not any(WAITING_WORDS[0] in s for s in (free.out, free.err)), "control: a free lock prints no waiting line"

    entered = threading.Event()
    failed: list[BaseException] = []

    def accept() -> None:
        try:
            with host_tenant(root, TENANT, directory=directory):
                entered.set()
        except BaseException as e:  # noqa: BLE001 — reported on the main thread
            failed.append(e)

    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    waiter = threading.Thread(target=accept, daemon=True)
    text = ""
    try:
        waiter.start()
        deadline = time.monotonic() + 20
        while not all(w in text for w in WAITING_WORDS) and time.monotonic() < deadline and not failed:
            got = capfd.readouterr()
            text += got.out + got.err
            time.sleep(0.05)
        assert not entered.is_set(), "acceptance went past an exclusive hold"
        assert waiter.is_alive(), f"acceptance gave up instead of waiting: {failed}"
    finally:
        host_lock.release_lock(fd)
    waiter.join(timeout=20)
    got = capfd.readouterr()
    text += got.out + got.err
    assert entered.is_set(), f"acceptance never proceeded once the lock was free: {failed}"
    lines = [line for line in text.splitlines() if all(w in line for w in WAITING_WORDS)]
    assert len(lines) == 1, text
    assert TENANT in lines[0]
