# ruff: noqa: F811, PT018
"""#1214 attack-1 on the execution host: teardown fails loudly when the lock cannot be freed (H-5), install and old-file
removal wait for the exclusive host lock (H-10), only the tenant's boxes are stopped (H-12), the secret file and its
directory are private (H-13) (DC-2, P3, RC-5, F-11)."""
from __future__ import annotations

import os
import stat
import threading
import time

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tenancy import host_lock  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._atk1 import DockerShim  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld, lifecycle_config  # noqa: E402

WAIT = 0.3
UNWRAP = "/v1/sys/wrapping/unwrap"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=WAIT),
                              containers=lambda _tenant: None)
    yield w
    w.close()


def _hold(world, tenant, *, exclusive):
    fd = host_lock.acquire(world.data_root, tenant, exclusive=exclusive, timeout=0)
    assert fd is not None
    return fd


# --- H-5 ---------------------------------------------------------------------------------------------

def test_teardown_fails_loudly_and_removes_nothing_when_a_holder_it_cannot_stop_keeps_the_lock(world):
    """A holder of T's lock that is in no registry cannot be signalled: teardown fails (restart at teardown), the folder,
    secrets and secret file stay and nothing is committed; once it lets go, resume finishes (P3, O4, Flow 2.3)."""
    tenant = world.active_tenant()
    secret_file = world.live(tenant).host_secret_file
    fd = _hold(world, tenant, exclusive=False)
    try:
        assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        world.drive()
        item = world.item(tenant)
        assert (item["state"], item["step"], item["step_actor"]) == ("offboarding", "teardown", "host")
        assert item["failure"] and item["failure"].startswith("teardown")
        assert (world.data_root / tenant).is_dir() and secret_file.is_file()
        assert (world.config.secrets_dir / tenant).is_dir()
    finally:
        host_lock.release_lock(fd)
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists()


# --- H-10 --------------------------------------------------------------------------------------------

def _at_install(world):
    tenant = world.create()
    world.drive(stop=lambda: world.item(tenant)["step"] == "install")
    return tenant


def test_install_does_not_unwrap_while_prepare_or_teardown_holds_the_lock_exclusive(world):
    """With the exclusive host lock held, install waits the bound and fails before the OpenBao unwrap (the wrapper is not
    spent, no file is written); after the lock is free, resume completes the job (RC-5, P3)."""
    tenant = _at_install(world)
    fd = _hold(world, tenant, exclusive=True)
    try:
        world.host_pass()
        assert world.openbao.made("POST", UNWRAP) == [], "install unwrapped beside an exclusive holder"
        assert world.item(tenant)["failure"]
        assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()]
    finally:
        host_lock.release_lock(fd)
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "active"


def test_install_that_waits_for_the_exclusive_lock_goes_ahead_once_it_is_free(world, tmp_path, data_root):
    """The exclusive holder lets go inside the bound: install then unwraps and the job moves on (RC-5)."""
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=10.0),
                                      containers=lambda _tenant: None)
    tenant = _at_install(world)
    fd = _hold(world, tenant, exclusive=True)
    ran = threading.Thread(target=world.host_pass, daemon=True)
    ran.start()
    try:
        time.sleep(0.5)
        assert world.openbao.made("POST", UNWRAP) == [], "install unwrapped beside an exclusive holder"
    finally:
        host_lock.release_lock(fd)
    ran.join(timeout=30)
    assert not ran.is_alive()
    item = world.item(tenant)
    assert (item["step"], item["failure"]) == ("sweep", None)
    assert len(world.openbao.made("POST", UNWRAP)) == 1


def test_removing_the_old_secret_file_waits_for_the_exclusive_lock_too(world):
    """Rotation's `remove_old_file` holds the lock shared: with it held exclusive the old file stays and the step fails,
    then resume removes it (RC-5)."""
    tenant = world.active_tenant()
    old = world.live(tenant).host_secret_file
    assert world.ops.post(f"/admin/tenants/{tenant}/rotate-forge-credential").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "remove_old_file")
    fd = _hold(world, tenant, exclusive=True)
    try:
        world.host_pass()
        assert old.is_file(), "the old file was removed beside an exclusive holder"
        assert world.item(tenant)["failure"]
    finally:
        host_lock.release_lock(fd)
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert not old.exists() and world.item(tenant)["pending_action"] is None


# --- H-12 --------------------------------------------------------------------------------------------

def test_teardown_removes_the_containers_labelled_with_the_tenant_and_no_others(tmp_path, data_root, monkeypatch):
    """With a `docker` on PATH, teardown of T lists with the exact filter `label=defender.tenant=<T>` and removes only the
    ids that listed; another tenant's and an unlabelled container keep running (F-11, O7, P3)."""
    w = LifecycleWorld(tmp_path, data_root)
    try:
        w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=WAIT))
        mine, other = w.active_tenant(), w.active_tenant()
        shim = DockerShim(tmp_path / "bin", {"box-mine-1": {"defender.tenant": mine}, "box-mine-2": {"defender.tenant": mine},
                                             "box-other": {"defender.tenant": other}, "box-plain": {"unrelated": "x"}})
        monkeypatch.setenv("PATH", f"{shim.root}{os.pathsep}{os.environ['PATH']}")
        assert w.ops.post(f"/admin/tenants/{mine}/offboard").status_code == 202
        w.drive()
        assert w.item(mine)["state"] == "offboarded"
        listings = [c for c in shim.calls() if c[:1] == ["ps"]]
        assert listings and all(c[c.index("--filter") + 1] == f"label=defender.tenant={mine}" for c in listings)
        assert sorted(shim.removed()) == ["box-mine-1", "box-mine-2"]
        assert shim.remaining() == {"box-other", "box-plain"}
    finally:
        w.close()


# --- H-13 --------------------------------------------------------------------------------------------

def test_the_host_secret_file_is_private_to_the_host_user(world):
    """The AppRole secret id is written `0600` as `<secret id>\\n`, in a `0700` tenant directory (DC-2)."""
    tenant = world.active_tenant()
    path = world.live(tenant).host_secret_file
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert path.read_text(encoding="utf-8").endswith("\n") and path.read_text(encoding="utf-8").count("\n") == 1
