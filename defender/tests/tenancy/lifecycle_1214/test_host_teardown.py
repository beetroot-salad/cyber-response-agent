# ruff: noqa: F811, PT018
"""#1214 attack-1 on the execution host: teardown fails loudly when the lock cannot be freed (H-5), install and old-file
removal wait for the exclusive host lock (H-10), only the tenant's boxes are stopped (H-12), the secret file and its
directory are private (H-13), a landed install whose answer is lost keeps its secret file, a box started after teardown's first removal is removed
once the lock is held (DC-2, P3, RC-1, RC-5, F-11)."""
from __future__ import annotations

import contextlib
import os
import re
import stat
import subprocess
import sys
import threading
import time
from typing import Any

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
        assert item["failure"] and "teardown" in item["failure"]
        assert (world.data_root / tenant).is_dir() and secret_file.is_file()
        assert (world.config.secrets_dir / tenant).is_dir()
    finally:
        host_lock.release_lock(fd)
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists()


def test_a_teardown_whose_container_removal_fails_gives_the_host_lock_back(tmp_path, data_root):
    """Nothing else holds T's lock and removing T's containers fails: teardown fails naming why, and the exclusive lock
    it took is released, so a resume (and every entry point for T) is not locked out until the process restarts."""
    w = LifecycleWorld(tmp_path, data_root)

    def broken(_tenant: str) -> None:
        raise RuntimeError("docker could not remove the containers")
    try:
        w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=WAIT),
                                  containers=broken)
        tenant = w.active_tenant()
        assert w.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        w.drive()
        item = w.item(tenant)
        assert item["step"] == "teardown" and "docker could not remove" in (item["failure"] or ""), item
        fd = host_lock.acquire(w.data_root, tenant, exclusive=True, timeout=0)
        assert fd is not None, "the failed teardown kept T's host lock"
        host_lock.release_lock(fd)
    finally:
        w.close()


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
    assert len(world.openbao.made("POST", UNWRAP)) == 2, "install unwraps the delivery and the sign secret (A24')"


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


# --- #1360 ------------------------------------------------------------------------------------------

_LATE_WRITER = """
import os, sys, time
folder, before, seconds = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.monotonic() + 30
while time.monotonic() < deadline:
    try:
        if os.stat(folder).st_mtime_ns != before:
            break
    except FileNotFoundError:
        sys.exit(1)
else:
    sys.exit(1)
try:
    if not seconds:
        open(os.path.join(folder, 'late-launch.json'), 'w').write('{}')
        sys.exit(0)
    until, n = time.monotonic() + seconds, 0
    while time.monotonic() < until:
        os.mkdir(os.path.join(folder, 'late-dir-%d' % n))
        n += 1
except FileNotFoundError:
    sys.exit(0 if n else 1)
"""


def _late_writer(folder, *, keep_adding_for=0.0):
    """A process (so no interpreter lock to share with the test) that, the moment the folder's removal has begun unlinking
    its entries (its listing is complete by then), creates one file in `folder`, like a job writing its launch files
    mid-teardown; or, for `keep_adding_for` seconds, empty directories in a tight loop: removing one costs more than
    making one, so the backlog grows and no removal pass can empty the folder meanwhile. Exits 0 once it has landed."""
    return subprocess.Popen([sys.executable, "-I", "-c", _LATE_WRITER, str(folder), str(folder.stat().st_mtime_ns),
                             str(keep_adding_for)])


def _plant_runs(folder, count=8000):
    """A `runs` directory of many files in `folder`, so its removal is long enough for a late writer to land mid-way."""
    runs = folder / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    for n in range(count):
        (runs / f"entry-{n}").write_text("x")
    return runs


@pytest.mark.parametrize("target", ["data", "secrets", "publish"])
def test_teardown_removes_what_a_late_writer_adds_to_the_folder_while_it_is_being_removed(
        world, tmp_path, data_root, monkeypatch, target):
    """A file created in one of T's three folders (data, secrets, dev output) after teardown has listed it makes one
    removal pass fail 'directory not empty'; the offboarding goes on to `offboarded` with all three folders, and nothing
    of the late file, gone (#1360 O1). The wait is shorter than the first pass: it runs from the first failed pass, not
    from the start of the removal."""
    from defender.configuration import _env, publish_root

    published = tmp_path / "published"
    published.mkdir()
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")
    monkeypatch.setenv(publish_root.PUBLISH_DIR_ENV, str(published))
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=0.02),
                                      containers=lambda _tenant: None)
    tenant = world.active_tenant()
    folders = {"data": world.data_root / tenant, "secrets": world.config.secrets_dir / tenant, "publish": published / tenant}
    folders["publish"].mkdir()
    assert folders["secrets"].is_dir(), "premise: the tenant has a secrets folder"
    runs = _plant_runs(folders[target])
    writer = _late_writer(runs)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    assert writer.wait(timeout=35) == 0, "the late write never happened, so this run did not race the removal"
    item = world.item(tenant)
    assert (item["state"], item["failure"]) == ("offboarded", None), item
    assert not any(folder.exists() for folder in folders.values()), {k: f.exists() for k, f in folders.items()}


_PASS_WRITER = """
import os, sys, time
folder, ballast, entries = sys.argv[1], sys.argv[2], int(sys.argv[3])
for k in range(entries):
    landed = os.path.join(folder, 'late-%d' % k)
    try:
        os.rename(os.path.join(ballast, str(k)), landed)
    except FileNotFoundError:
        sys.exit(1)
    if k == entries - 1:
        sys.exit(0)
    children = len(os.listdir(landed))
    deadline = time.monotonic() + 20
    while True:
        try:
            if len(os.listdir(landed)) < children:
                break
        except FileNotFoundError:
            break
        if time.monotonic() > deadline:
            sys.exit(2)
"""


def _pass_writer(folder, ballast, entries):
    """A process that moves `entries` prepared directories (`ballast/0`, `ballast/1`, ...) into `folder` as `late-0`,
    `late-1`, ..., each one only once a removal pass has begun deleting the previous one's children. That pass listed
    `folder` before the next entry landed, so it ends "directory not empty"; the next entry is deleted only by a later
    pass. It never removes anything. Exits 0 once every entry landed: then at least `entries - 1` passes in a row failed
    because something appeared, and after the last one nothing more is added."""
    return subprocess.Popen([sys.executable, "-I", "-c", _PASS_WRITER, str(folder), str(ballast), str(entries)])


def test_teardown_keeps_removing_for_its_wait_however_many_passes_a_writer_that_then_stops_makes_fail(
        world, tmp_path, data_root):
    """A writer adds an entry to T's folder during each of 30 removal passes in a row, then stops. Late writes per pass
    are not bounded by any fixed number, so the bound is the wait (`teardown_wait`, here far longer than the whole
    race), not a pass count: the offboarding goes on to `offboarded` with the folder gone. (#1360 O1, Flow 4)"""
    entries, children = 30, 400
    ballast = tmp_path / "ballast"
    for k in range(entries):
        for n in range(children):
            (ballast / str(k) / f"c-{n}").mkdir(parents=True)
    assert ballast.stat().st_dev == world.data_root.stat().st_dev, "premise: the entries can be moved into the folder"
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=60.0),
                                      containers=lambda _tenant: None)
    tenant = world.active_tenant()
    folder = world.data_root / tenant
    writer = _pass_writer(folder, ballast, entries)
    try:
        deadline = time.monotonic() + 10
        while not (folder / "late-0").exists():
            assert time.monotonic() < deadline and writer.poll() is None, "the writer never placed its first entry"
            time.sleep(0.01)
        assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        world.drive()
        item = world.item(tenant)
        assert (item["state"], item["failure"]) == ("offboarded", None), item
        assert not folder.exists()
        assert writer.wait(timeout=30) == 0, "not every entry landed, so fewer passes than intended failed"
    finally:
        if writer.poll() is None:
            writer.kill()
            writer.wait()


_LATE_REMOVER = """
import os, sys, time
folder = sys.argv[1]
names = os.listdir(folder)
deadline = time.monotonic() + 30
while True:
    try:
        if len(os.listdir(folder)) < len(names):
            break
    except FileNotFoundError:
        sys.exit(1)
    if time.monotonic() > deadline:
        sys.exit(1)
removed = 0
for name in reversed(names):
    try:
        os.unlink(os.path.join(folder, name))
        removed += 1
    except FileNotFoundError:
        pass
sys.exit(0 if removed else 1)
"""


def _late_remover(folder):
    """A process that, the moment a removal pass has begun deleting `folder`'s entries (so it has listed all of them),
    deletes the rest itself, as a late job removes its database's journal files. Exits 0 once it deleted at least one
    entry before the pass reached it: that pass then met an entry it had listed and found it gone ("no such file")."""
    return subprocess.Popen([sys.executable, "-I", "-c", _LATE_REMOVER, str(folder)])


@pytest.mark.parametrize("target", ["data", "secrets", "publish"])
def test_teardown_removes_a_folder_whose_entries_a_late_job_removes_while_it_is_being_removed(
        world, tmp_path, data_root, monkeypatch, target):
    """An entry of one of T's three folders that the removal had listed is removed by someone else before the removal
    reaches it, so that pass fails "no such file"; like an entry that appeared, it is removed again under the same wait,
    and the offboarding goes on to `offboarded` with all three folders gone (#1360 O1, O2 as amended by D1)."""
    from defender.configuration import _env, publish_root

    published = tmp_path / "published"
    published.mkdir()
    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")
    monkeypatch.setenv(publish_root.PUBLISH_DIR_ENV, str(published))
    world.host_actor = world.new_host(world.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=30.0),
                                      containers=lambda _tenant: None)
    tenant = world.active_tenant()
    folders = {"data": world.data_root / tenant, "secrets": world.config.secrets_dir / tenant, "publish": published / tenant}
    folders["publish"].mkdir()
    assert folders["secrets"].is_dir(), "premise: the tenant has a secrets folder"
    remover = _late_remover(_plant_runs(folders[target]))
    try:
        assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        world.drive()
        item = world.item(tenant)
        assert (item["state"], item["failure"]) == ("offboarded", None), item
        assert not any(folder.exists() for folder in folders.values()), {k: f.exists() for k, f in folders.items()}
        assert remover.wait(timeout=35) == 0, "the late removal never beat the pass to an entry, so no pass met one gone"
    finally:
        if remover.poll() is None:
            remover.kill()
            remover.wait()


def test_teardown_that_keeps_finding_new_files_fails_naming_the_folder_and_resume_finishes_it(world):
    """A writer that adds entries to the folder itself after every removal pass never lets the folder empty: after the
    wait teardown gives its holders the step fails (restart at teardown) naming the folder and an entry left in it,
    and once the writer stops a resume finishes the offboarding (#1360 O2). Its wording is not pinned (it may carry the
    underlying error, which names only the folder): it names the folder path and the name of an entry the writer added."""
    tenant = world.active_tenant()
    folder = world.data_root / tenant
    for n in range(4000):  # a first pass long enough for the writer to land mid-way, whichever entry it removes first
        (folder / f"entry-{n}").write_text("x")
    writer = _late_writer(folder, keep_adding_for=3.0)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["step"]) == ("offboarding", "teardown"), item
    failure = item["failure"]
    assert str(folder) in failure, failure
    assert re.search(r"late-dir-\d+", failure), f"the failure does not name an entry left in the folder: {failure}"
    assert writer.wait(timeout=35) == 0, "the late writes never happened, so this run did not race the removal"
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert not (world.data_root / tenant).exists()


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses mode bits; CI runs unprivileged")
def test_a_removal_that_fails_for_any_other_reason_fails_the_step_at_once(tmp_path, data_root):
    """Only 'directory not empty' is waited out: a folder that cannot be removed for another reason (here a subdirectory
    that grants no write, holding an entry) fails the step promptly, far inside the configured wait, with no claim that
    the folder was still being added to; once the mode is restored a resume finishes (#1360 O2)."""
    wait = 30.0
    w = LifecycleWorld(tmp_path, data_root)
    w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=wait),
                              containers=lambda _tenant: None)
    try:
        tenant = w.active_tenant()
        locked = w.data_root / tenant / "locked"
        locked.mkdir()
        (locked / "entry").write_text("x")
        locked.chmod(0o500)
        try:
            assert w.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
            started = time.monotonic()
            w.drive()
            elapsed = time.monotonic() - started
            item = w.item(tenant)
            assert (item["state"], item["step"]) == ("offboarding", "teardown"), item
            assert item["failure"], item
            assert "still being added to" not in item["failure"], item["failure"]
            assert elapsed < wait / 2, f"the step waited {elapsed:.1f}s of a {wait:g}s wait for a failure that cannot clear"
            assert (locked / "entry").is_file()
        finally:
            locked.chmod(0o700)
        assert w.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
        w.drive()
        assert w.item(tenant)["state"] == "offboarded"
        assert not (w.data_root / tenant).exists()
    finally:
        w.close()


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


def test_teardown_removes_a_paused_box_that_refuses_the_first_removal(tmp_path, data_root, monkeypatch):
    """A tenant's box paused under gVisor refuses `rm -f` until it has exited: teardown waits for it and removes it, as
    every other box removal does (#1202), so the offboarding finishes (P3)."""
    w = LifecycleWorld(tmp_path, data_root)
    try:
        w.host_actor = w.new_host(w.tenants, config=lifecycle_config(tmp_path, data_root, teardown_wait=WAIT))
        tenant = w.active_tenant()
        shim = DockerShim(tmp_path / "bin", {"box-paused": {"defender.tenant": tenant, "paused": "1"}})
        monkeypatch.setenv("PATH", f"{shim.root}{os.pathsep}{os.environ['PATH']}")
        assert w.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
        w.drive()
        assert w.item(tenant)["state"] == "offboarded", w.item(tenant)
        assert shim.remaining() == set()
    finally:
        w.close()


def test_a_host_with_no_docker_has_no_box_to_remove():
    """No `docker` binary: there is nothing to remove and nothing failed; a docker that cannot be run for another
    reason is a failure naming it (P3)."""
    from defender.box import remove_tenant_containers

    def missing(_argv: list[str]) -> Any:
        raise FileNotFoundError("docker")

    def denied(_argv: list[str]) -> Any:
        raise PermissionError("docker")
    assert remove_tenant_containers("some-tenant", docker=missing) is None
    assert "could not invoke docker" in (remove_tenant_containers("some-tenant", docker=denied) or "")


# --- H-13 --------------------------------------------------------------------------------------------

def test_the_host_secret_file_is_private_to_the_host_user(world):
    """Each AppRole secret id (delivery and sign) is written `0600` as `<secret id>\\n`, in a tenant directory that grants group
    and other nothing (DC-2, A24')."""
    tenant = world.active_tenant()
    gen = world.live(tenant)
    assert gen.host_secret_file != gen.sign_secret_file
    for path in (gen.host_secret_file, gen.sign_secret_file):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0
        assert path.read_text(encoding="utf-8").endswith("\n") and path.read_text(encoding="utf-8").count("\n") == 1


def test_an_install_that_fails_after_writing_its_secret_file_removes_it(world):
    """The AppRole login fails after both unwraps wrote their files: nothing records them, so install removes both
    (DC-2, DC-4, A24')."""
    from defender.tests.tenancy.lifecycle_1214._job_cases import host_openbao_failing

    tenant = _at_install(world)
    host_openbao_failing(world, lambda r: r.url.path.endswith("/approle/login"))
    world.host_pass()
    assert "install" in (world.item(tenant)["failure"] or ""), world.item(tenant)
    assert len(world.openbao.made("POST", UNWRAP)) == 2, "control: both secrets were unwrapped (and written) before any check"
    assert not [p for p in world.config.secrets_dir.rglob("*") if p.is_file()], "a failed install left its secret file"

class _AnswerLost:
    """A hold whose first commit with generation changes lands and then raises `FenceMissed`, as when the lock
    connection fails after the server committed; everything else is the real hold's."""

    def __init__(self, held: Any, landed: list[Any]) -> None:
        self._held, self._landed = held, landed

    def __getattr__(self, name: str) -> Any:
        return getattr(self._held, name)

    async def commit(self, **kwargs: Any) -> Any:
        from defender.tenancy import FenceMissed

        done = await self._held.commit(**kwargs)
        if not self._landed and kwargs.get("update_generations"):
            self._landed.append(done)
            raise FenceMissed("the commit landed, but its answer was lost with the lock connection")
        return done


def test_an_install_whose_commit_landed_but_whose_answer_was_lost_keeps_the_recorded_secret_file(world):
    """Install's commit lands, then the hold reports `FenceMissed` (the answer was lost): the file the generation now
    records stays on disk, and the job goes on to use it at prepare and finishes (DC-2, RC-1)."""
    tenant = _at_install(world)
    real, landed = world.tenants.lock, []

    @contextlib.asynccontextmanager
    async def lock(tenant_id: str) -> Any:
        async with real(tenant_id) as held:
            yield None if held is None else _AnswerLost(held, landed)
    world.tenants.lock = lock
    world.host_pass()
    world.tenants.lock = real
    assert landed, "control: install committed its generation"
    [recorded] = [(g.host_secret_file, g.sign_secret_file) for g in world.generations(tenant) if g.host_secret_file]
    assert all(p.is_file() for p in recorded), "a secret file the landed install recorded was removed"
    world.drive()
    item = world.item(tenant)
    assert (item["state"], item["failure"]) == ("active", None), item
    live = world.live(tenant)
    assert (live.host_secret_file, live.sign_secret_file) == recorded and all(p.is_file() for p in recorded)


class _Boxes:
    """The containers seam over a set of running boxes: each call removes every one there is, and records which."""

    def __init__(self, *running: str, fail_on: int = 0) -> None:
        self.running, self.removals, self._fail_on = set(running), [], fail_on

    def __call__(self, _tenant: str) -> None:
        if len(self.removals) + 1 == self._fail_on:
            self.removals.append(set())
            raise RuntimeError("docker could not remove the containers")
        self.removals.append(set(self.running))
        self.running.clear()


def _starts_a_box_then_lets_go(world: Any, tenant: str, boxes: _Boxes) -> threading.Thread:
    """A shared holder of T's lock that is inside `docker run` when teardown begins: its box appears after teardown's
    first removal, then it lets go of the lock."""
    fd = _hold(world, tenant, exclusive=False)

    def run() -> None:
        time.sleep(0.5)
        boxes.running.add("box-late")
        host_lock.release_lock(fd)
    holder = threading.Thread(target=run, daemon=True)
    holder.start()
    return holder


def test_a_box_started_after_teardowns_first_removal_is_removed_once_the_lock_is_held(world):
    """The holder's box comes up after the first listing; once teardown holds the exclusive lock it removes the tenant's
    boxes again, so no box is left running with the folder it mounts about to go (P3, Flow 2.3)."""
    from defender.lifecycle._teardown import take_exclusive

    tenant = str(world.create())
    boxes = _Boxes("box-early")
    holder = _starts_a_box_then_lets_go(world, tenant, boxes)
    fd = take_exclusive(world.data_root, tenant, wait=10.0, containers=boxes)
    try:
        holder.join(timeout=10)
        assert boxes.removals[0] == {"box-early"}, boxes.removals
        assert boxes.running == set(), f"a box started during teardown is still running: {boxes.running}"
    finally:
        host_lock.release_lock(fd)


def test_a_teardown_whose_removal_under_the_lock_fails_gives_the_host_lock_back(world):
    """The removal made once the exclusive lock is held fails: teardown fails naming why and releases the lock."""
    from defender.lifecycle._teardown import take_exclusive

    tenant = str(world.create())
    boxes = _Boxes(fail_on=2)
    with pytest.raises(RuntimeError, match="docker could not remove"):
        take_exclusive(world.data_root, tenant, wait=10.0, containers=boxes)
    assert len(boxes.removals) == 2, "control: the second removal was made"
    fd = host_lock.acquire(world.data_root, tenant, exclusive=True, timeout=0)
    assert fd is not None, "the failed teardown kept T's host lock"
    host_lock.release_lock(fd)
