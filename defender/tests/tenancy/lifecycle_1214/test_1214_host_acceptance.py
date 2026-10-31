"""#1214 r10.1: the process hold (A2) and the host acceptance step (A1, C3, C4, C6) seen at the hold and the step themselves.

The entry points' own refusals and recording are in `test_1214_host_entry.py` and `test_1214_host_lock.py`; the
names this file uses for what the design leaves to the implementer are in `tests/support/tenancy/_host1214.py`.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._repo import seed_repo
from defender.tests.support.shared._postgres1339 import empty_database, migrated_database  # noqa: F401 — fixtures
from defender.tests.support.tenancy import _host1214 as H
from defender.tests.support.tenancy._active1214 import (
    DSN_ENV,
    active_directory,
    active_repository,
    database_env,
    insert_active_tenant,
)
from defender.tests.support.tenancy._host1214 import exclusive_free, host_tenant, recorded, this_process

TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"
OTHER = "0b9e6d2a-41c8-4f57-8e3b-6a7d1c5f9e24"
REPO_ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture
def placed(data_root) -> Path:
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    place_tenant(data_root, TENANT)
    (data_root / TENANT / "learning").mkdir(exist_ok=True)
    return data_root


# --- the hold lasts for the scope, nesting reuses it (A2, O-A3) --------------------------------------------------

def test_a_nested_hold_keeps_the_record_until_the_outer_scope_ends(data_root):
    """Inner exit of a nested shared hold leaves this process recorded and the lock held; the outer exit releases both
    (r10 O-A3, A2; R10-3 probed the inner exit deleting the outer record)."""
    from defender.tenancy import host_lock

    with host_lock.hold_shared(data_root, TENANT):
        with host_lock.hold_shared(data_root, TENANT):
            assert recorded(data_root, TENANT) == this_process()
        assert recorded(data_root, TENANT) == this_process(), "the inner exit removed the outer scope's record"
        assert not exclusive_free(data_root, TENANT), "the inner exit released the outer scope's lock"
    assert recorded(data_root, TENANT) == []
    assert exclusive_free(data_root, TENANT)


def test_two_spellings_of_one_data_root_share_one_hold(data_root, tmp_path):
    """The table is keyed by the resolved lock folder: a symlinked spelling nested in the plain one reuses its hold,
    so the inner exit leaves the record (r10 "Data model"; O-A3)."""
    from defender.tenancy import host_lock

    link = tmp_path / "spelled-differently"
    link.symlink_to(data_root, target_is_directory=True)
    with host_lock.hold_shared(data_root, TENANT):
        with host_lock.hold_shared(link, TENANT):
            assert recorded(data_root, TENANT) == this_process()
        assert recorded(data_root, TENANT) == this_process(), "the second spelling opened a hold of its own"
        assert not exclusive_free(data_root, TENANT)
    assert recorded(data_root, TENANT) == []
    assert exclusive_free(data_root, TENANT)


def test_a_scope_in_another_thread_keeps_the_record_until_the_last_scope_leaves(data_root):
    """Two threads' scopes on one tenant share the hold; the record outlasts whichever leaves first (r10 "Data model":
    the table's lock makes the second reuse the first)."""
    from defender.tenancy import host_lock

    inside, leave = threading.Event(), threading.Event()
    failed: list[BaseException] = []

    def other() -> None:
        try:
            with host_lock.hold_shared(data_root, TENANT):
                inside.set()
                leave.wait(30)
        except BaseException as e:  # noqa: BLE001 — reported on the main thread
            failed.append(e)

    thread = threading.Thread(target=other, daemon=True)
    thread.start()
    assert inside.wait(30), f"the other thread never got its scope: {failed}"
    with host_lock.hold_shared(data_root, TENANT):
        assert recorded(data_root, TENANT) == this_process()
    assert recorded(data_root, TENANT) == this_process(), "this thread's exit removed the other thread's record"
    assert not exclusive_free(data_root, TENANT)
    leave.set()
    thread.join(30)
    assert not failed, failed
    assert recorded(data_root, TENANT) == []
    assert exclusive_free(data_root, TENANT)


# --- the host acceptance: checked at the call, released with `with` (C3, O-A2, O-A6) -----------------------------

def test_the_host_acceptance_holds_from_the_call_until_its_scope_ends(placed):
    """`host_tenant(...)` checks and holds at the call, `with admitted:` releases, and the value carries the tenant
    (r10.1 C3, O-A2)."""
    from defender import tenancy

    root = tenancy.resolve_data_root()
    admitted = host_tenant(root, TENANT, directory=active_directory(placed, TENANT))
    assert str(getattr(admitted, H.ADMITTED_TENANT).id) == TENANT
    assert recorded(placed, TENANT) == this_process(), "the acceptance did not hold at the call"
    assert not exclusive_free(placed, TENANT)
    with admitted:
        assert recorded(placed, TENANT) == this_process()
    assert recorded(placed, TENANT) == []
    assert exclusive_free(placed, TENANT)


@pytest.mark.parametrize("step", ["id grammar", "record: offboarding", "record: creating", "record: no row",
                                  "record: no wiring", "folder rules"])
def test_a_refused_acceptance_raises_at_the_call_and_releases_what_it_took(placed, step):
    """A refusal at any step raises `TenantRefused` at the call, naming the tenant, and leaves neither record nor lock
    (r10.1 C3; r10 O-A6, A1 order: id, root, hold, record, folder)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused

    root = tenancy.resolve_data_root()
    with host_tenant(root, TENANT, directory=active_directory(placed, TENANT)):
        assert recorded(placed, TENANT) == this_process(), "control: an admitted scope is recorded"
    assert recorded(placed, TENANT) == []
    bare = "7a2c4e6f-8b1d-4c3a-9e5f-0d1b2a3c4e5f"  # active in the directory, no folder under the data root
    raw, directory, named = {
        "id grammar": ("not-a-tenant-id", active_directory(placed, TENANT), "not-a-tenant-id"),
        "record: offboarding": (TENANT, active_directory(placed, TENANT, state="offboarding"), "offboarding"),
        "record: creating": (TENANT, active_directory(placed, TENANT, state="creating"), "creating"),
        "record: no row": (OTHER, active_directory(placed, TENANT), OTHER),
        "record: no wiring": (TENANT, active_directory(placed, TENANT, wiring=False), TENANT),
        "folder rules": (bare, active_directory(placed, bare), bare),
    }[step]
    with pytest.raises(TenantRefused) as refused:
        host_tenant(root, raw, directory=directory)
    assert named in str(refused.value), str(refused.value)
    assert recorded(placed, TENANT) == []
    assert exclusive_free(placed, TENANT)
    if step != "id grammar":  # the grammar is judged before any lock folder is named
        assert recorded(placed, raw) == []
        assert exclusive_free(placed, raw)


# --- the waiting line (C4, owner ruling) ------------------------------------------------------------------------

def test_an_acceptance_blocked_on_the_host_lock_waits_and_says_so_once_on_stderr(placed, capfd):
    """While prepare or teardown holds T's lock exclusive, acceptance waits (no timeout) and prints one stderr line
    naming that it waits for T's host lock; a free lock prints none (r10.1 C4, owner ruling)."""
    from defender import tenancy
    from defender.tenancy import host_lock

    root = tenancy.resolve_data_root()
    directory = active_directory(placed, TENANT)
    with host_tenant(root, TENANT, directory=directory):
        pass
    free = capfd.readouterr()
    assert not any(H.WAITING_WORDS[0] in s for s in (free.out, free.err)), "control: a free lock prints a waiting line"

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
    out = err = ""
    try:
        waiter.start()
        deadline = time.monotonic() + 20
        while not all(w in err for w in H.WAITING_WORDS) and time.monotonic() < deadline and not failed:
            got = capfd.readouterr()
            out, err = out + got.out, err + got.err
            time.sleep(0.05)
        time.sleep(1.0)  # no timeout: it is still waiting after the line
        assert not entered.is_set(), "acceptance went past an exclusive hold"
        assert waiter.is_alive(), f"acceptance gave up instead of waiting: {failed}"
    finally:
        host_lock.release_lock(fd)
    waiter.join(timeout=20)
    got = capfd.readouterr()
    out, err = out + got.out, err + got.err
    assert entered.is_set(), f"acceptance never proceeded once the lock was free: {failed}"
    lines = [line for line in err.splitlines() if all(w in line for w in H.WAITING_WORDS)]
    assert len(lines) == 1, err
    assert TENANT in lines[0]
    assert H.WAITING_WORDS[0] not in out, f"the waiting line went to stdout: {out}"


# --- a refusal at the version check releases what was taken (O-A6) ---------------------------------------------

@pytest.mark.postgres
def test_a_database_behind_is_refused_at_the_version_check_and_the_hold_and_record_are_released(
        placed, empty_database, monkeypatch):  # noqa: F811
    """The check runs after the hold is taken: a database at another revision raises `TenantRefused` naming both
    revisions and leaves neither record nor lock; at head the same call admits (r10 O-A6, A1 order)."""
    from defender import tenancy
    from defender.migrations import head, upgrade
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to
    from defender.records.formats import TenantRefused
    from defender.systems.run_tenant import RecordsUnreachable

    root = tenancy.resolve_data_root()
    monkeypatch.setenv(DSN_ENV, empty_database)
    _upgrade_to(empty_database, BASELINE)
    with pytest.raises(TenantRefused) as refused:
        host_tenant(root, TENANT)
    assert not isinstance(refused.value, RecordsUnreachable), "a revision mismatch is not a transient outage"
    assert BASELINE in str(refused.value), str(refused.value)
    assert head() in str(refused.value), str(refused.value)
    assert recorded(placed, TENANT) == [], "the refusal kept the record"
    assert exclusive_free(placed, TENANT), "the refusal kept the lock"
    upgrade(empty_database)
    insert_active_tenant(empty_database, TENANT, data_root=placed)
    with host_tenant(root, TENANT):
        assert recorded(placed, TENANT) == this_process(), "control: at head the acceptance holds"
    assert recorded(placed, TENANT) == []


@pytest.mark.postgres
def test_an_unreachable_database_is_refused_as_transient_and_the_hold_and_record_are_released(
        placed, migrated_database, monkeypatch):  # noqa: F811
    """A database nothing answers at raises `RecordsUnreachable` (a drain's transient case) and leaves neither record
    nor lock; the reachable database admits the same call (r10 O-A6, the version check step)."""
    from defender import tenancy
    from defender.systems.run_tenant import RecordsUnreachable

    root = tenancy.resolve_data_root()
    insert_active_tenant(migrated_database, TENANT, data_root=placed)
    monkeypatch.setenv(DSN_ENV, "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=3")
    with pytest.raises(RecordsUnreachable):
        host_tenant(root, TENANT)
    assert recorded(placed, TENANT) == [], "the refusal kept the record"
    assert exclusive_free(placed, TENANT), "the refusal kept the lock"
    monkeypatch.setenv(DSN_ENV, migrated_database)
    with host_tenant(root, TENANT):
        assert recorded(placed, TENANT) == this_process(), "control: the reachable database admits"


# --- one repository open per acceptance (Finding 9) ---------------------------------------------------------

def test_an_acceptance_opens_one_repository_for_its_admission_read(placed):
    """Each acceptance through a given directory opens the tenant repository once (state and wiring in one read); a
    second acceptance opens one more (r10 Finding 9; the version check is not part of it)."""
    from defender import tenancy
    from defender.tenancy import TenantDirectory

    root = tenancy.resolve_data_root()
    twin = active_repository(placed, TENANT)
    opened: list[int] = []

    def repository() -> object:
        opened.append(1)
        return twin

    directory = TenantDirectory(repository)
    with host_tenant(root, TENANT, directory=directory):
        pass
    assert len(opened) == 1, f"an acceptance opened {len(opened)} repositories"
    with host_tenant(root, TENANT, directory=directory):
        pass
    assert len(opened) == 2, f"the second acceptance opened {len(opened) - 1} repositories"


# --- the lifecycle never admits (A4, C6) -----------------------------------------------------------------------

def test_the_host_acceptance_refuses_in_a_process_marked_as_the_lifecycle(placed, monkeypatch):
    """In a process carrying the lifecycle mark the host acceptance refuses and takes nothing; unmarked it admits
    (r10.1 C6: a missed path must not deadlock prepare, which holds the lock exclusive in that process)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused

    root = tenancy.resolve_data_root()
    directory = active_directory(placed, TENANT)
    with host_tenant(root, TENANT, directory=directory):
        pass  # control: unmarked, admitted
    monkeypatch.setenv(H.LIFECYCLE_MARK, "1")
    with pytest.raises((TenantRefused, RuntimeError), match="lifecycle"):
        host_tenant(root, TENANT, directory=directory)
    assert recorded(placed, TENANT) == []
    assert exclusive_free(placed, TENANT)


def _in_a_process(placed: Path, *, as_lifecycle: bool) -> str:
    code = textwrap.dedent(f"""
        import os
        if {as_lifecycle!r}:
            from defender.lifecycle import __main__ as lifecycle
            try:
                lifecycle.main(["serve"])
            except BaseException:  # noqa: BLE001 — it refuses its missing configuration; the mark is set before
                pass
        from pathlib import Path
        from defender import tenancy
        from defender.tests.support.tenancy._active1214 import active_directory
        from defender.tests.support.tenancy._host1214 import host_tenant
        root = tenancy.resolve_data_root()
        try:
            host_tenant(root, {TENANT!r}, directory=active_directory(Path(os.environ["DEFENDER_DATA_ROOT"]), {TENANT!r}))
        except Exception as e:
            print("REFUSED", type(e).__name__, e)
        else:
            print("ADMITTED")
    """)
    env = {k: v for k, v in os.environ.items() if k not in (H.LIFECYCLE_MARK, "DEFENDER_DATABASE_DSN")}
    env |= {"PYTHONPATH": str(REPO_ROOT), "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    return done.stdout + done.stderr


def test_the_lifecycle_entry_marks_its_process_so_the_host_acceptance_refuses_there(placed):
    """After the lifecycle command's own `main` ran, a real `host_tenant` call in that process is refused; in a process
    that never ran it, the same call is admitted (r10.1 C6, A4)."""
    assert "ADMITTED" in _in_a_process(placed, as_lifecycle=False), "control"
    refused = _in_a_process(placed, as_lifecycle=True)
    assert "REFUSED" in refused, refused
    assert "lifecycle" in refused, refused


# --- the version check, once per process (Finding 9, r10 "The host acceptance step") ---------------------------

@pytest.mark.postgres
def test_the_version_check_runs_once_per_process_across_acceptances(placed, migrated_database):  # noqa: F811
    """Three acceptances through a database address check the schema revision once; each still reads the tenant's
    record (r10 Finding 9). Observed on `defender.migrations.check_version`, the light check the bridge calls."""
    insert_active_tenant(migrated_database, TENANT, data_root=placed)
    code = textwrap.dedent(f"""
        from defender import migrations, tenancy
        counted = []
        real = migrations.check_version
        migrations.check_version = lambda dsn: (counted.append(dsn), real(dsn))[1]
        from defender.tests.support.tenancy._host1214 import host_tenant
        root = tenancy.resolve_data_root()
        for _ in range(3):
            with host_tenant(root, {TENANT!r}):
                pass
        print("CHECKS", len(counted))
    """)
    env = {**os.environ, **database_env(migrated_database), "PYTHONPATH": str(REPO_ROOT),
           "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    assert "CHECKS 1" in done.stdout, done.stdout + done.stderr


# --- the starter-covered set needs no hold and no database (A3, O-A4) ------------------------------------------

class _WiringReads:
    """A directory that records the tenants whose forge wiring the publish child asked for."""

    def __init__(self, inner: object) -> None:
        self.inner, self.wiring_reads = inner, []

    def forge_wiring(self, tenant_id: str) -> object:
        self.wiring_reads.append(tenant_id)
        return self.inner.forge_wiring(tenant_id)  # type: ignore[attr-defined]

    def __getattr__(self, name: str) -> object:
        return getattr(self.inner, name)


def test_the_publish_child_works_under_an_exclusive_hold_where_the_host_acceptance_waits(placed):
    """With T's lock held exclusive (prepare's), the publish child still gets past acceptance for a `creating` tenant
    to its wiring read and reports what an `active` tenant's child reports, while the host acceptance on the same lock
    blocks (r10 A3, O-A4; the control shows the hold bites)."""
    from defender import tenancy
    from defender.learning.author import version_control as vc
    from defender.tenancy import host_lock

    root = tenancy.resolve_data_root()
    seed_repo(placed / TENANT / "knowledge")  # a real git repository, as a tenant's clone is
    active = _WiringReads(active_directory(placed, TENANT))
    control = vc.publish_for_run(TENANT, data_root=placed, directory=active, budget=5.0)
    assert active.wiring_reads == [TENANT], f"control: the active tenant's child never read its wiring: {control}"
    creating = _WiringReads(active_directory(placed, TENANT, state="creating"))
    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    lines: list[str] = []
    gate = threading.Event()

    def publish() -> None:
        lines.append(vc.publish_for_run(TENANT, data_root=placed, directory=creating, budget=5.0))

    def accept() -> None:
        with host_tenant(root, TENANT, directory=active_directory(placed, TENANT)):
            gate.set()

    child = threading.Thread(target=publish, daemon=True)
    waiter = threading.Thread(target=accept, daemon=True)
    try:
        child.start()
        waiter.start()
        child.join(60)
        assert not child.is_alive(), "the publish child waited for the exclusive hold"
        assert waiter.is_alive(), "control: the host acceptance gave up on an exclusive hold"
        assert not gate.is_set(), "control: the host acceptance went past an exclusive hold"
    finally:
        host_lock.release_lock(fd)
    waiter.join(30)
    assert gate.is_set()
    [line] = lines
    assert creating.wiring_reads == [TENANT], f"the child of a creating tenant never reached its wiring read: {line}"
    assert "was not accepted" not in line, line
    assert not any(w in line.lower() for w in ("creating", "offboarding", "not active")), line
    assert line == control, "a creating tenant's child reported differently from an active tenant's"
