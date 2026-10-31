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
    """While prepare or teardown holds T's lock exclusive, acceptance waits (no timeout) and prints one stderr line, before
    the lock is free, naming that it waits for T's host lock; a free lock prints none (r10.1 C4, C11)."""
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
        assert all(w in err for w in H.WAITING_WORDS), f"no waiting line on stderr while the lock is still held: {err!r}"
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

def _accept_in_a_process(placed: Path, dsn: str) -> str:
    """One `host_tenant` acceptance of T in a fresh process against `dsn`, printing what it raised or `ADMITTED`, and the
    hold as that process sees it before exiting (an exit drops any lock; the check runs once per process)."""
    code = textwrap.dedent(f"""
        import os
        from pathlib import Path
        from defender import tenancy
        from defender.records.formats import TenantRefused
        from defender.tests.support.tenancy._host1214 import exclusive_free, host_tenant, recorded, this_process
        from defender.systems.run_tenant import RecordsUnreachable
        placed = Path(os.environ["DEFENDER_DATA_ROOT"])
        root = tenancy.resolve_data_root()
        try:
            with host_tenant(root, {TENANT!r}):
                print("ADMITTED HELD", recorded(placed, {TENANT!r}) == this_process())
        except Exception as failed:
            print("RAISED refusal", isinstance(failed, TenantRefused), "transient",
                  isinstance(failed, RecordsUnreachable), failed)
            print("AFTER-REFUSAL recorded", recorded(placed, {TENANT!r}), "free", exclusive_free(placed, {TENANT!r}))
    """)
    env = {k: v for k, v in os.environ.items() if k not in (H.LIFECYCLE_MARK, DSN_ENV)}
    env |= {**database_env(dsn), "PYTHONPATH": str(REPO_ROOT), "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    return done.stdout + done.stderr


@pytest.mark.postgres
def test_a_database_behind_is_refused_at_the_version_check_and_the_hold_and_record_are_released(
        placed, empty_database):  # noqa: F811
    """The check runs after the hold is taken: a database at another revision raises `TenantRefused` naming both
    revisions and leaves neither record nor lock; at head the same call admits (r10 O-A6, A1 order). Each acceptance is
    its own process: the check runs once per process."""
    from defender.migrations import head, upgrade
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to

    _upgrade_to(empty_database, BASELINE)
    refused = _accept_in_a_process(placed, empty_database)
    assert "RAISED refusal True transient False" in refused, (
        f"a revision mismatch is a refusal, not a transient outage: {refused}")
    assert BASELINE in refused, refused
    assert head() in refused, refused
    assert "AFTER-REFUSAL recorded [] free True" in refused, f"the refusal kept the record or the lock: {refused}"
    upgrade(empty_database)
    insert_active_tenant(empty_database, TENANT, data_root=placed)
    admitted = _accept_in_a_process(placed, empty_database)
    assert "ADMITTED HELD True" in admitted, f"control: at head the acceptance holds: {admitted}"


@pytest.mark.postgres
def test_an_unreachable_database_is_refused_as_transient_and_the_hold_and_record_are_released(
        placed, migrated_database):  # noqa: F811
    """A database nothing answers at raises `RecordsUnreachable` (a drain's transient case) and leaves neither record
    nor lock; the reachable database admits the same call (r10 O-A6, the version check step). Each acceptance is its own
    process: the check runs once per process."""
    insert_active_tenant(migrated_database, TENANT, data_root=placed)
    dead = "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=3"
    refused = _accept_in_a_process(placed, dead)
    assert "RAISED refusal True transient True" in refused, refused
    assert "AFTER-REFUSAL recorded [] free True" in refused, f"the refusal kept the record or the lock: {refused}"
    admitted = _accept_in_a_process(placed, migrated_database)
    assert "ADMITTED HELD True" in admitted, f"control: the reachable database admits and holds: {admitted}"


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
    # budget=None on both: the creating child runs in a thread, where the deadline's signal handler cannot be set, so a
    # budget would put "signal only works in main thread" in its line alone. A closed port is the fast-failing origin.
    origin = "http://127.0.0.1:1/x.git"
    active = _WiringReads(active_directory(placed, TENANT, origin=origin))
    control = vc.publish_for_run(TENANT, data_root=placed, directory=active, budget=None)
    assert active.wiring_reads == [TENANT], f"control: the active tenant's child never read its wiring: {control}"
    creating = _WiringReads(active_directory(placed, TENANT, state="creating", origin=origin))
    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    lines: list[str] = []
    gate = threading.Event()

    def publish() -> None:
        lines.append(vc.publish_for_run(TENANT, data_root=placed, directory=creating, budget=None))

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


# --- repair round 1: the order, the line, the mark and the record seen at their boundaries ----------------------

def _blocked_accept(root: object, directory: object = None) -> tuple[threading.Thread, list[BaseException], threading.Event]:
    """`host_tenant` for T in a thread: the thread, what it raised, and the event set once it is admitted."""
    admitted, failed = threading.Event(), []  # type: tuple[threading.Event, list[BaseException]]

    def accept() -> None:
        try:
            with host_tenant(root, TENANT, directory=directory):
                admitted.set()
        except BaseException as e:  # noqa: BLE001 — reported on the main thread
            failed.append(e)

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    return thread, failed, admitted


@pytest.mark.postgres
def test_a_database_behind_is_refused_again_by_every_acceptance_in_the_process(placed, empty_database):  # noqa: F811
    """A failed version check is not remembered: a second acceptance in the same process against a database still behind
    checks again and is refused again (r10.3 C12: the check is remembered once it passes)."""
    from defender.tests.migrations.test_1214_migrations import BASELINE, _upgrade_to

    _upgrade_to(empty_database, BASELINE)
    code = textwrap.dedent(f"""
        from defender import migrations, tenancy
        from defender.records.formats import TenantRefused
        counted = []
        real = migrations.check_version
        migrations.check_version = lambda dsn: (counted.append(dsn), real(dsn))[1]
        from defender.tests.support.tenancy._host1214 import host_tenant
        root = tenancy.resolve_data_root()
        for attempt in range(2):
            try:
                with host_tenant(root, {TENANT!r}):
                    print("ADMITTED", attempt)
            except TenantRefused:
                print("REFUSED", attempt)
        print("CHECKS", len(counted))
    """)
    env = {**os.environ, **database_env(empty_database), "PYTHONPATH": str(REPO_ROOT), "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "REFUSED 0" in out, out
    assert "REFUSED 1" in out, out
    assert "ADMITTED" not in out, out
    assert "CHECKS 2" in out, out


def test_the_version_check_waits_for_the_hold_where_the_lock_is_exclusive(placed, monkeypatch):
    """With T's lock held exclusive, an acceptance against an unreachable database waits for the lock and is recorded; only
    once the lock is free does it reach the check and raise (r10 A1 order: hold, then version check)."""
    from defender import tenancy
    from defender.systems.run_tenant import RecordsUnreachable
    from defender.tenancy import host_lock

    monkeypatch.setenv(DSN_ENV, "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=3")
    root = tenancy.resolve_data_root()
    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    try:
        thread, failed, _ = _blocked_accept(root)
        thread.join(1.5)
        assert not failed, f"the version check ran before the hold was taken: {failed}"
        assert thread.is_alive(), "the acceptance ended while the lock was held exclusive"
        assert recorded(placed, TENANT) == this_process(), "the waiting acceptance is not recorded for teardown"
    finally:
        host_lock.release_lock(fd)
    thread.join(30)
    assert [type(e) for e in failed] == [RecordsUnreachable], failed


def test_the_waiting_line_is_the_holds_own_one_line_on_stderr(placed, capfd):
    """`hold_shared` itself prints one waiting line to stderr, before the lock is free, when it is held exclusive and none
    when it is free (r10.1 C4: the hold prints it, a separate probe would race)."""
    from defender.tenancy import host_lock

    with host_lock.hold_shared(placed, TENANT):
        pass
    free = capfd.readouterr()
    assert H.WAITING_WORDS[0] not in free.out + free.err, f"control: a free lock printed {free}"
    admitted = threading.Event()

    def enter() -> None:
        with host_lock.hold_shared(placed, TENANT):
            admitted.set()

    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    waiter = threading.Thread(target=enter, daemon=True)
    try:
        waiter.start()
        time.sleep(1.0)
        assert not admitted.is_set()
        during = capfd.readouterr()  # read while the lock is still held: the line comes before the wait
        assert all(w in during.err for w in H.WAITING_WORDS), f"no waiting line while the lock was held: {during.err!r}"
    finally:
        host_lock.release_lock(fd)
    waiter.join(20)
    assert admitted.is_set()
    after = capfd.readouterr()
    err, out = during.err + after.err, during.out + after.out
    lines = [line for line in err.splitlines() if all(w in line for w in H.WAITING_WORDS)]
    assert len(lines) == 1, err
    assert TENANT in lines[0], err
    assert out == ""


def test_the_lifecycle_mark_is_judged_before_the_lock_is_waited_for(placed, monkeypatch):
    """In a marked process the acceptance refuses at once even while the lock is held exclusive; it does not wait for
    the lock it would deadlock on (r10.1 C6, A4)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused
    from defender.tenancy import host_lock

    monkeypatch.setenv(H.LIFECYCLE_MARK, "1")
    root = tenancy.resolve_data_root()
    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    try:
        thread, failed, admitted = _blocked_accept(root, active_directory(placed, TENANT))
        thread.join(5)
        assert not thread.is_alive(), "a marked process waited for the lock instead of refusing"
        assert not admitted.is_set()
        assert [type(e) for e in failed] == [TenantRefused], failed
        assert recorded(placed, TENANT) == []
    finally:
        host_lock.release_lock(fd)


def test_a_forked_child_does_not_inherit_its_parents_hold(placed):
    """A child forked inside an open scope that enters its own scope is recorded under its own pid: the hold table is
    keyed by process (r10 O-A2; the child's record is what teardown signals)."""
    from defender.tenancy import host_lock

    read, write = os.pipe()
    with host_lock.hold_shared(placed, TENANT):
        child = os.fork()
        if child == 0:  # pragma: no cover — runs in the forked child, which leaves through os._exit
            status = 1
            try:
                os.close(read)
                with host_lock.hold_shared(placed, TENANT):
                    pids = sorted(h.pid for h in host_lock.holders(placed, TENANT))
                os.write(write, (",".join(map(str, pids))).encode())
                status = 0
            finally:
                os._exit(status)
        os.close(write)
        with os.fdopen(read) as reader:
            seen = reader.read()
        _, wait = os.waitpid(child, 0)
    assert wait == 0, f"the forked child failed (status {wait})"
    pids = [int(p) for p in seen.split(",") if p]
    assert child in pids, f"the child entered a scope but was not recorded: {pids} (child {child})"
    assert os.getpid() in pids


def test_a_scope_entered_while_the_last_one_leaves_is_still_recorded(placed):
    """A scope that enters while the last exit is giving the lock back waits for it and is recorded afterwards; the
    exit's removal does not take the newcomer's record with it (r10 O-A3: the last exit is gated against entering)."""
    from defender.tenancy import host_lock
    from defender.tests.support.tenancy._calls1214 import watching

    leaving, proceed, entered, quit_ = (threading.Event() for _ in range(4))
    errors: list[BaseException] = []

    def first() -> None:
        try:
            with host_lock.hold_shared(placed, TENANT):
                pass  # the exit is watched below: it stops at the lock's release
        except BaseException as e:  # noqa: BLE001 — reported on the main thread
            errors.append(e)

    def second() -> None:
        try:
            with host_lock.hold_shared(placed, TENANT):
                entered.set()
                quit_.wait(30)
        except BaseException as e:  # noqa: BLE001 — reported on the main thread
            errors.append(e)

    def release_held(_args: dict) -> None:
        if threading.current_thread().name == "first":
            leaving.set()
            proceed.wait(30)

    with watching(host_lock.release_lock, release_held):
        a = threading.Thread(target=first, name="first", daemon=True)
        a.start()
        assert leaving.wait(30), "the last exit never reached the lock's release"
        b = threading.Thread(target=second, name="second", daemon=True)
        b.start()
        entered.wait(1.0)  # honest: still waiting on the exit; a racing entry gets in here
        proceed.set()
        a.join(30)
        assert entered.wait(30), f"the second scope never entered: {errors}"
        try:
            assert recorded(placed, TENANT) == this_process(), "the last exit removed the newcomer's record"
            assert not exclusive_free(placed, TENANT)
        finally:
            quit_.set()
            b.join(30)
    assert not errors, errors
    assert recorded(placed, TENANT) == []
    assert exclusive_free(placed, TENANT)


@pytest.mark.parametrize("exit_", [SystemExit, KeyboardInterrupt], ids=["SystemExit", "KeyboardInterrupt"])
def test_an_exit_from_the_admission_step_releases_the_hold_and_the_record(placed, exit_):
    """`SystemExit` or `KeyboardInterrupt` out of the records read releases the hold and the record before the exception
    is handled (r10 O-A6: a refused acceptance releases whatever it took)."""
    from defender import tenancy
    from defender.tenancy import TenantDirectory

    class Leaving(TenantDirectory):
        def __init__(self) -> None:
            super().__init__(lambda: None)

        def admission(self, tenant_id: str) -> object:
            raise exit_()

    root = tenancy.resolve_data_root()
    with pytest.raises(exit_) as caught:  # kept: its traceback keeps the acceptance's frame alive, as a handler's would
        host_tenant(root, TENANT, directory=Leaving())
    assert recorded(placed, TENANT) == [], "the exit left this process recorded"
    assert exclusive_free(placed, TENANT), "the exit left the lock held"
    assert caught.value is not None


def test_an_interrupt_while_waiting_for_the_lock_removes_the_record(placed):
    """A `KeyboardInterrupt` that arrives while a scope waits for the lock leaves no record behind (r10 O-A6)."""
    from defender.tenancy import host_lock

    code = textwrap.dedent(f"""
        import os, signal
        from pathlib import Path
        from defender.tenancy import host_lock
        from defender.tests.support.tenancy._host1214 import recorded
        placed = Path(os.environ["DEFENDER_DATA_ROOT"])
        def interrupt(*_):
            raise KeyboardInterrupt
        signal.signal(signal.SIGALRM, interrupt)
        signal.setitimer(signal.ITIMER_REAL, 1.0)
        try:
            with host_lock.hold_shared(placed, {TENANT!r}):
                print("ENTERED")
        except KeyboardInterrupt:
            print("INTERRUPTED recorded", recorded(placed, {TENANT!r}))
    """)
    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    try:
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), "DEFENDER_DATA_ROOT": str(placed)}
        done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                              timeout=60, check=False)
    finally:
        host_lock.release_lock(fd)
    assert "INTERRUPTED recorded []" in done.stdout, done.stdout + done.stderr


def test_a_waiter_is_recorded_while_the_lock_is_held_exclusive(placed):
    """A scope blocked on an exclusive hold is already in the registry, so teardown (which holds the lock) can see and
    signal it (r10 O-A2: a process records itself before it takes the lock)."""
    from defender.tenancy import host_lock

    admitted = threading.Event()

    def enter() -> None:
        with host_lock.hold_shared(placed, TENANT):
            admitted.set()

    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    waiter = threading.Thread(target=enter, daemon=True)
    try:
        waiter.start()
        deadline = time.monotonic() + 10
        while recorded(placed, TENANT) != this_process() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert recorded(placed, TENANT) == this_process(), "a waiting scope was invisible to the holder of the lock"
        assert not admitted.is_set()
    finally:
        host_lock.release_lock(fd)
    waiter.join(20)
    assert admitted.is_set()


def test_the_wait_for_the_lock_has_no_timeout(placed):
    """Once the first try fails, the hold waits for the lock with no timeout (r10.1 C11, owner ruling). Mechanism pin:
    the timeouts `acquire` is called with; the practical observation is the clock test below."""
    from defender.tenancy import host_lock
    from defender.tests.support.tenancy._calls1214 import watching

    timeouts: list[object] = []
    admitted = threading.Event()

    def enter() -> None:
        with host_lock.hold_shared(placed, TENANT):
            admitted.set()

    fd = host_lock.acquire(placed, TENANT, exclusive=True, timeout=0)
    assert fd is not None
    with watching(host_lock.acquire, lambda args: timeouts.append(args["timeout"])):
        waiter = threading.Thread(target=enter, daemon=True)
        try:
            waiter.start()
            time.sleep(1.0)
        finally:
            host_lock.release_lock(fd)
        waiter.join(20)
    assert admitted.is_set()
    assert timeouts[-1] is None, f"the wait is bounded: {timeouts}"
    assert all(t in (0, None) for t in timeouts), f"the wait is bounded: {timeouts}"


@pytest.mark.postgres
def test_a_wiring_less_tenant_in_the_database_is_refused_at_acceptance(placed, migrated_database):  # noqa: F811
    """An active tenant whose forge wiring was never recorded is refused by the host acceptance over the real database,
    naming the tenant; with wiring the same call admits (r10 A1 step 4: wiring is read, never invented)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused
    from defender.tests.support.tenancy._active1214 import postgres_directory

    root = tenancy.resolve_data_root()
    insert_active_tenant(migrated_database, TENANT, data_root=placed, wiring=False)
    with pytest.raises(TenantRefused) as refused:
        host_tenant(root, TENANT, directory=postgres_directory(migrated_database))
    assert TENANT in str(refused.value), str(refused.value)
    assert recorded(placed, TENANT) == []
    assert exclusive_free(placed, TENANT)
    from defender.tests.support.tenancy._tenants1106 import place_tenant

    place_tenant(placed, OTHER)
    (placed / OTHER / "learning").mkdir(exist_ok=True)
    insert_active_tenant(migrated_database, OTHER, data_root=placed)
    with host_tenant(root, OTHER, directory=postgres_directory(migrated_database)):
        pass  # control: with wiring recorded the database admits


# --- repair round 2: the wait without a bound, the check after an outage, holds side by side, exits ---------------

def test_the_wait_for_the_lock_outlasts_any_clock_jump(placed):
    """`acquire(timeout=None)` is still waiting after the clock has jumped a day per reading, and takes the lock once it is
    free (r10.3 C11: no timeout of any size). The clock is replaced in a child process only."""
    code = textwrap.dedent(f"""
        import os, threading, time
        from pathlib import Path
        from defender.tenancy import host_lock
        placed = Path(os.environ["DEFENDER_DATA_ROOT"])
        held = host_lock.acquire(placed, {TENANT!r}, exclusive=True, timeout=0)
        real, begun, readings = time.monotonic, time.monotonic(), []
        def leaping():
            readings.append(1)
            return begun + 86400.0 * len(readings)
        time.monotonic = leaping
        got = []
        waiter = threading.Thread(target=lambda: got.append(host_lock.acquire(placed, {TENANT!r}, exclusive=False,
                                                                              timeout=None)), daemon=True)
        waiter.start()
        waiter.join(1.5)
        print("STILL-WAITING", waiter.is_alive(), "GAVE-UP", got)
        time.monotonic = real
        host_lock.release_lock(held)
        waiter.join(20)
        print("TOOK-IT", bool(got) and got[0] is not None)
    """)
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT), "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=60, check=False)
    out = done.stdout + done.stderr
    assert "STILL-WAITING True GAVE-UP []" in out, out
    assert "TOOK-IT True" in out, out


def test_an_unreachable_check_is_not_remembered_and_the_next_acceptance_checks_and_refuses(placed):
    """In one process the first acceptance meets an unreachable database (transient), the second a database behind: the
    second runs the check again and is refused as a revision mismatch, not admitted (r10.3 C12). The check is the
    light one `defender.migrations.check_version`, replaced in the child process only."""
    code = textwrap.dedent(f"""
        from defender import migrations, tenancy
        from defender.records.formats import TenantRefused
        from defender.systems.run_tenant import RecordsUnreachable
        answers = [migrations.DatabaseUnreachable("down"), migrations.RevisionMismatch("old", "new")]
        counted = []
        def check(dsn):
            counted.append(dsn)
            raise answers[len(counted) - 1] if len(counted) <= len(answers) else AssertionError("a third check")
        migrations.check_version = check
        from defender.tests.support.tenancy._host1214 import host_tenant
        root = tenancy.resolve_data_root()
        for attempt in range(2):
            try:
                with host_tenant(root, {TENANT!r}):
                    print("ADMITTED", attempt)
            except RecordsUnreachable:
                print("TRANSIENT", attempt)
            except TenantRefused as refused:
                print("REFUSED", attempt, "behind" if "new" in str(refused) else str(refused))
        print("CHECKS", len(counted))
    """)
    env = {**os.environ, DSN_ENV: "postgresql://nobody:nothing@127.0.0.1:1/none", "PYTHONPATH": str(REPO_ROOT),
           "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "TRANSIENT 0" in out, out
    assert "REFUSED 1 behind" in out, out
    assert "ADMITTED" not in out, out
    assert "CHECKS 2" in out, out


def test_two_tenants_held_at_once_are_each_recorded_and_locked_under_their_own_tenant(placed):
    """Holds of two tenants in one process are independent: each is recorded and locked, and the exit of one leaves the
    other's record and lock (r10 "Data model": the table is keyed by the tenant's lock folder)."""
    from defender.tenancy import host_lock

    with host_lock.hold_shared(placed, TENANT):
        with host_lock.hold_shared(placed, OTHER):
            for tenant in (TENANT, OTHER):
                assert recorded(placed, tenant) == this_process(), f"{tenant} not recorded"
                assert not exclusive_free(placed, tenant), f"{tenant} not locked"
        assert recorded(placed, OTHER) == [] and exclusive_free(placed, OTHER), "the inner tenant's hold outlived its scope"
        assert recorded(placed, TENANT) == this_process(), "the inner exit removed the other tenant's record"
        assert not exclusive_free(placed, TENANT), "the inner exit released the other tenant's lock"
    for tenant in (TENANT, OTHER):
        assert recorded(placed, tenant) == [] and exclusive_free(placed, tenant)


def test_two_tenants_held_by_the_outer_scope_leave_the_other_when_the_first_exits(placed):
    """With two tenants' scopes open, the exit of the one entered first (its scope ended while the other's stays open in
    another thread) leaves the other tenant recorded and locked (r10 "Data model": one entry per tenant)."""
    from defender.tenancy import host_lock

    inside, leave = threading.Event(), threading.Event()

    def other() -> None:
        with host_lock.hold_shared(placed, OTHER):
            inside.set()
            leave.wait(30)

    thread = threading.Thread(target=other, daemon=True)
    thread.start()
    assert inside.wait(30)
    try:
        with host_lock.hold_shared(placed, TENANT):
            assert recorded(placed, TENANT) == this_process()
        assert recorded(placed, TENANT) == [] and exclusive_free(placed, TENANT)
        assert recorded(placed, OTHER) == this_process(), "one tenant's exit removed the other tenant's record"
        assert not exclusive_free(placed, OTHER), "one tenant's exit released the other tenant's lock"
    finally:
        leave.set()
        thread.join(30)
    assert recorded(placed, OTHER) == [] and exclusive_free(placed, OTHER)


def test_one_tenant_held_under_two_data_roots_has_a_hold_under_each(placed, tmp_path):
    """The same tenant id held under two data roots at once is recorded and locked under each root; one root's exit leaves
    the other's (r10 "Data model": keyed by the tenant's resolved lock folder, so roots do not meet)."""
    from defender.tenancy import host_lock

    second = tmp_path / "second-data-root"
    second.mkdir()
    with host_lock.hold_shared(placed, TENANT):
        with host_lock.hold_shared(second, TENANT):
            for root in (placed, second):
                assert recorded(root, TENANT) == this_process(), f"not recorded under {root}"
                assert not exclusive_free(root, TENANT), f"not locked under {root}"
        assert recorded(second, TENANT) == [] and exclusive_free(second, TENANT), "the second root's hold outlived its scope"
        assert recorded(placed, TENANT) == this_process(), "the second root's exit removed the first root's record"
        assert not exclusive_free(placed, TENANT)
    assert recorded(placed, TENANT) == [] and exclusive_free(placed, TENANT)


def test_an_exception_raised_in_a_direct_hold_releases_the_record_and_the_lock(placed):
    """An error raised inside `with hold_shared(...)` leaves no record and no lock behind (r10 O-A6: the scope's end
    releases whatever it took, however it ends)."""
    from defender.tenancy import host_lock

    with pytest.raises(RuntimeError, match="boom"), host_lock.hold_shared(placed, TENANT):
        assert recorded(placed, TENANT) == this_process(), "control: recorded inside the scope"
        raise RuntimeError("boom")
    assert recorded(placed, TENANT) == [], "the error left this process recorded"
    assert exclusive_free(placed, TENANT), "the error left the lock held"


@pytest.mark.parametrize("step", ["record: offboarding", "folder rules"])
def test_a_refused_acceptance_inside_an_open_hold_leaves_the_outer_scope_to_release_everything(placed, step):
    """A refused acceptance nested in an open hold of the same tenant takes nothing it keeps: after the outer scope ends the
    record and the lock are gone (r10 O-A6, A2: a refusal releases its own scope only, and does not leak one)."""
    from defender import tenancy
    from defender.records.formats import TenantRefused
    from defender.tenancy import host_lock

    root = tenancy.resolve_data_root()
    bare = "7a2c4e6f-8b1d-4c3a-9e5f-0d1b2a3c4e5f"
    refusing = {"record: offboarding": (TENANT, active_directory(placed, TENANT, state="offboarding")),
                "folder rules": (bare, active_directory(placed, bare))}[step]
    raw, directory = refusing
    with host_lock.hold_shared(placed, raw):
        with pytest.raises(TenantRefused) as refused:  # kept: its traceback keeps the acceptance's frame alive
            host_tenant(root, raw, directory=directory)
        assert recorded(placed, raw) == this_process(), "the refusal removed the outer scope's record"
    assert recorded(placed, raw) == [], "the refused acceptance leaked a scope: the record outlived the outer exit"
    assert exclusive_free(placed, raw), "the refused acceptance leaked a scope: the lock outlived the outer exit"
    assert refused.value is not None


@pytest.mark.parametrize("exit_", [SystemExit, KeyboardInterrupt], ids=["SystemExit", "KeyboardInterrupt"])
def test_an_exit_from_the_folder_rules_step_releases_the_hold_and_the_record(placed, exit_):
    """`SystemExit` or `KeyboardInterrupt` raised while the folder rules run (the mounts they iterate) releases the hold and
    the record, the exception kept alive (r10 O-A6)."""
    from defender import tenancy

    def mounts():
        raise exit_()
        yield  # pragma: no cover — makes this a generator, raising when the folder rules iterate it

    root = tenancy.resolve_data_root()
    with host_tenant(root, TENANT, directory=active_directory(placed, TENANT), box_mounted=()):
        pass  # control: the same call with nothing to iterate admits
    with pytest.raises(exit_) as caught:
        host_tenant(root, TENANT, directory=active_directory(placed, TENANT), box_mounted=mounts())
    assert recorded(placed, TENANT) == [], "the exit left this process recorded"
    assert exclusive_free(placed, TENANT), "the exit left the lock held"
    assert caught.value is not None


@pytest.mark.parametrize("exit_", ["SystemExit", "KeyboardInterrupt"])
def test_an_exit_from_the_version_check_step_releases_the_hold_and_the_record(placed, exit_):
    """`SystemExit` or `KeyboardInterrupt` raised by the version check releases the hold and the record, the exception kept
    alive (r10 O-A6). The check is `defender.migrations.check_version`, replaced in the child process only."""
    code = textwrap.dedent(f"""
        import os
        from pathlib import Path
        from defender import migrations, tenancy
        from defender.tests.support.tenancy._host1214 import exclusive_free, host_tenant, recorded
        def check(dsn):
            raise {exit_}()
        migrations.check_version = check
        placed = Path(os.environ["DEFENDER_DATA_ROOT"])
        root = tenancy.resolve_data_root()
        try:
            host_tenant(root, {TENANT!r})
        except {exit_} as kept:
            print("EXIT recorded", recorded(placed, {TENANT!r}), "free", exclusive_free(placed, {TENANT!r}))
    """)
    env = {**os.environ, DSN_ENV: "postgresql://nobody:nothing@127.0.0.1:1/none", "PYTHONPATH": str(REPO_ROOT),
           "DEFENDER_DATA_ROOT": str(placed)}
    done = subprocess.run([sys.executable, "-c", code], env=env, cwd=REPO_ROOT, capture_output=True, text=True,  # noqa: S603
                          timeout=120, check=False)
    assert "EXIT recorded [] free True" in done.stdout, done.stdout + done.stderr


def test_the_admitted_value_carries_the_recorded_wiring_and_the_directory_it_was_admitted_through(placed):
    """The admitted value's wiring is the recorded repo and origin, and its directory is the very one handed in
    (r10 A1, "the host acceptance step": `admitted` carries the Tenant, the directory and the forge wiring)."""
    from defender import tenancy

    root = tenancy.resolve_data_root()
    origin = "http://forge.test/elsewhere/special.git"
    directory = active_directory(placed, TENANT, repo="tenants/special", origin=origin)
    recorded_wiring = directory.forge_wiring(TENANT)
    assert (recorded_wiring.repo, recorded_wiring.origin) == ("tenants/special", origin), "control: the seed's wiring"
    with host_tenant(root, TENANT, directory=directory) as admitted:
        wiring = getattr(admitted, H.ADMITTED_WIRING)
        assert (wiring.repo, wiring.origin) == ("tenants/special", origin)
        assert getattr(admitted, H.ADMITTED_DIRECTORY) is directory


@pytest.mark.postgres
def test_an_acceptance_with_no_directory_handed_in_carries_a_usable_directory(placed, migrated_database, monkeypatch):  # noqa: F811
    """With no directory handed in, the admitted value's directory is the database-backed one the acceptance read through:
    it answers the tenant's state and wiring (r10 A1: `admitted` carries the directory for the drain's per-claim check)."""
    from defender import tenancy

    insert_active_tenant(migrated_database, TENANT, data_root=placed, repo="tenants/pg", origin="http://forge.test/pg.git")
    monkeypatch.setenv(DSN_ENV, migrated_database)
    root = tenancy.resolve_data_root()
    with host_tenant(root, TENANT) as admitted:
        directory = getattr(admitted, H.ADMITTED_DIRECTORY)
        assert directory is not None, "no directory was carried"
        assert directory.state(TENANT) == "active"
        wiring = directory.forge_wiring(TENANT)
        assert (wiring.repo, wiring.origin) == ("tenants/pg", "http://forge.test/pg.git")
        assert (getattr(admitted, H.ADMITTED_WIRING).origin) == "http://forge.test/pg.git"


def test_watching_puts_back_the_earlier_profile_hooks_and_a_thread_started_inside_stops_reporting():
    """After a `watching` block the profile hooks are the ones in place before it, and a thread started inside, which keeps
    its hook, reports nothing of a call made after the block (test support: a watcher leaves no trace)."""
    from defender.tests.support.tenancy._calls1214 import watching

    def target(value: int) -> int:
        return value

    seen: list[int] = []
    before = (sys.getprofile(), threading.getprofile())
    started, go, done = threading.Event(), threading.Event(), threading.Event()

    def worker() -> None:
        target(1)  # inside the block: reported
        started.set()
        go.wait(30)
        target(2)  # after the block: not reported
        done.set()

    with watching(target, lambda args: seen.append(args["value"])):
        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        assert started.wait(30)
        target(3)
    assert (sys.getprofile(), threading.getprofile()) == before, "the earlier profile hooks were not put back"
    go.set()
    assert done.wait(30)
    thread.join(30)
    assert sorted(seen) == [1, 3], seen
