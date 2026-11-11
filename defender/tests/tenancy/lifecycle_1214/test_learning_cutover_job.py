# ruff: noqa: PT018
"""#1278 Migration, RULED: the import and cutover of a tenant's file learning state is a lifecycle job per tenant
(the existing job machinery, like credential rotation), not an operator command. Interface requests: `_cutover_job`.
"""
from __future__ import annotations

import pytest

from defender.tenancy import Conflict, NotFound, host_lock
from defender.tests.support.learning.core import _legacy1278 as legacy
from defender.tests.support.learning.core._store1278 import files_under, finding
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.lifecycle_1214._cutover_job import ACTION, CutoverWorld
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant, second_tenant

pytestmark = pytest.mark.postgres


@pytest.fixture
def cw(tmp_path, data_root, migrated_database, monkeypatch):  # noqa: F811 — the imported fixture
    w = CutoverWorld(tmp_path, data_root, migrated_database, monkeypatch, teardown_wait=0.2)
    yield w
    w.close()


@pytest.fixture
def blue(cw, tmp_path, data_root):
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        yield cw.add(t)


def _store_view(w):
    from defender.learning.store import blocking

    with blocking(w.dsn) as store:
        return ({(i.kind, i.key): i.status for i in store.work(w.tid)}, len(store.batches(w.tid)),
                len(store.commit_record(w.tid)))


def _plant(w):
    legacy.queue(w.root, "finding", [finding("f1"), finding("f2")])
    legacy.consumed(w.root, "finding", [finding("c1")], "consumed_committed")
    legacy.leftovers(w.root, trace=b"trace", worktree=b"draft")


def test_job_imports_the_tenants_state_then_removes_the_learning_folder_and_returns_the_tenant_to_idle(cw, blue):
    """One job: the rows are in the store, the folder is gone, the tenant is active with nothing pending. (Migration)"""
    _plant(blue)
    cw.request(blue.tid)
    assert cw.run() == 2, "import then cutover"
    assert _store_view(blue)[0] == {("finding", "f1"): "waiting", ("finding", "f2"): "waiting",
                                   ("finding", "c1"): "published"}
    assert not blue.root.exists()
    record = cw.record(blue.tid)
    assert (record.state, record.pending_action, record.step, record.failure) == ("active", None, None, None)


def test_the_job_is_requested_only_for_an_active_tenant_with_nothing_pending(cw, blue):
    """Like rotation: an unknown tenant is NotFound; a second request while one is pending is a Conflict, row unchanged."""
    with pytest.raises(NotFound):
        cw.request("00000000-0000-4000-8000-000000000000")
    first = cw.request(blue.tid)
    assert first.pending_action == ACTION
    before = cw.record(blue.tid)
    with pytest.raises(Conflict):
        cw.request(blue.tid)
    assert cw.record(blue.tid) == before


@pytest.mark.parametrize("how", ["unknown ledger category", "NUL character", "store unreachable"])
def test_a_record_the_import_refuses_fails_the_job_at_import_naming_it_and_nothing_is_written_or_deleted(
        cw, blue, monkeypatch, how):
    """Refused or faulted import: failure recorded at `import` naming the record; no rows; every file byte-identical. (G-I10)"""
    legacy.queue(blue.root, "finding", [finding("f1")])
    legacy.consumed(blue.root, "finding", [finding("c1")], "consumed_committed")
    named = {"unknown ledger category": "consumed_from_the_future", "NUL character": "n1",
             "store unreachable": "connect"}[how]
    if how == "unknown ledger category":
        legacy.consumed(blue.root, "finding", [finding("x1")], named)
    elif how == "NUL character":
        legacy.queue(blue.root, "finding", [{**finding("n1"), "note": "a\x00b"}])
    else:
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", "postgresql://nobody:x@127.0.0.1:1/none")
    legacy.leftovers(blue.root, trace=b"trace", worktree=b"draft")
    files = files_under(blue.root)
    cw.request(blue.tid)

    cw.run()

    record = cw.record(blue.tid)
    assert record.failure and record.step == "import", record
    assert named in record.failure.lower(), record.failure
    assert record.pending_action == ACTION
    assert files_under(blue.root) == files, "nothing is deleted before a successful import"
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", blue.dsn)
    assert _store_view(blue) == ({}, 0, 0)
    assert cw.run() == 0, "a failed job is not retried until it is resumed"


def test_a_job_that_failed_at_import_goes_through_once_the_record_is_fixed_and_it_is_resumed(cw, blue):
    """Positive control: remove the offending ledger rows, resume: imported and cut over. (Migration)"""
    legacy.queue(blue.root, "finding", [finding("f1")])
    legacy.consumed(blue.root, "finding", [finding("x1")], "consumed_from_the_future")
    cw.request(blue.tid)
    cw.run()
    assert cw.record(blue.tid).failure
    for path in blue.root.rglob("*consumed*"):
        path.unlink()
    cw.resume(blue.tid)
    cw.run()
    assert _store_view(blue)[0] == {("finding", "f1"): "waiting"}
    assert not blue.root.exists()
    assert cw.record(blue.tid).failure is None


def test_a_cutover_that_fails_after_the_import_resumes_at_cutover_without_importing_twice(cw, blue):
    """Import is in, the folder holds a link the cutover refuses: failure at `cutover`; resumed, the rows are unchanged. (one-way)"""
    _plant(blue)
    link = blue.root / "worktrees" / "b2"
    link.symlink_to(blue.root)
    cw.request(blue.tid)
    cw.run()
    record = cw.record(blue.tid)
    assert record.failure and record.step == "cutover", record
    rows = _store_view(blue)
    assert len(rows[0]) == 3, "the import is in"
    assert blue.root.exists()
    link.unlink()
    cw.resume(blue.tid)
    cw.run()
    assert _store_view(blue) == rows, "the resumed job imported nothing a second time"
    assert not blue.root.exists()
    assert cw.record(blue.tid).failure is None


def test_the_job_requested_again_after_success_changes_nothing_and_does_not_bring_the_folder_back(cw, blue):
    """Safe to re-run: same rows, no folder, no failure. (Migration, one-way)"""
    _plant(blue)
    cw.request(blue.tid)
    cw.run()
    rows = _store_view(blue)
    cw.request(blue.tid)
    cw.run()
    assert _store_view(blue) == rows
    assert not blue.root.exists(), "the cutover is one-way: nothing recreates the learning folder"
    record = cw.record(blue.tid)
    assert (record.state, record.pending_action, record.failure) == ("active", None, None)


def test_a_running_user_of_the_tenants_host_lock_fails_the_job_untouched(cw, blue, data_root):
    """Quiesce: a shared holder of the tenant's host lock fails the job at import, naming the lock; it runs once free. (Migration)"""
    _plant(blue)
    files = files_under(blue.root)
    fd = host_lock.acquire(data_root, blue.tid, exclusive=False, timeout=0)
    assert fd is not None, "control: the lock is takeable"
    try:
        cw.request(blue.tid)
        cw.run()
        record = cw.record(blue.tid)
        assert record.failure and "lock" in record.failure.lower() and record.step == "import", record
        assert files_under(blue.root) == files
        assert _store_view(blue) == ({}, 0, 0)
    finally:
        host_lock.release_lock(fd)
    cw.resume(blue.tid)
    cw.run()
    assert not blue.root.exists()
    assert len(_store_view(blue)[0]) == 3


def test_one_tenants_refused_import_does_not_stop_another_tenants_job(cw, blue, tmp_path):
    """Per tenant: Blue's malformed record fails Blue's job; Green is imported and cut over in the same pass. (Migration)"""
    legacy.consumed(blue.root, "finding", [finding("x1")], "consumed_from_the_future")
    with second_tenant(blue.t) as t2:
        green = cw.add(t2)
        legacy.queue(green.root, "finding", [finding("g1")])
        cw.request(blue.tid)
        cw.request(green.tid)
        cw.run()
        assert cw.record(blue.tid).failure and blue.root.exists()
        assert cw.record(green.tid).failure is None and not green.root.exists()
        assert _store_view(green)[0] == {("finding", "g1"): "waiting"}
        assert _store_view(blue) == ({}, 0, 0)
