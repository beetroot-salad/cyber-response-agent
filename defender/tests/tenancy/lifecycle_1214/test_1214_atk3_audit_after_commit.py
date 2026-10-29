# ruff: noqa: PT018
"""#1214 attack-3 hole 10 (O10, DC-4): `tenant.repo.delete` is audited only after the fenced commit that records the
deletion succeeds: a commit that fails after the forge call emits nothing; the resume commits and audits once.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from defender.tests.support.api._identity1306 import AuditLog  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._fakes import ORG  # noqa: E402
from defender.tests.tenancy.lifecycle_1214._support import REPO_DELETE, REPO_WINDOW, LifecycleWorld  # noqa: E402


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def test_a_repo_deletion_whose_commit_fails_is_not_audited_and_the_resume_audits_it_once(world, caplog, monkeypatch):
    """The forge deletes the repo but the commit recording it is lost: no event, `repo_url` kept; after resume one event (O10)."""
    import datetime as _dt

    from defender.tenancy import memory

    tenant = world.active_tenant()
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive()
    audit = AuditLog(caplog)
    real = memory._Held.commit
    lose = [True]

    async def commit(self, **kw):
        if lose[0] and kw.get("drop_wiring"):
            raise ConnectionError("database lost at the commit")
        return await real(self, **kw)

    monkeypatch.setattr(memory._Held, "commit", commit)
    mark = audit.mark()
    world.clock.advance(REPO_WINDOW + _dt.timedelta(seconds=1))
    world.drive()
    assert (f"{ORG}/{tenant}") not in world.forge.repos, "premise: the forge call happened before the lost commit"
    record = world.record(tenant)
    assert record.repo_url is not None, "premise: the commit was lost"
    assert audit.actions(mark) == [], "the deletion was audited before its commit"
    lose[0] = False
    world.ops = world.sign_in_admin()
    assert record.failure, "premise: the lost commit is a failed step"
    assert world.ops.post(f"/admin/tenants/{tenant}/resume").status_code == 202
    mark = audit.mark()
    world.drive()
    assert world.record(tenant).repo_url is None
    assert audit.actions(mark) == [REPO_DELETE]
