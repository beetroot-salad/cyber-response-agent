# ruff: noqa: PT018, F811
"""#1214 O6: the tenant's last publish outcome lives in `tenancy.publish_status` (not `publish-status.json`): recorded by
host processes, readable, replaced by the next outcome and deleted at `finish` (O6, P2, Flow 2.4). Successors of #1108 P4's
file-based assertions: a misconfiguration is recorded then cleared by a success; a transient outage and an operator
refusal are told apart.

GAP-Rc-2 (pinned here, not by r9): on both repositories, `await repo.record_publish_status(T, line, *, by)` stores the
outcome a launch-time publish report `line` states (`fresh <commit>`; `stale:transient <why>`; `stale:operator <why>`;
`misconfigured <why>`) and `await repo.publish_status(T) -> dict | None` reads it with the keys of the old file: `by`,
`published` (the commit) or `refused` (the reason) with `kind` (`transient` | `operator`); None when none is recorded.
Who records the first publish in prepare (the publish child or the host actor) is not pinned (GAP-Rc-3): the recording
publish fake writes nothing, so no case asserts prepare's own write.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from defender.tests.tenancy.lifecycle_1214._support import LifecycleWorld  # noqa: E402
from defender.tests.tenancy.lifecycle_1214.test_1214_repository_contract import (  # noqa: E402,F401
    ABSENT,
    T1,
    Store,
    store,
)

pytestmark = pytest.mark.anyio

BY = "launch-time publish"


async def _record(s: Store, line: str, tenant: str = T1) -> None:
    await s.repo.record_publish_status(tenant, line, by=BY)


async def test_a_tenant_with_no_outcome_reads_none(store):
    """Nothing recorded reads as None, also for an unknown tenant (O6)."""
    await store.seed(T1)
    assert await store.repo.publish_status(T1) is None
    assert await store.repo.publish_status(ABSENT) is None


async def test_a_published_commit_is_recorded_and_readable(store):
    """`fresh <commit>` reads back as published at that commit by the recorder, with no refusal (O6)."""
    await store.seed(T1)
    await _record(store, "fresh 0123abcd")
    status = await store.repo.publish_status(T1)
    assert status["published"] == "0123abcd" and status["by"] == BY
    assert "refused" not in status


@pytest.mark.parametrize(("line", "kind"), [
    ("stale:transient the forge is unreachable", "transient"),
    ("stale:operator the history diverged", "operator"),
    ("misconfigured no issuer config", "operator"),
])
async def test_a_refusal_is_recorded_with_its_kind_and_reason(store, line, kind):
    """A transient outage and an operator refusal are told apart; a misconfiguration needs a human (O6, O-SEE)."""
    await store.seed(T1)
    await _record(store, "fresh 0123abcd")  # control: a published outcome is replaced, not kept beside
    await _record(store, line)
    status = await store.repo.publish_status(T1)
    assert status["kind"] == kind and line.partition(" ")[2] in status["refused"]
    assert "published" not in status


async def test_a_misconfiguration_is_recorded_and_a_later_success_clears_it(store):
    """The refusal stands until a publish succeeds; then only the commit is left (O6)."""
    await store.seed(T1)
    await _record(store, "misconfigured the issuer config is missing")
    assert (await store.repo.publish_status(T1))["refused"]
    await _record(store, "fresh feedbeef")
    status = await store.repo.publish_status(T1)
    assert status["published"] == "feedbeef" and "refused" not in status and "kind" not in status


async def test_one_tenants_outcome_is_not_anothers(store):
    """Status is keyed by tenant (O6)."""
    await store.seed(T1)
    await store.seed(ABSENT)
    await _record(store, "stale:operator diverged", T1)
    assert await store.repo.publish_status(ABSENT) is None
    assert (await store.repo.publish_status(T1))["kind"] == "operator"


@pytest.fixture
def world(tmp_path, data_root):
    w = LifecycleWorld(tmp_path, data_root)
    yield w
    w.close()


def test_finish_deletes_the_publish_status_and_nothing_earlier_does(world):
    """The status is still there while the tenant is being torn down and gone once `finish` has run (Flow 2.4, O6)."""
    tenant = world.active_tenant()
    world.call(world.tenants.record_publish_status, tenant, "fresh 0123abcd", by=BY)
    assert world.ops.post(f"/admin/tenants/{tenant}/offboard").status_code == 202
    world.drive(stop=lambda: world.item(tenant)["step"] == "finish")
    assert world.item(tenant)["step"] == "finish"
    assert world.call(world.tenants.publish_status, tenant)["published"] == "0123abcd", "deleted before finish"
    world.drive()
    assert world.item(tenant)["state"] == "offboarded"
    assert world.call(world.tenants.publish_status, tenant) is None
