"""#1108 P4 drain edge cases, each a wrong-but-green production variant: a retained batch whose
redelivery fails again, and a forge outage while a batch starts."""
from __future__ import annotations

import logging

import httpx

import pytest

from defender.tests.support.learning.core._store1278 import (
    batches,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — the tick's world: tenant, forge and learning store
)
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    CuratorTrigger,
    author_drain,
    critical_text,
    items_of,
    queue,
    remote_branches,
)

pytestmark = pytest.mark.postgres


def _retained(w) -> list:
    """The batches the lane has not ended (the store's record of a batch retained for delivery,
    #1278: the file state's retained delivery record is retired with the file state)."""
    return sorted((str(b.id), b.phase) for b in batches(w.dsn, w.t.tenant_id) if b.phase != "ended")


def test_r6_a_failing_redelivery_serves_no_new_work_and_keeps_the_retained_record(world, caplog):  # noqa: F811 — the imported fixture
    t, paths = world.t, world.paths
    queue(paths, [S.finding_row("f1", run_id="f1")])
    box = BoxSpy()
    # The PR request never reaches the forge: the branch is pushed, no PR exists (so no open PR
    # holds the writer lease: only the retained record does).
    t.forge.fault = lambda request: (
        httpx.ConnectError("the forge is down", request=request)
        if request.method == "POST" and request.url.path.endswith("/pulls") else None)
    author_drain(t, paths, trigger=CuratorTrigger(author=S.FakeCurator(
        writes={LESSON_NAME: S.lesson("f1")})), box=box)
    held = _retained(world)
    assert len(held) == 1, "premise: the failed PR request retained the batch"
    branches = remote_branches(t.remote)

    # The forge now loses the pull-request status lookup `deliver` makes (publishing and the lease
    # listing still work), so the retained batch cannot be delivered.
    t.forge.fault = lambda request: (
        httpx.ConnectError("the forge is down", request=request)
        if "/pulls" in request.url.path and request.url.params.get("state") == "all" else None)
    queue(paths, [S.finding_row("f2", run_id="f2")])
    trigger = CuratorTrigger(author=S.FakeCurator(writes={"r6-second.md": S.lesson("f2")}))
    starts_before = len(box.requests)
    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert trigger.calls == [], f"new work was served over an undelivered batch: {trigger.calls}"
    assert len(box.requests) == starts_before, "a box was started over an undelivered batch"
    assert _retained(world) == held, "the retained delivery record was dropped by a failed redelivery"
    assert remote_branches(t.remote) == branches
    assert rc in (0, 2), (rc, critical_text(caplog))


def test_an_outage_while_the_lane_is_listed_is_a_passing_fault_that_loses_nothing(world, caplog):  # noqa: F811 — the imported fixture
    """A forge outage while the batch looks for a PR holding the lane (the open-PR listing unreachable)
    is a passing fault, not a configuration one: exit 0, nothing critical, the failure logged, no PR
    opened and the item kept in its batch, whose commits wait for a takeover; once the forge is back
    the next tick delivers that batch without authoring again. (#1278: the listing is made when the
    batch opens its PR, after authoring, so the tick no longer serves nothing; the stage's one-line
    refusal for a refusal that needs a human stays test_drain_credentials.py's O9 matrix.)"""
    t, paths = world.t, world.paths
    queue(paths, [S.finding_row("f1", run_id="f1")])
    box = BoxSpy()
    t.forge.fault = lambda request: (
        httpx.ConnectError("the forge is down", request=request)
        if request.method == "GET" and request.url.path.endswith("/pulls") else None)
    trigger = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")}))
    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert [r for r in caplog.records if r.levelno >= logging.CRITICAL] == [], critical_text(caplog)
    assert any("could not be delivered" in r.getMessage() for r in caplog.records
               if r.levelno >= logging.WARNING), "the failed delivery says why"
    assert t.forge.creates == []
    assert items_of(paths)[("finding", "f1")].status == "in_batch", "the item left its batch"
    [batch] = batches(world.dsn, t.tenant_id)
    assert batch.phase == "working", batch.phase

    t.forge.fault = None
    caplog.clear()
    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)
    assert rc == 0, critical_text(caplog)
    assert trigger.calls == ["author"], "the takeover authored again"
    (branch, _tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in t.forge.creates] == [branch]
    assert batches(world.dsn, t.tenant_id)[0].phase == "in_review"
