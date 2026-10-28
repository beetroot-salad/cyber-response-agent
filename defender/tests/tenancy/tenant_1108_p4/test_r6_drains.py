"""#1108 P4 drain edge cases, each a wrong-but-green production variant: a retained batch whose
redelivery fails again, and a forge outage while a batch starts."""
from __future__ import annotations

import logging

import httpx

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
    BoxSpy,
    CuratorTrigger,
    author_drain,
    critical_text,
    drain_paths,
    product_repo,
    queue,
    remote_branches,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge
from defender.tests.tenancy.tenant_1108_p4.test_drains import thresholds  # noqa: F401, F811 — fixture


def _retained(paths) -> list:
    from defender.learning.core.state import LearningState

    with LearningState.open(paths) as state:
        return [d.id for d in state.deliveries("lessons/")]


def test_r6_a_failing_redelivery_serves_no_new_work_and_keeps_the_retained_record(
        p4_tenant, tmp_path, thresholds, caplog):  # noqa: F811 — fixture
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    box = BoxSpy()
    # The PR request never reaches the forge: the branch is pushed, no PR exists (so no open PR
    # holds the writer lease: only the retained record does).
    t.forge.fault = lambda request: (
        httpx.ConnectError("the forge is down", request=request)
        if request.method == "POST" and request.url.path.endswith("/pulls") else None)
    author_drain(t, paths, trigger=CuratorTrigger(author=S.FakeCurator(
        writes={LESSON_NAME: S.lesson("f1")})), box=box)
    held = _retained(paths)
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
    assert _retained(paths) == held, "the retained delivery record was dropped by a failed redelivery"
    assert remote_branches(t.remote) == branches
    assert rc in (0, 2), (rc, critical_text(caplog))


def test_an_outage_while_the_batch_starts_skips_the_tick_and_serves_nothing(
        p4_tenant, tmp_path, thresholds, caplog):  # noqa: F811 — fixture
    """A forge outage while the batch starts (the writer-lease listing unreachable) is a passing
    fault, not a configuration one: the tick warns, exits 0 for the next tick to retry, and
    serves nothing. A refusal that needs a human stays the stage's one-line refusal
    (test_drain_credentials.py's O9 matrix)."""
    from defender.learning.core.state import FINDINGS

    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
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
    assert any("outage" in r.getMessage() for r in caplog.records
               if r.levelno == logging.WARNING), "the skipped tick says why"
    assert trigger.calls == []
    assert box.requests == []
    assert "f1" in S.pending_by_id(paths, FINDINGS), "the row left the queue"
