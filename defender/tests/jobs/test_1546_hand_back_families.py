"""#1546 (triage 1, family D2): the hand-back rule over the worker's whole family table, never one family. A stop can never
permanently fail or skip a job, and nothing about a job failed when the store could not be reached: in both cases the row
is handed back (still `running`, no failure reason, its lease lapsed), and the next take-over decides it as any lapsed row:
from its staged outcome when there is one, else a fresh attempt.

The cases, for each family that is handed back (an investigation, a learning job):
- a stop that lands while the row is being claimed (the claim answers after the stop is set: nothing starts);
- a store outage in the worker's decision read once the child is gone (`staged`, the read every family's end is decided
  from: for a learning job, inside `_decide_learning`).

A host request is never handed back (B2: a stop ends it `worker_stopped`), so the census below names the families and which
of them hand back; a new family fails it until it is placed. The rigs are `test_worker`'s and `test_1344_learning_jobs`'s:
no synchronous database write runs on the loop while the worker's task lives (the wrappers only raise or signal)."""
from __future__ import annotations

import asyncio
import os
import signal

import pytest

from defender.tests.jobs.test_1344_learning_jobs import (
    END,
    ended_child,
    job_row,
    jobs_of,
    learning_end,
    learning_worker,
    post_child,
    queued_job,
    world,  # noqa: F401 — the fixture
)
from defender.tests.support.jobs._jobs1342 import job_store, lease_left, row
from defender.tests.support.jobs._worker1342 import _FAST, _committed, _queued, _worker
from defender.tests.support.jobs._worker1342 import _helper_child as _child
from defender.tests.support.shared._postgres1339 import execute

pytestmark = [pytest.mark.anyio, pytest.mark.postgres]

#: The worker's families (its decision table, `_DECIDES`), and whether each is handed back by a stop or an outage.
HANDED_BACK = {"investigation": True, "learning": True, "host_request": False}


def test_the_hand_back_census_covers_every_family_of_the_worker():
    """Every family the worker decides is placed here: those handed back are the parametrisation below; a host request is
    not (B2). A family added to the worker fails this until it is placed. (D2)"""
    from defender.worker import _worker as W

    assert set(W._DECIDES) == set(HANDED_BACK), sorted(W._DECIDES)


FAMILIES = [name for name, back in HANDED_BACK.items() if back]


class _Armed:
    """The real store, except for one armed fault: `stop` sends this process SIGTERM inside the family's claim and lets the
    worker's handler run before the claim answers; `outage` makes every read of a claim's staged rows (`staged`) raise an
    environment fault (the database is gone)."""

    def __init__(self, store, *, claim: str, fault: str) -> None:
        self._store, self._claim, self._fault, self.fired = store, claim, fault, 0

    def __getattr__(self, name):
        inner = getattr(self._store, name)
        if name == self._claim and self._fault == "stop":
            async def claim(*args, **kwargs):
                if not self.fired:
                    self.fired += 1
                    os.kill(os.getpid(), signal.SIGTERM)
                    await asyncio.sleep(0.05)  # the worker's handler runs: the stop is set before the claim answers
                return await inner(*args, **kwargs)
            return claim
        if name == "staged" and self._fault == "outage":
            async def staged(*_args, **_kwargs):
                self.fired += 1
                raise ConnectionError("the database is gone")
            return staged
        return inner


async def _scene(world, store, family: str):  # noqa: F811 — the imported fixture
    """`(row id, the family's claim method, a worker factory over a store)` for one queued row of `family`."""
    if family == "investigation":
        rid = await _queued(store)
        return rid, "claim", lambda used: _worker(world, used, _child(world, files=_committed()), **_FAST)
    rid = await queued_job(world, store, ticket="T-1")
    return rid, "claim_learning_job", lambda used: learning_worker(
        world, used, job=ended_child(world, files={END: learning_end("completed")}), post=post_child(world), **_FAST)


def _state(dsn: str, family: str, rid: str) -> dict:
    """The row as a hand-back leaves it: its stage or status, its failure reason, whether its lease has lapsed."""
    if family == "investigation":
        got = row(dsn, rid)
        left = lease_left(dsn, rid)
        return {"stage": got["stage"], "reason": got["failure_reason"], "lapsed": left is not None and left <= 0}
    got = job_row(dsn, rid)
    [(lapsed,)] = execute(dsn, "SELECT lease_expires_at <= now() FROM jobs.learning_jobs WHERE id = %s", (rid,))
    return {"stage": got["status"], "reason": got["reason"], "lapsed": bool(lapsed)}


def _after_take_over(dsn: str, family: str, rid: str) -> tuple[tuple, list[tuple]]:
    """The row's `(stage or status, failure reason)` after a take-over, and those of the other attempts of its request."""
    if family == "investigation":
        got = execute(dsn, "SELECT stage, failure_reason FROM jobs.investigations WHERE id = %s", (rid,))[0]
        others = execute(dsn, "SELECT stage, failure_reason FROM jobs.investigations WHERE id <> %s AND (alert_id, "
                              "request_key) = (SELECT alert_id, request_key FROM jobs.investigations WHERE id = %s)",
                         (rid, rid))
        return tuple(got), [tuple(o) for o in others]
    inv = execute(dsn, "SELECT investigation_id FROM jobs.learning_jobs WHERE id = %s", (rid,))[0][0]
    attempts = jobs_of(dsn, str(inv))
    mine = next(j for j in attempts if j["id"] == rid)
    return (mine["status"], mine["reason"]), [(j["status"], j["reason"]) for j in attempts if j["id"] != rid]


#: What the take-over makes of the handed-back row: with nothing staged (the stop landed at the claim) it is undecided, so it
#: fails `lease_lapsed` and a fresh attempt is queued; with the child's outcome staged (the outage struck the decision read)
#: it keeps that staged verdict and queues nothing.
AFTER_TAKE_OVER = {
    ("investigation", "stop"): (("failed", "lease_lapsed"), [("queued", None)]),
    ("learning", "stop"): (("failed", "lease_lapsed"), [("queued", None)]),
    ("investigation", "outage"): (("completed", None), []),
    ("learning", "outage"): (("completed", None), []),
}


@pytest.mark.parametrize("fault", ["stop", "outage"], ids=["stop-at-the-claim", "store-outage-in-the-decision"])
@pytest.mark.parametrize("family", FAMILIES)
async def test_a_stop_at_the_claim_or_a_store_outage_hands_the_row_back_in_every_family(world, family, fault):  # noqa: F811
    """For each family the worker hands back: a stop landing at the claim, or a store outage when the row's end is decided,
    leaves the row handed back (running, no failure reason, lease lapsed; a hand-back is not an ending of its own), and the
    next take-over decides it as any lapsed row (`AFTER_TAKE_OVER`): never a permanent failure or skip by the worker. (D2; D-end; r5 item
    13: an outage is waited out)"""
    dsn = world["dsn"]
    async with job_store(dsn) as store:
        rid, claim, worker = await _scene(world, store, family)
        used = _Armed(store, claim=claim, fault=fault)
        run = worker(used)
        if fault == "stop":
            await asyncio.wait_for(run.serve(), timeout=30)
        else:
            await asyncio.wait_for(run.drain(), timeout=60)
        assert used.fired, f"premise: the armed {fault} never fired"
        handed = _state(dsn, family, rid)
        assert handed == {"stage": "running", "reason": None, "lapsed": True}, (
            f"the {family} was not handed back after the {fault}: {handed}")
        await store.take_over()
    assert _after_take_over(dsn, family, rid) == AFTER_TAKE_OVER[(family, fault)], (
        f"the take-over of a {family} handed back by a {fault}: {_after_take_over(dsn, family, rid)}")
