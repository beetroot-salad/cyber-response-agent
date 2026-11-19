"""#1278 feedback, H15 counting: every status the forge can answer, against a model of the design's rule. Split from
`test_1278_feedback.py` (one file's CI cost), whose scene, fixture and helpers these cases use.
"""
from __future__ import annotations

import random

import httpx
import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    Scene,
    opened,
    tick,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback import (
    _files,
)
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`

# --- H15 counting: every status the forge can answer, against a model of the design's rule ------------------------------


def _counts_as_refusal(answer) -> bool:
    """The design's rule (H15): a 4xx but a timeout (408) or a rate limit (429) is a refusal and counts."""
    return isinstance(answer, int) and 400 <= answer < 500 and answer not in (408, 429)


def _answers() -> list:
    """Every status 400..599 once, in a seeded order, with network faults and good reads woven between."""
    rng = random.Random(1278)
    statuses = list(range(400, 600))
    rng.shuffle(statuses)
    out: list = []
    for n, status in enumerate(statuses):
        out.append(status)
        if n % 7 == 6:
            out.append("ok")
        if n % 11 == 5:
            out.append(rng.choice(["connect", "timeout"]))
    return out


def _answer_with(w: Scene, target_suffix: str, answer) -> None:
    w.t.forge.clear_refusals()
    w.t.forge.fault = None
    if answer == "ok":
        return
    if isinstance(answer, int):
        w.t.forge.refuse(target_suffix, answer, method="GET")
        return
    error = httpx.ConnectError if answer == "connect" else httpx.ReadTimeout
    w.t.forge.fault = lambda r: (error("down", request=r)
                                 if r.method == "GET" and r.url.path.rstrip("/").endswith(target_suffix) else None)


@pytest.mark.parametrize("target", ["reviews", "pull"])
def test_h15_each_answer_the_forge_can_give_counts_or_not_as_the_rule_says_and_a_person_is_called_exactly_at_the_ceiling(
        world, caplog, target):
    """Every status 400..599, a lost connection, a timeout and good reads, one per tick, on the reviews read and on `GET /pulls/N`: 4xx but 408 and 429 count one; 5xx, 408, 429 and network faults leave the count; a good read zeroes it; the third counted refusal makes the batch needs_person, no sooner. (H15, D7)"""
    from defender.tests.support.shared._postgres1339 import execute

    w = world
    w.seed("f1")
    batch_id, _branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    suffix = "/reviews" if target == "reviews" else f"/pulls/{number}"
    writer = FeedbackCurator()
    count, previous = 0, None
    for answer in _answers():
        if count == 0 and not _counts_as_refusal(answer):
            _answer_with(w, suffix, 403)  # a primer: something for an unknown or a good read to leave or zero
            tick(w, writer)
            count = 1
        _answer_with(w, suffix, answer)
        before = len(w.t.forge.requests)
        tick(w, writer)
        asked = [r for r in w.t.forge.requests[before:] if r.method == "GET" and r.url.path.rstrip("/").endswith(suffix)]
        assert asked, f"answer {answer!r}: the tick never asked {suffix}, so nothing was refused or counted"
        count = 0 if answer == "ok" else count + (1 if _counts_as_refusal(answer) else 0)
        b = w.batch_rows()[batch_id]
        want = ("needs_person", count) if count >= 3 else ("in_review", count)
        assert (b.phase, b.refusals) == want, f"after {answer!r} (before it: {previous!r}) the batch is {(b.phase, b.refusals)}"
        previous = answer
        if b.phase == "needs_person":  # a person's release, by hand: back to review with the count at zero
            execute(w.dsn, "UPDATE learning.batches SET phase = 'in_review', refusals = 0, reason = NULL, cause = NULL, parked_at = NULL "
                    "WHERE id = %s",
                    (batch_id,))
            count = 0
    assert w.statuses() == {"f1": "in_batch"}, "a refusal lost the item"
