"""#1278 feedback, H15 counting over the port, pull read: the answers given on `GET /pulls/N`. One slice of
`test_1278_feedback_every_answer.py`'s case, in a file of its own so the case runs on a worker of its own (one file runs on
one worker); the function is that module's, restricted to its slice.
"""
from __future__ import annotations

import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    opened,
    tick,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback import (
    _files,
)
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback_every_answer import (
    _answer_with,
    _answers,
    _counts_as_refusal,
)

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

#: The port's case alone (conftest `ONLY_TICK_IMPLS`); the adapter's are in `test_1278_feedback_every_answer.py`.
ONLY_TICK_IMPLS = ("port",)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`


@pytest.mark.parametrize("target", ["pull"])
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
