"""#1278 feedback: the forge's refusals and unknowns on a batch's PR (A2 H15). Split from `test_1278_feedback.py` (one
file's CI cost), whose scene, fixture and helpers these cases use.
"""
from __future__ import annotations


import httpx
import pytest

from defender.tests.support.learning.core._feedback1278 import (
    FeedbackCurator,
    opened,
    tick,
)
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture
from defender.tests.tenancy.tenant_1108_delivery._support import (
    close_on_remote,
)
from defender.tests.tenancy.tenant_1108_p4.test_1278_feedback import (
    _end,
    _files,
)
from defender.tests.tenancy.tenant_1108_p4 import test_1278_feedback as _1278_feedback
from defender.tests.tenancy.tenant_1108_p4._drain_support import own_store

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

world = _1278_feedback.world  # the fixture, from `test_1278_feedback`

# --- A2 H15: refusals and unknowns ---------------------------------------------------------------------


@pytest.mark.parametrize("grant", ["write:issue", "read:issue"])
def test_h15_a_closed_prs_refused_comment_read_is_unknown_not_no_feedback(world, caplog, grant):
    """With neither issue scope the comment read is 403: the closed PR's batch stays unresolved, its item not held; with `write:issue` (A4) or `read:issue`, held. (C23, Feedback)"""
    w = world
    w.t.forge.scopes = {"write:repository"}
    w.seed("f1")
    batch_id, branch, number = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    tick(w, FeedbackCurator())

    assert [r for r in w.t.forge.requests if r.url.path.endswith(f"/issues/{number}/comments")]
    assert _end(w, batch_id) == ("in_review", None)
    assert w.statuses() == {"f1": "in_batch"}

    w.t.forge.scopes.add(grant)
    tick(w, FeedbackCurator())
    assert w.statuses() == {"f1": "held"}, "control: the same close, read in full, holds the item"


@pytest.mark.parametrize("status", [401, 403, 422])
def test_h15_repeated_refusals_send_the_batch_to_a_person_at_the_ceiling(world, caplog, status):
    """Three consecutive refusals (401, 403, a persistent 4xx) count; at the ceiling the batch is needs_person with its items kept. (H15, D7)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, _number = opened(w, writer, caplog)
    w.t.forge.refuse("/reviews", status)
    seen = []
    for _ in range(3):
        tick(w, writer)
        b = w.batch_rows()[batch_id]
        seen.append((b.phase, b.refusals))

    assert seen == [("in_review", 1), ("in_review", 2), ("needs_person", 3)]
    assert w.statuses() == {"f1": "in_batch"}


def test_h15_refused_comment_reads_count_toward_the_ceiling_too(world, caplog):
    """A closed PR whose comments the token may not read: three ticks send its batch to a person, the item kept. (G-F7, H15)"""
    w = world
    w.t.forge.scopes = {"write:repository"}
    w.seed("f1")
    batch_id, branch, _number = opened(w, FeedbackCurator(_files("f1")), caplog)
    close_on_remote(w.t.p3, branch)
    seen = []
    for _ in range(3):
        tick(w, FeedbackCurator())
        b = w.batch_rows()[batch_id]
        seen.append((b.phase, b.refusals))

    assert seen == [("in_review", 1), ("in_review", 2), ("needs_person", 3)]
    assert w.statuses() == {"f1": "in_batch"}


@pytest.mark.parametrize("failure", ["500", "502", "503", "connect"])
def test_h15_a_server_error_or_a_lost_connection_is_unknown_and_never_counts(world, caplog, failure):
    """5xx and network faults leave the batch in review with no refusal counted, however many ticks. (H15, D7)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, number = opened(w, writer, caplog)
    if failure == "connect":
        w.t.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                     if r.url.path.endswith(f"/pulls/{number}/reviews") else None)
    else:
        w.t.forge.refuse("/reviews", int(failure))
    before = len(w.t.forge.requests)
    for _ in range(5):
        tick(w, writer)

    asked = [r for r in w.t.forge.requests[before:] if r.method == "GET" and r.url.path.endswith(f"/pulls/{number}/reviews")]
    assert len(asked) >= 5, "the reconcile never asked for the reviews, so nothing was refused or counted"
    b = w.batch_rows()[batch_id]
    assert (b.phase, b.refusals) == ("in_review", 0)


@own_store("five ticks over the port were ~140 s; the count rule over the port is `test_1278_feedback_every_answer_{pull,reviews}.py`'s")
def test_h15_a_good_read_resets_the_refusals(world, caplog):
    """Two refusals, one good read, two more: the count restarts and the batch stays in review. (H15)"""
    w = world
    w.seed("f1")
    writer = FeedbackCurator(_files("f1"))
    batch_id, _branch, _number = opened(w, writer, caplog)
    counts = []
    for refusing in (True, True, False, True, True):
        w.t.forge.clear_refusals()
        if refusing:
            w.t.forge.refuse("/reviews", 403)
        tick(w, writer)
        b = w.batch_rows()[batch_id]
        counts.append((b.phase, b.refusals))

    assert counts == [("in_review", 1), ("in_review", 2), ("in_review", 0), ("in_review", 1), ("in_review", 2)]
