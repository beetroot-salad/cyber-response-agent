"""#1278 the author tick's crash recovery under a forge that cannot be asked (H15, Crash recovery). Split from
`test_1278_tick.py` (one file's CI cost), whose helpers these cases use.
"""
from __future__ import annotations


import httpx
import pytest

from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    ONE,
    LessonWriter,
    call,
    lapse_lease,
    lesson_citing,
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (
    LESSON_NAME,
)
from defender.tests.tenancy.tenant_1108_p4.test_1278_tick import (
    _batches,
    _opened,
    _seed,
    _stranded,
    _tick,
    _work,
)

pytestmark = [pytest.mark.postgres, pytest.mark.usefixtures("tick_impl")]  # the tick over each store implementation (conftest)

# --- Crash recovery under a forge that cannot be asked (H15, Crash recovery) -----------------------------------------


def _asked(forge, method, suffix):
    """The requests of `method` made to a path ending `suffix`, refused or not."""
    return [r for r in forge.requests if r.method == method and r.url.path.rstrip("/").endswith(suffix)]


@pytest.mark.parametrize("where", ["preflight", "pr_lookup"])
@pytest.mark.parametrize("failure", ["500", "503", "connect"])
@pytest.mark.parametrize("scene", ["stranded", "nothing_pushed"])
def test_o1_a_lapsed_batch_whose_forge_cannot_be_asked_waits_and_is_never_abandoned(world, caplog, scene, failure, where):  # noqa: F811 — the imported fixture
    """A forge answering 5xx or refusing the connection, on every request or on the recovery's PR lookup alone, is unknown, not empty: the batch stays working, opens no PR, its items stay. (Crash recovery, H15, R2-1)"""
    w = world
    if scene == "stranded":
        writer, batch_id, _branch = _stranded(w, caplog)
    else:
        _seed(w, "f1")
        writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
        batch_id = call(w.dsn, "claim", w.t.tenant_id, AUTHOR_LANE, owner="lost-host", thresholds=ONE).batch_id
    lapse_lease(w.dsn, batch_id)
    before = {k: (i.status, i.batch_id, i.attempts) for k, i in _work(w).items()}
    lookup = where == "pr_lookup"
    if failure == "connect":
        w.t.forge.fault = lambda r: (httpx.ConnectError("down", request=r)
                                     if not lookup or (r.method == "GET" and r.url.path.rstrip("/").endswith("/pulls"))
                                     else None)
    else:
        w.t.forge.refuse("/pulls" if lookup else "", int(failure), method="GET" if lookup else None)
    w.t.forge.requests.clear()
    creates = len(w.t.forge.creates)

    for _ in range(3):
        _tick(w, writer)

    assert w.t.forge.requests, "the tick never asked the forge, so the failure was not what it waited on"
    if lookup:
        assert _asked(w.t.forge, "GET", "/pulls"), "recovery never looked the PR up, so its lookup was not what failed"
    assert _asked(w.t.forge, "POST", "/pulls") == [], "a PR was opened though the lookup could not say none exists"
    batch = _batches(w)[batch_id]
    assert (batch.phase, batch.outcome) == ("working", None), "a forge that could not answer was read as 'nothing there'"
    assert (batch.refusals, len(w.t.forge.creates)) == (0, creates)
    assert {k: (i.status, i.batch_id, i.attempts) for k, i in _work(w).items()} == before


@pytest.mark.parametrize("where", ["preflight", "pr_lookup"])
@pytest.mark.parametrize("status", [401, 403])
def test_o5_repeated_refusals_on_a_takeover_send_the_batch_to_a_person_at_the_ceiling(world, caplog, status, where):  # noqa: F811 — the imported fixture
    """A forge that keeps refusing the bot (401, 403) on every request or on the takeover's PR lookup alone: three ticks count, at the ceiling the batch is needs_person, items kept, no PR. (H15, R2-1, Crash recovery)"""
    w = world
    writer, batch_id, _branch = _stranded(w, caplog)
    lapse_lease(w.dsn, batch_id)
    lookup = where == "pr_lookup"
    w.t.forge.refuse("/pulls" if lookup else "", status, method="GET" if lookup else None)
    w.t.forge.requests.clear()
    seen = []
    for _ in range(3):
        _tick(w, writer)
        seen.append((_batches(w)[batch_id].phase, _batches(w)[batch_id].refusals))

    assert seen == [("working", 1), ("working", 2), ("needs_person", 3)], seen
    if lookup:
        assert _asked(w.t.forge, "GET", "/pulls"), "recovery never looked the PR up, so its lookup was not what was refused"
    assert _asked(w.t.forge, "POST", "/pulls") == []
    assert _work(w)[("finding", "f1")].status == "in_batch", "the item is not lost"
    assert [r for r in w.t.forge.prs if r["state"] == "open"] == []


@pytest.mark.parametrize(("status", "counted"), [(403, True), (503, False)])
def test_d11_a_lasting_refusal_at_the_reconcile_counts_toward_the_person_ceiling_and_a_transient_one_does_not(world, caplog, status, counted):  # noqa: F811 — the imported fixture
    """The forge refusing the bot (403, lasting) on a batch in review counts one refusal a tick and parks it at three; refusing with 503
    (transient) counts none and parks nothing, the items kept either way. (D11, K9)"""
    w = world
    writer = LessonWriter({LESSON_NAME: lesson_citing("f1")})
    _seed(w, "f1")
    batch_id, _branch, _pr = _opened(w, writer, caplog)
    assert (_batches(w)[batch_id].phase, _batches(w)[batch_id].refusals) == ("in_review", 0), "control: in review, nothing counted"
    w.t.forge.refuse("", status)
    w.t.forge.requests.clear()
    seen = []
    for _ in range(3):
        _tick(w, writer)
        seen.append((_batches(w)[batch_id].phase, _batches(w)[batch_id].refusals))

    assert w.t.forge.requests, "the tick never asked the forge, so the refusal was not what it met"
    expected = [("in_review", 1), ("in_review", 2), ("needs_person", 3)] if counted else [("in_review", 0)] * 3
    assert seen == expected, seen
    assert _work(w)[("finding", "f1")].status == "in_batch", "the item is not lost"
