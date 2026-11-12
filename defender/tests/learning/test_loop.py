"""The learning loop's reply parsing, and its two drains' plumbing over the learning store.

#1278 moved the drains' queues, markers, locks and quarantine into the store (design r8 Flows, Locks, Schema). The tests below
drive the real `author_drain` / `lead_author_drain` tick over the real store and read items back from it.

Retired from this file (design r8 Locks, Schema "Retired files"):
- `test_rotate_preserves_concurrent_appends`: a file queue's rotation under concurrent appends; the append locks and the
  rotation are gone ("transactions and the unique key"); concurrent inserts are pinned by `test_1241_queue_idempotency.py`.
- `test_enqueue_for_authoring_writes_marker`: the marker file under `author-queue/`; a request is a store item
  (`enqueue_request`, `test_items_1278.py`, and the run-end enqueue in `test_1135_exemptions.py::test_e1_*`).
- `test_author_drain_triggers_all_curators`: a curator whose kind has no items is not run (A2 D1); each curator is handed
  its own kind's items by `test_1278_curator_fates.py::test_d1_each_curator_is_handed_its_own_kinds_items_from_the_claim`.
- `test_author_drain_singleton_lock_exits_without_work`, `test_lead_author_drain_singleton_lock_distinct_from_lessons`: the
  drain flock files are deleted; one working batch per lane, a live batch of another holder and the lanes' independence are
  `test_1278_tick.py::test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly` and
  `test_1278_curator_fates.py::test_d9_each_tick_claims_only_its_own_lanes_kinds`.

Retired with deleted files (their plumbing is the file queue's, design r8 Schema "Retired files", Locks):
- `core/test_1135_claims_fixes.py` (queue rotation with a keyless row, the rotate read window, a stuck record written for a
  contained fault): the rotate, the read window and the stuck records are gone; that a fault contained to a curator leaves
  its item waiting with the attempt counted is `state_contracts/test_1135_drain_halt.py` and
  `test_lead_author_drain_contains_a_poison_request_and_counts_its_attempt` below.
- `core/test_881_loop_plumbing.py` (the held report, stuck records, unreadable queue lines and the pending count of a file
  queue): the report, the records and the lines are gone; a row the gate holds keeps its reason in the store
  (`test_1278_curator_fates.py::test_d1_the_gate_holds_a_retired_row...`), and the wake gate's count is
  `core/test_orchestrate_thresholds.py::test_881_the_wake_gate_counts_what_a_tick_could_take`.
"""
from __future__ import annotations

import pytest
import yaml

from defender._yaml import safe_load
from defender.learning import loop


def test_reply_document_text_passes_through_plain_yaml():
    """A bare document comes back stripped and otherwise unchanged."""
    assert loop.reply_document_text("outcome: caught\nconfidence: high\n") == (
        "outcome: caught\nconfidence: high"
    )


def test_reply_document_text_unwraps_a_whole_string_yaml_fence():
    """Exactly one fenced block, nothing around it, is the document it holds (the parser's one
    deliberate leniency)."""
    fenced = "```yaml\noutcome: caught\n```\n"
    assert loop.reply_document_text(fenced) == "outcome: caught"


def test_reply_document_text_leaves_a_trailing_close_tag_for_the_loader_to_refuse():
    text = "outcome: caught\nconfidence: high\n</content>\n"
    assert loop.reply_document_text(text) == text.strip()
    with pytest.raises(yaml.YAMLError):
        safe_load(loop.reply_document_text(text))


def test_reply_document_text_refuses_a_dangling_close_fence():
    """A lone column-0 ``` after a plain document is a fence inside the reply: `MalformedReply`,
    not a trim."""
    text = "outcome: caught\nconfidence: high\n```\n"
    with pytest.raises(loop.MalformedReply):
        loop.reply_document_text(text)


def test_reply_document_text_strips_thinking_prelude():
    """A column-0 `</thinking>` line ends a prelude that has no opening tag (a shape recorded
    live)."""
    text = (
        "outcome: caught\n(reasoning trace…)\n</thinking>\n"
        "outcome: survived\nconfidence: high\n"
    )
    assert loop.reply_document_text(text) == "outcome: survived\nconfidence: high"




# --- the drains over the store ---------------------------------------------------------------------------------------------

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.core import _state1135 as S  # noqa: E402
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: E402, F401 — fixtures
from defender.tests.tenancy.tenant_1108_p4._drain_support import (  # noqa: E402
    BoxSpy, author_drain, critical_text, lead_author_drain, remote_branches)
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: E402, F401 — fixture `world` is built on


def _items(w) -> dict:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _request(w, label: str):
    """A finished run of the tenant and its curation request filed in the store (the run end's `enqueue_curation` row)."""
    run_dir = S.curation_run_dir(label)
    call(w.dsn, "enqueue_request", w.t.tenant_id, run_dir.name, f"case-{label}", S.curation_row(f"case-{label}", run_dir))
    return run_dir


def _lead_tick(w, **seams):
    return lead_author_drain(w.t, w.paths, box=BoxSpy(), **seams)


@pytest.mark.postgres
def test_author_drain_skips_when_no_work(world):  # noqa: F811 — the imported fixture
    """With nothing queued the tick starts no batch, spawns no curator and opens no PR."""
    w = world
    triggered: list = []

    rc = author_drain(w.t, w.paths, trigger=lambda *a, **_kw: triggered.append(a), box=BoxSpy())

    assert rc == 0
    assert triggered == []
    assert call(w.dsn, "batches", w.t.tenant_id) == [], "a batch was started with nothing queued"
    assert remote_branches(w.t.remote, "") == {"main": w.t.origin_main()}
    assert w.t.forge.creates == []


@pytest.mark.postgres
def test_lead_author_drain_serves_a_queued_request_with_its_run(world):  # noqa: F811 — the imported fixture
    """A queued curation request is served once: the lead step is handed the run the request names, through the claim."""
    w = world
    run_dir = _request(w, "case-b")
    seen: list = []

    def lead(paths, state, run, *, on_done, items, **_kw):
        seen.append((run.run_dir, [key for _kind, key, _payload in items]))
        on_done(None)

    assert _lead_tick(w, run_lead_author=lead) == 0
    assert seen == [(run_dir.resolve(), [run_dir.name])]


@pytest.mark.postgres
def test_lead_author_drain_runs_pitfalls_after_the_requests(world, monkeypatch):  # noqa: F811 — the imported fixture
    """In one tick the lead step serves the claim's requests first, then the pitfalls curation runs over the claim's pitfalls."""
    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    _request(w, "case-p")
    call(w.dsn, "add_pitfall", w.t.tenant_id, {"pitfall_id": "p1", "system": "elastic"})
    order: list[str] = []

    rc = _lead_tick(w, run_lead_author=lambda *_a, on_done, **_k: (order.append("request"), on_done(None)),
                    run_pitfalls=lambda _p, _s, *, items, **_k: (order.append("pitfalls:" + ",".join(k for _kind, k, _pl in items)), 0)[1])

    assert rc == 0
    assert order == ["request", "pitfalls:p1"]


@pytest.mark.postgres
def test_the_lead_lane_wakes_at_the_pitfalls_threshold(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The lead lane has work for pitfalls only at `LEARNING_PITFALLS_THRESHOLD` (digest-less rows stay distinct mistakes)."""
    from defender.learning.core.store_tick import LEAD_LANE, lane_waiting
    from defender.learning.store import blocking

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "2")

    def waiting() -> bool:
        with blocking(w.dsn) as store:
            return lane_waiting(store, w.t.tenant_id, LEAD_LANE)

    assert waiting() is False
    call(w.dsn, "add_pitfall", w.t.tenant_id, {"pitfall_id": "r:0", "system": "elastic"})
    assert waiting() is False, "one pitfall woke a lane whose threshold is two"
    call(w.dsn, "add_pitfall", w.t.tenant_id, {"pitfall_id": "r:1", "system": "elastic"})
    assert waiting() is True


@pytest.mark.postgres
def test_lead_author_drain_kills_a_request_whose_run_is_gone_and_serves_the_rest(world):  # noqa: F811 — the imported fixture
    """A well-formed request naming a run its tenant cannot open is dead, `artifact-missing`; the healthy one beside it is served."""
    w = world
    run_dir = _request(w, "case-real")
    gone = run_dir.parent / fixture_uuid("case-gone")
    call(w.dsn, "enqueue_request", w.t.tenant_id, gone.name, "case-gone", S.curation_row("case-gone", gone))
    seen: list = []

    assert _lead_tick(w, run_lead_author=lambda _p, _s, run, *, on_done, **_k: (seen.append(run.run_dir), on_done(None))) == 0

    assert seen == [run_dir.resolve()]
    dead = _items(w)[("curation_request", gone.name)]
    assert (dead.status, dead.reason) == ("dead", "artifact-missing")


@pytest.mark.postgres
@pytest.mark.parametrize("payload", [
    {}, {"run_id": "case-broken"}, {"run_id": None, "tenant_id": None}, {"run_id": 7, "tenant_id": 7}, {"tenant_id": fixture_uuid("someone-else"), "run_id": fixture_uuid("run-x")},
], ids=["empty", "no-tenant", "null-run", "number-run", "other-tenant"])
def test_lead_author_drain_serves_nothing_for_an_unservable_request_and_leaves_it_unclaimed(world, payload):  # noqa: F811 — the imported fixture
    """A request naming no openable run of the drain's tenant is never served and not left claimed by its batch; the healthy
    request in the same pass is served."""
    w = world
    run_dir = _request(w, "case-real")
    call(w.dsn, "enqueue_request", w.t.tenant_id, "broken", "case-broken", payload)
    seen: list = []

    assert _lead_tick(w, run_lead_author=lambda _p, _s, run, *, on_done, **_k: (seen.append(run.run_dir), on_done(None))) == 0

    assert seen == [run_dir.resolve()], "the healthy request was not served, or the unservable one was"
    assert _items(w)[("curation_request", "broken")].status != "in_batch", \
        "the unservable request was left claimed: the next tick reclaims and re-fails on it"


@pytest.mark.postgres
def test_lead_author_drain_contains_a_poison_request_and_counts_its_attempt(world):  # noqa: F811 — the imported fixture
    """A request whose step raises does not stop the pass: the healthy request is served, the poison one has its attempt counted."""
    w = world
    poison, good = _request(w, "case-poison"), _request(w, "case-good")
    seen: list = []

    def lead(_p, _s, run, *, on_done, **_k):
        if run.run_dir.name == poison.name:
            raise RuntimeError("lead-author blew up")
        seen.append(run.run_dir)
        on_done(None)

    assert _lead_tick(w, run_lead_author=lead) == 0

    assert seen == [good.resolve()]
    bad = _items(w)[("curation_request", poison.name)]
    assert (bad.status, bad.attempts) == ("waiting", 1)


@pytest.mark.postgres
def test_lead_author_drain_does_not_count_a_nonzero_step_as_served(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The default lead step returning a non-zero rc is a failure of that request, not a success: the request is not done."""
    import defender.learning.leads.lead_author as la

    w = world
    run_dir = _request(w, "case-rc")
    monkeypatch.setattr(la, "run_under_held_queue_lock", lambda rd, paths=None, box=None, **_kw: 2)  # lint-monkeypatch: ok — drives the real _invoke_lead_author

    assert _lead_tick(w) == 0
    item = _items(w)[("curation_request", run_dir.name)]
    assert (item.status, item.attempts) == ("waiting", 1), "the failed step was recorded as done"


@pytest.mark.postgres
def test_lead_author_drain_bounds_the_retries_of_a_failing_request(world, monkeypatch):  # noqa: F811 — the imported fixture
    """A request whose step keeps failing is retried a bounded number of ticks, then taken out of the queue for a person
    (held or dead), never served for ever. (`LEARNING_AUTHOR_MAX_ATTEMPTS`, design r8 Schema: attempts)"""
    import defender.learning.leads.lead_author as la

    w = world
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    run_dir = _request(w, "case-transient")

    def boom(rd, paths=None, box=None, **_kw):
        raise OSError("disk hiccup")

    monkeypatch.setattr(la, "run_under_held_queue_lock", boom)  # lint-monkeypatch: ok — drives the real _invoke_lead_author

    statuses = []
    for _ in range(5):
        _lead_tick(w)
        statuses.append(_items(w)[("curation_request", run_dir.name)].status)

    assert statuses[:2] == ["waiting", "waiting"], statuses
    assert statuses[-1] in {"held", "dead"}, f"a request that failed five ticks running is still {statuses[-1]}: {statuses}"


@pytest.mark.postgres
def test_lead_author_drain_stops_with_exit_two_on_a_misconfigured_step(world, monkeypatch, caplog):  # noqa: F811 — the imported fixture
    """A `FatalConfigError` out of the lead step (a malformed `LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD`) is systemic: it ends the
    tick with exit 2 rather than being quarantined against the request, which is not charged an attempt it can never clear."""
    from defender.learning.leads import lead_author

    w = world
    run_dir = _request(w, "case-lift")
    monkeypatch.setenv("LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD", "high")

    def lead(_p, _s, _run, **_k):
        lead_author._lift_threshold()

    assert _lead_tick(w, run_lead_author=lead) == 2, critical_text(caplog)
    assert "LEARNING_LEAD_AUTHOR_LIFT_THRESHOLD" in caplog.text
    assert _items(w)[("curation_request", run_dir.name)].status != "dead"


@pytest.mark.postgres
def test_a_pitfall_the_curator_keeps_declining_is_taken_out_at_the_ceiling(world, monkeypatch):  # noqa: F811 — the imported fixture
    """A reducer pitfall the pitfalls curator is offered and declines every tick is not offered for ever: after the attempt
    ceiling it is held for a person (or dead), where it was once retired to the graveyard. (design r8 Schema: attempts, ceiling)"""
    from defender.learning.leads import pitfalls_curator
    from defender.tests.support.learning.core._declared870 import shim_row
    from defender.tests.tenancy.tenant_1108_p4._drain_support import LEAD_DRAFT_LANES, draft_lane_trees

    w = world
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    call(w.dsn, "add_pitfall", w.t.tenant_id, shim_row("r:l-003:0"))
    offers: list = []

    def declining(paths, state, *, batch, box=None, on_curated, items, outcomes, **_kw):
        with draft_lane_trees(batch, LEAD_DRAFT_LANES) as trees:
            return pitfalls_curator.run_pitfalls(paths=paths, trees=trees, batch=batch, items=items, outcomes=outcomes,
                                                 on_curated=on_curated, invoke=lambda handoffs, **_k: offers.append(handoffs) or 0)

    statuses = []
    for _ in range(5):
        _lead_tick(w, run_pitfalls=declining)
        statuses.append(_items(w)[("pitfall", "r:l-003:0")].status)

    assert len(offers) >= 1, "the reducer offer was never made, so the decline is vacuous"
    assert statuses[0] == "waiting"
    assert statuses[-1] in {"held", "dead"}, f"a pitfall declined five ticks running is still {statuses[-1]}: {statuses}"
    assert len(offers) <= 3, f"the curator was offered the declined pitfall {len(offers)} times, past the ceiling of 3"
