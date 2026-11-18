"""#1487 (design r5, Flow 2, P2): the author tick's store interface has two implementations, the adapter over the in-process
store and the port over the helper, and the port has no semantics of its own: for every call it returns what the adapter
returns and raises what it raises. The close test: scripted and generated call sequences with injected races (a second
reconciler, a lapse, a cancel) and an outage, run over both against the same seed, asserting identical results and
exceptions per call; the tick's own scenarios over both; and the three things only the helper adds (the references it
issued, the stop signal's `Stop`, the dead latch). The helper is the real one, as a process (`PostStepHelper`) so the
tick may run on the test's main thread, or in this process (`in_post_step`) for a stop the test delivers.

The port's wire request names are the implementer's: tests learn them by recording what the port sends (`Recorder`).
The tick's interface (`TickStore`) is the census's verbs without the tenant, lane, owner, threshold, `by` or settings
argument: `batches()`, `lane_work()`, `work(statuses=, kind=)`, `claim()`, `take_over(batch_id)`, `renew(held)`,
`record_commit(held, commit, base, start, changes)`, `in_review(held, pr, outcomes)`, `commit_record()`,
`note_check(batch_id, reset_refusals=)`, `note_refusal(batch_id, why)`, `needs_person(batch_id, why)` (a
`Why[BatchCause]`, #1537), `end_review(batch_id, expect_phase=, outcome=, published=, held=, detail=, items_why=)`,
`settle_abandon(batch_id, pr_number=, pr_state=, published=, held=)`, `expire_own(held)`, `abandon_clean(held)`,
`abandon(batch_id)`, `end_no_commits(held, outcomes)`, `abandon_crashed(held)`; attributes `renew_every`,
`generation_ceiling`."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import re
import signal
import sys
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from defender.records.learning_causes import Why
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs import _relay1487 as R
from defender.tests.support.jobs._job_helper import OTHER_TENANT
from defender.tests.support.jobs._job_helper_learning import run_kind
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the scene's database
from defender.tests.support.learning.core._store1278 import (
    AUTHOR_LANE,
    FINDING,
    LEAD_LANE,
    ONE,
    LessonWriter,
    TickChild,
    await_file,
    blocked_in_subprocess,
    call,
    changes_of,
    finding,
    lapse_lease,
    lease_seconds_left,
    lesson_citing,
    oid,
)

process_state = J.process_state
scene = J.scene

pytestmark = [pytest.mark.postgres, pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")]

_STOP_WINDOW = 22  # `job_host._container.STOP_GRACE`: the seconds a container is given to unwind


# --- fixtures and helpers -----------------------------------------------------------------------------------------------


@pytest.fixture
def start(scene, tmp_path, monkeypatch):
    """`start()`: a real post-step helper over the scene's tenant, reading the settings in the environment now."""
    R.settings_env(monkeypatch)
    started: list[Any] = []

    def go() -> R.PostStepHelper:
        helper = R.PostStepHelper(scene, tmp_path)
        started.append(helper)
        return helper

    yield go
    for helper in started:
        helper.close()


def _exceptions() -> SimpleNamespace:
    from defender.learning_store.tick import ForeignBatch, StoreUnavailable

    return SimpleNamespace(ForeignBatch=ForeignBatch, StoreUnavailable=StoreUnavailable)


def run_over(impl: str, scene, start, ops: list[tuple], *, dsn: str | None = None, seed: bool = True) -> list[tuple]:
    """`ops` over `impl`, from the same seed laid down afresh: each step's canonical outcome."""
    R.reset_learning(scene.dsn)
    if seed:
        R.seed_work(scene.dsn, scene.tenant)
    if impl == "adapter":
        with R.adapter_store(dsn or scene.dsn, scene.tenant) as store:
            return R.Runner(store, scene.dsn, scene.tenant).run(ops)
    helper = start()
    try:
        return R.Runner(helper.port(), scene.dsn, scene.tenant).run(ops)
    finally:
        helper.close()


def assert_same(ops: list[tuple], adapter: list[tuple], port: list[tuple]) -> None:
    assert len(adapter) == len(port) == len(ops)
    for i, (op, a, p) in enumerate(zip(ops, adapter, port, strict=True)):
        assert a == p, f"call {i} {op}: the adapter answered {a!r}, the port {p!r}"


def snapshot(dsn: str, tenant: str) -> list[tuple]:
    """Every batch of `tenant` as the store holds it (the fields a refused call must not move)."""
    return [(str(b.id), b.phase, b.outcome, b.token, b.lease_expiry, b.refusals, b.reason, b.last_checked, b.pr_number)
            for b in call(dsn, "batches", tenant)]


def item_states(dsn: str, tenant: str) -> dict[str, tuple]:
    return {i.key: (i.status, i.attempts, i.reason) for i in call(dsn, "work", tenant)}


# --- P2: the same answers, per call, over one store ---------------------------------------------------------------------

_SCRIPTS: dict[str, tuple[list[tuple], dict[int, str]]] = {
    "a tick's own order": (R.LIFE, {}),
    "a lost lease": ([("claim",), ("race", "rival_takeover", 0), ("renew", 0), ("in_review", 0, 5)],
                     {2: "LeaseLost", 3: "LeaseLost"}),
    "a cancel": ([("claim",), ("race", "cancel"), ("renew", 0)], {2: "Stop"}),
    "a takeover that is no longer due": (
        [("claim",), ("race", "lapse", 0), ("batches",), ("race", "rival_takeover", 0), ("take_over", 0)],
        {4: "NotLapsed"}),
    "a lane held by another": ([("race", "rival_claim"), ("claim",)], {1: "LaneBusy"}),
    "a listed batch a purge deleted": (
        [("claim",), ("in_review", 0, 9), ("batches",), ("race", "delete_batch", 0), ("note_refusal", 0)],
        {4: "LookupError"}),
    "an outcome the store does not know": (
        [("claim",), ("in_review", 0, 9), ("batches",), ("end_review", 0, "bogus")], {3: "ValueError"}),
}


@pytest.mark.parametrize("script", sorted(_SCRIPTS))
def test_p2_a_scripted_sequence_is_answered_alike_and_raises_the_store_exceptions_as_they_are(scene, start, script):
    """The census's verbs in a tick's order and in the races it has (a rival's takeover, a lapse, a cancel, a lane held
    by another, a purged batch) answer and raise the same over the adapter and the port; each exception named is the
    store's own class. (P2, O4; Exceptions that cross)"""
    ops, raises = _SCRIPTS[script]
    adapter = run_over("adapter", scene, start, ops)
    port = run_over("port", scene, start, ops)

    assert_same(ops, adapter, port)
    for index, name in raises.items():
        got = adapter[index]
        assert got[0] == "raised", f"call {index} {ops[index]}: {got!r}"
        assert got[1].rsplit(".", 1)[-1] == name, f"call {index} {ops[index]}: {got!r}"
        assert got[1].startswith("defender.learning_store"), f"{name} is not the store's own class: {got[1]}"
    if not raises:
        assert [o[0] for o in adapter[:6]] == ["ok"] * 6, adapter[:6]
        assert adapter[0][1][0] == "Held", "control: the claim did not return a Held"


@pytest.mark.parametrize("seed", range(12))
def test_p2_a_generated_sequence_with_races_is_answered_alike_per_call(scene, start, seed):
    """A call sequence drawn from the census and the races, in no tick's order, over the same seed: every call's result
    or exception equal, adapter and port. (P2)"""
    ops = R.generate(seed)
    adapter = run_over("adapter", scene, start, ops)
    port = run_over("port", scene, start, ops)

    assert_same(ops, adapter, port)
    assert sum(1 for o in adapter if o[0] != "skipped") >= 8, f"the sequence mostly skipped: {adapter}"


def test_p2_a_tenant_not_active_refuses_a_claim_alike(scene, start):
    """The tenant goes to offboarding after the helper started: the claim raises the store's `TenantInactive` over both.
    (P2, Exceptions that cross)"""
    from defender.tests.support.jobs._jobs1342 import restate_tenant

    outcomes = {}
    for impl in R.IMPLS:
        R.reset_learning(scene.dsn)
        if impl == "adapter":
            helper = None
            store_cm = R.adapter_store(scene.dsn, scene.tenant)
        else:
            helper = start()
            store_cm = contextlib.nullcontext(helper.port())
        with store_cm as store:
            call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("f/w/0/0")], kind=FINDING)
            restate_tenant(scene.dsn, scene.tenant, state="offboarding", data_root=scene.root)
            outcomes[impl] = R.Canon().outcome(store.claim)
        if helper is not None:
            helper.close()
        restate_tenant(scene.dsn, scene.tenant, state="active", data_root=scene.root)

    assert outcomes["adapter"][0] == "raised", outcomes["adapter"]
    assert outcomes["adapter"][1].endswith(".TenantInactive"), outcomes["adapter"]
    assert outcomes["port"] == outcomes["adapter"]


_AFTER_CUT = [("batches",), ("lane_work",), ("work",), ("commit_record",), ("claim",), ("renew", 0),
              ("record_commit", 0), ("in_review", 0, 5), ("note_check", 0, True), ("note_refusal", 0),
              ("needs_person", 0), ("end_review", 0, "closed"), ("expire_own", 0), ("abandon_clean", 0),
              ("abandon_crashed", 0), ("end_no_commits", 0), ("abandon", 0), ("take_over", 0)]


@pytest.mark.parametrize("impl", R.IMPLS)
def test_p2_o3_a_store_outage_is_the_one_outage_exception_on_every_verb(scene, start, monkeypatch, impl):
    """Both sides reach the database through a relay the test cuts after a batch was claimed and put in review: every
    census verb then raises `StoreUnavailable` (never an `OSError`, never the driver's exception), and the interface's
    settings are still answered. (P2, Outages)"""
    E = _exceptions()
    relay = J.TcpRelay(scene.dsn)
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", relay.dsn)  # the helper's own login, read at its start
    prefix = [("claim",), ("in_review", 0, 5), ("batches",)]
    R.reset_learning(scene.dsn)
    R.seed_work(scene.dsn, scene.tenant)
    helper = None
    try:
        if impl == "adapter":
            cm = R.adapter_store(relay.dsn, scene.tenant)
        else:
            helper = start()
            cm = contextlib.nullcontext(helper.port())
        with cm as store:
            runner = R.Runner(store, scene.dsn, scene.tenant)
            before = runner.run(prefix)
            relay.cut()
            after = runner.run(_AFTER_CUT)
            settings = (float(store.renew_every), int(store.generation_ceiling))
    finally:
        relay.cut()
        if helper is not None:
            helper.close()

    assert [o[0] for o in before] == ["ok"] * 3, before
    answered = [(op, o) for op, o in zip(_AFTER_CUT, after, strict=True) if o != ("skipped",)]
    assert len(answered) >= 12, f"too few verbs met the outage: {after}"
    for op, got in answered:
        assert got[0] == "raised", (op, got)
        assert got[1] == f"{E.StoreUnavailable.__module__}.StoreUnavailable", (op, got)
    assert not issubclass(E.StoreUnavailable, OSError), "the tick reads an OSError as a forge fault"
    assert settings == (R.RENEW, 3)


# --- shapes and the wire ---------------------------------------------------------------------------------------------------


def _field_names(value: Any) -> set[str]:
    if dataclasses.is_dataclass(value):
        return {f.name for f in dataclasses.fields(value)}
    return set(getattr(value, "_fields", None) or vars(value))


@pytest.mark.parametrize("impl", R.IMPLS)
def test_p2_the_held_keeps_todays_fields_and_the_batch_view_drops_the_token_and_the_lease_owner(scene, start, impl):
    """`Held` has every field today's has; the listed batch has every field of today's view but the token and the lease
    owner, in both implementations; the settings are numbers. (Shapes)"""
    from defender.learning_store import BatchView, Held

    R.reset_learning(scene.dsn)
    R.seed_work(scene.dsn, scene.tenant)
    helper = None
    cm = R.adapter_store(scene.dsn, scene.tenant) if impl == "adapter" else contextlib.nullcontext(
        (helper := start()).port())
    with cm as store:
        held = store.claim()
        views = store.batches()
        renew_every, ceiling = store.renew_every, store.generation_ceiling
    if helper is not None:
        helper.close()

    assert held is not None
    assert _field_names(held) == {f.name for f in dataclasses.fields(Held)}
    assert views
    for view in views:
        assert _field_names(view) == {f.name for f in dataclasses.fields(BatchView)} - {"token", "lease_owner"}
    assert float(renew_every) == R.RENEW
    assert int(ceiling) == 3


_TAGS = {"a_bytes": {"$bytes": "AAAA"}, "a_type": {"$type": "Held", "batch_id": "x"},
         "a_datetime": {"__type__": "datetime", "value": "2026-01-01T00:00:00+00:00"},
         "a_nested": [{"$bytes": "AAAA"}, {"k": {"$bytes": "AAAA"}}], "text": '{"$bytes": "AAAA"}'}


def test_p2_a_payload_that_looks_like_a_wire_tag_comes_back_as_the_data_it_is(scene, start):
    """A finding whose payload holds `{"$bytes": ...}` and other tag-shaped values (the job socket's own bytes tag among
    them) reaches the tick as exactly the dicts and strings the adapter returns, in a claim's items and in `work()`:
    nothing decodes a type from model text. (Wire)"""
    row = {**finding("tag/w/0/0"), **_TAGS}
    results = {}
    for impl in R.IMPLS:
        R.reset_learning(scene.dsn)
        call(scene.dsn, "publish_findings", scene.tenant, "run-tags", [row], kind=FINDING)
        helper = None
        cm = R.adapter_store(scene.dsn, scene.tenant) if impl == "adapter" else contextlib.nullcontext(
            (helper := start()).port())
        with cm as store:
            items = store.work()
            held = store.claim()
        if helper is not None:
            helper.close()
        results[impl] = (items, held)

    for impl, (items, held) in results.items():
        [item] = items
        [(_kind, _key, payload)] = held.items
        for where in (item.payload, payload):
            assert {k: where[k] for k in _TAGS} == _TAGS, (impl, where)
    canon = R.Canon()
    assert canon(results["port"]) == R.Canon()(results["adapter"])
    assert canon(results["adapter"])  # control: the comparison saw something


# --- trusted values (P1) -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("impl", R.IMPLS)
def test_p1_thresholds_are_the_trusted_side_s_and_a_claim_waits_for_them(scene, start, monkeypatch, impl):
    """The threshold in the helper's environment (the adapter's binding) is three: two findings are no claim, three are;
    the tick sends no threshold. (P1, O5)"""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "3")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "3")
    R.reset_learning(scene.dsn)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding(f"t/w/0/{i}") for i in range(2)], kind=FINDING)
    helper = None
    limits = {**R.due_thresholds(), "finding": 3, "questioner_finding": 3}
    cm = R.adapter_store(scene.dsn, scene.tenant, thresholds=limits) if impl == "adapter" else contextlib.nullcontext(
        (helper := start()).port())
    with cm as store:
        two = (store.lane_work().claimable, store.claim())
        call(scene.dsn, "publish_findings", scene.tenant, "run-2", [finding("t/w/0/9")], kind=FINDING)
        three = (store.lane_work().claimable, store.claim())
    if helper is not None:
        helper.close()

    assert two == (False, None), two
    assert three[0] is True, three
    assert three[1] is not None, three
    assert len(three[1].items) == 3, three


@pytest.mark.parametrize("impl", R.IMPLS)
def test_o5_the_store_acts_on_its_own_tenant_and_never_shows_another_s_work(scene, start, impl):
    """Another active tenant has work and a lapsed batch: `work()` lists only the bound tenant's items and the other
    tenant's batch is never moved. (O5, P1)"""
    register_tenant(scene.dsn, OTHER_TENANT)
    R.reset_learning(scene.dsn)
    call(scene.dsn, "publish_findings", scene.tenant, "run-own", [finding("own/w/0/0")], kind=FINDING)
    call(scene.dsn, "publish_findings", OTHER_TENANT, "run-other", [finding("other/w/0/0")], kind=FINDING)
    theirs = call(scene.dsn, "claim", OTHER_TENANT, AUTHOR_LANE, owner="other-tick", thresholds=ONE)
    lapse_lease(scene.dsn, str(theirs.batch_id))
    before = snapshot(scene.dsn, OTHER_TENANT)
    helper = None
    cm = R.adapter_store(scene.dsn, scene.tenant) if impl == "adapter" else contextlib.nullcontext(
        (helper := start()).port())
    with cm as store:
        keys = [i.key for i in store.work()]
        listed = [str(b.id) for b in store.batches()]
    if helper is not None:
        helper.close()

    assert keys == ["own/w/0/0"], keys
    assert str(theirs.batch_id) not in listed
    assert snapshot(scene.dsn, OTHER_TENANT) == before


@pytest.mark.parametrize("impl", R.IMPLS)
def test_p1_abandon_is_the_recoveries_and_the_batch_is_the_lapsed_ones(scene, start, impl):
    """`abandon(batch_id)` has no `by`: a lapsed own-lane batch listed by the tick ends `abandoned` for its lost holder,
    its items back with the attempt counted (the recovery's abandon, not a person's). (P1, `by="recovery"` bound)"""
    R.reset_learning(scene.dsn)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("r/w/0/0")], kind=FINDING)
    crashed = call(scene.dsn, "claim", scene.tenant, AUTHOR_LANE, owner="crashed-tick", thresholds=ONE)
    lapse_lease(scene.dsn, str(crashed.batch_id))
    helper = None
    cm = R.adapter_store(scene.dsn, scene.tenant) if impl == "adapter" else contextlib.nullcontext(
        (helper := start()).port())
    with cm as store:
        [lapsed] = [b for b in store.batches() if b.lapsed]
        store.abandon(str(lapsed.id))
    if helper is not None:
        helper.close()

    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.phase, batch.outcome, batch.reason) == ("ended", "abandoned", "its holder was lost"), batch
    assert item_states(scene.dsn, scene.tenant) == {"r/w/0/0": ("waiting", 1, None)}


# --- settings answered at the port's start ------------------------------------------------------------------------------


def test_p2_the_port_answers_the_helpers_own_settings_not_a_default(scene, start, monkeypatch):
    """A renewal period of 7.5 s in the helper's environment (not the default) is the port's `renew_every`; the
    generation ceiling is the adapter's. (Census settings)"""
    R.settings_env(monkeypatch, renew=7.5)
    helper = start()
    port = helper.port()
    with R.adapter_store(scene.dsn, scene.tenant, renew=7.5) as adapter:
        assert float(port.renew_every) == 7.5
        assert float(adapter.renew_every) == 7.5
        assert port.generation_ceiling == adapter.generation_ceiling


@pytest.mark.parametrize(("lease", "starts"), [(10, False), (_STOP_WINDOW, False), (_STOP_WINDOW + 1, True)])
def test_o6_the_port_refuses_to_start_when_the_lease_is_not_longer_than_the_stop_window(scene, start, monkeypatch,
                                                                                      lease, starts):
    """A lease of 10 s or of 22 s (the stop window) is refused at the port's start with a `ValueError` naming both
    durations (amendment 4); 23 s starts. A batch the unwind could not reach then lapses to recovery. (O6)"""
    R.settings_env(monkeypatch, lease=lease)
    helper = start()
    if starts:
        assert helper.port() is not None
        return
    with pytest.raises(ValueError, match=r"\d") as refused:
        helper.port()
    for seconds in (lease, _STOP_WINDOW):
        assert re.search(rf"(?<![\d.]){seconds}(\.0+)?(?![\d.])", str(refused.value)), (
            f"the refusal does not name {seconds} s: {refused.value}")
    assert call(scene.dsn, "batches", scene.tenant) == [], "a store verb ran on a port that refused to start"


# --- Flow 2, batch references: the helper's one check ----------------------------------------------------------------


def _by_id(store: Any, batch_id: str) -> dict[str, Any]:
    return {
        "take_over": lambda: store.take_over(batch_id),
        "abandon": lambda: store.abandon(batch_id),
        "end_review": lambda: store.end_review(batch_id, expect_phase="in_review", outcome="closed", published=[], held=[]),
        "note_check": lambda: store.note_check(batch_id),
        "note_refusal": lambda: store.note_refusal(batch_id, Why.batch("forge_refused", "the forge said no")),
        "needs_person": lambda: store.needs_person(batch_id, Why.batch("foreign_commits_remote", "a foreign tip")),
    }


def _holder_verbs(store: Any, held: Any) -> dict[str, Any]:
    return {
        "renew": lambda: store.renew(held),
        "record_commit": lambda: store.record_commit(held, oid(1), oid(2), oid(3), changes_of("agent/lessons/x.md")),
        "in_review": lambda: store.in_review(held, 5, {}),
        "expire_own": lambda: store.expire_own(held),
        "abandon_clean": lambda: store.abandon_clean(held),
        "abandon_crashed": lambda: store.abandon_crashed(held),
        "end_no_commits": lambda: store.end_no_commits(held, {}),
    }


def _refused(E: SimpleNamespace, calls: dict[str, Any], dsn: str, tenant: str, *, but: tuple[str, ...] = ()) -> None:
    """Each call raises `ForeignBatch` and moves nothing (those named in `but` are skipped: they are asserted apart)."""
    for name, make in calls.items():
        if name in but:
            continue
        before = snapshot(dsn, tenant), item_states(dsn, tenant)
        with pytest.raises(E.ForeignBatch):
            make()
        assert (snapshot(dsn, tenant), item_states(dsn, tenant)) == before, f"{name} moved a batch it was refused"


def _operator_batch(dsn: str, tenant: str, *, lapsed: bool = False) -> Any:
    """An own-lane working batch held by someone else (an operator's host drain): its `Held`, the real token and all."""
    call(dsn, "publish_findings", tenant, "run-op", [finding("op/w/0/0")], kind=FINDING)
    held = call(dsn, "claim", tenant, AUTHOR_LANE, owner="operator-host-drain", thresholds=ONE)
    assert held is not None, "premise: the operator's drain claimed"
    if lapsed:
        lapse_lease(dsn, str(held.batch_id))
    return held


def test_o5_an_id_the_helper_never_issued_is_foreign_to_every_verb_by_id(scene, start):
    """A random id, a malformed one and another tenant's real batch: every verb by id raises `ForeignBatch` (not
    `LookupError`, not the store's answer) and nothing moves. (O5, Batch references)"""
    E = _exceptions()
    register_tenant(scene.dsn, OTHER_TENANT)
    call(scene.dsn, "publish_findings", OTHER_TENANT, "run-other", [finding("other/w/0/0")], kind=FINDING)
    theirs = call(scene.dsn, "claim", OTHER_TENANT, AUTHOR_LANE, owner="other-tick", thresholds=ONE)
    lapse_lease(scene.dsn, str(theirs.batch_id))
    mine = _operator_batch(scene.dsn, scene.tenant, lapsed=True)
    port = start().port()
    for batch_id in (str(uuid.uuid4()), "not-an-id", str(theirs.batch_id), str(mine.batch_id)):  # mine: lapsed, never listed
        _refused(E, _by_id(port, batch_id), scene.dsn, scene.tenant)
    assert snapshot(scene.dsn, OTHER_TENANT)[0][1] == "working"


def test_o5_a_live_working_batch_of_the_lane_is_listed_but_no_verb_may_reach_it(scene, start):
    """An operator's host drain holds the lane's working batch: the tick lists it, and every verb by id on it, and every
    holder's verb with its real `Held` (token read from the database), raises `ForeignBatch` and moves nothing. (O5)"""
    E = _exceptions()
    operator = _operator_batch(scene.dsn, scene.tenant)
    port = start().port()
    listed = port.batches()
    assert [str(b.id) for b in listed] == [str(operator.batch_id)], "control: the live batch is listed"

    _refused(E, _by_id(port, str(operator.batch_id)), scene.dsn, scene.tenant)
    _refused(E, _holder_verbs(port, operator), scene.dsn, scene.tenant)
    assert call(scene.dsn, "batches", scene.tenant)[0].lease_owner == "operator-host-drain"


def test_o5_an_id_issued_while_live_is_refused_once_it_lapses_until_the_next_listing_issues_it(scene, start):
    """Listed live, then lapsed: `take_over` raises `ForeignBatch` (the helper judges what it issued, not the batch's
    state now); listed again as lapsed it is taken over, and the lease it holds then is renewable. (O5)"""
    E = _exceptions()
    operator = _operator_batch(scene.dsn, scene.tenant)
    port = start().port()
    port.batches()
    lapse_lease(scene.dsn, str(operator.batch_id))
    _refused(E, {"take_over": lambda: port.take_over(str(operator.batch_id))}, scene.dsn, scene.tenant)

    [view] = port.batches()
    assert view.lapsed
    held = port.take_over(str(view.id))
    port.renew(held)
    assert lease_seconds_left(scene.dsn, str(operator.batch_id)) > 0


def test_o5_a_listed_lapsed_batch_is_acted_on_by_id_but_its_lease_verbs_need_this_sessions_lease(scene, start):
    """A lapsed own-lane batch listed: `abandon` and `take_over` accept its id; a `Held` forged from the real token
    is refused by every lease verb until this session holds the lease. (O5, Batch references)"""
    E = _exceptions()
    operator = _operator_batch(scene.dsn, scene.tenant, lapsed=True)
    port = start().port()
    [view] = port.batches()
    assert view.lapsed
    _refused(E, _holder_verbs(port, operator), scene.dsn, scene.tenant)

    held = port.take_over(str(view.id))
    port.renew(held)
    port.abandon_clean(held)
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.phase, batch.outcome) == ("ended", "abandoned")


def test_o5_another_reconcile_lanes_batch_is_closed_or_checked_but_never_taken_over_abandoned_or_parked(scene, start):
    """A lead-lane batch in review, listed: `end_review`, `note_check` and `note_refusal` are accepted; `take_over`,
    `abandon` and `needs_person` raise `ForeignBatch`. (O5, #1546; the lane's working batch is the next case's)"""
    E = _exceptions()
    review = lead_review = R.lead_batch_in_review(scene.dsn, scene.tenant)
    port = start().port()
    assert review in [str(b.id) for b in port.batches()]

    _refused(E, _by_id(port, lead_review), scene.dsn, scene.tenant, but=("end_review", "note_check", "note_refusal"))
    port.note_check(lead_review)
    assert port.note_refusal(lead_review, Why.batch("forge_refused", "the forge said no"))[0] == 1
    assert port.end_review(lead_review, expect_phase="in_review", outcome="closed", published=[], held=[]) is True


def test_o5_another_lanes_working_batch_cannot_be_parked_or_ended_and_its_lapsed_one_cannot_be_taken(scene, start):
    """#1546's live lead batch: not listed as issued, so `end_review`, `note_check`, `note_refusal`, `needs_person`,
    `abandon` and `take_over` on it raise `ForeignBatch` and it does not move; lapsed, it is still not issued (a lead
    batch is issued only in review or closing), so every verb raises `ForeignBatch` again. (O5, Flow 2, decision 4)"""
    E = _exceptions()
    for n in range(2):
        call(scene.dsn, "add_pitfall", scene.tenant, {"schema_version": 1, "source_run": f"r{n}", "system": "elastic",
                                                      "query_id": "elastic.esql", "goal": f"goal {n}",
                                                      "executed_query": f"q {n}", "stderr_digest": "",
                                                      "error_class": "agent-fixable"})
    lead = call(scene.dsn, "claim", scene.tenant, LEAD_LANE, owner="lead-drain", thresholds=ONE)
    assert lead is not None, "premise: the lead lane's batch is working"
    port = start().port()
    port.batches()
    _refused(E, _by_id(port, str(lead.batch_id)), scene.dsn, scene.tenant)
    lapse_lease(scene.dsn, str(lead.batch_id))
    port.batches()
    _refused(E, _by_id(port, str(lead.batch_id)), scene.dsn, scene.tenant)  # a lapsed lead batch is never issued: every verb


def test_o5_an_id_one_session_was_issued_is_foreign_to_the_next(scene, start):
    """The registry is per session: the lead batch listed (issued) to one helper is refused by a second helper that
    never listed it. (O5)"""
    E = _exceptions()
    review = R.lead_batch_in_review(scene.dsn, scene.tenant)
    first = start()
    assert review in [str(b.id) for b in first.port().batches()]
    first.close()
    second = start().port()

    _refused(E, _by_id(second, review), scene.dsn, scene.tenant)
    assert second.batches()
    assert review in [str(b.id) for b in second.batches()]
    assert second.note_check(review) is None


def test_o5_a_listed_in_review_batch_of_the_lane_is_accepted_by_every_verb_by_id(scene, start):
    """An own-lane batch in review, listed: `note_check`, `note_refusal` and `needs_person` are accepted (it is parked for
    a person); the lease verbs still need a lease. (O5)"""
    call(scene.dsn, "publish_findings", scene.tenant, "run-r", [finding("rv/w/0/0")], kind=FINDING)
    held = call(scene.dsn, "claim", scene.tenant, AUTHOR_LANE, owner="earlier-tick", thresholds=ONE)
    call(scene.dsn, "in_review", held, 12, {})
    port = start().port()
    [view] = port.batches()
    assert view.phase == "in_review"

    port.note_check(str(view.id))
    assert port.note_refusal(str(view.id), Why.batch("forge_refused", "no"))[0] == 1
    port.needs_person(str(view.id), Why.batch("foreign_commits_remote", "a foreign tip"))
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert batch.phase == "needs_person"


# --- O6: stop through the port ---------------------------------------------------------------------------------------------


def _signal_and_wait(container: Any) -> None:
    os.kill(os.getpid(), signal.SIGTERM)  # the helper's own handler takes it on the test's main thread
    assert container.stopping.wait(20), "the helper never stopped the container"


def test_o6_after_the_signal_a_lease_is_refused_with_stop_whatever_else_the_lane_says(scene, monkeypatch):
    """After the signal `claim` raises the store's `Stop`, each time it is asked, even though the lane has a working
    batch (not `LaneBusy`). `take_over` is the next case's. (O6, Stop signal)"""
    from defender.learning_store import Stop

    R.settings_env(monkeypatch)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("s/w/0/0")], kind=FINDING)
    got: dict[str, Any] = {}

    def body(c: Any) -> None:
        port = R.container_port(c, scene.tenant)
        got["held"] = port.claim()
        _signal_and_wait(c)
        for name, make in (("claim", port.claim), ("claim-lane-busy", port.claim)):
            try:
                make()
            except Exception as raised:  # noqa: BLE001 — kept for the case
                got[name] = raised

    R.in_post_step(scene, body, rc=143)

    assert got["held"] is not None, "control: the claim before the signal was answered"
    for name in ("claim", "claim-lane-busy"):
        assert type(got.get(name)) is Stop, (name, got.get(name))


def test_o6_after_the_signal_take_over_of_a_listed_lapsed_batch_is_stop(scene, monkeypatch):
    """A lapsed batch listed before the signal: after it `take_over` raises `Stop` and the batch is still lapsed and
    unmoved; the unwind's `abandon` on it is answered. (O6)"""
    from defender.learning_store import Stop

    R.settings_env(monkeypatch)
    lapsed = _operator_batch(scene.dsn, scene.tenant, lapsed=True)
    got: dict[str, Any] = {}

    def body(c: Any) -> None:
        port = R.container_port(c, scene.tenant)
        [view] = port.batches()
        got["listed"] = view.lapsed
        _signal_and_wait(c)
        before = snapshot(scene.dsn, scene.tenant)
        try:
            port.take_over(str(view.id))
        except Exception as raised:  # noqa: BLE001 — kept for the case
            got["take_over"] = raised
        got["unmoved"] = snapshot(scene.dsn, scene.tenant) == before
        port.abandon(str(view.id))

    R.in_post_step(scene, body, rc=143)

    assert got["listed"] is True
    assert type(got.get("take_over")) is Stop, got.get("take_over")
    assert got["unmoved"], "a refused take_over moved the batch"
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.id, batch.phase, batch.outcome) == (lapsed.batch_id, "ended", "abandoned")


_UNWIND = {
    "abandon_clean": (lambda s, h: s.abandon_clean(h), ("ended", "abandoned", "stopped"), "waiting"),
    "end_no_commits": (lambda s, h: s.end_no_commits(h, {}), ("ended", "abandoned", "no commits"), "waiting"),
    "abandon_crashed": (lambda s, h: s.abandon_crashed(h), ("ended", "abandoned", "its holder crashed"), "waiting"),
    "in_review": (lambda s, h: s.in_review(h, 5, {}), ("in_review", None, None), "in_batch"),
}


@pytest.mark.parametrize("verb", sorted(_UNWIND))
def test_o6_the_stop_windows_unwind_verbs_are_answered_after_the_signal(scene, monkeypatch, verb):
    """A batch claimed before the signal: after it the unwind's `abandon_clean`, `end_no_commits`, `abandon_crashed` and
    `in_review` are answered, with the store's effect. (O6)"""
    R.settings_env(monkeypatch)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("u/w/0/0")], kind=FINDING)
    do, (phase, outcome, reason), item = _UNWIND[verb]

    def body(c: Any) -> None:
        port = R.container_port(c, scene.tenant)
        held = port.claim()
        _signal_and_wait(c)
        do(port, held)

    R.in_post_step(scene, body, rc=143)

    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.phase, batch.outcome, batch.reason) == (phase, outcome, reason), batch
    assert item_states(scene.dsn, scene.tenant)["u/w/0/0"][0] == item


def test_o6_a_renewal_after_the_signal_is_answered_and_extends_the_lease_and_a_commit_is_recorded(scene, monkeypatch):
    """`renew` after the signal answers as the adapter does (not `Stop`): the lease is longer afterwards; a commit pushed in
    the stop window is recorded; the lease is then given up with `expire_own`. (O6; r5's first draft refused `renew`)"""
    from defender.tests.support.shared._postgres1339 import execute

    R.settings_env(monkeypatch)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("w/w/0/0")], kind=FINDING)
    got: dict[str, Any] = {}

    def body(c: Any) -> None:
        port = R.container_port(c, scene.tenant)
        held = port.claim()
        execute(scene.dsn, "UPDATE learning.batches SET lease_expiry = now() + interval '100 seconds'")
        _signal_and_wait(c)
        got["before"] = lease_seconds_left(scene.dsn, str(held.batch_id))
        port.renew(held)
        got["after"] = lease_seconds_left(scene.dsn, str(held.batch_id))
        port.record_commit(held, oid(7), oid(1), oid(2), changes_of("agent/lessons/w.md"))
        port.expire_own(held)

    R.in_post_step(scene, body, rc=143)

    assert got["after"] > got["before"] + 100, got
    assert [c.commit for c in call(scene.dsn, "commit_record", scene.tenant)] == [oid(7)]
    assert call(scene.dsn, "batches", scene.tenant)[0].lapsed is True


def test_o6_every_reader_and_reconciling_verb_is_answered_after_the_signal(scene, monkeypatch):
    """After the signal the readers and the reconcile verbs on listed ids are answered as before. (O6, Stop signal)"""
    R.settings_env(monkeypatch)
    review = R.lead_batch_in_review(scene.dsn, scene.tenant)
    got: dict[str, Any] = {}

    def body(c: Any) -> None:
        port = R.container_port(c, scene.tenant)
        port.batches()
        _signal_and_wait(c)
        got["views"] = [str(b.id) for b in port.batches()]
        got["work"], got["lane_work"], got["record"] = port.work(), port.lane_work(), port.commit_record()
        port.note_check(review)
        got["refusal"] = port.note_refusal(review, Why.batch("forge_refused", "no"))
        got["ended"] = port.end_review(review, expect_phase="in_review", outcome="closed", published=[], held=[])

    R.in_post_step(scene, body, rc=143)

    assert review in got["views"]
    assert got["refusal"][0] == 1
    assert got["ended"] is True


# --- Outages the port adds: lost transport, unreadable answers, the helper's own faults ----------------------------------

_LOST = [TimeoutError("the 300 s wait ran out"), ConnectionResetError("reset"), ConnectionRefusedError("refused"),
         FileNotFoundError("the socket is gone"), BrokenPipeError("broken"), OSError("some other transport fault")]


@pytest.mark.parametrize("fault", _LOST, ids=lambda f: type(f).__name__)
def test_p2_a_lost_transport_or_a_timed_out_wait_latches_the_port_dead(scene, start, fault):
    """One request that never gets an answer raises `StoreUnavailable` (never the `OSError`), and every later call on that
    port raises it at once without reaching the socket: nothing is claimed after it. (Outages)"""
    E = _exceptions()
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("l/w/0/0")], kind=FINDING)
    helper = start()
    wire = R.Recorder(helper.ask)
    port = helper.port(wire)
    assert port.work(), "control: the live port answered"
    wire.fail_next(fault)

    with pytest.raises(E.StoreUnavailable) as lost:
        port.batches()
    assert not isinstance(lost.value, OSError)
    reached = len(wire.calls)
    forged = SimpleNamespace(batch_id=str(uuid.uuid4()), token=1)
    for make in (port.batches, port.lane_work, port.work, port.commit_record, port.claim, lambda: port.renew(forged),
                 lambda: port.abandon_clean(forged), lambda: port.expire_own(forged),
                 lambda: port.note_check(str(uuid.uuid4())), lambda: port.take_over(str(uuid.uuid4()))):
        with pytest.raises(E.StoreUnavailable):
            make()
    assert len(wire.calls) == reached, "a call reached the socket after the port was dead"
    assert call(scene.dsn, "batches", scene.tenant) == [], "a claim got through a dead port"


@pytest.mark.parametrize("verb", ["batches", "lane_work", "work", "commit_record", "claim"])
@pytest.mark.parametrize("answer", [{}, {"junk": "x"}, {"ok": 1}, {"result": "not the shape"}], ids=repr)
def test_p2_an_answer_that_is_not_the_wire_s_reads_as_the_outage_exception(scene, start, verb, answer):
    """A helper answer the port cannot read (nothing, or something of another shape) raises `StoreUnavailable`, not a
    `KeyError` or `TypeError` the tick has no handler for. (Outages)"""
    E = _exceptions()
    helper = start()
    wire = R.Recorder(helper.ask)
    port = helper.port(wire)
    wire.answer_next(answer)

    with pytest.raises(E.StoreUnavailable):
        getattr(port, verb)()


def test_p2_a_reply_the_socket_cannot_decode_is_the_outage_exception(scene, start):
    """`job_socket.ask` raising `ValueError` for an unreadable answer reaches the tick as `StoreUnavailable`. (Outages)"""
    E = _exceptions()
    helper = start()
    wire = R.Recorder(helper.ask)
    port = helper.port(wire)
    wire.fail_next(ValueError("an unreadable job socket message"))

    with pytest.raises(E.StoreUnavailable):
        port.work()


def test_p2_a_fault_the_helpers_store_raises_outside_the_list_crosses_as_the_outage_exception(scene, start):
    """A database fault no tick handler exists for (a table gone) raises `StoreUnavailable` at the port, with nothing of
    the helper's text as another type; the port is not dead after it. (Exceptions that cross)"""
    from defender.tests.support.shared._postgres1339 import execute

    E = _exceptions()
    port = start().port()
    execute(scene.dsn, "ALTER TABLE learning.commits RENAME TO commits_moved_away")
    try:
        with pytest.raises(E.StoreUnavailable):
            port.commit_record()
    finally:
        execute(scene.dsn, "ALTER TABLE learning.commits_moved_away RENAME TO commits")
    assert port.work() == [], "the port stayed dead after a helper fault"


# --- P1, P6: what the job can send, and which kinds can send it ----------------------------------------------------------


def _drive_every_verb(port: Any) -> None:
    """Each census verb once, in whatever state the store is in (a refusal is fine: the request is what is recorded)."""
    held = None
    steps = [lambda: port.batches(), lambda: port.lane_work(), lambda: port.work(statuses=("waiting",), kind=None),
             lambda: port.commit_record()]
    for step in steps:
        with contextlib.suppress(Exception):
            step()
    with contextlib.suppress(Exception):
        held = port.claim()
    ghost = SimpleNamespace(tenant_id="t", batch_id=str(uuid.uuid4()), lane="author", kind="author", branch="b", token=1,
                            owner="o", items=(), replaces=None, feedback_pr=None)
    target = held if held is not None else ghost
    other = str(uuid.uuid4())
    for step in (lambda: port.record_commit(target, oid(1), oid(2), oid(3), changes_of("a.md")), lambda: port.renew(target),
                 lambda: port.in_review(target, 5, {}), lambda: port.note_check(other), lambda: port.note_refusal(other, Why.batch("forge_refused", "x")),
                 lambda: port.needs_person(other, Why.batch("foreign_commits_remote", "x")),
                 lambda: port.end_review(other, expect_phase="in_review", outcome="closed", published=[], held=[]),
                 lambda: port.take_over(other), lambda: port.abandon(other), lambda: port.expire_own(target),
                 lambda: port.abandon_clean(target), lambda: port.end_no_commits(target, {}),
                 lambda: port.abandon_crashed(target)):
        with contextlib.suppress(Exception):
            step()


def _recorded(scene, start) -> list[tuple[str, dict[str, Any]]]:
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("p/w/0/0")], kind=FINDING)
    helper = start()
    wire = R.Recorder(helper.ask)
    _drive_every_verb(helper.port(wire))
    helper.close()
    seen: list[tuple[str, dict[str, Any]]] = []
    for name, fields in wire.calls:
        if name != "launch" and (name, fields) not in seen:
            seen.append((name, fields))
    return seen


def test_p1_no_request_the_port_sends_has_a_field_for_the_tenant_lane_owner_thresholds_or_by(scene, start):
    """The requests the tick's verbs send, recorded: none names or carries the tenant, a lane, an owner, thresholds, `by`
    or a lease; and one with such a field added is refused `bad-fields` with the store unmoved. (P1, O5)"""
    from defender import job_host

    seen = _recorded(scene, start)
    assert len({name for name, _ in seen}) >= 1, f"the port sent too little to judge: {seen}"
    assert len(seen) >= 10, f"the port sent too little to judge: {seen}"
    banned = {"tenant", "tenant_id", "lane", "owner", "thresholds", "by", "lease", "grace", "settings"}
    for name, fields in seen:
        assert not banned & set(fields), (name, fields)
        assert scene.tenant not in json.dumps(fields), (name, fields)
        assert "recovery" not in json.dumps(fields), (name, fields)

    helper = start()
    before = snapshot(scene.dsn, scene.tenant), item_states(scene.dsn, scene.tenant)
    for name, fields in seen:
        for extra, value in (("tenant", OTHER_TENANT), ("lane", "lead_author"), ("owner", "forged"),
                             ("thresholds", {"finding": 1000}), ("by", "person")):
            with pytest.raises(job_host.Refused) as refused:
                helper.ask(name, **{**fields, extra: value})
            assert refused.value.code == "bad-fields", (name, extra, refused.value.code)
    assert (snapshot(scene.dsn, scene.tenant), item_states(scene.dsn, scene.tenant)) == before


@pytest.mark.parametrize("kind", ["learning", "investigation"])
def test_p6_o5_a_learning_job_and_an_investigation_get_no_store_request(scene, start, kind):
    """Every request the tick's port sends, replayed from a learning job's container and an investigation's, is refused
    `not-for-kind` while the kind's own request is answered. (O5, P6)"""
    seen = _recorded(scene, start)
    assert seen, "the port sent nothing to replay"
    job_id = str(uuid.uuid4())
    if kind == "investigation":
        scene.plant(job_id)
    got: dict[str, Any] = {}

    def job(c) -> int:
        got["own"] = c.request("pass", id=job_id) if kind == "learning" else c.request("launch")
        got["refusals"] = {(name, json.dumps(fields, sort_keys=True)): c.refused(name, **fields).code
                           for name, fields in seen}
        return 0

    run_kind(scene, kind, job, job_id=job_id)

    assert got["own"] is not None, "control: the kind's own request was refused"
    assert set(got["refusals"].values()) == {"not-for-kind"}, got["refusals"]


# --- O4: the tick itself, over both ----------------------------------------------------------------------------------


@pytest.fixture(params=R.IMPLS)
def tick(request, scene, start, tmp_path):
    """The tick's world over the scene's tenant, and `run(trigger)`: one author tick with its store the adapter or the
    port. Seeds go through the adapter (`_drain_support.author_drain`'s default); only the tick under test takes `store=`."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, drain_paths, product_repo

    paths = drain_paths(scene.t, product_repo(tmp_path, adapters=("cmdb",)))
    world = SimpleNamespace(t=scene.t, dsn=scene.dsn, paths=paths, scratch=tmp_path, impl=request.param)

    def run(trigger: Any) -> int:
        if request.param == "adapter":
            with R.adapter_store(scene.dsn, scene.tenant) as store:
                return author_drain(scene.t, paths, trigger=trigger, box=BoxSpy(), store=store)
        helper = start()
        try:
            return author_drain(scene.t, paths, trigger=trigger, box=BoxSpy(), store=helper.port())
        finally:
            helper.close()

    world.run = run
    return world


def test_o4_a_tick_claims_authors_and_opens_a_review_through_either_store(scene, tick):
    """Findings waiting: the tick claims them, the curator writes a lesson, the branch and PR are made, and the batch is
    in review with its items in the batch. (O4)"""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME, remote_branches

    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("t1")], kind=FINDING)
    writer = LessonWriter({LESSON_NAME: lesson_citing("t1")})

    rc = tick.run(writer)

    assert rc == 0
    assert len(writer.served) == 1, "the curator was not served the claimed batch"
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert batch.phase == "in_review", batch
    assert batch.pr_number is not None, batch
    assert [b for b in remote_branches(scene.t.remote)] == [batch.branch]
    assert item_states(scene.dsn, scene.tenant)["t1"][0] == "in_batch"


def test_o4_a_merged_review_is_reconciled_through_either_store(scene, tick):
    """A lesson a person merged on the forge: the next tick ends its review `merged` and its items `published`. (O4)"""
    from defender.tests.support.learning.core._store1278 import authored_and_merged

    batch_id, _branch = authored_and_merged(tick)

    tick.run(LessonWriter({}))

    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (str(batch.id), batch.phase, batch.outcome) == (batch_id, "ended", "merged"), batch
    assert item_states(scene.dsn, scene.tenant)["f1"][0] == "published"


def test_o4_a_lapsed_batch_is_recovered_through_either_store(scene, tick):
    """A holder died with nothing on any branch and its lease and grace ran out: the tick recovers the batch (its holder
    was lost) and the items it held are claimed again. (O4)"""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import LESSON_NAME

    _operator_batch(scene.dsn, scene.tenant, lapsed=True)
    writer = LessonWriter({LESSON_NAME: lesson_citing("op/w/0/0")})

    tick.run(writer)

    old, *later = call(scene.dsn, "batches", scene.tenant)
    assert (old.phase, old.outcome, old.reason) == ("ended", "abandoned", "its holder was lost"), old
    assert later, "the recovered items were not claimed again"
    assert item_states(scene.dsn, scene.tenant)["op/w/0/0"][1] == 1, "the lost holder's attempt was not counted"


def _wire_names_of(helper: R.PostStepHelper, verb: str) -> set[str]:
    """The request names the port sends for `verb()` alone (a reference port over a recorder, its start's own requests
    left out): the wire's names are the implementer's, so they are learned, never spelled."""
    recorder = R.Recorder(helper.ask)
    port = helper.port(recorder)
    before = len(recorder.calls)
    getattr(port, verb)()
    names = {name for name, _fields in recorder.calls[before:]}
    assert names, f"premise: `{verb}()` sent nothing"
    return names


def test_amendment1_the_real_post_step_hands_its_tick_the_port_and_the_tick_s_calls_arrive_at_the_helper(scene, start):
    """`post_step.main` over a real helper (the job socket forwards to it), only its tick replaced: the tick is called
    with `store=` a port (not the adapter), and a call it makes on that store is a request the helper received. The
    container's environment holds no database address, so a store the post-step built for itself could not be reached.
    (Amendment 1, O4)"""
    from defender.learning_store.tick import StoreAdapter
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container

    helper = start()
    listing = _wire_names_of(helper, "batches")
    reference = type(helper.port())
    got: dict[str, Any] = {}
    asked: list = []

    def tick(paths: Any, **kwargs: Any) -> int:
        got["kwargs"] = set(kwargs)
        got["store"] = kwargs.get("store")
        got["batches"] = got["store"].batches()
        return 0

    code = post_step_in_container(None, scene.tenant, forward=helper.ask, record=asked, author_tick=tick)

    assert code == 0
    assert got["kwargs"] == {"store"}, got["kwargs"]
    assert type(got["store"]) is reference, f"the tick's store is a {type(got['store']).__name__}, not the job container's port"
    assert not isinstance(got["store"], StoreAdapter)
    assert got["batches"] == [], "premise: the scene's tenant holds no batch"
    assert listing <= {name for name, _fields in asked}, f"the tick's listing never reached the helper: {asked}"


def test_amendment1_the_real_post_step_s_default_tick_reads_the_lane_through_the_helper(scene, start):
    """`post_step.main` over a real helper with nothing replaced (no tick, no curator: nothing is due, so none is asked
    for): the default tick, `author_drain(paths, store=store)`, ends 0 and its reconcile's listing of the tenant's batches
    is a request the helper received. With no address in the environment, a default tick that opened its own store
    would raise instead. (Amendment 1, O4, Flow 2)"""
    from defender.tests.learning.branch.test_1344_post_step import post_step_in_container

    R.reset_learning(scene.dsn)
    helper = start()
    listing = _wire_names_of(helper, "batches")
    asked: list = []

    code = post_step_in_container(None, scene.tenant, forward=helper.ask, record=asked)

    assert code == 0
    assert listing <= {name for name, _fields in asked}, f"the default tick's listing never reached the helper: {asked}"
    assert call(scene.dsn, "batches", scene.tenant) == [], "nothing was due: no batch should exist"


def test_o6_a_stopping_tick_returns_its_unpushed_batch_through_the_port(scene, start, tmp_path, monkeypatch):
    """The helper is signalled, then the tick's process (a forked child, as `TickChild`): its unwind goes through the
    port after the signal and returns the batch (ended `abandoned`, items waiting). The tick, its store and its
    curator are today's; only the store is the port. Runs the helper in this process; needs a main thread for SIGTERM
    in the child. (O6)"""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, drain_paths, product_repo

    R.settings_env(monkeypatch)
    call(scene.dsn, "publish_findings", scene.tenant, "run-1", [finding("st1")], kind=FINDING)
    paths = drain_paths(scene.t, product_repo(tmp_path, adapters=("cmdb",)))
    marker = tmp_path / "curator-blocked"
    writer = LessonWriter({"lesson.md": lesson_citing("st1")}, before_commit=blocked_in_subprocess(marker))
    got: dict[str, Any] = {}

    def body(c: Any) -> None:
        store = R.container_port(c, scene.tenant)
        child = TickChild(lambda: author_drain(scene.t, paths, trigger=writer, box=BoxSpy(), store=store),
                          tmp_path / "result.json")
        try:
            await_file(marker)
            _signal_and_wait(c)
            child.terminate()
            got["child"] = child.wait()
        finally:
            with contextlib.suppress(OSError):
                os.kill(child.pid, signal.SIGKILL)

    R.in_post_step(scene, body, rc=143)

    assert "child" in got, "the tick never ended"
    [batch] = call(scene.dsn, "batches", scene.tenant)
    assert (batch.phase, batch.outcome, batch.reason) == ("ended", "abandoned", "stopped"), (batch, got)
    assert item_states(scene.dsn, scene.tenant)["st1"][0] == "waiting"
