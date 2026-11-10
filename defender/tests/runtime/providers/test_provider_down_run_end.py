from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest

from defender import run as run_mod
from defender.providers import SETUP_STATUSES, ProviderDown
from defender.hooks.budget_enforcer import BudgetKill
from defender.investigation.challenge_gate import REVIEW_ROLES
from defender.investigation.review_roles import ReviewStages
from defender.learning.branch import cli
from defender.learning.branch.outcome import DID_NOT_FINISH
from defender.records import run_end
from defender.records import run_end as rb
from defender.run_common import learning_refusal_gate
from defender.systems.circuit_breaker import RunAborted
from defender.tests.support.runtime.permissions import _review_bundle as RB
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared.filesystem import _spec1047 as T47
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.runtime.providers import _spec1243 as P

L3 = P.L3
LEAD = "l-001"
CORR = "CORR-1243: correlation summary delivered."
SHAPES = ["bare", *sorted(P.GROUPED_PROVIDER_DOWN)]  # a bare ProviderDown, and one inside each group shape
CONTROL_SHAPES = sorted(P.GROUPED_WITHOUT_PROVIDER_DOWN)


def _down_at(n: int = 1, model: str = "fake") -> S.LeadFault:
    """A scripted conversation whose `n`th request raises `ProviderDown`."""
    return S.LeadFault(raise_on=n, exc=P.provider_down_fault(model))


def _store(stores: list) -> Path:
    assert stores, "the run opened no session store"
    return stores[-1].path
def _grouped_down(shape: str) -> P.Recorded:
    """The `shape` group around a `ProviderDown` as the retrier raises it, recorded."""
    return P.Recorded(P.GROUPED_PROVIDER_DOWN[shape](P.provider_down_fault()))

def _assert_fired_a_group(fault: P.Recorded, *, holding_provider_down: bool) -> BaseException:
    """The fault fired exactly once, as an exception group that does (or does not) hold a
    `ProviderDown`. This is the guard that the scenario put a group, not a bare failure, on its
    path."""
    assert len(fault.raised) == 1, (
        f"the grouped fault fired {len(fault.raised)} times; the scenario raises it once")
    group = fault.raised[0]
    assert isinstance(group, BaseExceptionGroup), f"the fault raised {group!r}, not a group"
    if holding_provider_down:
        assert P.carries(group, ProviderDown), group
    else:
        # Read without `ProviderDown`, so the control does not lean on the class it controls for.
        assert all(isinstance(leaf, (RuntimeError, ValueError)) for leaf in _leaves(group)), group
    return group

def _leaves(exc: BaseException) -> list[BaseException]:
    if isinstance(exc, BaseExceptionGroup):
        return [leaf for inner in exc.exceptions for leaf in _leaves(inner)]
    return [exc]

def _assert_not_provider_down(d: S.Drive, stores: list) -> None:
    """The run did not end provider-down on any channel: summary, run-end record, exit code, or
    MAIN's session stamp."""
    assert (d.summary or {}).get("truncated_by") != P.PROVIDER_DOWN, d.summary
    rec = P.sidecar(d.folder)
    assert rec is None or rec["truncated_by"] != P.PROVIDER_DOWN, rec
    assert d.rc != P.PROVIDER_DOWN_EXIT, f"a run with no ProviderDown exited {d.rc}"
    assert P.sessions(_store(stores)).get("main") != P.PROVIDER_DOWN, (
        "MAIN's session is stamped provider-down by a group that holds no ProviderDown")

def _assert_escaped_as_itself(d: S.Drive, group: BaseException) -> None:
    """MAIN's loop on a group with no `ProviderDown` (and no `CallRecordWriteFailed`):
    `_drive_agent` re-raises it and the run crashes on it, every failure it carries escaping,
    none dropped or relabelled. The members' identity is pinned, not the group's."""
    assert d.raised is not None, (
        "a group holding no ProviderDown was swallowed: the run did not crash on it "
        f"(summary {d.summary!r})")
    assert {id(e) for e in _leaves(d.raised)} == {id(e) for e in _leaves(group)}, (
        f"what escaped ({d.raised!r}) is not the group's own failures ({group!r})")

def _correlation_ending(d: S.Drive) -> str:
    """The correlation section of MAIN's opening message, with the run folder and id
    normalised away. It holds the lead's framed summary or its one named ending."""
    assert d.run_dir is not None
    _heading, body = S.correlation_section(d.main.opening_message)
    return S.normalize(body, run_dir=d.run_dir, run_id=d.run_dir.name)

def _provider_down(shape: str, at: int) -> tuple[S.LeadFault, Any]:
    """A fault that raises `ProviderDown` on request `at`, bare or inside the `shape` group, and the
    check that it fired in that shape."""
    if shape == "bare":
        return S.LeadFault(raise_on=at, exc=P.provider_down_fault()), lambda: None
    fault = _grouped_down(shape)
    return (S.LeadFault(raise_on=at, exc=fault),
            lambda: _assert_fired_a_group(fault, holding_provider_down=True))


@pytest.mark.parametrize("shape", SHAPES)
def test_o3_d6_main_request_down_ends_the_run_provider_down_with_no_report_and_exit_4(
        tmp_path: Path, shape: str) -> None:
    stores: list = []
    fault, fired = _provider_down(shape, at=2)
    main = S.MainScript([S.call("read_file", path="alert.json"), S.text(S.DONE)], fault=fault)
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert main.requests == 2, f"MAIN made {main.requests} requests; the fault is on its 2nd"
    fired()
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN, (
        "MAIN's session is not stamped provider-down")


@pytest.mark.parametrize("shape", SHAPES)
def test_o3_d6_a_main_lead_down_stamps_its_session_and_ends_the_run(tmp_path: Path, shape: str) -> None:
    stores: list = []
    fault, fired = _provider_down(shape, at=2)
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: fault},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its failing request"
    fired()
    P.assert_ended_provider_down(d)
    ended = P.sessions(_store(stores))
    assert ended.get(P.gather_agent(LEAD)) == P.PROVIDER_DOWN, (
        f"the lead's session reads {ended.get(P.gather_agent(LEAD))!r}, not provider-down")
    assert ended.get("main") == P.PROVIDER_DOWN, "MAIN's session is not stamped provider-down"


@pytest.mark.parametrize("shape", SHAPES)
def test_o3_d6_correlation_lead_provider_down_is_not_a_lead_ending_and_stops_before_main(
        tmp_path: Path, shape: str) -> None:
    """A `ProviderDown` raised in l-00c, bare or inside a group, passes the lead's catch-all like
    `BudgetKill`: the run stops before MAIN."""
    stores: list = []
    fault, fired = _provider_down(shape, at=1)
    d = S.run_alert(tmp_path, leads={L3: [S.text(CORR)]}, lead_faults={L3: fault},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.dispatched(L3), "l-00c never ran"
    fired()
    assert d.main.requests == 0, (
        f"MAIN was asked for {d.main.requests} turn(s) after the correlation lead's provider "
        "went down: the lead ended dispatch_raised and the run went on")
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN, (
        "MAIN's session is not stamped provider-down")


def test_o3_scenario2_main_behind_the_real_retrier_ends_provider_down(tmp_path: Path) -> None:
    main = P.MainFailing([S.text(S.DONE)], P.ALWAYS_503)
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    wrap_model=P.wrap_with(P.instant_policy(), kinds=("main",)))
    assert main.attempts == P.MAX_ATTEMPTS, (
        f"MAIN's request reached its model {main.attempts} times; the retrier makes 4 attempts")
    assert all(a == main.inbound[0] for a in main.inbound), "a retry changed MAIN's request"
    P.assert_ended_provider_down(d)


def test_o3_concurrent_leads_down_end_the_run_once(tmp_path: Path) -> None:
    stores: list = []
    two = S.Turn(tool_calls=(S.gather(LEAD, "cmdb").tool_calls[0],
                             S.gather("l-002", "cmdb").tool_calls[0]))
    d = S.run_alert(
        tmp_path, main=[two, S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.text("x")], "l-002": [S.text("y")]},
        lead_faults={LEAD: _down_at(1), "l-002": _down_at(1)},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.dispatched(LEAD) or d.router.dispatched("l-002"), "no lead ran"
    P.assert_ended_provider_down(d)
    ended = P.sessions(_store(stores))
    stamped = [lead for lead in (LEAD, "l-002") if ended.get(P.gather_agent(lead)) == P.PROVIDER_DOWN]
    assert stamped, f"neither down lead's session is stamped provider-down: {ended}"
    for lead in (LEAD, "l-002"):
        assert ended.get(P.gather_agent(lead)) in (None, P.PROVIDER_DOWN), (
            f"{lead}'s session reads {ended.get(P.gather_agent(lead))!r}: a down lead ended as "
            "something else")


def test_o3_scenario5_correlation_lead_down_stops_before_main(tmp_path: Path) -> None:
    stores: list = []
    router = P.LeadsFailing({L3: [S.text(CORR)]},
                            {L3: P.Plan(exc=P.no_response, fail_from=1)})
    d = S.run_alert(tmp_path, router=router,
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores,
                    wrap_model=P.wrap_with(P.instant_policy(), kinds=("gather",)))
    assert router.attempts(L3) == P.MAX_ATTEMPTS, (
        f"l-00c's request reached its model {router.attempts(L3)} times; the retrier makes 4")
    assert d.main.requests == 0, (
        f"MAIN was asked for {d.main.requests} turn(s) after the correlation lead met a down "
        "provider: the run went on (dispatch_raised) instead of stopping before MAIN")
    P.assert_ended_provider_down(d)
    assert P.sessions(_store(stores)).get("main") == P.PROVIDER_DOWN


def test_o3_a_deadline_cutting_a_backoff_keeps_its_own_ending(tmp_path: Path) -> None:
    stall_s = 12.0

    async def stall(_seconds: float) -> None:
        await asyncio.sleep(stall_s)

    stores: list = []
    router = P.LeadsFailing({L3: [S.text(CORR)]}, {L3: P.ALWAYS_503})
    main = S.MainScript([S.text(S.DONE)])
    began = time.monotonic()
    d = S.run_alert(tmp_path, main=main, router=router, limits=S.with_deadline(S.SHORT_DEADLINE_S),
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores,
                    wrap_model=P.wrap_with(P.retry_policy(sleep=stall), kinds=("gather",)))
    assert router.attempts(L3) == 1, (
        f"l-00c made {router.attempts(L3)} attempts: the deadline should land in the first backoff")
    assert main.first_at is not None, "MAIN never started: the backoff was not cut by the deadline"
    assert main.first_at - began < stall_s, "MAIN started only after the stalled backoff finished"
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") != P.PROVIDER_DOWN, d.summary
    timed_out = run_end.TRUNCATED_BY_TIMED_OUT
    assert P.sessions(_store(stores)).get(P.gather_agent(L3)) == timed_out, (
        "the correlation lead cut mid-backoff is not stamped timed out")


_GATE_BOUND_S = 30.0


class _Lens:
    """A review stage: answers `reply` after `delay` seconds on the loop, or raises `exc()`;
    records whether it started, finished, or was cancelled, and appends "<name>-raised" /
    "<name>-finished" to `events`. `raised` is an event it sets just before raising; `after`
    is an event it waits for (bounded) before its `delay` starts — so a sibling's hold can be
    measured from the moment the failing lens raised, not from when both started."""

    def __init__(self, reply: str = RB.LENS_READING, *, delay: float = 0.0,  # noqa: PLR0913 — one switch per lens behaviour
                 exc: Any = None, events: list[str] | None = None, name: str = "lens",
                 raised: asyncio.Event | None = None, after: asyncio.Event | None = None) -> None:
        self.reply = reply
        self.delay = delay
        self.exc = exc
        self.events = events if events is not None else []
        self.name = name
        self.raised = raised
        self.after = after
        self.started = 0
        self.finished = 0
        self.cancelled = 0

    async def __call__(self, _request: Any) -> str:
        self.started += 1
        try:
            if self.after is not None:
                await asyncio.wait_for(self.after.wait(), timeout=_GATE_BOUND_S)
            if self.delay:
                await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        if self.exc is not None:
            self.events.append(f"{self.name}-raised")
            if self.raised is not None:
                self.raised.set()
            raise self.exc()
        self.finished += 1
        self.events.append(f"{self.name}-finished")
        return self.reply


def _review_run(tmp_path: Path, stages: Any, events: list[str]) -> S.Drive:
    """MAIN writes the golden investigation and closes `inconclusive`, so the gate reviews;
    `events` gets "run-ended" when the run's lifecycle has returned (run.py's page step)."""
    main = S.MainScript(S.closing_main_turns("inconclusive"))
    return S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]}, review_stages=stages,
                       visualize=lambda *_a, **_k: events.append("run-ended"))


def _assert_round_marked_incomplete(d: S.Drive) -> None:
    for role in REVIEW_ROLES:
        rows = P.trace_rows(d.folder, role)
        assert any(r.get("incomplete") is True for r in rows), (
            f"the {role} trace is not marked incomplete for the round the provider ended: {rows}")


SIBLING_HOLD_S = 5.0


def test_o3_d5_a_review_stage_down_ends_the_run_after_its_sibling_settles(tmp_path: Path) -> None:
    events: list[str] = []
    failed = asyncio.Event()
    support = _Lens(exc=P.provider_down_fault("review"), events=events, name="support",
                    raised=failed)
    ablation = _Lens(delay=SIBLING_HOLD_S, events=events, name="ablation", after=failed)
    stages = ReviewStages(
        support=support, ablation=ablation, composer=RB.stage(RB.composer_reply("holds")))
    d = _review_run(tmp_path, stages, events)
    assert support.started >= 1, "the review gate never dispatched the support lens"
    assert ablation.started >= 1, (
        "the golden investigation dispatched no ablation lens — this scenario needs two lenses")
    assert "support-raised" in events, f"the support lens never raised: {events}"
    P.assert_ended_provider_down(d)
    assert ablation.cancelled == 0, (
        f"the sibling lens was cancelled ({ablation.cancelled}) while it worked on after the "
        f"failing lens raised: the gate must raise only after its lenses settle ({events})")
    assert "ablation-finished" in events, f"the sibling lens never finished: it was orphaned ({events})"
    assert "run-ended" in events, "run.py never reached its page step"
    assert events.index("support-raised") < events.index("ablation-finished") < events.index("run-ended"), (
        f"the sibling lens did not finish between the failure and the run's end ({events}): "
        "it was orphaned")
    _assert_round_marked_incomplete(d)


def test_o3_d5_the_composer_down_ends_the_run(tmp_path: Path) -> None:
    """With both lenses answering, a down composer ends the run `provider-down` the same way,
    and the round's traces are marked incomplete."""
    events: list[str] = []
    composer = _Lens(exc=P.provider_down_fault("review"), events=events, name="composer")
    support, ablation = _Lens(events=events, name="support"), _Lens(events=events, name="ablation")
    stages = ReviewStages(
        support=support, ablation=ablation, composer=composer)
    d = _review_run(tmp_path, stages, events)
    assert support.finished >= 1, "the lenses never answered — the composer was never reached"
    assert composer.started >= 1, "the review gate never dispatched the composer"
    P.assert_ended_provider_down(d)
    _assert_round_marked_incomplete(d)


def test_o3_d5_a_review_stage_failing_otherwise_still_fails_the_review_closed(tmp_path: Path) -> None:
    stores: list = []
    support = _Lens(exc=lambda: RuntimeError("lens broke"))
    stages = ReviewStages(
        support=support, ablation=_Lens(), composer=RB.stage(RB.composer_reply("holds")))
    main = S.MainScript(S.closing_main_turns("inconclusive"))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]}, review_stages=stages,
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert support.started >= 1, "the review gate never dispatched the support lens"
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") != P.PROVIDER_DOWN, d.summary
    assert d.rc == 0, f"an ordinary lens fault changed the run's exit to {d.rc}"
    assert main.requests == len(S.closing_main_turns("inconclusive")), (
        "MAIN was not given its turn after the failed review")
    # The same channels the provider-down test reads, on a run that reached them: an uncut
    # run-end record, an unstamped MAIN session, and the failed round marked incomplete.
    rec = P.sidecar(d.folder)
    assert rec is not None, "no run-end record on an uncut run"
    assert rec["truncated_by"] is None
    assert P.sessions(_store(stores)).get("main") is None
    assert any(r.get("incomplete") is True for r in P.trace_rows(d.folder, "support"))


def test_o5_a_provider_down_run_hands_its_class_to_the_post_steps_and_renders(tmp_path: Path) -> None:
    from defender import run_common

    rendered: list[Path] = []

    def visualize(run: Any, *, tenant: Any, **kw: Any) -> None:
        run_common.visualize(run, tenant=tenant, **kw)
        rendered.append(Path(run.run_dir))

    d = S.run_alert(tmp_path, main=S.MainScript([S.text(S.DONE)], fault=_down_at(1)),
                    leads={L3: [S.text(CORR)]}, no_learn=False, enqueue=run_common.enqueue_curation,
                    visualize=visualize)
    P.assert_ended_provider_down(d)
    assert d.enqueued, "run.py never reached its curation step on a provider-down run"
    assert all(kw.get("truncated_by") == P.PROVIDER_DOWN for _a, kw in d.enqueued), d.enqueued
    assert rendered, "run.py never reached its page step on a provider-down run"
    assert d.paths.runtime_html.is_file(), "the run page was not written for a provider-down run"


def test_o6_exit_4_is_new_and_a_sibling_exiting_4_did_not_finish(tmp_path: Path,
                                                                monkeypatch: pytest.MonkeyPatch) -> None:
    from defender.records._episode_handle import Episode

    assert P.PROVIDER_DOWN_EXIT not in P.TAKEN_EXITS
    assert run_mod.UNSERVABLE_EXIT != P.PROVIDER_DOWN_EXIT
    _base, src, _root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn(exits={"b": P.PROVIDER_DOWN_EXIT})
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    with Episode.open(ep) as episode:
        T.episode_view(episode)
        exits = cli.start_family(
            episode, [T.world_id(ep, label) for label in ("a", "b")], spawn=spawn, tenant_id=T.SOURCE_TENANT)
    assert exits.get(T.world_id(ep, "b")) == P.PROVIDER_DOWN_EXIT
    records = {p.stem: p.read_text(encoding="utf-8") for p in ep.rglob("world_records/*.yaml")}
    assert T.world_id(ep, "b") in records, f"no world record for the sibling that exited 4: {sorted(records)}"
    assert DID_NOT_FINISH in records[T.world_id(ep, "b")]
    assert T.world_id(ep, "a") not in records, "a sibling that exited 0 was recorded as failed"


@pytest.mark.parametrize(("kill", "member"), [
    (lambda: BudgetKill("run budget spent"), "TRUNCATED_BY_BUDGET"),
    (lambda: RunAborted(5, ["cmdb"]), "TRUNCATED_BY_ABORTED"),
], ids=["budget", "aborted"])
def test_d4_exit_4_is_provider_downs_alone(tmp_path: Path, kill: Any, member: str) -> None:
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=kill))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]})
    assert main.requests == 1, f"MAIN made {main.requests} requests; the kill is on its first"
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") == getattr(run_end, member), d.summary
    assert d.rc == 0, f"a run ended {member} exited {d.rc}; only provider-down exits 4"


@pytest.mark.parametrize(("fault", "ends", "rc"), [
    (P.provider_down_fault("sibling"), P.PROVIDER_DOWN, P.PROVIDER_DOWN_EXIT),
    (lambda: BudgetKill("world budget spent"), "budget", 0),
], ids=["provider-down", "control-budget"])
def test_o6_d4_a_sibling_world_ending_provider_down_exits_4(tmp_path: Path,
                                                           monkeypatch: pytest.MonkeyPatch,
                                                           fault: Any, ends: str, rc: int) -> None:
    ep = P.sibling_episode(tmp_path, monkeypatch)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=fault))
    d = P.run_sibling(tmp_path / "sibling", ep, main)
    assert d.run_dir is not None, (
        f"the sibling never reached its run (rc={d.rc!r}, refusal={d.refusal!r}, raised={d.raised!r})")
    assert main.requests == 1, f"the sibling's MAIN made {main.requests} requests"
    assert d.raised is None, f"the sibling crashed instead of ending {ends}: {d.raised!r}"
    assert (d.summary or {}).get("truncated_by") == ends, d.summary
    assert d.rc == rc, f"a sibling world that ended {ends} exited {d.rc!r}, not {rc}"


@pytest.mark.parametrize("shape", CONTROL_SHAPES)
def test_d6_control_a_group_without_provider_down_still_escapes_mains_loop(tmp_path: Path,
                                                                          shape: str) -> None:
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN[shape])
    stores: list = []
    main = S.MainScript([S.call("read_file", path="alert.json"), S.text(S.DONE)],
                        fault=S.LeadFault(raise_on=2, exc=fault))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert main.requests == 2, f"MAIN made {main.requests} requests; the group is on its 2nd"
    group = _assert_fired_a_group(fault, holding_provider_down=False)
    _assert_escaped_as_itself(d, group)
    _assert_not_provider_down(d, stores)


def test_d6_control_a_group_without_provider_down_from_a_main_lead_still_escapes(
        tmp_path: Path) -> None:
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN["flat"])
    stores: list = []
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: S.LeadFault(raise_on=2, exc=fault)},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its failing request"
    group = _assert_fired_a_group(fault, holding_provider_down=False)
    _assert_escaped_as_itself(d, group)
    _assert_not_provider_down(d, stores)
    assert P.sessions(_store(stores)).get(P.gather_agent(LEAD)) != P.PROVIDER_DOWN


@pytest.mark.parametrize("shape", CONTROL_SHAPES)
def test_d6_control_a_group_without_provider_down_at_the_correlation_lead_is_dispatch_raised(
        tmp_path: Path, shape: str) -> None:
    tenant = S.plant_tenant()

    def drive(label: str, exc: P.Fault | None, stores: list) -> S.Drive:
        sub = tmp_path / label
        sub.mkdir()
        faults = {L3: S.LeadFault(raise_on=1, exc=exc)} if exc is not None else None
        return S.run_alert(sub, tenant=tenant, main=S.MainScript([S.text(S.DONE)]),
                           leads={L3: [S.text(CORR)]}, lead_faults=faults,
                           store_factory=S.store_factory(sub, sink=stores), stores=stores)

    summary = drive("summary", None, [])
    bare = drive("bare", P.ordinary_error(), [])
    fault = P.Recorded(P.GROUPED_WITHOUT_PROVIDER_DOWN[shape])
    stores: list = []
    d = drive("grouped", fault, stores)
    assert d.router.dispatched(L3), "l-00c never ran"
    _assert_fired_a_group(fault, holding_provider_down=False)
    assert d.raised is None, f"the run crashed on the lead's group: {d.raised!r}"
    assert d.main.requests == 1, (
        f"MAIN was asked {d.main.requests} time(s): the run stopped before MAIN on a group "
        "holding no ProviderDown")
    assert not (d.summary or {}).get("truncated_by"), f"the run was cut: {d.summary!r}"
    assert d.rc == 0, f"rc={d.rc!r}"
    _assert_not_provider_down(d, stores)
    named = _correlation_ending(d)
    assert named != _correlation_ending(summary), (
        "the grouped run's correlation section is the summary run's: the lead's failure was "
        "not named at all")
    assert named == _correlation_ending(bare), (
        "a correlation-lead group holding no ProviderDown is named differently from the same "
        f"bare error (dispatch_raised):\n  grouped: {named!r}\n  bare:    "
        f"{_correlation_ending(bare)!r}")


def test_o5_provider_down_is_a_member_of_the_run_end_vocabulary() -> None:
    """`provider-down` is a `truncated_by` member and normalizes to itself, not to `None`, which
    every reader takes as "not cut short"."""
    assert P.PROVIDER_DOWN in rb.TRUNCATED_BY_VALUES
    assert rb.normalized_truncated_by(P.PROVIDER_DOWN) == P.PROVIDER_DOWN
    # Control on the same normalizer: an unlisted spelling still reads as None.
    assert rb.normalized_truncated_by("provider_down") is None


def test_o5_a_provider_down_run_end_record_parses(tmp_path: Path) -> None:
    """The production reader reads a provider-down run-end record back as provider-down; a
    record it refused would read as "the host said nothing"."""
    rec = rb.parse_record({"truncated_by": P.PROVIDER_DOWN, "closed_before_cut": False})
    assert rec is not None, "parse_record refuses a provider-down run-end record"
    assert rec.truncated_by == P.PROVIDER_DOWN
    # Control: the same reader refuses an out-of-vocabulary value.
    assert rb.parse_record({"truncated_by": "provider_down", "closed_before_cut": False}) is None


def test_o4_provider_down_is_not_a_forced_close_exit() -> None:
    """Provider-down is an infrastructure end like budget and store, not in the forced
    unresolved-close set, so no report.md is written for it."""
    assert P.PROVIDER_DOWN not in rb.FORCED_CLOSE_EXITS
    assert rb.TRUNCATED_BY_BUDGET not in rb.FORCED_CLOSE_EXITS
    assert rb.TRUNCATED_BY_REQUEST_LIMIT in rb.FORCED_CLOSE_EXITS  # control: the set is not empty


def test_o5_the_ticket_lane_leaves_a_provider_down_ticket_open_with_no_call(tmp_path: Path) -> None:
    for report in (False, True):
        run_dir = T47.closed_run_dir(tmp_path / f"report-{report}", report=report)
        fake = T47.record_ticket(run_dir, truncated_by=P.PROVIDER_DOWN, closed_before_cut=False)
        assert fake.calls == [], (
            f"report={report}: the lane made {fake.calls} for a provider-down run — it must "
            "make no call at all")
        assert T47.receipt(run_dir) is None


def test_o5_the_ticket_lane_records_a_provider_down_run_whose_model_had_closed(tmp_path: Path) -> None:
    run_dir = T47.closed_run_dir(tmp_path, disposition="malicious")
    fake = T47.record_ticket(run_dir, truncated_by=P.PROVIDER_DOWN, closed_before_cut=True)
    assert len(fake.records) == 1, f"a closed-before-cut provider-down run recorded {fake.calls}"
    assert "malicious" in fake.records[0].text()
    assert fake.transitions == []


def test_o5_ticket_lane_control_an_uncut_run_still_records(tmp_path: Path) -> None:
    """Positive control on the same channel: an uncut run with a report records its comment,
    so "no call" above is the provider-down arm, not a lane that never calls."""
    run_dir = T47.closed_run_dir(tmp_path, disposition="malicious")
    fake = T47.record_ticket(run_dir, truncated_by=None)
    assert len(fake.records) == 1, f"an uncut run recorded {fake.records}"


def test_o5_curation_refuses_a_provider_down_run(tmp_path: Path) -> None:
    """The learning refusal gate refuses a provider-down run because it was cut short: a
    truncated investigation never trains the corpus."""
    run_dir = T47.closed_run_dir(tmp_path, report=False)
    reason = learning_refusal_gate(run_dir, truncated_by=P.PROVIDER_DOWN)
    assert reason is not None, "curation was not refused for a provider-down run"
    assert P.PROVIDER_DOWN in reason, f"the refusal does not name the cut: {reason!r}"
    # Control: the same gate with no cut does not refuse for truncation.
    other = learning_refusal_gate(run_dir, truncated_by=None)
    assert other is None or "truncated" not in other


def test_o5_the_run_end_record_written_for_provider_down_round_trips(tmp_path: Path) -> None:
    """The production writer and reader agree on a provider-down record: written in
    `write_sidecar`'s document shape, read back by `parse_record` as the same value."""
    doc = rb.RunEnd(P.PROVIDER_DOWN, False).doc()
    assert rb.parse_record(json.loads(json.dumps(doc))) == rb.RunEnd(P.PROVIDER_DOWN, False)


@pytest.mark.parametrize(("status", "ends_run"),
                         [(s, True) for s in sorted(SETUP_STATUSES)] + [(400, False)])
def test_1447_a_lead_refused_for_its_setup_ends_the_run_and_a_400_only_the_lead(
        tmp_path: Path, status: int, ends_run: bool) -> None:
    """A lead refused with a setup status (401-404, and 412: Fireworks' suspended or blocked
    account, #1447) ends the run `provider-rejected`: every lead on the key gets the same
    answer. A 400 ends only that lead, and the run finishes. Either way the lead's session is
    stamped `provider-rejected`."""
    stores: list = []
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: S.LeadFault(raise_on=2, exc=lambda: P.http_error(status))},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its refused request"
    assert d.raised is None, f"the run crashed on a lead's {status}: {d.raised!r}"
    ended = (d.summary or {}).get("truncated_by")
    if ends_run:
        assert ended == run_end.TRUNCATED_BY_PROVIDER_REJECTED, (
            f"a lead's {status} ended the run {ended!r}, not provider-rejected")
        assert not d.paths.report.exists(), "a provider-rejected run wrote report.md"
        assert d.rc == 7, f"run.py exited {d.rc!r} on a provider-rejected run, not 7"
    else:
        assert ended is None, f"a lead's {status} ended the whole run {ended!r}; only the lead ends"
        assert d.rc == 0, f"a run whose lead was refused {status} exited {d.rc!r}, not 0"
    assert P.sessions(_store(stores)).get(P.gather_agent(LEAD)) == (
        run_end.TRUNCATED_BY_PROVIDER_REJECTED), "the refused lead's session is not stamped"
