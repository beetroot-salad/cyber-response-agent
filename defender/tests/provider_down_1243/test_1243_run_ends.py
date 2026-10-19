from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _review_bundle as RB
from defender.tests import _triplet_947 as T
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.provider_down_1243 import _spec1243 as P

L3 = P.L3
LEAD = "l-001"
CORR = "CORR-1243: correlation summary delivered."


def _down_at(n: int = 1, model: str = "fake") -> S.LeadFault:
    """A scripted conversation whose `n`th request raises `ProviderDown`."""
    return S.LeadFault(raise_on=n, exc=P.provider_down_fault(model))


def _store(stores: list) -> Path:
    assert stores, "the run opened no session store"
    return stores[-1].path


def test_o3_main_down_ends_the_run_provider_down_with_no_report_and_exit_4(tmp_path: Path) -> None:
    stores: list = []
    main = S.MainScript([S.call("read_file", path="alert.json"), S.text(S.DONE)],
                        fault=_down_at(2))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]},
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert main.requests == 2, f"MAIN made {main.requests} requests; the fault is on its 2nd"
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


def test_o3_a_main_lead_down_stamps_its_session_and_ends_the_run(tmp_path: Path) -> None:
    stores: list = []
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={L3: [S.text(CORR)], LEAD: [S.list_verbs("cmdb"), S.text("unreached")]},
        lead_faults={LEAD: _down_at(2)},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.router.requests(LEAD) == 2, "MAIN's lead never reached its failing request"
    P.assert_ended_provider_down(d)
    ended = P.sessions(_store(stores))
    assert ended.get(P.gather_agent(LEAD)) == P.PROVIDER_DOWN, (
        f"the lead's session reads {ended.get(P.gather_agent(LEAD))!r}, not provider-down")
    assert ended.get("main") == P.PROVIDER_DOWN


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


def test_o3_correlation_lead_provider_down_is_not_a_lead_ending(tmp_path: Path) -> None:
    """O3 (amends #1222 A2): a `ProviderDown` raised in l-00c passes the lead's catch-all like
    `BudgetKill` — the same stop as the real-retrier scenario, from the typed failure alone."""
    d = S.run_alert(tmp_path, leads={L3: [S.text(CORR)]}, lead_faults={L3: _down_at(1)})
    assert d.router.dispatched(L3), "l-00c never ran"
    assert d.main.requests == 0, "MAIN ran after the correlation lead's provider went down"
    P.assert_ended_provider_down(d)


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
    timed_out = P.sym("runtime.run_end", "TRUNCATED_BY_TIMED_OUT")
    assert P.sessions(_store(stores)).get(P.gather_agent(L3)) == timed_out, (
        "the correlation lead cut mid-backoff is not stamped timed out")


#: How long a lens waits for the event it is gated on before giving up (a gate that never ran
#: the other lens) — a bound on a broken scenario, never reached on a conforming one.
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
    for role in P.sym("runtime.challenge_gate", "REVIEW_ROLES"):
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
    stages = P.sym("runtime.review_roles", "ReviewStages")(
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
    """O3/D5 (R7): with both lenses answering, a down COMPOSER ends the run `provider-down`
    the same way, and the round's traces are marked incomplete."""
    events: list[str] = []
    composer = _Lens(exc=P.provider_down_fault("review"), events=events, name="composer")
    support, ablation = _Lens(events=events, name="support"), _Lens(events=events, name="ablation")
    stages = P.sym("runtime.review_roles", "ReviewStages")(
        support=support, ablation=ablation, composer=composer)
    d = _review_run(tmp_path, stages, events)
    assert support.finished >= 1, "the lenses never answered — the composer was never reached"
    assert composer.started >= 1, "the review gate never dispatched the composer"
    P.assert_ended_provider_down(d)
    _assert_round_marked_incomplete(d)


def test_o3_d5_a_review_stage_failing_otherwise_still_fails_the_review_closed(tmp_path: Path) -> None:
    stores: list = []
    support = _Lens(exc=lambda: RuntimeError("lens broke"))
    stages = P.sym("runtime.review_roles", "ReviewStages")(
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

    def visualize(run: Any, **kw: Any) -> None:
        run_common.visualize(run, **kw)
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
    from defender._episode_handle import Episode

    assert P.PROVIDER_DOWN_EXIT not in P.TAKEN_EXITS
    assert P.sym("run", "UNSERVABLE_EXIT") != P.PROVIDER_DOWN_EXIT
    _base, src, _root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn(exits={"b": P.PROVIDER_DOWN_EXIT})
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    with Episode.open(ep) as episode:
        T.episode_view(episode)
        exits = P.mod("learning.branch.cli").start_family(
            episode, ["a", "b"], spawn=spawn, tenant_id=T.SOURCE_TENANT)
    assert exits.get("b") == P.PROVIDER_DOWN_EXIT
    records = {p.stem: p.read_text(encoding="utf-8") for p in ep.rglob("world_records/*.yaml")}
    assert "b" in records, f"no world record for the sibling that exited 4: {sorted(records)}"
    assert P.sym("learning.branch.outcome", "DID_NOT_FINISH") in records["b"]
    assert "a" not in records, "a sibling that exited 0 was recorded as failed"


@pytest.mark.parametrize(("kill", "member"), [
    (lambda: P.sym("hooks.budget_enforcer", "BudgetKill")("run budget spent"), "TRUNCATED_BY_BUDGET"),
    (lambda: P.sym("runtime.circuit_breaker", "RunAborted")(5, ["cmdb"]), "TRUNCATED_BY_ABORTED"),
], ids=["budget", "aborted"])
def test_d4_exit_4_is_provider_downs_alone(tmp_path: Path, kill: Any, member: str) -> None:
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=kill))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(CORR)]})
    assert main.requests == 1, f"MAIN made {main.requests} requests; the kill is on its first"
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") == P.sym("runtime.run_end", member), d.summary
    assert d.rc == 0, f"a run ended {member} exited {d.rc}; only provider-down exits 4"


SIBLING_TENANT = "acme"
SIBLING_WORLD = "b"


def _sibling_episode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A launched episode a sibling process can run as (`test_1222_judge_and_episode`'s
    `_source` + `_launch` shape): a finished source run on tenant `acme` (the #947 runs base's
    branchable run, recorded: its alert and record at the front door's places), the episode primed from
    it by the REAL launcher door (`cli.prepare_episode`) with its container made, and the
    family manifest (worlds a, b, c) written. The episodes root is pointed at its parent."""
    from defender.run_repository import Run

    planted = S.plant_tenant(SIBLING_TENANT)
    _base, src = T.runs_base(tmp_path, tenant_id=SIBLING_TENANT, recorded=True)
    accepted = planted.accept()
    with P.mod("learning.branch.cli").prepare_episode(
            T.EPISODE_ID, Run.at(src), data_root=accepted.data_root) as episode:
        with accepted.runs_repository().episode(episode.dir.name, held=episode) as view:
            view.create_container()
        ep = Path(episode.dir)
    T.write_family(ep, T.family_doc(source_run_dir=str(src)))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(ep.parent))
    return ep


def _run_sibling(tmp_path: Path, ep: Path, main: S.MainScript) -> S.Drive:
    """World `b`'s sibling through the REAL `run.main --episode/--world` door; its lifecycle
    seam drives the REAL investigation (`_spec1222.drive_run`, the replay harness) over the run
    folder the door materialized, with `main` as MAIN's model."""
    d = S.new_drive(tmp_path, main=main)

    def lifecycle(**kw: Any) -> dict:
        return S.drive_run(d, Path(kw["run"].run_dir), tenant=kw["tenant"].tenant)

    argv = ["--episode", ep.name, "--world", SIBLING_WORLD, "--tenant", SIBLING_TENANT,
            "--no-learn"]
    try:
        d.rc = P.sym("run", "main")(argv, lifecycle=lifecycle, visualize=lambda *_a, **_k: None,
                                    preflight=lambda *_a, **_k: 0, ticket_writer=S.NoTicket())
    except SystemExit as exit_:
        d.refusal = exit_.code if isinstance(exit_.code, str) else None
        d.rc = exit_.code if isinstance(exit_.code, int) else 1
    except Exception as e:  # noqa: BLE001 — kept for the test to assert on
        d.raised = e
    return d


@pytest.mark.parametrize(("fault", "ends", "rc"), [
    (P.provider_down_fault("sibling"), P.PROVIDER_DOWN, P.PROVIDER_DOWN_EXIT),
    (lambda: P.sym("hooks.budget_enforcer", "BudgetKill")("world budget spent"), "budget", 0),
], ids=["provider-down", "control-budget"])
def test_o6_d4_a_sibling_world_ending_provider_down_exits_4(tmp_path: Path,
                                                           monkeypatch: pytest.MonkeyPatch,
                                                           fault: Any, ends: str, rc: int) -> None:
    ep = _sibling_episode(tmp_path, monkeypatch)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=fault))
    d = _run_sibling(tmp_path / "sibling", ep, main)
    assert d.run_dir is not None, (
        f"the sibling never reached its run (rc={d.rc!r}, refusal={d.refusal!r}, raised={d.raised!r})")
    assert main.requests == 1, f"the sibling's MAIN made {main.requests} requests"
    assert d.raised is None, f"the sibling crashed instead of ending {ends}: {d.raised!r}"
    assert (d.summary or {}).get("truncated_by") == ends, d.summary
    assert d.rc == rc, f"a sibling world that ended {ends} exited {d.rc!r}; D4/O6 say {rc}"
