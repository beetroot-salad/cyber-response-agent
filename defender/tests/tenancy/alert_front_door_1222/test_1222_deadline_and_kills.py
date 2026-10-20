"""The correlation phase's single deadline, and the run-level kills (budget, failure count,
operator interrupt) it must not absorb."""
from __future__ import annotations

import functools
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.tests.support.storage import _session_store_705 as SS
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.support.shared._fixture_uuid import fixture_uuid

L3 = S.L3
#: The correlation deadline every timed scenario configures (seconds).
DEADLINE_S = S.SHORT_DEADLINE_S
#: Headroom for a loaded CI runner: between the run folder existing and the lead starting, and
#: between the cut and MAIN's first request (orientation, MAIN's agent build).
SLACK_S = 5.0
#: A stalled model request: far past `DEADLINE_S + SLACK_S`, so "MAIN started in time" can only
#: mean "something cut it" — and bounded, so a missing deadline costs seconds, not `S.HANG_S`.
STALL_S = 12.0
#: The run wall clock a budget-kill scenario sets, and how long the lead's first request takes:
#: the lead starts inside the clock and makes its first tool call past it (RJ-04 d).
KILL_WALL_S = 3
KILL_DELAY_S = 3.6
#: Distinct texts the scripted lead writes, so "delivered" and "never delivered" are observable.
SUMMARY = "Window bound: 2026-09-30T07:15Z..09:15Z on detected_at. CORR-SUMMARY-6c1f: 3 scoped."
LATE = "LATE-SUMMARY-91d2: window bound late; 12 scoped, 40 unscoped."


# Observation helpers

class _Clock:
    """`run_alert(before=...)`: notes when the run folder exists (a lower bound on the lead's
    start) and remembers the folder, then runs `then` (a fault planted in the folder)."""

    def __init__(self, then: Callable[[Path], None] | None = None) -> None:
        self.at: float | None = None
        self.run_dir: Path | None = None
        self._then = then

    def __call__(self, run_dir: Path) -> None:
        self.at = time.monotonic()
        self.run_dir = Path(run_dir)
        if self._then is not None:
            self._then(Path(run_dir))


def _run_end() -> Any:
    return S.mod("runtime.run_end")


def _base_members() -> frozenset[str]:
    """The six `truncated_by` members at base (runtime/run_end.py:33-42) — the endings a lead
    MAIN dispatches keeps; the timed-out member A7 adds is none of these."""
    rb = _run_end()
    return frozenset({rb.TRUNCATED_BY_REQUEST_LIMIT, rb.TRUNCATED_BY_RETRY_EXHAUSTED,
                      rb.TRUNCATED_BY_ABORTED, rb.TRUNCATED_BY_BUDGET, rb.TRUNCATED_BY_STORE,
                      rb.TRUNCATED_BY_DEAD_END})


def _agent(lead: str) -> str:
    return f"{S.sym('runtime.agent_role', 'GATHER_AGENT_ID_PREFIX')}{lead}"


def _session_ending(stores: list, lead: str) -> str | None:
    """The `truncated_by` stamped on `lead`'s gather session, read straight off the real store
    file (a fresh connection, so a store the run closed still reads)."""
    assert stores, "the run opened no session store"
    con = sqlite3.connect(str(stores[-1].path))
    try:
        rows = con.execute("SELECT truncated_by FROM session WHERE agent_id = ?",
                           (_agent(lead),)).fetchall()
    finally:
        con.close()
    assert len(rows) == 1, f"expected one session for {_agent(lead)}, found {rows!r}"
    return rows[0][0]


def _assert_timed_out_member(value: str | None, *, who: str) -> str:
    """`value` is the timed-out member: a `truncated_by` member that reads back as itself, and
    none of the six base endings (its spelling is the implementer's)."""
    assert value is not None, (
        f"{who}'s session carries no ending: a timed-out lead reads back as one that finished "
        "(RJ-10: stamped nothing at base)")
    read_back = _run_end().normalized_truncated_by(value)
    assert read_back == value, (
        f"{who}'s session is stamped {value!r}, which normalized_truncated_by reads back as "
        f"{read_back!r} — not a member of the truncated_by vocabulary (RJ-10, RF-S3)")
    assert value not in _base_members(), (
        f"{who}'s timed-out session reads back as the base ending {value!r}: 'timed out' is "
        "named as something else")
    return value


def _assert_lead_ran(d: S.Drive) -> None:
    """The design's behaviour every test here rides on: `l-00c` was dispatched on this fresh run
    (A4) — at base the generic alert never dispatches it (c3)."""
    assert d.router.dispatched(L3), (
        f"l-00c never ran: the correlation lead is dispatched on every fresh run, before MAIN's "
        f"opening message is built (A4, D3); gather conversations: {d.router.leads()}")


def _assert_main_never_asked(d: S.Drive, why: str) -> None:
    assert d.main.requests == 0, (
        f"MAIN was asked for {d.main.requests} turn(s) although {why}: the stop was absorbed and "
        "the run went on")


def _prose(d: S.Drive) -> str:
    """MAIN's opening message as HARNESS prose (every untrusted frame removed), normalized for
    run id and folder, without the workspace's run-folder listing (which lists incidental
    files). Two runs whose correlation ended the same way compare equal."""
    assert d.run_dir is not None
    parts = []
    for head, body in S.sections(d.opening_message):
        if head.startswith("## Run dir"):
            continue
        parts.append(f"{head}\n{body}")
    return S.normalize("".join(parts), run_dir=d.run_dir, run_id=d.run_dir.name)


def _assert_summary_delivered(d: S.Drive, text: str) -> None:
    opening = d.opening_message
    assert any(text in body for body in S.framed_bodies(opening)), (
        "the correlation lead's summary is not inside a frame of MAIN's opening message — MAIN's "
        "first request did not follow the lead's end (A4)")
    assert text not in S.harness_text(opening), "the summary sits outside its frame"


def _assert_never_delivered(d: S.Drive, text: str) -> None:
    """`text` (a late summary, a count) reached nothing MAIN read, nor the lead's stored summary."""
    if d.main.requests:
        assert text not in d.main.history_text, (
            f"{text[:24]!r}... reached MAIN: a response the deadline cut was delivered late")
    stored = d.gather_summary(L3)
    assert stored is None or text not in stored, (
        "the lead's stored summary holds the late response the deadline cut")


def _assert_killed(d: S.Drive, member: str, exit_reason: str) -> None:
    """The run stopped through the existing early-stop path: a summary naming the kill."""
    assert d.raised is None, f"the run crashed instead of stopping on its kill: {d.raised!r}"
    assert d.summary, "run_investigation returned no run summary"
    assert d.summary.get("truncated_by") == member, (
        f"the run did not stop on the {member} kill: truncated_by "
        f"{d.summary.get('truncated_by')!r}, exit {d.summary.get('exit_reason')!r}")
    assert d.summary.get("exit_reason") == exit_reason, d.summary


def _assert_stopped_with(d: S.Drive, error: type[BaseException]) -> None:
    """A setup fault stops the run loudly WITH the setup error: it escapes the run, or the run's
    summary names it as the exit."""
    named = (isinstance(d.raised, error)
             or (d.summary or {}).get("exit_reason") == error.__name__)
    assert named, (
        f"the setup fault ({error.__name__}) did not stop the run loudly: raised {d.raised!r}, "
        f"summary {d.summary!r}")


def _assert_stopped_loudly(d: S.Drive) -> None:
    """Any loud stop: an escaped error, or a summary naming an exit class and a reason."""
    summary = d.summary or {}
    stopped = d.raised is not None or (
        _run_end().normalized_truncated_by(summary.get("truncated_by")) is not None
        and bool(summary.get("exit_reason")))
    assert stopped, f"the run did not stop loudly: raised {d.raised!r}, summary {summary!r}"


def _wire_records(run_dir: Path) -> list[dict]:
    return read_jsonl_rows(RunPaths(run_dir).wire_log)


# Scripts and faults (data)

def _alerts_call(i: int = 0) -> S.Turn:
    """One correlation call on the granted pair (`elastic.alerts`)."""
    return S.query("elastic", "alerts", {"native_query": f'host.hostname:"app-7" AND seq:{i}'})


def _parallel(system: str, verb: str, n: int, *, start: int = 0) -> S.Turn:
    """ONE model response carrying `n` concurrent calls with distinct params (PR-14's shape)."""
    def params(i: int) -> dict:
        if (system, verb) == ("elastic", "alerts"):
            return {"native_query": f'host.hostname:"app-7" AND seq:{i}'}
        if system == "identity":
            return {"user": f"svc-{i}"}
        return {"host": f"host-{i}"}

    return S.Turn(tool_calls=tuple(
        ("query", {"system": system, "verb": verb, "params": params(i)})
        for i in range(start, start + n)))


def _kill_limit() -> int:
    """The run-level failure kill's count (`circuit_breaker.RUN_FAIL_KILL_LIMIT`)."""
    return int(S.sym("runtime.circuit_breaker", "RUN_FAIL_KILL_LIMIT"))


def _enforce_flag() -> str:
    return str(S.sym("runtime.driver", "BUDGET_ENFORCE_FLAG"))


class _AgentAppendFault(SS.FaultStore):
    """`FaultStore` whose append fault counts only the appends ONE agent makes (`agent_id`), so
    "the first append MAIN's session makes" is data, not a calibrated count of the lead's
    appends. It injects only: the real file is put into the spec's real state, the real call
    follows. Local until the shared machinery carries an agent-keyed store fault."""

    def __init__(self, real: Any, fault: SS.StoreFault, *, agent_id: str) -> None:
        super().__init__(real, fault)
        self._agent_id = agent_id

    def append(self, session_id: Any, messages: Any, **kw: Any) -> Any:
        self.appends.append({"session_id": session_id, "messages": list(messages), **kw})
        if kw.get("agent_id") == self._agent_id:
            self._maybe_break("append")
        return self._real.append(session_id, messages, **kw)


def _main_append_fault_store(tmp: Path, sink: list) -> Callable[..., Any]:
    """`run_investigation(store_factory=...)`: a REAL store whose file is filled to its growth
    ceiling at MAIN's first append — after the lead produced its output (RJ-01)."""
    base = SS.runs_base(tmp)
    fault = SS.StoreFault(on="append", after=0, mode="disk-full")

    def factory(case_id: str, run_dir: Path) -> Any:
        real = SS.store_mod().open_store(case_id=case_id, sessions=S.sym("run_repository", "SessionPaths")(base))
        handle = _AgentAppendFault(real, fault, agent_id="main")
        sink.append(handle)
        return handle

    return factory


def _tree_without_main_prompt(tmp: Path) -> Path:
    """A deployed tree that is this checkout's in every entry but one: MAIN's prompt file
    (`SKILL.md`, read when MAIN's agent is built) is a directory — a real file-system state."""
    tree = tmp / "deployed-defender"
    tree.mkdir(parents=True)
    for entry in S.DEFENDER.iterdir():
        if entry.name != "SKILL.md":
            (tree / entry.name).symlink_to(entry)
    (tree / "SKILL.md").mkdir()
    return tree


# --- the four kills from other causes (n12), shared with the demands that name one ---------

def _budget_kill_during_lead(tmp: Path, tenant: S.Planted, monkeypatch: pytest.MonkeyPatch, *,
                             run_id: str, stores: list, **kw: Any) -> S.Drive:
    """Budget enforcement on; the run's wall clock (KILL_WALL_S) expires while the lead's first
    model request is in flight, so its first tool call meets the kill (RJ-04 d)."""
    with monkeypatch.context() as m:
        m.setenv(_enforce_flag(), "true")
        return S.run_alert(
            tmp, tenant=tenant, run_id=run_id,
            leads={L3: [_alerts_call(), S.text(SUMMARY)]},
            lead_faults={L3: S.LeadFault(delay=KILL_DELAY_S)},
            limits=S.default_limits(wall_clock_timeout=KILL_WALL_S, grace_seconds=0),
            store_factory=S.store_factory(tmp, sink=stores), stores=stores, **kw)


def _assert_budget_kill_during_lead(d: S.Drive, stores: list) -> None:
    result, = (r for r in read_jsonl_rows(RunPaths(d.folder).tool_trace)
               if r.get("type") == "result")
    assert result["duration_ms"] >= KILL_DELAY_S * 1000 - 1

    _assert_lead_ran(d)
    assert d.router.requests(L3) >= 1, "the lead never made its model request"
    _assert_main_never_asked(d, "a budget kill was raised at the lead's own tool call")
    _assert_killed(d, _run_end().TRUNCATED_BY_BUDGET, "BudgetKill")
    assert _session_ending(stores, L3) == _run_end().TRUNCATED_BY_BUDGET, (
        "the lead's session does not read as killed by the budget — the kill was turned into "
        "one of the lead's own endings")


def _kill_by_mains_failures(tmp: Path, tenant: S.Planted, *, run_id: str, stores: list,
                            correlation: list[S.Turn] | None = None) -> S.Drive:
    """MAIN's own lead (`l-001`, cmdb) fails RUN_FAIL_KILL_LIMIT calls in one response."""
    return S.run_alert(
        tmp, tenant=tenant, run_id=run_id,
        main=[S.gather("l-001", "cmdb"), S.text(S.DONE)],
        leads={L3: correlation or [S.text(SUMMARY)],
               "l-001": [_parallel("cmdb", "get-host", _kill_limit()), S.text("no host")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.",))),
        store_factory=S.store_factory(tmp, sink=stores), stores=stores)


def _store_fault_after_lead_output(tmp: Path, tenant: S.Planted, *, run_id: str,
                                   stores: list, **kw: Any) -> S.Drive:
    return S.run_alert(tmp, tenant=tenant, run_id=run_id, leads={L3: [S.text(SUMMARY)]},
                       store_factory=_main_append_fault_store(tmp, stores), stores=stores, **kw)


def _assert_store_fault_stopped_the_run(d: S.Drive) -> None:
    _assert_lead_ran(d)
    assert d.router.requests(L3) >= 1, "the lead never produced its output"
    assert SUMMARY in (d.gather_summary(L3) or ""), (
        "the lead's output was not produced before the store fault")
    store_member = _run_end().TRUNCATED_BY_STORE
    escaped = isinstance(d.raised, (sqlite3.Error, S.sym("runtime.session_store", "StoreError")))
    stopped = escaped or (d.summary or {}).get("truncated_by") == store_member
    assert stopped, (
        f"a store fault after the lead's output did not stop the run: raised {d.raised!r}, "
        f"summary {d.summary!r} (RJ-01: truncated_by {store_member!r})")
    assert d.main.requests <= 1, "MAIN went on past a refused store write"


def _setup_fault_after_lead(tmp: Path, tenant: S.Planted, *, run_id: str, stores: list,
                            before: Callable[[Path], None] | None = None) -> S.Drive:
    return S.run_alert(tmp, tenant=tenant, run_id=run_id, leads={L3: [S.text(SUMMARY)]},
                       defender_dir=_tree_without_main_prompt(tmp), before=before,
                       store_factory=S.store_factory(tmp, sink=stores), stores=stores)


def _assert_setup_fault_stopped_the_run(d: S.Drive) -> None:
    _assert_lead_ran(d)
    assert SUMMARY in (d.gather_summary(L3) or ""), (
        "the lead had not ended with its summary when MAIN's agent was built")
    _assert_main_never_asked(d, "building MAIN's agent failed")
    _assert_stopped_with(d, IsADirectoryError)


# The demands

def test_n12_kills_from_other_causes_end_the_run(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = S.plant_tenant()

    stores: list = []
    budget = _budget_kill_during_lead(tmp_path / "budget", tenant, monkeypatch,
                                      run_id=fixture_uuid("r1222-n12-budget"), stores=stores)
    _assert_budget_kill_during_lead(budget, stores)

    stores = []
    failures = _kill_by_mains_failures(tmp_path / "abort", tenant, run_id=fixture_uuid("r1222-n12-abort"),
                                       stores=stores)
    _assert_lead_ran(failures)
    _assert_summary_delivered(failures, SUMMARY)
    _assert_killed(failures, _run_end().TRUNCATED_BY_ABORTED, "RunAborted")
    assert _session_ending(stores, "l-001") == _run_end().TRUNCATED_BY_ABORTED
    assert _session_ending(stores, L3) is None, (
        "the correlation lead finished with its summary, yet its session reads as ended by "
        "something — MAIN's kill was laid onto the correlation lead")

    stores = []
    store = _store_fault_after_lead_output(tmp_path / "store", tenant, run_id=fixture_uuid("r1222-n12-store"),
                                           stores=stores)
    _assert_store_fault_stopped_the_run(store)

    stores = []
    setup = _setup_fault_after_lead(tmp_path / "setup", tenant, run_id=fixture_uuid("r1222-n12-setup"),
                                    stores=stores)
    _assert_setup_fault_stopped_the_run(setup)


def test_a7_one_deadline_bounds_how_late_main_starts(tmp_path: Path) -> None:
    tenant = S.plant_tenant()
    limits = S.with_deadline(DEADLINE_S)
    stall_kinds: dict[str, dict[str, Any]] = {
        # A request that does not come back within any bound near the deadline (hung; a
        # trickling response the per-read client timeout never cuts, PA-15).
        "hung": {"leads": {L3: [S.text(LATE)]},
                 "lead_faults": {L3: S.LeadFault(delay=STALL_S)}},
        # Requests each well under the deadline whose run is over it (retries, slow-but-steady).
        "retried": {"leads": {L3: [S.list_verbs("elastic")] * 3 + [S.text(LATE)]},
                    "lead_faults": {L3: S.LeadFault(delay=0.6 * DEADLINE_S)}},
        # A backend call blocking past the deadline on its worker thread (RJ-10 b1).
        "slow-call": {"leads": {L3: [_alerts_call(), S.text(LATE)]},
                      "backend": S.Backend(fault=T.Fault(delay=DEADLINE_S + 1.0))},
    }
    stores: list = []
    control = S.run_alert(tmp_path / "control", tenant=tenant, run_id=fixture_uuid("r1222-a7-control"),
                          leads={L3: [S.text(SUMMARY)]}, limits=limits,
                          store_factory=S.store_factory(tmp_path / "control", sink=stores),
                          stores=stores)
    _assert_lead_ran(control)
    _assert_summary_delivered(control, SUMMARY)
    assert _session_ending(stores, L3) is None, "a lead that finished inside the deadline was cut"

    prose: dict[str, str] = {}
    for kind, spec in stall_kinds.items():
        stores = []
        clock = _Clock()
        main = S.MainScript()
        d = S.run_alert(tmp_path / kind, tenant=tenant, run_id=fixture_uuid(f"r1222-a7-{kind}"), main=main,
                        limits=limits, before=clock,
                        store_factory=S.store_factory(tmp_path / kind, sink=stores),
                        stores=stores, **spec)
        _assert_lead_ran(d)
        assert main.first_at is not None, f"[{kind}] MAIN never started"
        assert clock.at is not None
        waited = main.first_at - clock.at
        assert waited <= DEADLINE_S + SLACK_S, (
            f"[{kind}] MAIN's opening request came {waited:.1f}s after the run folder existed — "
            f"the {DEADLINE_S}s correlation deadline did not bound the stalled lead")
        _assert_never_delivered(d, LATE)
        _assert_timed_out_member(_session_ending(stores, L3), who=f"[{kind}] l-00c")
        prose[kind] = _prose(d)

    first = next(iter(prose.values()))
    for kind, text in prose.items():
        assert text == first, (
            f"[{kind}] MAIN's opening prose differs from another stall's: the same ending "
            "('timed out') must reach MAIN as the same fixed sentence, whatever stalled")
    assert first != _prose(control), (
        "a timed-out lead and a lead that delivered its summary gave MAIN the same opening prose")


def test_a7_a_timed_out_lead_session_reads_back_as_timed_out(tmp_path: Path) -> None:
    """The lead's session is stamped with its ending, and a timed-out lead's session reads back as
    timed out — a member of the truncated_by vocabulary — never as no ending."""
    tenant = S.plant_tenant()
    stores: list = []
    d = S.run_alert(tmp_path / "cut", tenant=tenant, run_id=fixture_uuid("r1222-a7s-cut"),
                    leads={L3: [S.text(LATE)]}, lead_faults={L3: S.LeadFault(delay=STALL_S)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path / "cut", sink=stores), stores=stores)
    _assert_lead_ran(d)
    member = _assert_timed_out_member(_session_ending(stores, L3), who="l-00c")
    assert member in S.sym("runtime.run_end", "TRUNCATED_BY_VALUES")

    # The same member every time the lead times out: the stamp is the ending, not a detail.
    again: list = []
    d2 = S.run_alert(tmp_path / "again", tenant=tenant, run_id=fixture_uuid("r1222-a7s-again"),
                     leads={L3: [_alerts_call(), S.text(LATE)]},
                     backend=S.Backend(fault=T.Fault(delay=DEADLINE_S + 1.0)),
                     limits=S.with_deadline(DEADLINE_S),
                     store_factory=S.store_factory(tmp_path / "again", sink=again), stores=again)
    _assert_lead_ran(d2)
    assert _session_ending(again, L3) == member, (
        "two timed-out leads' sessions read back as different members")


def test_r5_a_correlation_dispatch_without_a_usable_deadline_refuses_to_run(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    tenant = S.plant_tenant()

    # Positive control: a small positive deadline cuts a stalled lead as "timed out".
    stores: list = []
    clock = _Clock()
    main = S.MainScript()
    ok = S.run_alert(tmp_path / "valid", tenant=tenant, run_id=fixture_uuid("r1222-r5-valid"), main=main,
                     before=clock, leads={L3: [S.text(LATE)]},
                     lead_faults={L3: S.LeadFault(delay=STALL_S)}, limits=S.with_deadline(1),
                     store_factory=S.store_factory(tmp_path / "valid", sink=stores),
                     stores=stores)
    _assert_lead_ran(ok)
    assert main.first_at is not None, "MAIN never started"
    assert clock.at is not None
    assert main.first_at - clock.at <= 1 + SLACK_S, "a 1 s deadline did not cut the stalled lead"
    _assert_timed_out_member(_session_ending(stores, L3), who="l-00c (1 s deadline)")
    _assert_never_delivered(ok, LATE)

    refused = {
        "no deadline": S.without_deadline(),
        "zero": S.with_deadline(0),
        "negative": S.with_deadline(-1),
        "non-number": S.with_deadline("abc"),
        "infinite": S.with_deadline(float("inf")),
        "not-a-number": S.with_deadline(float("nan")),
    }
    for i, (label, limits) in enumerate(refused.items()):
        caplog.clear()
        # A lead that WOULD answer (late) if a fallback deadline let it start.
        d = S.run_alert(tmp_path / f"refused-{i}", tenant=tenant, run_id=fixture_uuid(f"r1222-r5-{i}"),
                        leads={L3: [S.text(LATE)]}, lead_faults={L3: S.LeadFault(delay=3.0)},
                        limits=limits)
        assert d.router.requests(L3) == 0, (
            f"[{label}] the correlation lead started under an unusable deadline: it was replaced "
            "by a fallback (or 'unbounded') instead of refused")
        _assert_main_never_asked(d, f"the correlation deadline was unusable ({label})")
        _assert_stopped_loudly(d)
        said = " ".join([str(d.raised or ""), str(d.refusal or ""),
                         str((d.summary or {}).get("exit_reason") or ""), caplog.text])
        assert S.DEADLINE_KEY in said, (
            f"[{label}] the refusal does not name the setting {S.DEADLINE_KEY!r}: {said[-400:]!r}")


def test_r7_a_lead_main_dispatched_is_stamped_and_read_back_as_before(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rb = _run_end()
    tenant = S.plant_tenant()
    stalled = {"leads_l3": [S.text(LATE)], "fault_l3": S.LeadFault(delay=STALL_S)}
    gather_cmdb = [S.gather("l-001", "cmdb"), S.text(S.DONE)]
    same_host = S.query("cmdb", "get-host", {"host": "app-7"})
    # One scenario per existing ending: l-001's script and fault, the backend, whether l-00c
    # stalls beside it (the positive control), and any extra cap.
    endings: dict[str, dict[str, Any]] = {
        rb.TRUNCATED_BY_REQUEST_LIMIT: {"l001": [S.list_verbs("cmdb")] * 45, **stalled},
        # PR-19: the provider path's UnexpectedModelBehavior.
        rb.TRUNCATED_BY_RETRY_EXHAUSTED: {
            "l001": [S.text("unused")],
            "fault": S.LeadFault(raise_on=1, exc=S.unexpected_behavior), **stalled},
        # PR-14: parallel transport failures reach the run-level kill.
        rb.TRUNCATED_BY_ABORTED: {
            "l001": [_parallel("cmdb", "get-host", 5), S.text("x")],
            "backend": S.Backend(fault=T.Fault(fail_on=("cmdb.",))), **stalled},
        # RJ-04 d: the run's wall clock expires while l-001's first request is in flight.
        rb.TRUNCATED_BY_BUDGET: {
            "l001": [S.list_verbs("cmdb"), S.text("x")],
            "fault": S.LeadFault(delay=KILL_DELAY_S), "enforce": True,
            "limits": S.default_limits(wall_clock_timeout=KILL_WALL_S, grace_seconds=0)},
        # The store's own refusal of a payload it cannot represent (a non-finite tool arg).
        rb.TRUNCATED_BY_STORE: {
            "l001": [S.Turn(tool_calls=(("list_verbs", {"system": "cmdb",
                                                        "note": float("nan")}),)),
                     S.text("y"), S.text("z")], **stalled},
        # Three identical calls trip the repeat guard; each request takes long enough that
        # l-001 outlives the correlation deadline (which must not cut it).
        rb.TRUNCATED_BY_DEAD_END: {
            "l001": [same_host, same_host, same_host, same_host, S.text("w")],
            "fault": S.LeadFault(delay=0.8), **stalled},
    }
    for member, spec in endings.items():
        stores: list = []
        run_kw: dict[str, Any] = {
            "tenant": tenant, "run_id": fixture_uuid(f"r1222-r7-{member}"), "main": list(gather_cmdb),
            "leads": {"l-001": spec["l001"],
                      **({L3: spec["leads_l3"]} if "leads_l3" in spec else {})},
            "lead_faults": {**({"l-001": spec["fault"]} if "fault" in spec else {}),
                            **({L3: spec["fault_l3"]} if "fault_l3" in spec else {})},
            "limits": spec.get("limits", S.with_deadline(DEADLINE_S)),
            "store_factory": S.store_factory(tmp_path / member, sink=stores), "stores": stores,
        }
        if "backend" in spec:
            run_kw["backend"] = spec["backend"]
        with monkeypatch.context() as m:
            if spec.get("enforce"):
                m.setenv(_enforce_flag(), "true")
            d = S.run_alert(tmp_path / member, **run_kw)
        _assert_lead_ran(d)
        assert d.router.dispatched("l-001"), f"[{member}] MAIN's lead never ran"
        stamped = _session_ending(stores, "l-001")
        assert stamped == member, (
            f"MAIN's lead ended by {member!r} is stamped {stamped!r}: its terminator changed")
        assert rb.normalized_truncated_by(stamped) == member, (
            f"normalized_truncated_by reads MAIN's {member!r} lead back as "
            f"{rb.normalized_truncated_by(stamped)!r}")
        if "fault_l3" in spec:
            _assert_timed_out_member(_session_ending(stores, L3), who=f"[{member}] l-00c")


def test_p002_spawn_budget_sized_to_mains_own_leads(tmp_path: Path,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = S.plant_tenant()

    # One budget, no reserved allowance: a spawn cap sized for exactly one lead is spent by the
    # correlation lead, so MAIN's planned lead meets the cap.
    with monkeypatch.context() as m:
        m.setenv(_enforce_flag(), "true")
        d = S.run_alert(tmp_path / "spawn", tenant=tenant, run_id=fixture_uuid("r1222-p002-spawn"),
                        main=[S.gather("l-001", "cmdb"), S.text(S.DONE)],
                        leads={L3: [_alerts_call(0), _alerts_call(1), S.text(SUMMARY)]},
                        limits=S.default_limits(max_subagent_spawns=1))
    _assert_lead_ran(d)
    assert d.budget.get("subagent_spawns") == 1, (
        f"the run's spawn count does not hold the correlation lead's spawn: {d.budget!r}")
    assert isinstance(d.budget.get("tool_calls"), int), d.budget
    assert d.budget["tool_calls"] >= 2, (
        f"the run's tool-call count does not hold the correlation lead's two calls: {d.budget!r}")
    assert not d.router.dispatched("l-001"), (
        "MAIN's planned lead ran past a spawn cap the correlation lead had already spent — the "
        "lead was given a reserved allowance")
    assert d.run_dir is not None
    refusals = [r for r in _wire_records(d.run_dir) if r.get("event_type") == "budget_refusal"]
    assert any(r.get("tool_name") == "gather" for r in refusals), (
        f"MAIN's gather was not refused for budget: {refusals!r}")

    # The lead's failures never count toward the run-level failure kill.
    over = S.run_alert(tmp_path / "failures", tenant=tenant, run_id=fixture_uuid("r1222-p002-failures"),
                       leads={L3: [_parallel("elastic", "alerts", _kill_limit()),
                                   S.text(SUMMARY)]},
                       backend=S.Backend(fault=T.Fault(fail_on=("elastic.",))))
    _assert_lead_ran(over)
    assert over.raised is None, over.raised
    assert over.summary is not None
    assert over.summary.get("truncated_by") != _run_end().TRUNCATED_BY_ABORTED, (
        "the correlation lead's own failures reached the run-level kill")
    assert over.main.requests >= 1, "MAIN never started after the lead's failures"

    # A budget kill while the lead runs stops the run loudly, as a kill from another cause.
    stores: list = []
    killed = _budget_kill_during_lead(tmp_path / "kill", tenant, monkeypatch,
                                      run_id=fixture_uuid("r1222-p002-kill"), stores=stores)
    _assert_budget_kill_during_lead(killed, stores)


def test_p003_correlation_lead_still_running_at_mains_second_r(tmp_path: Path) -> None:
    tenant = S.plant_tenant()
    done = S.run_alert(tmp_path / "done", tenant=tenant, run_id=fixture_uuid("r1222-p003-done"),
                       leads={L3: [_alerts_call(), S.text(SUMMARY)]},
                       main=S.closing_main_turns(), limits=S.with_deadline(DEADLINE_S))
    _assert_lead_ran(done)
    _assert_summary_delivered(done, SUMMARY)
    assert done.report is not None, "a run whose lead delivered its summary did not reach report.md"

    stores: list = []
    clock = _Clock()
    main = S.MainScript(S.closing_main_turns())
    hung = S.run_alert(tmp_path / "hung", tenant=tenant, run_id=fixture_uuid("r1222-p003-hung"), main=main,
                       before=clock, leads={L3: [S.text(LATE)]},
                       lead_faults={L3: S.LeadFault(delay=STALL_S)},
                       limits=S.with_deadline(DEADLINE_S),
                       store_factory=S.store_factory(tmp_path / "hung", sink=stores),
                       stores=stores)
    _assert_lead_ran(hung)
    assert main.first_at is not None, "MAIN never started"
    assert clock.at is not None
    assert main.first_at - clock.at <= DEADLINE_S + SLACK_S, (
        "MAIN waited on the hung model request past the correlation deadline")
    _assert_timed_out_member(_session_ending(stores, L3), who="l-00c")
    _assert_never_delivered(hung, LATE)
    assert hung.report is not None, "the run did not reach report.md after the named ending"


def test_p009_l00c_alone_reaches_the_run_kill_count(tmp_path: Path) -> None:
    """l-00c's failures alone never reach the run-level kill; MAIN's sentence is 'tripped breaker'
    when the breaker refused any of its calls; the run reaches report.md."""
    tenant = S.plant_tenant()
    n = _kill_limit()
    runs = {
        # Enough failures for the kill, then one call the tripped breaker refuses.
        "tripped-many": [_parallel("elastic", "alerts", n), _alerts_call(50), S.text(SUMMARY)],
        # Fewer failures (just the trip) and different fault text: the same ending.
        "tripped-few": [_parallel("elastic", "alerts", 2), _alerts_call(60), S.text(SUMMARY)],
        # One failed call and no refusal: a different ending ('every call failed').
        "one-failure": [_alerts_call(70), S.text(SUMMARY)],
    }
    details = {"tripped-many": "docker exec curl timed out after 40s",
               "tripped-few": "connection refused by es-acme:9200",
               "one-failure": "docker exec curl timed out after 40s"}
    prose: dict[str, str] = {}
    for label, script in runs.items():
        detail = details[label]
        d = S.run_alert(tmp_path / label, tenant=tenant, run_id=fixture_uuid(f"r1222-p009-{label}"),
                        main=S.closing_main_turns(), leads={L3: script},
                        backend=S.Backend(fault=T.Fault(fail_on=("elastic.",)),
                                          exc=functools.partial(S.transport_fault, detail)))
        _assert_lead_ran(d)
        assert d.raised is None, d.raised
        assert d.summary is not None
        assert d.summary.get("truncated_by") != _run_end().TRUNCATED_BY_ABORTED, (
            f"[{label}] l-00c's failures alone ended the run")
        assert d.report is not None, f"[{label}] the run did not reach report.md"
        text = _prose(d)
        assert detail not in text, f"[{label}] the fault's own text reached MAIN's harness prose"
        prose[label] = text
    assert prose["tripped-many"] == prose["tripped-few"], (
        "two runs whose breaker refused one of l-00c's calls gave MAIN different sentences")
    assert prose["tripped-many"] != prose["one-failure"], (
        "a refused call ('tripped breaker') and a lone failed call ('every call failed') gave "
        "MAIN the same sentence")


def test_p167_model_request_slow_retried_or_just_past_the_time(tmp_path: Path) -> None:
    """A trickling, retried or just-late response is cut at the deadline and is the named ending
    'timed out', never a late summary; MAIN waits at most the deadline."""
    tenant = S.plant_tenant()
    late_by = {
        "trickling": STALL_S,
        # Three attempts, each under the deadline, together past it (PA-15: per attempt).
        "retried": 3 * 0.8 * DEADLINE_S,
        "just-late": DEADLINE_S + 0.75,
    }
    for kind, delay in late_by.items():
        stores: list = []
        clock = _Clock()
        main = S.MainScript()
        d = S.run_alert(tmp_path / kind, tenant=tenant, run_id=fixture_uuid(f"r1222-p167-{kind}"), main=main,
                        before=clock, leads={L3: [S.text(LATE)]},
                        lead_faults={L3: S.LeadFault(delay=delay)},
                        limits=S.with_deadline(DEADLINE_S),
                        store_factory=S.store_factory(tmp_path / kind, sink=stores),
                        stores=stores)
        _assert_lead_ran(d)
        _assert_never_delivered(d, LATE)
        _assert_timed_out_member(_session_ending(stores, L3), who=f"[{kind}] l-00c")
        assert main.first_at is not None, f"[{kind}] MAIN never started"
        assert clock.at is not None
        assert main.first_at - clock.at <= DEADLINE_S + SLACK_S, (
            f"[{kind}] MAIN waited past the deadline")

    # Positive control: a response just inside the deadline is the lead's summary.
    early: list = []
    d = S.run_alert(tmp_path / "early", tenant=tenant, run_id=fixture_uuid("r1222-p167-early"),
                    leads={L3: [S.text(SUMMARY)]},
                    lead_faults={L3: S.LeadFault(delay=0.25 * DEADLINE_S)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path / "early", sink=early), stores=early)
    _assert_lead_ran(d)
    _assert_summary_delivered(d, SUMMARY)
    assert _session_ending(early, L3) is None, "a response inside the deadline was cut"


def test_p171_run_stopped_before_mains_first_request(tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    tenant = S.plant_tenant()
    real_enqueue = S.sym("run_common", "enqueue_curation")

    def post_steps() -> tuple[Any, Callable[..., bool], list[dict], list[bool]]:
        """The REAL ticket writer over a recording store, and the REAL curation enqueue behind
        a recorder of what run.main handed it and what it answered."""
        handed: list[dict] = []
        answers: list[bool] = []

        def enqueue(run_dir: Path, alert: Path, **kw: Any) -> bool:
            handed.append(dict(kw))
            answers.append(bool(real_enqueue(run_dir, alert, **kw)))
            return answers[-1]

        return S.ticket_writer(S.TicketStore()), enqueue, handed, answers

    # The existing path: MAIN's own budget kill at its first tool call.
    tickets_a, enqueue_a, handed_a, answers_a = post_steps()
    with monkeypatch.context() as m:
        m.setenv(_enforce_flag(), "true")
        main_kill = S.run_alert(
            tmp_path / "main", tenant=tenant, run_id=fixture_uuid("r1222-p171-main"),
            main=S.MainScript(S.default_main_turns(), S.LeadFault(delay=KILL_DELAY_S)),
            limits=S.default_limits(wall_clock_timeout=KILL_WALL_S, grace_seconds=0),
            tickets=tickets_a, update_ticket=True, no_learn=False,
            enqueue=enqueue_a)
    # The stop before MAIN's first request: a budget kill at the lead's own tool call.
    tickets_b, enqueue_b, handed_b, answers_b = post_steps()
    stores: list = []
    lead_kill = _budget_kill_during_lead(
        tmp_path / "lead", tenant, monkeypatch, run_id=fixture_uuid("r1222-p171-lead"), stores=stores,
        tickets=tickets_b, update_ticket=True, no_learn=False,
        enqueue=enqueue_b)
    _assert_budget_kill_during_lead(lead_kill, stores)
    assert lead_kill.summary is not None
    assert lead_kill.summary.get("output") is None, (
        "the run summary of a run whose agent never started carries an output")
    _assert_killed(main_kill, _run_end().TRUNCATED_BY_BUDGET, "BudgetKill")
    assert main_kill.main.requests >= 1
    assert handed_b == handed_a, (
        f"the curation enqueue was handed {handed_b!r} for the stop before MAIN, {handed_a!r} for "
        "MAIN's own kill")
    assert answers_b == answers_a
    assert tickets_b.store.comments() == tickets_a.store.comments(), (
        "the ticket's record leg did something different for the stop before MAIN")
    assert len(tickets_b.store.opened()) == len(tickets_a.store.opened()) == 1


def test_p174_lead_and_main_failures_together_pass_the_kill_co(tmp_path: Path) -> None:
    """The run-kill count is MAIN's failures alone. The run is not killed while MAIN's failures
    alone are below the limit."""
    tenant = S.plant_tenant()
    n = _kill_limit()
    backend_faults = T.Fault(fail_on=("elastic.alerts", "cmdb.get-host"))
    outcome: dict[int, S.Drive] = {}
    for mains in (n - 1, n):
        stores: list = []
        d = S.run_alert(tmp_path / f"m{mains}", tenant=tenant, run_id=fixture_uuid(f"r1222-p174-{mains}"),
                        main=[S.gather("l-001", "cmdb"), S.text(S.DONE)],
                        leads={L3: [_parallel("elastic", "alerts", n - 1), S.text(SUMMARY)],
                               "l-001": [_parallel("cmdb", "get-host", mains), S.text("x")]},
                        backend=S.Backend(fault=backend_faults),
                        store_factory=S.store_factory(tmp_path / f"m{mains}", sink=stores),
                        stores=stores)
        _assert_lead_ran(d)
        assert len([r for r in d.rows_for(L3) if r.get("exit_code")]) == n - 1, (
            "the correlation lead's failed calls are not all recorded")
        outcome[mains] = d
    below = outcome[n - 1]
    assert below.raised is None, below.raised
    assert below.summary is not None
    assert below.summary.get("truncated_by") is None, (
        f"the run was killed with MAIN's failures ({n - 1}) below the limit ({n}): the correlation "
        f"lead's {n - 1} failures were counted ({below.summary!r})")
    assert below.main.requests >= 2, "MAIN never finished its run"
    _assert_killed(outcome[n], _run_end().TRUNCATED_BY_ABORTED, "RunAborted")


def test_run_duration_includes_correlation_and_main(tmp_path: Path) -> None:
    """The trace covers the interval from the lead's first request through MAIN's last."""
    delay = 0.3
    main = S.MainScript(fault=S.LeadFault(delay=delay))
    d = S.run_alert(tmp_path, main=main, leads={L3: [S.text(SUMMARY)]},
                    lead_faults={L3: S.LeadFault(delay=delay)})
    _assert_lead_ran(d)
    assert d.raised is None
    assert main.started
    minimum_ms = (main.started[-1] + delay - d.router.started(L3)[0]) * 1000
    result, = (r for r in read_jsonl_rows(RunPaths(d.folder).tool_trace)
               if r.get("type") == "result")
    # The persisted duration is rounded to whole milliseconds.
    assert result["duration_ms"] >= minimum_ms - 1
