"""#1222 spec, slice S06 — the correlation phase's one deadline, and the kills it never absorbs.

A7: one harness deadline frames the whole correlation lead (`l-00c`), retries included; its
expiry is the named ending "timed out", stamped on the lead's session as a member of the
`truncated_by` vocabulary; MAIN's own leads keep their base terminators and are never cut by it;
a dispatch without a usable deadline is refused before the lead starts. A2: the lead's failures
mark per-system health and spend the run budget but never count toward the run-level failure
kill; a budget kill, a run-level failure kill reached by MAIN's own failures, a store fault after
the lead produced output and a setup fault each stop the run loudly and never become one of the
lead's endings. A4: the lead ends before MAIN's opening message is built (no background task).

Every scenario drives the production front door (`run.main` through `S.run_alert`) with the
generic, non-Kibana alert. At base `301f196c` that alert never dispatches `l-00c` (item 1's gate
and the `alert_timestamp` gate, c3), so each test asserts FIRST that the lead ran — the design's
behaviour — and only then its own demand; a stall on `l-00c` is therefore unreachable at base.

Faults, each through a fake's data spec or a real primitive (no `monkeypatch.setattr`):
* a stalled model request: `LeadFault(delay=...)`, awaited on the event loop so a deadline can cut
  it (RJ-10 a: control returned at T mid-request; PA-15: the per-attempt client timeout never
  bounds a trickling or retried request). Stalls are BOUNDED (`STALL_S`, not `S.HANG_S`): a
  missing deadline then fails in seconds with a late summary, never a ten-minute hang.
* a slow backend call: `Backend(fault=T.Fault(delay=...))` — a blocking verb on the worker thread
  (RJ-10 b1: control returned at T; the thread finishes on its own).
* a budget kill at the lead's own tool call: `DEFENDER_BUDGET_ENFORCE` set (`monkeypatch.setenv`)
  and a run wall clock shorter than the lead's first request (RJ-04 d: "the lead's NEXT tool call
  raised BudgetKill").
* the run-level failure kill: ONE model response carrying parallel failing calls, each the
  transport's own `TransportFault` (exit 2), all executing before the breaker can refuse any
  (PR-14: "one l-00c response with 7 parallel failing calls reaches total_failures 7").
* a store fault after the lead's output: the REAL store's file filled to its growth ceiling at the
  first append MAIN's session makes (`_session_store_705.FaultStore`'s `disk-full`, keyed here on
  the appending agent; RJ-01: StoreAppendError, truncated_by store).
* a setup fault: a deployed tree whose MAIN prompt file (`SKILL.md`) is a directory, read only when
  MAIN's agent is built (the real `read_text_utf8` raising `IsADirectoryError`).
* a run folder that refuses a write: a directory squatting the lead's summary file.
* an operator interrupt while the lead runs: `KeyboardInterrupt` out of the lead's model request
  (PA-16: a BaseException in the stretch between store setup and MAIN's drive).
"""
from __future__ import annotations

import functools
import math
import os
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.run_repository import RunPaths
from defender.tests import _session_store_705 as SS
from defender.tests import _triplet_947 as T
from defender.tests.alert_front_door_1222 import _spec1222 as S

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
LEAD_SUMMARY = "MAIN-LEAD-SUMMARY-4b07: the host answered after a long wait."


# =================================================================================================
# Observation helpers
# =================================================================================================

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


def _snapshot(root: Path) -> list[tuple[str, int, int]]:
    out = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            st = p.lstat()
            out.append((str(p.relative_to(root)), st.st_size, st.st_mtime_ns))
    return sorted(out)


def _wire_records(run_dir: Path) -> list[dict]:
    return read_jsonl_rows(RunPaths(run_dir).wire_log)


def _judge_lead_blocks(run_dir: Path) -> dict[str, list[str]]:
    """The judge prompt's lead view of `run_dir`, built as the judge builds it (`lead_chain` per
    joined lead, rendered by `JudgeInput.as_prompt_sections`): each lead's field lines below its
    heading, frame salts normalised, keyed by lead id."""
    family = S.mod("learning.judge.family")
    by_id = family.leads_by_id(run_dir)
    with S.sym("_io", "bind")(run_dir) as world:
        chains = {lid: family.lead_chain(world, lid, {}, leads=by_id) for lid in sorted(by_id)}
    view = S.sym("learning.judge.render", "JudgeInput")(
        world_label="w", discriminator={}, leads=chains).as_prompt_sections()["leads"]
    blocks: dict[str, list[str]] = {}
    for chunk in S.normalize(view).split("### ")[1:]:
        head, _, body = chunk.partition("\n")
        blocks[head.strip()] = [line for line in body.splitlines() if line.startswith("- ")]
    return blocks


# =================================================================================================
# Scripts and faults (data)
# =================================================================================================

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


def _counting(total: int) -> Callable[[str, str, dict], Any]:
    """A backend answer: the real `search_envelope` reporting `total` matches (no hits)."""
    def answer(_system: str, _verb: str, params: dict) -> Any:
        return S.envelope([], total=total, index=params.get("index") or "alerts-*")

    return answer


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


# =================================================================================================
# The demands
# =================================================================================================

def test_n12_kills_from_other_causes_end_the_run(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    """A budget kill raised while the lead runs, a run-level failure kill reached by MAIN's own
    failures, a store fault after the lead produced output, and a setup fault each stop the run
    loudly; none is turned into a correlation ending."""
    tenant = S.plant_tenant()

    stores: list = []
    budget = _budget_kill_during_lead(tmp_path / "budget", tenant, monkeypatch,
                                      run_id="r1222-n12-budget", stores=stores)
    _assert_budget_kill_during_lead(budget, stores)

    stores = []
    failures = _kill_by_mains_failures(tmp_path / "abort", tenant, run_id="r1222-n12-abort",
                                       stores=stores)
    _assert_lead_ran(failures)
    _assert_summary_delivered(failures, SUMMARY)
    _assert_killed(failures, _run_end().TRUNCATED_BY_ABORTED, "RunAborted")
    assert _session_ending(stores, "l-001") == _run_end().TRUNCATED_BY_ABORTED
    assert _session_ending(stores, L3) is None, (
        "the correlation lead finished with its summary, yet its session reads as ended by "
        "something — MAIN's kill was laid onto the correlation lead")

    stores = []
    store = _store_fault_after_lead_output(tmp_path / "store", tenant, run_id="r1222-n12-store",
                                           stores=stores)
    _assert_store_fault_stopped_the_run(store)

    stores = []
    setup = _setup_fault_after_lead(tmp_path / "setup", tenant, run_id="r1222-n12-setup",
                                    stores=stores)
    _assert_setup_fault_stopped_the_run(setup)


def test_a7_one_deadline_bounds_how_late_main_starts(tmp_path: Path) -> None:
    """However the lead stalls — a hung model request, a retried one, a trickling response, a slow
    backend call — MAIN's opening request follows within the correlation deadline (plus the
    longest step that cannot be cut, a bash call of up to 120 s) of the lead's start, and the
    lead's ending is then 'timed out'."""
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
    control = S.run_alert(tmp_path / "control", tenant=tenant, run_id="r1222-a7-control",
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
        d = S.run_alert(tmp_path / kind, tenant=tenant, run_id=f"r1222-a7-{kind}", main=main,
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
    d = S.run_alert(tmp_path / "cut", tenant=tenant, run_id="r1222-a7s-cut",
                    leads={L3: [S.text(LATE)]}, lead_faults={L3: S.LeadFault(delay=STALL_S)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path / "cut", sink=stores), stores=stores)
    _assert_lead_ran(d)
    member = _assert_timed_out_member(_session_ending(stores, L3), who="l-00c")
    assert member in S.sym("runtime.run_end", "TRUNCATED_BY_VALUES")

    # The same member every time the lead times out: the stamp is the ending, not a detail.
    again: list = []
    d2 = S.run_alert(tmp_path / "again", tenant=tenant, run_id="r1222-a7s-again",
                     leads={L3: [_alerts_call(), S.text(LATE)]},
                     backend=S.Backend(fault=T.Fault(delay=DEADLINE_S + 1.0)),
                     limits=S.with_deadline(DEADLINE_S),
                     store_factory=S.store_factory(tmp_path / "again", sink=again), stores=again)
    _assert_lead_ran(d2)
    assert _session_ending(again, L3) == member, (
        "two timed-out leads' sessions read back as different members")


def test_r5_a_correlation_dispatch_without_a_usable_deadline_refuses_to_run(
        tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    """The correlation dispatch cannot be driven without a deadline: no deadline, zero, a negative
    value, a non-number and a non-finite one are each refused before the lead starts, naming the
    setting, and none is replaced by a fallback value (a zero is not a spelling of 'unbounded' or
    of 'use a default'). The deadline is a configured positive bound at or under 1200 s - 120 s -
    MAIN's minimum time; the spec fixes that ceiling against the default run clock, checked once
    and never recomputed per run (B3), and the implementer picks the number from real
    correlation timings (78, H1). A refused dispatch is a setup fault that stops the run loudly,
    not the lead's own 'timed out' ending. Positive control: the smallest valid deadline times a
    stalled lead out as 'timed out'."""
    tenant = S.plant_tenant()

    # Positive control: a small positive deadline cuts a stalled lead as "timed out".
    stores: list = []
    clock = _Clock()
    main = S.MainScript()
    ok = S.run_alert(tmp_path / "valid", tenant=tenant, run_id="r1222-r5-valid", main=main,
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
        d = S.run_alert(tmp_path / f"refused-{i}", tenant=tenant, run_id=f"r1222-r5-{i}",
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


def test_b3_the_shipped_correlation_deadline_sits_under_the_fixed_ceiling() -> None:
    """The shipped cap table carries the correlation deadline as a positive, finite number of
    seconds at or under 1080 s: the ceiling 1200 s (the default run clock) - 120 s (a bash call
    the deadline cannot cut) - MAIN's minimum time, taken as zero because it has no number. The
    ceiling is fixed against the default clock, checked once here; it is not recomputed from a
    run's own clock settings.

    Read off production's own default table (`hooks/budget_enforcer.DEFAULT_LIMITS`, through
    `S.default_limits()`); the number itself is the implementer's (78, H1; §7 round 3, B3)."""
    limits = S.default_limits()
    assert S.DEADLINE_KEY in limits, (
        f"the shipped cap table carries no {S.DEADLINE_KEY!r}: every production run would meet "
        "an unusable deadline at correlation (r5)")
    value = limits[S.DEADLINE_KEY]
    assert not isinstance(value, bool), (
        f"the shipped correlation deadline is a boolean, not seconds: {value!r}")
    assert isinstance(value, (int, float)), (
        f"the shipped correlation deadline is not a number of seconds: {value!r}")
    assert math.isfinite(value), f"the shipped correlation deadline is not finite: {value!r}"
    assert value > 0, f"the shipped correlation deadline is not a positive bound: {value!r}"
    assert value <= S.DEADLINE_CEILING_S, (
        f"the shipped correlation deadline {value!r} s is above the fixed ceiling "
        f"{S.DEADLINE_CEILING_S} s (1200 s - 120 s - MAIN's minimum time)")


def test_r7_a_lead_main_dispatched_is_stamped_and_read_back_as_before(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A lead MAIN dispatches, ended by each existing ending (request limit, retry exhausted,
    aborted, budget, store, dead end), is stamped with the same truncated_by member as at base and
    normalized_truncated_by reads each back as that member -- none as 'timed-out', none as no
    ending -- and the correlation deadline does not cut it. Positive control: the correlation
    lead's timed-out session reads back as timed-out beside it."""
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
            "tenant": tenant, "run_id": f"r1222-r7-{member}", "main": list(gather_cmdb),
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
    """The lead's spawn and calls spend the run's one budget with no reserved allowance; the
    lead's failures never count toward the run-level failure kill; a budget kill raised while
    the lead runs stops the run loudly as a kill from another cause."""
    tenant = S.plant_tenant()

    # One budget, no reserved allowance: a spawn cap sized for exactly one lead is spent by the
    # correlation lead, so MAIN's planned lead meets the cap.
    with monkeypatch.context() as m:
        m.setenv(_enforce_flag(), "true")
        d = S.run_alert(tmp_path / "spawn", tenant=tenant, run_id="r1222-p002-spawn",
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
    over = S.run_alert(tmp_path / "failures", tenant=tenant, run_id="r1222-p002-failures",
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
                                      run_id="r1222-p002-kill", stores=stores)
    _assert_budget_kill_during_lead(killed, stores)


def test_p003_correlation_lead_still_running_at_mains_second_r(tmp_path: Path) -> None:
    """MAIN's first request follows the lead's end. A hung model request in the lead ends as the
    named ending "timed out". Every backend call is bounded by its transport timeout (at most 40 s
    per HTTP call, 120 s per bash call; RJ-04). The run reaches report.md after the named
    ending."""
    tenant = S.plant_tenant()
    done = S.run_alert(tmp_path / "done", tenant=tenant, run_id="r1222-p003-done",
                       leads={L3: [_alerts_call(), S.text(SUMMARY)]},
                       main=S.closing_main_turns(), limits=S.with_deadline(DEADLINE_S))
    _assert_lead_ran(done)
    _assert_summary_delivered(done, SUMMARY)
    assert done.report is not None, "a run whose lead delivered its summary did not reach report.md"

    stores: list = []
    clock = _Clock()
    main = S.MainScript(S.closing_main_turns())
    hung = S.run_alert(tmp_path / "hung", tenant=tenant, run_id="r1222-p003-hung", main=main,
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


def test_p004_run_setup_fails_after_correlation_was_scheduled(tmp_path: Path) -> None:
    """A setup fault after the lead ended (building MAIN's agent or deps) stops the run loudly with
    the setup error. No task writes the run folder after the run unwinds. l-00c's leads row holds
    the lead's own outcome."""
    tenant = S.plant_tenant()
    stores: list = []
    clock = _Clock()
    d = _setup_fault_after_lead(tmp_path, tenant, run_id="r1222-p004", stores=stores,
                                before=clock)
    _assert_setup_fault_stopped_the_run(d)
    assert d.report is None, "a run stopped by a setup fault wrote a report"
    sidecar = d.sidecar(L3)
    assert sidecar.get("lead_id", L3) == L3, sidecar
    assert sidecar.get("goal"), f"l-00c's leads row lost its harness contract: {sidecar!r}"
    assert SUMMARY in (d.gather_summary(L3) or ""), "l-00c's own outcome is not recorded"
    assert clock.run_dir is not None
    settled = _snapshot(clock.run_dir)
    time.sleep(0.5)
    assert _snapshot(clock.run_dir) == settled, (
        "something kept writing the run folder after the run unwound")


def test_p007_siem_down_at_run_start(tmp_path: Path) -> None:
    """MAIN's first call to a system the lead found down meets the same outage mark. Correlation's
    failures never end the run."""
    tenant = S.plant_tenant()
    d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p007",
                    main=[S.gather("l-001", "elastic"), S.text(S.DONE)],
                    leads={L3: [_parallel("elastic", "alerts", _kill_limit()), S.text(SUMMARY)],
                           "l-001": [_alerts_call(99), S.text(LEAD_SUMMARY)]},
                    backend=S.Backend(fault=T.Fault(fail_on=("elastic.",))))
    _assert_lead_ran(d)
    assert d.raised is None, d.raised
    assert d.summary is not None
    assert d.summary.get("truncated_by") != _run_end().TRUNCATED_BY_ABORTED, (
        "correlation's failures ended the run")
    assert d.main.requests >= 2, "MAIN did not get past its first turn"
    assert S.sym("runtime.circuit_breaker", "is_tripped")(d.run_state, "elastic"), (
        f"the lead's failures did not mark elastic down: {d.breaker!r}")
    assert not d.router.dispatched("l-001"), (
        "MAIN's lead to the system the lead found down was dispatched as if it were healthy")
    assert d.rows_for("l-001") == [], "MAIN's lead reached the down system's backend"
    mark = S.sym("runtime.circuit_breaker", "down_message")(d.run_state, "elastic")
    assert mark in d.main.history_text, (
        "MAIN's dispatch to the down system did not meet the outage mark the lead left")


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
        d = S.run_alert(tmp_path / label, tenant=tenant, run_id=f"r1222-p009-{label}",
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


def test_p010_run_kill_in_a_task_nobody_awaits(tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """There is no background task: the lead ends before MAIN starts (A4, A7). A run-level kill
    raised while the lead runs stops the run loudly, as a kill from another cause."""
    tenant = S.plant_tenant()
    ended = S.run_alert(tmp_path / "ended", tenant=tenant, run_id="r1222-p010-ended",
                        main=[S.text(S.DONE)], leads={L3: [_alerts_call(), S.text(SUMMARY)]})
    _assert_lead_ran(ended)
    _assert_summary_delivered(ended, SUMMARY)
    assert ended.main.requests == 1, "MAIN's one-request run is not the run's only MAIN request"

    stores: list = []
    killed = _budget_kill_during_lead(tmp_path / "killed", tenant, monkeypatch,
                                      run_id="r1222-p010-killed", stores=stores)
    _assert_budget_kill_during_lead(killed, stores)


def test_p030_main_mints_l00c_after_the_harness_claim_failed(tmp_path: Path) -> None:
    """A lead MAIN mints as l-00c is an ordinary lead. No reader grants trust by lead id (l-00c,
    l-000). Its failures count toward the run kill."""
    # The table withholds correlation, so no harness claim exists and MAIN can mint l-00c (PR-23).
    tenant = S.plant_tenant(table=S.TABLE_WITHHELD)
    stores: list = []
    d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p030",
                    main=[S.gather("l-001", "identity"), S.gather("l-000", "identity"),
                          S.gather(L3, "identity"), S.text(S.DONE)],
                    leads={"l-001": [S.text(LEAD_SUMMARY)], "l-000": [S.text(LEAD_SUMMARY)],
                           L3: [_parallel("identity", "get-user", _kill_limit()),
                                S.text("never")]},
                    backend=S.Backend(fault=T.Fault(fail_on=("identity.get-user",))),
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    for lead in ("l-001", "l-000", L3):
        assert d.router.dispatched(lead), (
            f"MAIN's lead {lead} never ran: an ordinary id was refused to MAIN "
            f"(conversations: {d.router.leads()})")
    joined = {lead.lead_id: lead for lead in S.sym("learning.lead_repository", "joined")(d.run_dir)}
    for lead in ("l-000", L3):
        assert lead in joined, f"the lead repository does not carry MAIN's {lead}"
        assert joined[lead].provenance == joined["l-001"].provenance, (
            f"the lead repository reads MAIN's {lead} with provenance "
            f"{joined[lead].provenance!r}, MAIN's l-001 with {joined['l-001'].provenance!r}: "
            "trust granted by lead id")
        assert joined[lead].goal == joined["l-001"].goal, (
            f"MAIN's {lead} is read back with a goal other than the one MAIN gave it")
    # The judge's lead view, built the way the judge builds it: same fields, same framing.
    blocks = _judge_lead_blocks(d.folder)
    assert blocks["l-000"] == blocks["l-001"], (
        "the judge renders MAIN's l-000 unlike MAIN's l-001, which ran the same script: "
        f"{blocks['l-000']!r} vs {blocks['l-001']!r}")
    assert [line.split(":", 1)[0] for line in blocks[L3]] == [
        line.split(":", 1)[0] for line in blocks["l-001"]], (
        f"the judge renders MAIN's {L3} with other fields than an ordinary lead: {blocks[L3]!r}")
    assert blocks[L3][0] == blocks["l-001"][0], (
        f"the judge renders MAIN's {L3} with a goal other than the one MAIN gave it")
    _assert_killed(d, _run_end().TRUNCATED_BY_ABORTED, "RunAborted")
    assert _session_ending(stores, L3) == _run_end().TRUNCATED_BY_ABORTED


def test_p031_correlation_entry_cannot_be_written_to_mains_ses(tmp_path: Path) -> None:
    """A store fault after the lead produced output stops the run loudly. There is no injected
    entry any more."""
    tenant = S.plant_tenant()
    healthy = S.run_alert(tmp_path / "healthy", tenant=tenant, run_id="r1222-p031-healthy",
                          leads={L3: [S.text(SUMMARY)]})
    _assert_lead_ran(healthy)
    _assert_summary_delivered(healthy, SUMMARY)
    assert healthy.main.requests >= 2
    later = healthy.main.seen[-1]
    assert later.user_prompts == healthy.main.seen[0].user_prompts, (
        "a later MAIN request carries a host-injected entry beside the opening message: "
        f"{[p[:80] for p in later.user_prompts]!r}")
    assert later.text.count(SUMMARY) == 1, "the correlation summary reached MAIN twice"

    stores: list = []
    d = _store_fault_after_lead_output(tmp_path / "fault", tenant, run_id="r1222-p031-fault",
                                       stores=stores)
    _assert_store_fault_stopped_the_run(d)


def test_p032_l00c_summary_cannot_be_persisted(tmp_path: Path) -> None:
    """A run folder that refuses to persist a produced summary stops the run loudly. It is never
    named as one of the lead's endings."""
    tenant = S.plant_tenant()

    def squat(run_dir: Path) -> None:
        Path(RunPaths(run_dir).gather_summary(L3)).mkdir(parents=True)

    d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p032", leads={L3: [S.text(SUMMARY)]},
                    before=squat)
    _assert_lead_ran(d)
    assert d.router.requests(L3) >= 1, "the lead never produced its summary"
    _assert_main_never_asked(d, "the run folder refused the lead's produced summary")
    _assert_stopped_loudly(d)


def test_p165_lead_worst_case_exceeds_the_run_clock(tmp_path: Path) -> None:
    """One harness deadline bounds the whole lead, retries included: MAIN's opening request follows
    within the deadline plus the longest step that cannot be cut (a bash call, up to 120 s), and
    the lead's ending is 'timed out'."""
    tenant = S.plant_tenant()
    # Eight requests (the lead's whole request limit), each well under the deadline; run to the
    # end they would take about 9.6 s and close on a late summary.
    per_request = 0.6 * DEADLINE_S
    script = [S.list_verbs("elastic")] * (S.CORRELATION_REQUEST_LIMIT - 1) + [S.text(LATE)]
    stores: list = []
    clock = _Clock()
    main = S.MainScript()
    d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p165", main=main, before=clock,
                    leads={L3: script}, lead_faults={L3: S.LeadFault(delay=per_request)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    _assert_lead_ran(d)
    assert main.first_at is not None, "MAIN never started"
    assert clock.at is not None
    waited = main.first_at - clock.at
    assert waited <= DEADLINE_S + SLACK_S, (
        f"MAIN started {waited:.1f}s after the run folder existed: requests each under the "
        f"{DEADLINE_S}s deadline ran on past it — the bound is per request, not the whole lead")
    assert d.router.requests(L3) < len(script), "the lead ran every one of its requests"
    _assert_timed_out_member(_session_ending(stores, L3), who="l-00c")
    _assert_never_delivered(d, LATE)


def test_p166_budget_kill_raised_at_one_of_the_leads_tool_call(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A run-level budget kill raised at one of the lead's own tool calls is a kill from another
    cause: the run stops loudly."""
    tenant = S.plant_tenant()
    stores: list = []
    d = _budget_kill_during_lead(tmp_path, tenant, monkeypatch, run_id="r1222-p166",
                                 stores=stores)
    _assert_budget_kill_during_lead(d, stores)
    assert d.rows_for(L3) == [], "the lead's killed call ran anyway"


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
        d = S.run_alert(tmp_path / kind, tenant=tenant, run_id=f"r1222-p167-{kind}", main=main,
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
    d = S.run_alert(tmp_path / "early", tenant=tenant, run_id="r1222-p167-early",
                    leads={L3: [S.text(SUMMARY)]},
                    lead_faults={L3: S.LeadFault(delay=0.25 * DEADLINE_S)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path / "early", sink=early), stores=early)
    _assert_lead_ran(d)
    _assert_summary_delivered(d, SUMMARY)
    assert _session_ending(early, L3) is None, "a response inside the deadline was cut"


def test_p168_timeout_and_a_main_dispatched_lead_that_hangs(tmp_path: Path) -> None:
    """The deadline is correlation's only; a gather lead MAIN dispatched is not bound by it."""
    tenant = S.plant_tenant()
    stores: list = []
    d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p168",
                    main=[S.gather("l-001", "cmdb"), S.text(S.DONE)],
                    leads={L3: [S.text(LATE)], "l-001": [S.text(LEAD_SUMMARY)]},
                    lead_faults={L3: S.LeadFault(delay=STALL_S),
                                 "l-001": S.LeadFault(delay=DEADLINE_S + 1.5)},
                    limits=S.with_deadline(DEADLINE_S),
                    store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    _assert_lead_ran(d)
    _assert_timed_out_member(_session_ending(stores, L3), who="l-00c")
    assert d.router.dispatched("l-001"), "MAIN's lead never ran"
    assert d.main.requests >= 2, "MAIN never got its lead's answer"
    assert LEAD_SUMMARY in d.main.seen[-1].text, (
        "the answer MAIN's lead gave after a wait longer than the correlation deadline never "
        "reached MAIN — the deadline cut a lead MAIN dispatched")
    assert _session_ending(stores, "l-001") is None, (
        "MAIN's lead outlasting the correlation deadline was stamped as cut short")


def test_p169_lead_timed_out_after_its_calls_succeeded(tmp_path: Path) -> None:
    """A lead that timed out after successful calls gets "timed out" in the section. Its queries
    rows stay recorded, and their counts are not delivered."""
    tenant = S.plant_tenant()
    deadline = 3.0
    counts = {"a": 7340033, "b": 8650757}
    prose: dict[str, str] = {}
    for label, count in counts.items():
        stores: list = []
        backend = S.Backend(answer=_counting(count))
        # The first request answers at 2.0 s with one call (which succeeds); the next request
        # would answer at about 4.0 s, past the 3.0 s deadline.
        d = S.run_alert(tmp_path / label, tenant=tenant, run_id=f"r1222-p169-{label}",
                        leads={L3: [_alerts_call(), S.text(f"{count} scoped alerts")]},
                        lead_faults={L3: S.LeadFault(delay=2.0)}, backend=backend,
                        limits=S.with_deadline(deadline),
                        store_factory=S.store_factory(tmp_path / label, sink=stores),
                        stores=stores)
        _assert_lead_ran(d)
        rows = d.rows_for(L3)
        assert len(rows) == 1, (
            f"the lead's successful call is not recorded in the queries table: {rows!r}")
        assert rows[0].get("exit_code") == 0, rows
        _assert_timed_out_member(_session_ending(stores, L3), who=f"[{label}] l-00c")
        _assert_never_delivered(d, str(count))
        prose[label] = _prose(d)
    assert prose["a"] == prose["b"], (
        "two timed-out leads whose successful calls counted differently gave MAIN different "
        "opening prose: a count was delivered")


def test_p170_operator_interrupts_while_the_lead_runs_before_m(tmp_path: Path) -> None:
    """An interrupt while the lead runs propagates with no summary promised, but closes the wire
    log and the session store and reports the interruption."""
    tenant = S.plant_tenant()
    stores: list = []
    clock = _Clock()
    main = S.MainScript()
    interrupted = False
    try:
        d = S.run_alert(tmp_path, tenant=tenant, run_id="r1222-p170", main=main, before=clock,
                        leads={L3: [S.text(SUMMARY)]},
                        lead_faults={L3: S.LeadFault(raise_on=1, exc=KeyboardInterrupt)},
                        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    except KeyboardInterrupt:
        interrupted = True
    else:
        _assert_lead_ran(d)
    assert interrupted, "the interrupt raised while the lead ran did not reach the operator"
    assert main.requests == 0, "MAIN started although the run was interrupted during the lead"
    assert clock.run_dir is not None
    observe = S.mod("runtime.observe")
    try:
        reopened = observe.RequestLogger(observe.wire_log_path(clock.run_dir))
    except FileExistsError as leak:
        pytest.fail(f"the interrupted run left its wire log open: {leak}")
    reopened.close()
    assert stores, "the run opened no session store"
    with pytest.raises(sqlite3.ProgrammingError):
        stores[-1].connection.execute("SELECT 1")


def test_p171_run_stopped_before_mains_first_request(tmp_path: Path,
                                                     monkeypatch: pytest.MonkeyPatch) -> None:
    """A handled stop before MAIN's first request goes down the existing early-stop path: the run
    summary names the cause and that the agent never started, and the post-run steps do what they
    do for any truncated run."""
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
            tmp_path / "main", tenant=tenant, run_id="r1222-p171-main",
            main=S.MainScript(S.default_main_turns(), S.LeadFault(delay=KILL_DELAY_S)),
            limits=S.default_limits(wall_clock_timeout=KILL_WALL_S, grace_seconds=0),
            tickets=tickets_a, update_ticket=True, no_learn=False,
            enqueue=enqueue_a)
    # The stop before MAIN's first request: a budget kill at the lead's own tool call.
    tickets_b, enqueue_b, handed_b, answers_b = post_steps()
    stores: list = []
    lead_kill = _budget_kill_during_lead(
        tmp_path / "lead", tenant, monkeypatch, run_id="r1222-p171-lead", stores=stores,
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
        d = S.run_alert(tmp_path / f"m{mains}", tenant=tenant, run_id=f"r1222-p174-{mains}",
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


def test_p175_main_lead_named_l00c_when_no_harness_claim_exist(tmp_path: Path) -> None:
    """A lead MAIN dispatched counts toward the kill whatever its id, l-00c included."""
    # Correlation withheld: no harness claim exists, so the id is MAIN's to mint (PR-23).
    tenant = S.plant_tenant(table=S.TABLE_WITHHELD)
    n = _kill_limit()
    for lead in ("l-001", L3):
        stores: list = []
        d = S.run_alert(tmp_path / lead, tenant=tenant, run_id=f"r1222-p175-{lead}",
                        main=[S.gather(lead, "identity"), S.text(S.DONE)],
                        leads={lead: [_parallel("identity", "get-user", n), S.text("x")]},
                        backend=S.Backend(fault=T.Fault(fail_on=("identity.get-user",))),
                        store_factory=S.store_factory(tmp_path / lead, sink=stores),
                        stores=stores)
        assert d.router.dispatched(lead), f"MAIN's lead {lead} never ran"
        _assert_killed(d, _run_end().TRUNCATED_BY_ABORTED, "RunAborted")
        assert _session_ending(stores, lead) == _run_end().TRUNCATED_BY_ABORTED, (
            f"MAIN's {lead} reached the kill count and its session does not read as aborted")
