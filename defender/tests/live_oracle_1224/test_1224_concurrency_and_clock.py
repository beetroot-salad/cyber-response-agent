from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _episode_handle as EH
from defender.hooks.budget_enforcer import BUDGET_REFUSAL_MESSAGE, DEFAULT_LIMITS
from defender.run_repository import RunPaths
from defender.runtime.lead_zero import RESERVED_LEAD_IDS
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S

ENFORCE = "DEFENDER_BUDGET_ENFORCE"

EMPTY: dict = {"rows": []}
ALICE = S.query_params("user:alice")
BASE_ROW = {"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
            "ts": "2026-07-28T15:00:00Z"}
EDR_ROW = {"event_id": "x-7", "host": "db-1", "process": "sshd", "ts": "2026-07-28T15:10:00Z"}


def _episode(tmp_path: Path, calls: list[tuple[str, str, dict, Any]]) -> Path:
    """A v2 episode whose base recording captured exactly `calls`."""
    return S.episode_v2(tmp_path, base_rows=[S.captured(s, v, p, payload)
                                             for s, v, p, payload in calls])


def _forged(n: int, **over: Any) -> dict:
    """A forged idp row for fact f1 — the base row's columns and types (check 2), an id-like
    value no real row carries (check 3)."""
    row = {"user": "alice", "event_id": f"e-9{n:03d}", "action": "tgt", "host": "db-1",
           "ts": "2026-07-28T15:22:00Z"}
    row.update(over)
    return row


def _forge_and_submit(forged_id: str, row: dict, base_rows: list[dict], *,
                      fact_id: str = "f1", system: str = "idp") -> list[S.Move]:
    """One attempt that forges `row` for the fact and serves base + row, declaring it."""
    return [S.forge(forged_id, fact_id, system, row),
            S.submit({"rows": [*base_rows, row]}, S.claim(added=[S.added(forged_id, fact_id)]))]


def _as_text(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


class _Call(threading.Thread):
    """One investigator call on its own thread (the query tool's worker thread, GD-33)."""

    def __init__(self, fn: Callable[[], Any], barrier: threading.Barrier | None = None) -> None:
        super().__init__(daemon=True)
        self.fn, self.barrier = fn, barrier
        self.result: Any = None
        self.error: BaseException | None = None

    def run(self) -> None:
        if self.barrier is not None:
            self.barrier.wait(timeout=30)
        try:
            self.result = self.fn()
        except BaseException as failed:  # noqa: BLE001 — recorded, asserted by the test
            self.error = failed


def _together(*fns: Callable[[], Any]) -> list[_Call]:
    """Start every call at the same instant (a barrier) and wait for all of them."""
    barrier = threading.Barrier(len(fns))
    calls = [_Call(fn, barrier) for fn in fns]
    for c in calls:
        c.start()
    _join(calls)
    return calls


def _staggered(first: Callable[[], Any], then: Callable[[], Any],
               when: Callable[[], bool]) -> tuple[_Call, _Call]:
    """Start `first`; once `when()` holds (e.g. the oracle is inside its turn), start `then`."""
    a = _Call(first)
    a.start()
    _wait(when, what="the first call to reach the oracle")
    b = _Call(then)
    b.start()
    _join([a, b])
    return a, b


def _join(calls: list[_Call], timeout: float = 120) -> None:
    for c in calls:
        c.join(timeout)
    assert not any(c.is_alive() for c in calls), "a call never returned (a hung turn)"


def _wait(cond: Callable[[], bool], *, what: str, timeout: float = 30) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return
        time.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def _spans(*models: S.ScriptedModel) -> list[tuple[float, float, str]]:
    return sorted((s, f, m.name) for m in models
                  for s, f in zip(m.started, m.finished, strict=False))


def _assert_never_overlap(*models: S.ScriptedModel) -> None:
    """S11: within one world no oracle or verifier request is open while another is."""
    spans = _spans(*models)
    for (_s0, f0, n0), (s1, _f1, n1) in zip(spans, spans[1:], strict=False):
        assert s1 >= f0 - 1e-3, (
            f"a {n1} request started {f0 - s1:.3f}s before a {n0} request finished — two turns "
            "were open at once in one world")


def _held(*models: S.ScriptedModel) -> float:
    """Seconds the doubles spent answering (the oracle-held time the run must exclude)."""
    return sum(f - s for s, f, _n in _spans(*models))


def _max_in_window(times: list[float], width: float = 0.95) -> int:
    """The most calls inside any window of `width` seconds (a 1 s window, edge-tolerant)."""
    return max((sum(1 for u in times if t <= u < t + width) for t in times), default=0)


#: A response that carries several tool calls at once (parallel `run_query`s inside one turn).
_PARALLEL = "__parallel_1224__"


def parallel(*moves: S.Move) -> S.Move:
    return S.Move(_PARALLEL, {"moves": list(moves)})


class _ParallelScripted(S.ScriptedModel):
    """`ScriptedModel` whose `parallel(...)` move answers with several tool-call parts in one
    response, as a model issuing parallel tool calls does. It scripts content only."""

    def __call__(self, messages: list[Any], info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        response = super().__call__(messages, info)
        parts: list[Any] = []
        for part in response.parts:
            if getattr(part, "tool_name", None) == _PARALLEL:
                parts += [ToolCallPart(tool_name=m.tool, args=dict(m.args))
                          for m in part.args["moves"]]
            else:
                parts.append(part)
        return ModelResponse(parts=parts)


class _ExploreThenSubmit(_ParallelScripted):
    """An oracle double for pre-flight, where several worlds' turns share one double: every
    turn first answers `n` parallel `run_query`s, then — once their results are back — submits
    the base answer unchanged. It decides nothing; the turn's shape is its script."""

    def __init__(self, n: int, *, system: str = "idp") -> None:
        super().__init__(name="oracle")
        self.n, self.system, self._turn_lock = n, system, threading.Lock()
        self._issued = 0

    def __call__(self, messages: list[Any], info: Any) -> Any:
        last = messages[-1] if messages else None
        explored = any(getattr(p, "tool_name", None) == S.COINED["tool.run_query"]
                       for p in getattr(last, "parts", ()))
        with self._turn_lock:
            if explored:
                self.moves.insert(0, S.submit(EMPTY, S.EMPTY_CLAIM))
            else:
                first = self._issued
                self._issued += self.n
                self.moves.insert(0, parallel(*[
                    S.run_query(self.system, "query", S.query_params(f"probe-{first + i}"))
                    for i in range(self.n)]))
            return super().__call__(messages, info)


# --- the whole-run drive ---------------------------------------------------------------


class _Router:
    """The gather model for one or more parallel leads: routes each request to its lead by
    the lead's goal text and answers with that lead's next scripted turn. A step may be a
    callable returning the turn (it runs on the model's executor thread, so it may wait for
    the oracle or sleep — the investigator's own latency)."""

    __name__ = "Router"

    def __init__(self, scripts: dict[str, list[Any]], marks: dict[str, str]) -> None:
        self.scripts = {k: list(v) for k, v in scripts.items()}
        self.marks = marks
        self.seen: dict[str, list[str]] = {k: [] for k in scripts}

    def __call__(self, messages: list[Any], info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

        text = S.replay_harness().messages_text(messages)
        lead = next(k for k, mark in self.marks.items() if mark in text)
        self.seen[lead].append(text)
        script = self.scripts[lead]
        if not script:
            return ModelResponse(parts=[TextPart(content="(lead done)")])
        step = script.pop(0)
        if callable(step):
            step = step()
        parts: list[Any] = [TextPart(content=step.text)] if step.text else []
        parts += [ToolCallPart(tool_name=n, args=a) for n, a in step.tool_calls]
        return ModelResponse(parts=parts or [TextPart(content="(done)")])

    def shown(self, lead: str) -> str:
        return "\n".join(self.seen[lead])


def _mark(lead: str) -> str:
    return f"GOAL-{lead.upper()}-1224"


def _drive(tmp_path: Path, *, verbs: Any, tenant: Any, leads: dict[str, list[Any]],
           limits: dict | None = None, run_id: str = "run-1224",
           run_dir: Path | None = None, system: str = "idp") -> tuple[Path, _Router, dict]:
    """One investigation through the real driver: MAIN dispatches every lead in `leads` in ONE
    turn (parallel gather leads), each lead runs its own scripted turns. Returns the run dir,
    the router (what each lead was shown) and the run's summary."""
    H = S.replay_harness()
    run_dir = run_dir if run_dir is not None else H.materialize(tmp_path / run_id, H.GOLDEN_AB3)  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    marks = {lead: _mark(lead) for lead in leads}
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {"lead_id": lead, "system": system, "goal": marks[lead],
                                       "what_to_summarize": ["what the system says"]})
                           for lead in leads]),
        H.Turn(text="Investigation complete."),
    ])
    router = _Router(leads, marks)
    summary = H.drive(run_dir, run_id=run_id, main=main, gather=router, verbs=verbs,
                      limits=limits, tenant=tenant)
    return run_dir, router, summary


def _limits(wall_clock: float) -> dict:
    """The enforcer's caps with a short wall clock and a long grace (a refusal, never a kill)."""
    return {**DEFAULT_LIMITS, "wall_clock_timeout": wall_clock, "grace_seconds": 600,
            "max_tool_calls": 500}


def _q(params: dict, system: str = "idp", verb: str = "query") -> Any:
    return S.query_turn(system, verb, params)


def _refusal_stem() -> str:
    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, "the refusal message has no literal stem to observe"
    return stem


def _refused_queries(run_dir: Path) -> list[dict]:
    path = RunPaths(run_dir).wire_log
    return [r for r in S.read_jsonl(path)
            if r.get("kind") == "budget_refusal" and r.get("tool_name") == "query"]


def _own_rows(run_dir: Path) -> list[dict]:
    return [r for r in S.read_jsonl(run_dir / "executed_queries.jsonl")
            if r.get("lead_id") not in RESERVED_LEAD_IDS]


def _budget(summary: dict) -> dict:
    """The run's budget counters, read off the run's one `RunState`, which the driver hands back
    as `summary["run_state"]` (#1235: no file in the run dir holds them)."""
    return summary["run_state"].budget_snapshot()


def _slow_adapter(est: S.Estate, system: str, seconds: float) -> None:
    """Make the planted adapter for `system` slow: a REAL adapter module whose answer takes
    `seconds` (real-system latency, the investigator's own on a real run — GD-10)."""
    path = est.adapters / f"{system.replace('-', '_')}_adapter.py"
    head = "def _answer(ctx: VerbContext, name: str, params: dict):\n"
    src = path.read_text(encoding="utf-8")
    assert head in src, "the planted adapter's shape moved"
    path.write_text(src.replace(head, f"{head}    time.sleep({seconds!r})\n", 1),
                    encoding="utf-8")


def test_1224_oracle_latency_trips_no_investigator_time_limit(tmp_path, monkeypatch):
    monkeypatch.setenv(ENFORCE, "true")
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, [("idp", "query", ALICE, {"rows": [BASE_ROW]})])
    oracle = S.oracle(*_forge_and_submit("fg-1", _forged(1), [BASE_ROW]),
                      fault=S.Fault(delay=1.0))
    verifier = S.passing_verifier(fault=S.Fault(delay=1.0))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
    run_dir, router, summary = _drive(
        tmp_path, verbs=reg, tenant=est.place(), limits=_limits(1.5),
        leads={"l-001": [_q(ALICE), _q(ALICE), S.done_turn()]})

    assert oracle.submissions() == 1, "no oracle turn was taken"
    assert verifier.requests >= 1, "no oracle turn was taken"
    assert _held(oracle, verifier) >= 2.5, "the oracle and verifier held the turn too briefly"
    assert _refusal_stem() not in router.shown("l-001"), (
        "the budget enforcer refused the next call because of oracle latency")
    assert _refused_queries(run_dir) == []
    rows = [r for r in _own_rows(run_dir) if r["lead_id"] == "l-001"]
    assert [r["exit_code"] for r in rows] == [0, 0], "both queries were not executed"
    assert summary.get("truncated_by") != "budget", "the run was exhausted by oracle latency"

    control = tmp_path / "control"
    est_c = S.estate(control)
    ep_c = _episode(control, [("idp", "query", ALICE, {"rows": [BASE_ROW]})])
    reg_c = S.world_registry(ep_c, "b", est_c,
                             oracle=S.oracle(*_forge_and_submit("fg-1", _forged(1), [BASE_ROW])),
                             verifier=S.passing_verifier(), retry_cap=3)

    def slow_investigator() -> Any:
        time.sleep(2.5)
        return _q(ALICE)

    run_c, router_c, _ = _drive(control, verbs=reg_c, tenant=est_c.place(),
                                limits=_limits(1.5),
                                leads={"l-001": [_q(ALICE), slow_investigator, S.done_turn()]})
    assert _refusal_stem() in router_c.shown("l-001"), (
        "the investigator's own latency was not counted — the limit is dead, so the negative "
        "above proves nothing")


def test_conc_12_queue_wait_behind_another_leads_turn(tmp_path, monkeypatch):
    monkeypatch.setenv(ENFORCE, "true")
    est = S.estate(tmp_path)
    est.answer("idp", "query", None, EMPTY)
    other = S.query_params("user:bob")
    ep = _episode(tmp_path, [("idp", "query", ALICE, EMPTY), ("idp", "query", other, EMPTY)])
    oracle = S.oracle(S.run_query("idp", "query", S.query_params("probe-1")),
                      S.run_query("idp", "query", S.query_params("probe-2")),
                      S.submit(EMPTY, S.EMPTY_CLAIM),
                      then=S.submit(EMPTY, S.EMPTY_CLAIM), fault=S.Fault(delay=0.6))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3, rate=1.0)

    def queued() -> Any:
        _wait(lambda: len(oracle.started) >= 1, what="lead one's oracle turn")
        return _q(other)

    run_dir, router, summary = _drive(
        tmp_path, verbs=reg, tenant=est.place(), limits=_limits(1.5),
        leads={"l-001": [_q(ALICE), S.done_turn()],
               "l-002": [queued, _q(other), S.done_turn()]})

    assert len(est.calls("idp", "query")) >= 2, "the oracle's exploration never ran"
    assert oracle.submissions() == 2
    assert _refusal_stem() not in router.shown("l-002"), (
        "queue or limiter wait behind lead one's turn was counted")
    assert [r["exit_code"] for r in _own_rows(run_dir) if r["lead_id"] == "l-002"] == [0, 0]
    # Two gathers, one query on lead one, two on lead two — and nothing for the oracle.
    assert _budget(summary)["tool_calls"] == 5, (
        "the investigator's tool-call count is not one per investigator call")


def test_slow_real_system_and_slow_oracle_in_one_call(tmp_path, monkeypatch):
    monkeypatch.setenv(ENFORCE, "true")
    est = S.estate(tmp_path)
    _slow_adapter(est, "edr", 2.2)
    est.answer("edr", "query", None, {"events": [EDR_ROW]})
    ep = _episode(tmp_path, [])
    oracle = S.oracle(then=S.submit({"events": [EDR_ROW]}, S.EMPTY_CLAIM),
                      fault=S.Fault(delay=2.5))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    first, second, third = (S.query_params(f"host:db-{n}") for n in (1, 2, 3))
    run_dir, router, _ = _drive(
        tmp_path, verbs=reg, tenant=est.place(), limits=_limits(4.0), system="edr",
        leads={"l-001": [_q(first, "edr"), _q(first, "edr"), _q(second, "edr"),
                         _q(third, "edr"), S.done_turn()]})

    shown = router.seen["l-001"]
    assert len(est.calls("edr", "query")) >= 2, "the slow base reads never ran"
    # Each request carries the whole history: request 3 holds the first three calls' results,
    # request 4 the fourth's.
    assert len(shown) >= 5, "the lead stopped before its fourth call"
    assert _refusal_stem() not in shown[3], (
        "a call whose base read alone stays under the limit was refused for oracle time")
    assert _refusal_stem() in shown[4], (
        "two slow base reads crossed the limit and nothing was refused — real latency must count")
    assert not [c for c in est.calls("edr", "query") if c["params"] == third], (
        "the refused call reached the tenant")


def test_1224_two_identical_concurrent_calls_get_one_turn_and_identical_bytes(tmp_path):
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, [("idp", "query", ALICE, {"rows": [BASE_ROW]})])
    oracle = S.oracle(*_forge_and_submit("fg-1", _forged(1), [BASE_ROW]),
                      fault=S.Fault(delay=0.3))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    run_dir, _router, _ = _drive(tmp_path, verbs=reg, tenant=est.place(),
                                 leads={"l-001": [_q(ALICE), S.done_turn()],
                                        "l-002": [_q(ALICE), S.done_turn()]})

    rows = _own_rows(run_dir)
    assert sorted(r["lead_id"] for r in rows) == ["l-001", "l-002"]
    assert all(r["exit_code"] == 0 for r in rows)
    payloads = {(run_dir / r["payload_path"]).read_bytes() for r in rows}
    assert len(payloads) == 1, "the two leads received different bytes"
    assert oracle.submissions() == 1, "the identical call took two turns"
    assert not oracle.overrun, "the identical call took two turns"
    ledger = S.ledger_rows(ep, "b")
    assert len(ledger) == 2, "one ledger row per investigator call"
    assert ledger[0]["payload_text"] == ledger[1]["payload_text"]
    stored = [r for r in S.oracle_rows(ep, "b", "answers") if r["params"] == ALICE]
    assert len(stored) == 1, "the world holds more than one served answer for the call"
    assert [r["forged_id"] for r in S.oracle_rows(ep, "b", "forged")] == ["fg-1"]

    two = tmp_path / "two"
    est2 = S.estate(two)
    p1, p2 = S.query_params("user:carol"), S.query_params("user:dave")
    ep2 = _episode(two, [("idp", "query", p1, EMPTY), ("idp", "query", p2, EMPTY)])
    oracle2 = S.oracle(then=S.submit(EMPTY, S.EMPTY_CLAIM))
    reg2 = S.world_registry(ep2, "b", est2, oracle=oracle2, verifier=S.passing_verifier(),
                            retry_cap=3)
    ctx2 = est2.ctx(two / "run")
    _together(lambda: S.call(reg2, "idp", "query", ctx2, **p1),
              lambda: S.call(reg2, "idp", "query", ctx2, **p2))
    assert oracle2.submissions() == 2, "two different calls did not get two turns"

    faults = S.mod("scripts.adapters.faults")
    broken = S.query_params("user:erin")
    est2.fail("idp", "query", broken)
    for _ in range(2):
        with pytest.raises(faults.UpstreamFault):
            S.call(reg2, "idp", "query", ctx2, **broken)
    live = [c for c in est2.calls("idp", "query") if c["params"] == broken]
    assert len(live) == 2, "a repeat after a real error did not read live"
    errors = [r for r in S.ledger_rows(ep2, "b") if r["source"] == S.REAL_ERROR]
    assert len(errors) == 2
    assert not [r for r in S.oracle_rows(ep2, "b", "answers") if r["params"] == broken], (
        "a real error was cached as the world's answer")


def test_conc_03_two_calls_forge_for_one_fact_concurrently(tmp_path):
    est = S.estate(tmp_path)
    edr_params = S.query_params("host:db-1")
    ep = _episode(tmp_path, [("idp", "query", ALICE, {"rows": [BASE_ROW]}),
                             ("edr", "query", edr_params, {"events": [EDR_ROW]})])
    idp_row = _forged(1)
    edr_row = {"event_id": "x-9001", "host": "db-1", "process": "kinit",
               "ts": "2026-07-28T15:22:00Z"}
    oracle = S.oracle(
        *_forge_and_submit("fg-1", idp_row, [BASE_ROW]),
        S.forge("fg-1", "f1", "idp", _forged(1, ts="2026-07-28T18:00:00Z")),
        S.forge("fg-2", "f1", "edr", edr_row),
        S.submit({"events": [EDR_ROW, edr_row]}, S.claim(added=[S.added("fg-2", "f1")])),
        S.forge("fg-2", "f1", "edr", edr_row),
        S.submit({"events": [EDR_ROW, edr_row]}, S.claim(added=[S.added("fg-2", "f1")])),
        fault=S.Fault(delay=0.2))
    verifier = S.passing_verifier()
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
    ctx = est.ctx(tmp_path / "run")
    a, b = _staggered(lambda: S.call(reg, "idp", "query", ctx, **ALICE),
                      lambda: S.call(reg, "edr", "query", ctx, **edr_params),
                      when=lambda: len(oracle.started) >= 1)
    assert a.error is None, (a.error, b.error)
    assert b.error is None, (a.error, b.error)
    _assert_never_overlap(oracle, verifier)
    forged = S.oracle_rows(ep, "b", "forged")
    fg1 = [r for r in forged if r["forged_id"] == "fg-1"]
    assert len(fg1) == 1, "the fact's frozen row was re-versioned"
    assert fg1[0]["row"] == idp_row, "the fact's frozen row was re-versioned"
    assert [r["system"] for r in forged if r["forged_id"] == "fg-2"] == ["edr"]
    assert "e-9001" in verifier.seen[-1], (
        "the second call's verifier pass was not shown the fact's frozen telemetry")
    assert "2026-07-28T18:00:00Z" not in "".join(r["payload_text"] for r in S.ledger_rows(ep, "b"))


def test_conc_04_record_fact_conflict_between_concurrent_calls(tmp_path):
    est = S.estate(tmp_path)
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001"}
    idp = {"entity": "alice", "risk": "low"}
    ep = _episode(tmp_path, [("siem-x", "lookup", {"entity": "alice"}, siem),
                             ("idp", "lookup", {"entity": "alice"}, idp)])
    oracle = S.oracle(
        S.record_fact("alice", "risk", "high"),
        S.submit(dict(siem, risk="high"), S.claim(changed=[S.changed("alice", "risk", "low",
                                                                      "high")])),
        S.record_fact("alice", "risk", "critical"),
        S.submit(dict(idp, risk="critical"), S.claim(changed=[S.changed("alice", "risk", "low",
                                                                         "critical")])),
        S.submit(dict(idp, risk="high"), S.claim(changed=[S.changed("alice", "risk", "low",
                                                                     "high")])),
        fault=S.Fault(delay=0.2))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    ctx = est.ctx(tmp_path / "run")
    a, b = _staggered(lambda: S.call(reg, "siem-x", "lookup", ctx, entity="alice"),
                      lambda: S.call(reg, "idp", "lookup", ctx, entity="alice"),
                      when=lambda: len(oracle.started) >= 1)
    assert a.error is None, (a.error, b.error)
    assert b.error is None, (a.error, b.error)
    risk = [r for r in S.oracle_rows(ep, "b", "facts")
            if r["entity"] == "alice" and r["field"] == "risk"]
    assert [r["value"] for r in risk] == ["high"], "the field does not end with one value"
    served = "".join(r["payload_text"] for r in S.ledger_rows(ep, "b"))
    assert "critical" not in served, "a lead was served an answer contradicting the record"
    assert any(S.verdict_names(t, "check 4") for t in oracle.seen[2:]), (
        "the contradicting submission was not refused by check 4")


def test_conc_05_check_then_commit_window_on_frozen_rows(tmp_path):
    est = S.estate(tmp_path)
    later = S.query_params("user:alice", start="2026-07-28T15:00:00Z")
    ep = _episode(tmp_path, [("idp", "query", ALICE, {"rows": [BASE_ROW]}),
                             ("idp", "query", later, {"rows": [BASE_ROW]})])
    first, rival = _forged(1), _forged(1, host="RIVAL-HOST-1224")
    oracle = S.oracle(*_forge_and_submit("fg-1", first, [BASE_ROW]),
                      *_forge_and_submit("fg-1", rival, [BASE_ROW]),
                      S.submit({"rows": [BASE_ROW, first]}, S.claim(added=[S.added("fg-1", "f1")])),
                      fault=S.Fault(delay=0.2))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    ctx = est.ctx(tmp_path / "run")
    a, b = _staggered(lambda: S.call(reg, "idp", "query", ctx, **ALICE),
                      lambda: S.call(reg, "idp", "query", ctx, **later),
                      when=lambda: len(oracle.started) >= 1)
    assert a.error is None, (a.error, b.error)
    assert b.error is None, (a.error, b.error)
    fg1 = [r for r in S.oracle_rows(ep, "b", "forged") if r["forged_id"] == "fg-1"]
    assert len(fg1) == 1, "two versions of one frozen row"
    assert fg1[0]["row"] == first, "two versions of one frozen row"
    rows = S.ledger_rows(ep, "b")
    assert len(rows) == 2
    assert not [r for r in rows if "RIVAL-HOST-1224" in r["payload_text"]], (
        "an answer contradicting the committed frozen row was served")


def test_1224_two_concurrent_calls_take_sequential_oracle_turns_that_never_interleave(
        tmp_path, monkeypatch):
    monkeypatch.setenv(ENFORCE, "true")
    est = S.estate(tmp_path)
    first = S.query_params("user:alice-A-1224")
    second = S.query_params("host:db-B-1224")
    ep = _episode(tmp_path, [("idp", "query", first, {"rows": [BASE_ROW]}),
                             ("idp", "query", second, EMPTY)])
    oracle = S.oracle(S.submit({"rows": [BASE_ROW]}, S.EMPTY_CLAIM),
                      *_forge_and_submit("fg-1", _forged(1), [BASE_ROW]),
                      S.submit(EMPTY, S.EMPTY_CLAIM), fault=S.Fault(delay=0.5))
    verifier = S.verifier(S.verdict(False, "VERDICT-MARK-1224 fact f1 is missing"),
                          S.verdict(True), S.verdict(True), fault=S.Fault(delay=0.5))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)

    def mid_retry() -> Any:
        _wait(lambda: len(verifier.started) >= 1, what="the first call's verifier pass")
        return _q(second)

    run_dir, router, _ = _drive(
        tmp_path, verbs=reg, tenant=est.place(), limits=_limits(1.5),
        leads={"l-001": [_q(first), S.done_turn()],
               "l-002": [mid_retry, _q(second), S.done_turn()]})

    assert not oracle.overrun
    assert oracle.submissions() == 3
    _assert_never_overlap(oracle, verifier)
    assert verifier.finished[1] <= oracle.started[3] + 1e-3, (
        "the second call's turn began before the first call's verifier pass ended")
    for text in oracle.seen[:3]:
        assert "B-1224" not in text, "the second call's params entered the first call's turn"
    assert S.verdict_names(oracle.seen[1], "verifier")
    assert "VERDICT-MARK-1224" in oracle.seen[1], "the failure verdict never reached the retry"
    S.assert_wrapped_untrusted(oracle.seen[3], "host:db-B-1224",
                               "the second call's params in its own turn")
    for text in verifier.seen[:2]:
        assert "B-1224" not in text, "the second call's params entered the first's verifier pass"
    assert "VERDICT-MARK-1224" not in verifier.seen[2], (
        "the first call's verdict reached the second call's verifier pass")
    assert "A-1224" not in verifier.seen[2], (
        "the first call's params reached the second call's verifier pass")
    investigator = "\n".join([*router.seen["l-001"], *router.seen["l-002"]])
    assert _mark("l-001") in investigator
    for text in (*oracle.seen, *verifier.seen):
        assert _mark("l-001") not in text, "the investigator's own text reached an oracle-side turn"
        assert _mark("l-002") not in text, "the investigator's own text reached an oracle-side turn"
    assert _refusal_stem() not in router.shown("l-002"), "the queue wait was counted"
    assert [r["exit_code"] for r in _own_rows(run_dir) if r["lead_id"] == "l-002"] == [0, 0]


def test_conc_09_conversation_restart_with_a_turn_in_flight(tmp_path):
    est = S.estate(tmp_path)
    siem = {"entity": "alice", "risk": "low", "record_id": "r-0001"}
    ep = _episode(tmp_path, [("siem-x", "lookup", {"entity": "alice"}, siem),
                             ("idp", "query", ALICE, {"rows": [BASE_ROW]})])
    oracle = S.oracle(S.record_fact("alice", "risk_tier", "TIER-XQ7-1224"),
                      S.submit(siem, S.EMPTY_CLAIM),
                      S.submit({"rows": [BASE_ROW]}, S.EMPTY_CLAIM),
                      *_forge_and_submit("fg-1", _forged(1), [BASE_ROW]))
    verifier = S.verifier(S.verdict(True), S.verdict(False, "FAILMARK-1224 f1 is absent"),
                          S.verdict(True))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3,
                           restart_after=1)
    ctx = est.ctx(tmp_path / "run")
    S.call(reg, "siem-x", "lookup", ctx, entity="alice")
    S.call(reg, "idp", "query", ctx, **ALICE)
    assert not oracle.overrun
    assert oracle.submissions() == 3

    restarts = [i for i in range(1, len(oracle.messages))
                if len(oracle.messages[i]) < len(oracle.messages[i - 1])]
    assert restarts, "the conversation never restarted at its restart point"
    first = restarts[0]
    assert oracle.instructions[first] == oracle.instructions[0], "the prefix changed"
    statement = S.fact()["statement"]
    for i in range(first, oracle.requests):
        assert "TIER-XQ7-1224" in oracle.seen[i], (
            f"request {i} after the restart does not carry the recorded fact")
        assert statement in oracle.seen[i], f"request {i} lost the world block"
    assert "FAILMARK-1224" in oracle.seen[-2], (
        "the in-flight call's retry lost its failure history across the restart")


def test_conc_18_lead_ended_mid_serve(tmp_path, monkeypatch):
    monkeypatch.setenv(ENFORCE, "true")
    late = S.query_params("user:alice host:db-1")
    served_answer = {"rows": [BASE_ROW, _forged(1)]}

    def scenario(root: Path, *, read_s: float, limits: dict,
                 killer_after: float | None) -> dict[str, Any]:
        est = S.estate(root)
        _slow_adapter(est, "idp", read_s)
        est.answer("idp", "query", late, {"rows": [BASE_ROW]})
        ep = _episode(root, [])
        oracle = S.oracle(*_forge_and_submit("fg-1", _forged(1), [BASE_ROW]))
        reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                               retry_cap=3)
        marks: dict[str, float] = {}
        leads: dict[str, list[Any]] = {"l-001": [_q(late), S.done_turn()]}
        if killer_after is not None:
            def own_latency_then_query() -> Any:
                time.sleep(killer_after)  # l-002's own model latency: the investigator's
                marks["killing_turn"] = time.monotonic()
                return _q(S.query_params("user:bob"))

            leads["l-002"] = [own_latency_then_query, S.done_turn()]
        run_dir, _router, summary = _drive(root, verbs=reg, tenant=est.place(), limits=limits,
                                           leads=leads)
        return {"est": est, "ep": ep, "oracle": oracle, "reg": reg, "run_dir": run_dir,
                "summary": summary, "marks": marks}

    # The order the cut needs: startup < wall clock < l-002's latency (its hook then reads
    # elapsed past wall clock + grace) < l-001's live read.
    kill = {**DEFAULT_LIMITS, "wall_clock_timeout": 4.0, "grace_seconds": 0.5,
            "max_tool_calls": 500}
    run = scenario(tmp_path / "ended", read_s=7.5, limits=kill, killer_after=5.0)
    est, ep, oracle, reg = run["est"], run["ep"], run["oracle"], run["reg"]

    assert run["summary"].get("truncated_by") == "budget", (
        f"no limit ended the run, so no lead was ended mid-call: {run['summary']}")
    assert "killing_turn" in run["marks"], "lead l-002 never reached its killing query"
    assert [c["params"] for c in est.calls("idp", "query")] == [late], (
        "l-001's call never entered the live read, or l-002's query reached the tenant")
    assert oracle.started, "the worker never reached the oracle turn after its lead ended"
    assert oracle.started[0] > run["marks"]["killing_turn"], (
        "the oracle turn began before l-002's killing query: the lead was not ended while its "
        "call was inside serve_one's live read, so the scenario is moot")
    assert oracle.submissions() == 1
    assert not oracle.overrun
    assert [r for r in _own_rows(run["run_dir"]) if r["lead_id"] == "l-001"] == [], (
        "the undelivered call left an evidence row")
    assert not list((run["run_dir"] / "gather_raw").glob("l-001/*")), (
        "the undelivered call left an evidence payload")
    stored = [r for r in S.oracle_rows(ep, "b", "answers") if r["params"] == late]
    assert len(stored) == 1, "the verified answer of the undelivered call was not stored"
    assert "e-9001" in _as_text(stored[0]), "the stored answer is not the verified one"
    assert [r for r in S.ledger_rows(ep, "b") if r.get("params") == late] == [], (
        "the undelivered call left a world-ledger row")
    assert [r["forged_id"] for r in S.oracle_rows(ep, "b", "forged")] == ["fg-1"]

    # A later identical call is served the stored answer: no turn, no live read, one row.
    turns_before = oracle.requests
    again = S.call(reg, "idp", "query", est.ctx(tmp_path / "later"), **late)
    assert again == served_answer, "the later call was not served consistently with fg-1"
    assert oracle.requests == turns_before, "the later identical call took a turn"
    assert len(est.calls("idp", "query")) == 1, "the later identical call read live again"
    assert len([r for r in S.ledger_rows(ep, "b") if r.get("params") == late]) == 1, (
        "the delivered call did not leave exactly one world-ledger row")
    assert [r["forged_id"] for r in S.oracle_rows(ep, "b", "forged")] == ["fg-1"]

    # Positive control: nothing ends the lead, so the call is delivered on the same channels.
    ctl = scenario(tmp_path / "control", read_s=1.0, limits=_limits(600.0), killer_after=None)
    assert ctl["summary"].get("truncated_by") != "budget"
    rows = [r for r in _own_rows(ctl["run_dir"]) if r["lead_id"] == "l-001"]
    assert [r["exit_code"] for r in rows] == [0], "the control's call was not delivered"
    assert len([r for r in S.ledger_rows(ctl["ep"], "b") if r.get("params") == late]) == 1
    assert len([r for r in S.oracle_rows(ctl["ep"], "b", "answers")
                if r["params"] == late]) == 1


def test_conc_32_siblings_first_use_of_shared_state_together(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", None, EMPTY)
    ep = _episode(tmp_path, [("idp", "query", ALICE, EMPTY)])
    base_before = (ep / "served" / "base.jsonl").read_bytes()
    doubles: dict[str, S.ScriptedModel] = {}
    regs = {}
    for label in ("b", "c"):
        doubles[label] = S.oracle(*[S.run_query("idp", "query",
                                                S.query_params(f"probe-{label}-{i}"))
                                    for i in range(3)],
                                  S.submit(EMPTY, S.EMPTY_CLAIM))
        regs[label] = S.world_registry(ep, label, est, oracle=doubles[label],
                                       verifier=S.passing_verifier(), retry_cap=3, rate=1.0)
    ctx_b, ctx_c = est.ctx(tmp_path / "run-b"), est.ctx(tmp_path / "run-c")
    b, c = _together(lambda: S.call(regs["b"], "idp", "query", ctx_b, **ALICE),
                     lambda: S.call(regs["c"], "idp", "query", ctx_c, **ALICE))
    assert b.error is None, (b.error, c.error)
    assert c.error is None, (b.error, c.error)
    assert (ep / "served" / "base.jsonl").read_bytes() == base_before, (
        "a sibling wrote the shared base recording")
    for label, other in (("b", "c"), ("c", "b")):
        own = S.oracle_dir(ep, label)
        assert own.is_dir(), f"world {label} kept no oracle state of its own"
        text = "".join(p.read_text(encoding="utf-8") for p in own.rglob("*") if p.is_file())
        assert f"probe-{label}-" in text, f"world {label}'s exploration is not in its own ledger"
        assert f"probe-{other}-" not in text, f"world {label}'s store holds world {other}'s rows"
    probes = [c["t"] for c in est.calls("idp", "query") if c["params"]["q"].startswith("probe-")]
    assert len(probes) == 6, "an exploration query was refused or lost"
    assert _max_in_window(probes) <= 2, "the combined oracle-side rate exceeded R"


def test_1224_concurrent_leads_leave_one_intact_world_ledger_row_per_call(tmp_path):
    est = S.estate(tmp_path)
    served = [S.query_params(f"user:served-{i}") for i in range(3)]
    broken = [S.query_params(f"user:broken-{i}") for i in range(3)]
    for p in broken:
        est.fail("idp", "query", p)
    ep = _episode(tmp_path, [("idp", "query", p, EMPTY) for p in served])
    oracle = S.oracle(then=S.submit(EMPTY, S.EMPTY_CLAIM), fault=S.Fault(delay=0.1))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3)
    ctx = est.ctx(tmp_path / "run")
    fns: list[Callable[[], Any]] = []
    fns += [lambda p=p: S.call(reg, "idp", "query", ctx, **p) for p in served]
    fns += [lambda p=p: S.call(reg, "idp", "query", ctx, **p) for p in broken]
    fns += [lambda n=n: reg.authorize_call("edr", S.WRITE_VERB, {"host": f"db-{n}"})
            for n in range(3)]
    calls = _together(*fns)
    assert all(c.error is None for c in calls[:3]), [c.error for c in calls[:3]]
    assert all(c.error is not None for c in calls[3:6]), "the erroring calls did not error"

    lines = S.ledger_path(ep, "b").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    assert len(rows) == len(lines) == 9, "a row was torn, lost or doubled"
    by_source: dict[str, int] = {}
    for r in rows:
        by_source[r["source"]] = by_source.get(r["source"], 0) + 1
    assert by_source.get(S.REAL_ERROR) == 3, by_source
    assert by_source.get(S.REFUSED) == 3, by_source
    assert by_source.get(S.PASSTHROUGH, 0) + by_source.get(S.ORACLE_DECISION, 0) == 3, by_source
    assert S.FAULT not in by_source, "an error on the original query was filed as `fault`"
    assert len({_as_text(r["params"]) for r in rows}) == 9, "two rows carry the same call"


def test_1224_forged_store_has_one_writer_and_commits_rows_with_the_verified_answer(tmp_path):
    est = S.estate(tmp_path)
    ep = _episode(tmp_path, [("idp", "query", ALICE, {"rows": [BASE_ROW]})])
    store = S.oracle_dir(ep, "b")
    store.mkdir(parents=True, exist_ok=True)
    kept = {"forged_id": "fg-0", "fact_id": "f1", "system": "idp", "row": _forged(0)}
    (store / "forged.jsonl").write_text(
        json.dumps(kept) + "\n" + '{"forged_id": "fg-torn", "fact_id": "f1", "sys',
        encoding="utf-8")
    oracle = S.oracle(
        S.forge("fg-1", "f1", "idp", _forged(1)),
        S.record_fact("alice", "risk", "ATTEMPT-ONE-1224"),
        S.submit({"rows": [BASE_ROW, _forged(1)]}, S.claim(added=[S.added("fg-1", "f1")])),
        S.forge("fg-torn", "f1", "idp", _forged(2)),
        S.record_fact("alice", "risk", "ATTEMPT-TWO-1224"),
        S.submit({"rows": [BASE_ROW, _forged(2)]}, S.claim(added=[S.added("fg-torn", "f1")])))
    verifier = S.verifier(S.verdict(False, "the ticket grant is implausible"), S.verdict(True))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    assert not oracle.overrun
    assert oracle.submissions() == 2

    # The project's JSONL reader skips a line that is not a row: a torn trailing record reads
    # as not written, which is exactly the reading O-08 asks of every reader.
    complete = S.read_jsonl(store / "forged.jsonl")
    ids = [r["forged_id"] for r in complete]
    assert "fg-1" not in ids, "the failed attempt's forged row was committed"
    assert ids.count("fg-torn") == 1, "the torn trailing record was not treated as unwritten"
    assert ids.count("fg-0") == 1
    assert complete[ids.index("fg-0")] == kept
    facts = [r["value"] for r in S.oracle_rows(ep, "b", "facts")]
    assert facts == ["ATTEMPT-TWO-1224"], "the failed attempt's recorded fact was committed"

    launched = tmp_path / "launch"
    est_l = S.estate(launched)
    spawn = _SnapshotSpawn()
    out = S.launch(launched, est_l, calls=[S.Call("idp", "query", ALICE, EMPTY)],
                   oracle=S.oracle(then=S.submit(EMPTY, S.EMPTY_CLAIM)),
                   verifier=S.passing_verifier(), spawn=spawn)
    assert out.rc == 0, out.message
    assert spawn.snapshots, "no sibling was started"
    for label, before in spawn.snapshots.items():
        assert before.get("ledger.jsonl"), f"pre-flight left world {label} no oracle-side rows"
        assert _snapshot(S.oracle_dir(out.ep, label)) == before, (
            f"the launcher wrote world {label}'s oracle state after the sibling started")


def _snapshot(directory: Path) -> dict[str, bytes]:
    if not directory.is_dir():
        return {}
    return {p.relative_to(directory).as_posix(): p.read_bytes()
            for p in sorted(directory.rglob("*")) if p.is_file()}


class _SnapshotSpawn(S.FakeSpawn):
    """The launcher's process seam, recording each world's oracle-side state at the instant
    its sibling is started (it runs no sibling code, so nothing it starts writes there)."""

    def __init__(self) -> None:
        super().__init__()
        self.snapshots: dict[str, dict[str, bytes]] = {}

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **kw: Any) -> int:
        label = T._world_of(argv)
        if label is not None:
            ep = EH.episode_dir(T.current_tenant().data_root, S.EPISODE_ID)
            snap = _snapshot(S.oracle_dir(ep, label))
            if snap:
                self.snapshots[label] = snap
        return super().__call__(argv, env=env, **kw)


def test_1224_parallel_run_queries_in_one_turn_leave_one_intact_oracle_ledger_row_each(tmp_path):
    est = S.estate(tmp_path)
    est.answer("idp", "query", None, EMPTY)
    ep = _episode(tmp_path, [("idp", "query", ALICE, EMPTY)])
    probes = [S.query_params(f"probe-{i}") for i in range(5)]
    oracle = _ParallelScripted(parallel(*[S.run_query("idp", "query", p) for p in probes]),
                               S.submit(EMPTY, S.EMPTY_CLAIM), name="oracle")
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3, rate=100.0)
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    lines = (S.oracle_dir(ep, "b") / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    asked = [r for r in rows if r.get("actor") == "oracle" and r.get("params") in probes]
    assert len(asked) == 5, f"{len(asked)} oracle-side rows for 5 parallel run_query calls"
    assert {_as_text(r["params"]) for r in asked} == {_as_text(p) for p in probes}

    launched = tmp_path / "launch"
    est_l = S.estate(launched)
    out = S.launch(launched, est_l, calls=[S.Call("idp", "query", ALICE, EMPTY)],
                   oracle=_ExploreThenSubmit(2), verifier=S.passing_verifier())
    assert out.rc == 0, out.message
    side = S.oracle_dir(out.ep, "b") / "ledger.jsonl"
    before = side.read_text(encoding="utf-8").splitlines()
    assert before, "the world's oracle-side ledger is empty before the sibling's first call"
    sibling = S.world_registry(out.ep, "b", est_l, oracle=_ExploreThenSubmit(2),
                               verifier=S.passing_verifier(), retry_cap=3, rate=100.0)
    S.call(sibling, "idp", "query", est_l.ctx(launched / "run"), **S.query_params("user:zed"))
    after = side.read_text(encoding="utf-8").splitlines()
    assert after[:len(before)] == before, "the sibling rewrote pre-flight's rows"
    added_rows = [json.loads(line) for line in after[len(before):]]
    assert len([r for r in added_rows if r.get("actor") == "oracle"]) == 2, (
        "the sibling's two run_query calls are not one row each")
    assert all(json.loads(line) for line in after), "a row is torn"


def test_oracle_trace_sink_is_already_open_when_a_second_oracle_turn_starts(tmp_path):
    est = S.estate(tmp_path)
    one, two = S.query_params("user:alice-1"), S.query_params("user:alice-2")
    ep = _episode(tmp_path, [("idp", "query", one, EMPTY), ("idp", "query", two, EMPTY)])
    oracle = S.oracle(then=S.submit(EMPTY, S.EMPTY_CLAIM), fault=S.Fault(delay=0.3))
    verifier = S.passing_verifier(fault=S.Fault(delay=0.2))
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=verifier, retry_cap=3)
    H = S.replay_harness()
    both = H.Turn(tool_calls=[("query", {"system": "idp", "verb": "query", "params": one}),
                              ("query", {"system": "idp", "verb": "query", "params": two})])
    run_dir, _router, summary = _drive(tmp_path, verbs=reg, tenant=est.place(),
                                       leads={"l-001": [both, S.done_turn()]})

    assert oracle.submissions() == 2
    _assert_never_overlap(oracle, verifier)
    wire = S.read_jsonl(RunPaths(run_dir).wire_log)
    assert wire, "the investigator's wire log is empty (dead channel)"
    for row in wire:
        assert "fake-oracle" not in json.dumps(row), (
            "oracle-side traffic landed in the investigator's wire log")
        assert "fake-verifier" not in json.dumps(row), (
            "oracle-side traffic landed in the investigator's wire log")
    rows = _own_rows(run_dir)
    assert len(rows) == 2
    assert all(r["exit_code"] == 0 for r in rows)
    assert len(S.ledger_rows(ep, "b")) == 2, "oracle-side traffic landed in the world ledger"
    assert _budget(summary)["tool_calls"] == 3, "oracle requests were charged to the investigator"
    investigator_requests = sum(1 for r in wire if r.get("kind") == "request")
    assert summary["requests"] <= investigator_requests, (
        "the run's request count includes oracle-side requests")

    launched = tmp_path / "launch"
    est_l = S.estate(launched)
    out = S.launch(launched, est_l, calls=[S.Call("idp", "query", ALICE, EMPTY)],
                   oracle=S.oracle(then=S.submit(EMPTY, S.EMPTY_CLAIM), fault=S.Fault(delay=0.3)),
                   verifier=S.passing_verifier())
    assert out.rc == 0, out.message
    assert "FileExistsError" not in out.message, out.message
    traced = [p for p in out.ep.rglob("*.jsonl") if "fake-oracle" in p.read_text(encoding="utf-8")]
    assert len(traced) >= 2, "two worlds' concurrent pre-flight turns were not each traced"


def test_1224_in_process_limiter_never_passes_two_queries_for_one_remaining_slot(tmp_path,
                                                                                  monkeypatch):
    est = S.estate(tmp_path)
    est.answer("idp", "query", None, EMPTY)
    ep = _episode(tmp_path, [("idp", "query", ALICE, EMPTY)])
    probes = [S.query_params(f"probe-{i}") for i in range(5)]
    oracle = _ParallelScripted(parallel(*[S.run_query("idp", "query", p) for p in probes]),
                               S.submit(EMPTY, S.EMPTY_CLAIM), name="oracle")
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=3, rate=2.0)
    S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), **ALICE)
    times = [c["t"] for c in est.calls("idp", "query") if c["params"]["q"].startswith("probe-")]
    assert len(times) == 5, "an exploration query was refused instead of waiting"
    assert _max_in_window(times) <= 2, "the sibling's limiter passed two queries for one slot"

    monkeypatch.setenv(S.KNOB_RATE, "2")
    launched = tmp_path / "launch"
    est_l = S.estate(launched)
    est_l.answer("idp", "query", None, EMPTY)
    out = S.launch(launched, est_l, calls=[S.Call("idp", "query", ALICE, EMPTY)],
                   oracle=_ExploreThenSubmit(3), verifier=S.passing_verifier())
    assert out.rc == 0, out.message
    times = [c["t"] for c in est_l.calls("idp", "query")
             if c["params"]["q"].startswith("probe-")]
    assert len(times) >= 6, "both worlds' pre-flight exploration did not all run"
    assert _max_in_window(times) <= 2, "the launcher's limiter passed two queries for one slot"
