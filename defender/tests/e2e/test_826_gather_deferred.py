from __future__ import annotations

from dataclasses import replace as _with_fixture_run_1165
from defender.tests._spec1077 import fixture_run as _fixture_run_1165

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402

from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402
from defender.hooks.budget_enforcer import BudgetKill  # noqa: E402
from defender.runtime import circuit_breaker, session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools_gather import GatherRequest  # noqa: E402
from defender.scripts.adapters.faults import UpstreamFault  # noqa: E402
from defender.runtime.tools import DeadEnd  # noqa: E402
from defender.scripts.gather_tools.record_query import REPEAT_THRESHOLD  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import (  # noqa: E402
    DONE,
    elastic_ok,
    q,
    raising,
)

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
PARAMS = {"native_query": "FROM logs"}


class _Res:
    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn, stores: list):
        self.run_dir, self.main, self.gather, self.stores = run_dir, main, gather, stores

    @property
    def rows(self) -> list[dict]:
        from defender._io import read_jsonl_rows
        from defender.run_repository import RunPaths

        return read_jsonl_rows(RunPaths(self.run_dir).executed_queries)

    @property
    def own_rows(self) -> list[dict]:
        """`.rows` filtered to exclude #808's harness-authored leads (`l-000`/`l-00c`) —
        the rows THIS test's own dispatched lead wrote, not lead-0's unconditional
        pre-ORIENT resolution against `GOLDEN_AB3`'s alert (mirrors
        `test_query_tool_611._Run.own_rows`)."""
        from defender.runtime.lead_zero import RESERVED_LEAD_IDS
        return [r for r in self.rows if r.get("lead_id") not in RESERVED_LEAD_IDS]

    def summary(self, lead: str = LEAD) -> str:
        return (self.run_dir / "gather_summaries" / f"{lead}.md").read_text(encoding="utf-8")

    def sessions(self) -> dict[str, str | None]:
        """`agent_id -> truncated_by` for every session this run opened, read straight out of
        the real SQLite file rather than through any reader under test."""
        store = self.stores[-1]
        return {
            agent_id: truncated
            for agent_id, truncated in sql(
                store, "SELECT agent_id, truncated_by FROM session ORDER BY rowid")
        }


def _dispatch(lead: str, system: str = "elastic") -> tuple[str, dict]:
    return ("gather", {
        "lead_id": lead, "system": system, "goal": "measure this lead",
        "what_to_summarize": ["auth events"],
    })


def _run(root: Path, *, verbs, turns: list[Turn], run_id: str, tmp_path: Path,
         lead: str = LEAD) -> _Res:
    """A real run WITH a session store — the seam item 1 is about. `store_factory` is the
    production `run_investigation(store_factory=…)` injection point (#705)."""
    run_dir = materialize(root, GOLDEN_AB3, run_id=run_id)
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(lead)]), Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    stores: list = []
    drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs,
          store_factory=store_factory(tmp_path, sink=stores))
    return _Res(run_dir, main, gather, stores)


# ITEM 1 — no gather-side session terminator stamp.

def test_every_gather_terminator_arm_stamps_its_own_reason(tmp_path):
    """THE DEFECT (item 1): `_run_gather`'s terminal arms left the gather session ending on an
    unanswered tool call with `truncated_by` UNSET."""
    stamped: list[tuple[str, str]] = []

    def _deps(run_dir: Path):  # noqa: ANN202
        # `_run_gather` screens the run's breaker before it dispatches, so the main deps carry
        # the run's state, as the driver's do (#1235).
        from dataclasses import replace

        from defender.runtime.run_state import RunState

        return replace(_with_fixture_run_1165(bind(MAIN_DEF, run_dir, defender_dir=DEFENDER), run=_fixture_run_1165(run_dir)),
                       run_state=RunState(run_dir, "d826-terminators"))

    def _factory_raising(exc: BaseException):
        class _Agent:
            async def run(self, *a, **kw):
                raise exc

        return lambda agent_id, system, request_limit: _Agent()

    def _factory_dead_end():
        class _Agent:
            async def run(self, *a, deps, **kw):
                deps.stop.close_door(DeadEnd("repeats seq 0", "move on"))
                return SimpleNamespace(output="what I had")

        return lambda agent_id, system, request_limit: _Agent()

    arms = {
        _factory_raising(UsageLimitExceeded("limit")): session_store.TRUNCATED_BY_REQUEST_LIMIT,
        _factory_dead_end(): session_store.TRUNCATED_BY_DEAD_END,
        _factory_raising(UnexpectedModelBehavior("retries")):
            session_store.TRUNCATED_BY_RETRY_EXHAUSTED,
        _factory_raising(session_store.StoreError("disk full")): session_store.TRUNCATED_BY_STORE,
    }
    assert len(set(arms.values())) == len(arms), "two terminators share a reason string"

    for i, (factory, expected) in enumerate(arms.items()):
        run_dir = materialize(tmp_path / f"arm{i}", GOLDEN_AB3)
        deps = _deps(run_dir)
        lead = f"l-00{i}"
        out = asyncio.run(tools_gather._run_gather(
            deps, factory, 40,
            GatherRequest(lead, "elastic", "goal", ("what",)), T1106.fixture_grants().gather,
            lambda agent_id, reason: stamped.append((agent_id, reason)), catalog=None,
        ))
        assert stamped[-1] == (f"gather:{lead}", expected)
        assert "Treat this lead as incomplete" in out, \
            "stamping the terminator changed what main is told"

    propagating = {
        BudgetKill("tail exhausted"): session_store.TRUNCATED_BY_BUDGET,
        circuit_breaker.RunAborted(5, ["elastic"]): session_store.TRUNCATED_BY_ABORTED,
    }
    assert len(set(arms.values()) | set(propagating.values())) == len(arms) + len(propagating), \
        "two terminators share a reason string"

    for i, (exc, expected) in enumerate(propagating.items()):
        run_dir = materialize(tmp_path / f"prop{i}", GOLDEN_AB3)
        deps = _deps(run_dir)
        lead = f"l-01{i}"
        with pytest.raises(type(exc)):
            asyncio.run(tools_gather._run_gather(
                deps, _factory_raising(exc), 40,
                GatherRequest(lead, "elastic", "goal", ("what",)), T1106.fixture_grants().gather,
                lambda agent_id, reason: stamped.append((agent_id, reason)), catalog=None,
            ))
        assert stamped[-1] == (f"gather:{lead}", expected), \
            "a run-level kill left its gather session reading as one that finished"

    # The CLEAN end stamps nothing: `truncated_by` unset must keep meaning "this finished".
    class _Clean:
        async def run(self, *a, **kw):
            return SimpleNamespace(output="measured.")

    run_dir = materialize(tmp_path / "clean", GOLDEN_AB3)
    deps = _deps(run_dir)
    before = len(stamped)
    asyncio.run(tools_gather._run_gather(
        deps, lambda agent_id, system, request_limit: _Clean(), 40,
        GatherRequest("l-009", "elastic", "goal", ("what",)), T1106.fixture_grants().gather,
        lambda agent_id, reason: stamped.append((agent_id, reason)), catalog=None,
    ))
    assert len(stamped) == before, "a gather that finished was stamped as truncated"


def test_a_cut_off_lead_is_distinguishable_in_the_store_from_one_that_finished(tmp_path):
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='d826-store')
    rec = VerbRecorder()
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(LEAD)]),
        Turn(tool_calls=[_dispatch("l-002")]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        q("elastic", "query", PARAMS), q("elastic", "query", PARAMS),
        q("elastic", "query", PARAMS),          # the third trips the guard: dead end
        Turn(text="what I had before the stop"),  # ...and #987 lets it write its summary
        q("elastic", "query", {"native_query": "FROM other"}), DONE,   # the second lead
    ])
    stores: list = []
    drive(run_dir, run_id="d826-store", main=main, gather=gather,
          verbs=elastic_ok(rec), store_factory=store_factory(tmp_path, sink=stores))

    sessions = dict(sql(stores[-1], "SELECT agent_id, truncated_by FROM session"))
    assert sessions[f"gather:{LEAD}"] == session_store.TRUNCATED_BY_DEAD_END, \
        "the cut-off lead's session carries no terminator — it reads as one that finished"
    assert sessions["gather:l-002"] is None, \
        "the lead that finished was stamped as truncated"
    assert sessions["main"] is None, "the run itself did not end cleanly"


class _UnstampableStore:
    """A real store handle whose ONE broken operation is `set_truncated_by` — everything else
    is the real object, so the run this drives is a real run against a real SQLite file that
    happens to refuse the terminator write."""

    def __init__(self, real):
        self._real = real
        self.attempts: list[tuple[str, str]] = []

    def set_truncated_by(self, session_id: str, reason: str) -> None:
        self.attempts.append((session_id, reason))
        raise session_store.StoreError("the store cannot take the stamp")

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_a_broken_store_cannot_turn_a_lost_terminator_into_a_lost_lead(tmp_path):
    """The stamp is best-effort, for `_flush_run_end`'s reason: the store may be exactly what
    ended this lead."""
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='d826-nostamp')
    rec = VerbRecorder()
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(LEAD)]), Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        q("elastic", "query", PARAMS), q("elastic", "query", PARAMS),
        q("elastic", "query", PARAMS), DONE,
    ])
    real_factory = store_factory(tmp_path)
    wrapped: list[_UnstampableStore] = []

    def factory(case_id: str, run_dir_: Path):
        # The sink collects the WRAPPER, not the handle underneath it: `attempts` is the
        # observation this test turns on, and the inner handle never sees the call.
        handle = _UnstampableStore(real_factory(case_id, run_dir_))
        wrapped.append(handle)
        return handle

    drive(run_dir, run_id="d826-nostamp", main=main, gather=gather,
          verbs=elastic_ok(rec), store_factory=factory)

    attempts = [reason for h in wrapped for _, reason in h.attempts]
    assert session_store.TRUNCATED_BY_DEAD_END in attempts, \
        "the terminator write was skipped rather than attempted"
    summary = (run_dir / "gather_summaries" / f"{LEAD}.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" in summary, \
        "a failed terminator stamp cost the lead its summary"


def test_both_writers_of_the_column_draw_on_one_vocabulary(tmp_path):
    """One column, one vocabulary — structurally, not by agreement."""
    assert len(set(session_store.TRUNCATED_BY_VALUES)) == len(session_store.TRUNCATED_BY_VALUES)

    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='d826-vocab')
    rec = VerbRecorder()
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(LEAD)]), Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        q("elastic", "query", PARAMS), q("elastic", "query", PARAMS),
        q("elastic", "query", PARAMS), DONE,
    ])
    stores: list = []
    drive(run_dir, run_id="d826-vocab", main=main, gather=gather,
          verbs=elastic_ok(rec), store_factory=store_factory(tmp_path, sink=stores))

    stamped = [
        reason for (reason,) in sql(
            stores[-1], "SELECT truncated_by FROM session WHERE truncated_by IS NOT NULL")
    ]
    assert stamped, "no session was stamped at all — the scenario stopped cutting one off"
    for reason in stamped:
        assert reason in session_store.TRUNCATED_BY_VALUES, \
            f"{reason!r} is a value no reader of this column has been told about"
    assert session_store.TRUNCATED_BY_DEAD_END in stamped


# ITEM 3 — the failing repeat, live.

def test_a_lead_repeating_a_failing_request_is_told_so_before_it_is_stopped(tmp_path):
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-failrepeat",
        verbs=raising(rec, UpstreamFault("query failed (HTTP 400): parse_exception")),
        turns=[
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
            DONE,
        ])
    assert [row["exit_code"] for row in res.own_rows] == [1, 1], \
        "the faults stopped being recorded"
    second = res.gather.seen[-1]
    assert "REPEAT" in second, "a failing repeat still reaches the model with no repeat named"
    assert "seq 0" in second
    assert "parse_exception" in second, "the notice displaced the error it was prepended to"


# ITEM 4 — the argument-schema repeat class, live.

def _bad_args(params: dict) -> Turn:
    """A tool call the pydantic ARG SCHEMA turns back, so the row is written by
    `wrap_tool_validate` from the RAW pre-validation arguments (P-a's `extra_argument`
    shape)."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "query", "params": params, "bogus_extra_arg": "x",
    })])


def test_a_schema_rejected_repeat_loop_ends_the_lead_and_leaves_a_trip_row(tmp_path):
    """THE DEFECT (item 4): a repeat loop the argument schema turned back reached no guard at
    all."""
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-schema",
        verbs=elastic_ok(rec),
        turns=[_bad_args(PARAMS), _bad_args(PARAMS), _bad_args(PARAMS), DONE])

    rows = res.own_rows
    assert len(rows) == REPEAT_THRESHOLD, "the rejection rows stopped being written"
    assert [row["exit_code"] for row in rows] == [64] * REPEAT_THRESHOLD
    assert res.gather.calls == REPEAT_THRESHOLD + 1, (
        "the loop ran past the threshold — it is still bounded only by the retry count "
        f"(> {REPEAT_THRESHOLD + 1}) — or the lead stopped at the threshold and #987's "
        f"summary turn did not follow it ({REPEAT_THRESHOLD}). The `+ 1` is that turn: the "
        "third rejection is answered as a failed tool result that closes the lead's door, "
        "and the model's next turn is the summary main receives under this stop's own notice."
    )
    assert rec.calls == [], "a rejected call reached the backend"

    trip_row = rows[-1]
    assert "turned back at seq 0" in trip_row["payload_digest"], \
        "the trip row is byte-shaped like an ordinary schema rejection — no O4 diagnosis"
    summary = res.summary()
    assert "repeats the one already turned back at seq 0" in summary
    assert "Treat this lead as incomplete" in summary, "the shipped idiom was dropped"
    header = summary.split("\n\n", 1)[0]
    assert PARAMS["native_query"] not in header, \
        "model-authored params crossed into main's context on a refusal path"

    # The session terminator (item 1) covers this new stop too — a fourth terminator with the
    # same gap is exactly what item 1 warned the next one would be.
    assert dict(sql(res.stores[-1], "SELECT agent_id, truncated_by FROM session"))[
        f"gather:{LEAD}"] == session_store.TRUNCATED_BY_DEAD_END


def test_two_rejections_and_a_corrected_call_still_execute(tmp_path):
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-corrected", verbs=elastic_ok(rec),
        turns=[_bad_args(PARAMS), _bad_args(PARAMS), q("elastic", "query", PARAMS), DONE])
    assert [row["exit_code"] for row in res.own_rows] == [64, 64, 0]
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert "Treat this lead as incomplete" not in res.summary()


def test_the_two_guards_never_both_own_one_lead(tmp_path):
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-disjoint", verbs=elastic_ok(rec),
        turns=[
            _bad_args(PARAMS), q("elastic", "query", PARAMS),
            _bad_args(PARAMS), q("elastic", "query", PARAMS), DONE,
        ])
    assert [row["exit_code"] for row in res.own_rows] == [64, 0, 64, 0]
    assert len(rec.calls) == 2
    assert "Treat this lead as incomplete" not in res.summary(), \
        "a lead was stopped by a count no single guard's domain holds"
