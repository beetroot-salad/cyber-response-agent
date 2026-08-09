"""#826 end to end — the terminator stamp (item 1), and the live behaviour of items 3 and 4.

Everything between the two replay models is production code: dispatch, the query tool, both
repeat guards, the capture capability, the infra breaker, the session store, the two tables.
The unit-level halves (the elastic sort surface, `repeat_note`'s wording, the companion
guard's predicate) live in `tests/test_826_deferred_defects.py`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UnexpectedModelBehavior, UsageLimitExceeded  # noqa: E402

# `runtime.tools` and `runtime.tools_gather` import each other, the cycle broken by a bottom
# import in `tools`. Reaching `tools_gather` FIRST from outside the package enters that cycle
# at its unfinished end, so the driver (which pulls `tools` in properly) is imported ahead of
# it — the same order every other suite that touches `_run_gather` arrives in.
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime import session_store, tools_gather  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.tools_gather import GatherRequest  # noqa: E402
from defender.scripts.adapters.faults import UpstreamFault  # noqa: E402
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    REPEAT_THRESHOLD,
    GatherDeadEnd,
)
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
        from defender._run_paths import RunPaths

        return read_jsonl_rows(RunPaths(self.run_dir).executed_queries)

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
    run_dir = materialize(root, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(lead)]), Turn(text="Investigation complete."),
    ])
    gather = ReplayFn(turns)
    stores: list = []
    drive(run_dir, run_id=run_id, salt=SALT, main=main, gather=gather, verbs=verbs,
          store_factory=store_factory(tmp_path, sink=stores))
    return _Res(run_dir, main, gather, stores)


# --------------------------------------------------------------------------------------- #
# ITEM 1 — no gather-side session terminator stamp.
# --------------------------------------------------------------------------------------- #

def test_every_gather_terminator_arm_stamps_its_own_reason(tmp_path):
    """THE DEFECT (item 1): `_run_gather`'s terminal arms left the gather session ending on an
    unanswered tool call with `truncated_by` UNSET. `set_truncated_by` had exactly one
    production call site — `driver._flush_run_end`, on the MAIN session — so no reader of the
    session store could tell a lead that was CUT OFF from one that finished, and
    `GatherDeadEnd` made a fourth terminator with the same gap.

    Driven at the seam so all four arms are reachable without manufacturing a 40-request
    overrun: each raises out of the gather agent, and each must name a DISTINCT reason — a
    single "truncated" flag would answer "was this cut off" and lose "by what", which is the
    question a reader comparing leads is actually asking."""
    stamped: list[tuple[str, str]] = []

    def _factory_raising(exc: BaseException):
        class _Agent:
            async def run(self, *a, **kw):
                raise exc

        return lambda agent_id: _Agent()

    arms = {
        UsageLimitExceeded("limit"): tools_gather.REQUEST_LIMIT_TERMINATOR,
        GatherDeadEnd("repeats seq 0", "move on"): tools_gather.DEAD_END_TERMINATOR,
        UnexpectedModelBehavior("retries"): tools_gather.RETRY_EXHAUSTED_TERMINATOR,
        session_store.StoreError("disk full"): tools_gather.STORE_TERMINATOR,
    }
    assert len(set(arms.values())) == len(arms), "two terminators share a reason string"

    for i, (exc, expected) in enumerate(arms.items()):
        run_dir = materialize(tmp_path / f"arm{i}", GOLDEN_AB3)
        deps = bind(MAIN_DEF, run_dir, salt=SALT, defender_dir=DEFENDER)
        lead = f"l-00{i}"
        out = asyncio.run(tools_gather._run_gather(
            deps, _factory_raising(exc), 40,
            GatherRequest(lead, "elastic", "goal", ("what",)), GATHER_DEF.verb_grant,
            lambda agent_id, reason: stamped.append((agent_id, reason)),
        ))
        assert stamped[-1] == (f"gather:{lead}", expected)
        assert "Treat this lead as incomplete" in out, \
            "stamping the terminator changed what main is told"

    # The CLEAN end stamps nothing: `truncated_by` unset must keep meaning "this finished".
    class _Clean:
        async def run(self, *a, **kw):
            class R:
                output = "measured."
            return R()

    run_dir = materialize(tmp_path / "clean", GOLDEN_AB3)
    deps = bind(MAIN_DEF, run_dir, salt=SALT, defender_dir=DEFENDER)
    before = len(stamped)
    asyncio.run(tools_gather._run_gather(
        deps, lambda agent_id: _Clean(), 40,
        GatherRequest("l-009", "elastic", "goal", ("what",)), GATHER_DEF.verb_grant,
        lambda agent_id, reason: stamped.append((agent_id, reason)),
    ))
    assert len(stamped) == before, "a gather that finished was stamped as truncated"


def test_a_cut_off_lead_is_distinguishable_in_the_store_from_one_that_finished(tmp_path):
    """The whole chain, on a real store: the composition root opens a session per gather agent
    and owns the stamp, so a reader joining `session` rows can separate the lead that was cut
    off from the lead that finished — the discrimination item 1 says does not exist.

    Two leads, one run: the first loops itself into the repeat guard's dead end, the second
    measures its lead and stops. One `truncated_by`, one NULL."""
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3)
    rec = VerbRecorder()
    main = ReplayFn([
        Turn(tool_calls=[_dispatch(LEAD)]),
        Turn(tool_calls=[_dispatch("l-002")]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([
        q("elastic", "query", PARAMS), q("elastic", "query", PARAMS),
        q("elastic", "query", PARAMS),          # the third trips the guard: dead end
        q("elastic", "query", {"native_query": "FROM other"}), DONE,   # the second lead
    ])
    stores: list = []
    drive(run_dir, run_id="d826-store", salt=SALT, main=main, gather=gather,
          verbs=elastic_ok(rec), store_factory=store_factory(tmp_path, sink=stores))

    sessions = dict(sql(stores[-1], "SELECT agent_id, truncated_by FROM session"))
    assert sessions[f"gather:{LEAD}"] == tools_gather.DEAD_END_TERMINATOR, \
        "the cut-off lead's session carries no terminator — it reads as one that finished"
    assert sessions["gather:l-002"] is None, \
        "the lead that finished was stamped as truncated"
    assert sessions["main"] is None, "the run itself did not end cleanly"


def test_a_broken_store_cannot_turn_a_lost_terminator_into_a_lost_lead(tmp_path):
    """The stamp is best-effort, for `_flush_run_end`'s reason: the store may be exactly what
    ended this lead. A stamp that raised would replace a missing session row with a missing
    gather summary — trading the smaller loss for the larger one."""
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3)
    deps = bind(MAIN_DEF, run_dir, salt=SALT, defender_dir=DEFENDER)

    class _Agent:
        async def run(self, *a, **kw):
            raise session_store.StoreError("the store is gone")

    def _exploding_stamp(agent_id: str, reason: str) -> None:
        raise session_store.StoreError("and it is still gone")

    with pytest.raises(session_store.StoreError):
        asyncio.run(tools_gather._run_gather(
            deps, lambda agent_id: _Agent(), 40,
            GatherRequest(LEAD, "elastic", "goal", ("what",)), GATHER_DEF.verb_grant,
            _exploding_stamp,
        ))
    # The driver's own stamp swallows it, which is what production actually installs; this
    # asserts the swallowing lives THERE and not in a `try` around every arm of `_run_gather`.
    from defender.runtime import driver

    assert "gather truncated_by write skipped" in Path(driver.__file__).read_text(
        encoding="utf-8"), "the composition root stopped absorbing a failed stamp"


def test_the_gather_terminator_vocabulary_is_the_main_sessions(tmp_path):
    """One column, one vocabulary. A reader joining `session` rows across both kinds asks
    "was this cut off, and by what" once — three of gather's four terminators are shapes the
    main loop has too, and they are spelled identically. `dead-end` is the one with no main
    analogue: only a lead can be stopped by a repeat guard."""
    driver_src = (Path(session_store.__file__).parent / "driver.py").read_text(encoding="utf-8")
    for shared in (tools_gather.REQUEST_LIMIT_TERMINATOR,
                   tools_gather.RETRY_EXHAUSTED_TERMINATOR,
                   tools_gather.STORE_TERMINATOR):
        assert f'"{shared}"' in driver_src, \
            f"gather spells {shared!r} but the main loop does not — one column, two vocabularies"
    assert f'"{tools_gather.DEAD_END_TERMINATOR}"' not in driver_src


# --------------------------------------------------------------------------------------- #
# ITEM 3 — the failing repeat, live.
# --------------------------------------------------------------------------------------- #

def test_a_lead_repeating_a_failing_request_is_told_so_before_it_is_stopped(tmp_path):
    """Live proof of item 3: `_model_view`'s early return meant the notice never reached a
    lead whose calls keep failing. The second identical failure now carries it, one call
    BEFORE the repeat guard's dead end — which is the whole point of a notice, since a lead
    that is only ever stopped is never given the chance to change course itself."""
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-failrepeat",
        verbs=raising(rec, UpstreamFault("query failed (HTTP 400): parse_exception")),
        turns=[
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
            DONE,
        ])
    assert [row["exit_code"] for row in res.rows] == [1, 1], "the faults stopped being recorded"
    second = res.gather.seen[-1]
    assert "REPEAT" in second, "a failing repeat still reaches the model with no repeat named"
    assert "seq 0" in second
    assert "parse_exception" in second, "the notice displaced the error it was prepended to"


# --------------------------------------------------------------------------------------- #
# ITEM 4 — the argument-schema repeat class, live.
# --------------------------------------------------------------------------------------- #

def _bad_args(params: dict) -> Turn:
    """A tool call the pydantic ARG SCHEMA turns back, so the row is written by
    `wrap_tool_validate` from the RAW pre-validation arguments (P-a's `extra_argument`
    shape)."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": "query", "params": params, "bogus_extra_arg": "x",
    })])


def test_a_schema_rejected_repeat_loop_ends_the_lead_and_leaves_a_trip_row(tmp_path):
    """THE DEFECT (item 4): a repeat loop the argument schema turned back reached no guard at
    all. It was bounded only by `DEFAULT_TOOL_RETRIES = 10`, whose exhaustion raised
    `UnexpectedModelBehavior`, was caught at `_run_gather`, and returned the SAME "Treat this
    lead as incomplete" idiom — with none of the repeat naming and no trip row. A second,
    silent terminator.

    It is neither silent nor unbounded now: the lead stops at the threshold, main is told what
    repeated, and the table carries a row that says so."""
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-schema",
        verbs=elastic_ok(rec),
        turns=[_bad_args(PARAMS), _bad_args(PARAMS), _bad_args(PARAMS), DONE])

    rows = res.rows
    assert len(rows) == REPEAT_THRESHOLD, "the rejection rows stopped being written"
    assert [row["exit_code"] for row in rows] == [64] * REPEAT_THRESHOLD
    assert res.gather.calls == REPEAT_THRESHOLD, \
        "the loop ran past the threshold — it is still bounded only by the retry count"
    assert rec.calls == [], "a rejected call reached the backend"

    trip_row = rows[-1]
    assert "turned back at seq 0" in trip_row["payload_digest"], \
        "the trip row is byte-shaped like an ordinary schema rejection — no O4 diagnosis"
    summary = res.summary()
    assert "repeats the one already turned back at seq 0" in summary
    assert "Treat this lead as incomplete" in summary, "the shipped idiom was dropped"
    assert PARAMS["native_query"] not in summary, \
        "model-authored params crossed into main's context on a refusal path"

    # The session terminator (item 1) covers this new stop too — a fourth terminator with the
    # same gap is exactly what item 1 warned the next one would be.
    assert dict(sql(res.stores[-1], "SELECT agent_id, truncated_by FROM session"))[
        f"gather:{LEAD}"] == tools_gather.DEAD_END_TERMINATOR


def test_two_rejections_and_a_corrected_call_still_execute(tmp_path):
    """The guard must refuse only a call that REPEATS, never one that differs — the same O3
    property the first guard carries, at the second placement. Two rejections are below the
    threshold, and the corrected third call runs."""
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-corrected", verbs=elastic_ok(rec),
        turns=[_bad_args(PARAMS), _bad_args(PARAMS), q("elastic", "query", PARAMS), DONE])
    assert [row["exit_code"] for row in res.rows] == [64, 64, 0]
    assert len(rec.calls) == 1, "the corrected call never reached the backend"
    assert "Treat this lead as incomplete" not in res.summary()


def test_the_two_guards_never_both_own_one_lead(tmp_path):
    """Complementary domains, live: rejections do not top up an executed-call count and
    executed calls do not top up a rejection count. Two of each at ONE key is four
    occurrences and no trip — under a single merged domain it would be a stop the lead never
    earned at either placement."""
    rec = VerbRecorder()
    res = _run(
        tmp_path / "run", tmp_path=tmp_path, run_id="d826-disjoint", verbs=elastic_ok(rec),
        turns=[
            _bad_args(PARAMS), q("elastic", "query", PARAMS),
            _bad_args(PARAMS), q("elastic", "query", PARAMS), DONE,
        ])
    assert [row["exit_code"] for row in res.rows] == [64, 0, 64, 0]
    assert len(rec.calls) == 2
    assert "Treat this lead as incomplete" not in res.summary(), \
        "a lead was stopped by a count no single guard's domain holds"
