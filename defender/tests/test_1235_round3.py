"""#1235, round 3 — the review's fix list, pinned at the unit edge (the owner approved it).

Round 2 gave every run one `RunState` (`defender/runtime/run_state.py`), carried by reference.
A /code-review pass then found where the state still followed the file, where a missing state
failed open, and where one gate read a different clock from the rest. What this module pins:

  O1. The state is the record; `executed_queries.jsonl` is the model's view of it. A failing
      call whose view write is refused still charges the circuit breaker, and its row is in
      the state, before the write's error propagates (`QueryCapture._record`). The append's own
      contract — validate, record, then write the view — is `tests/test_record_query.py`'s
      `test_a_row_whose_view_write_failed_is_in_the_state_with_its_seq_spent`; the driven run
      is `tests/e2e/test_1235_round3_e2e.py`.
  O2. An enforced role whose deps carry no run state RAISES on its first tool call (pinned,
      with the live state of that folder untouched, in `tests/e2e/test_1235_adversary_round2.py`
      as `test_a_deps_with_no_state_raises_and_never_reaches_a_live_runs_state`); a
      non-enforced one neither counts nor raises (`driver/_budget.py`), here.
  O3. Lead-0's budget gate reads the clock the budget hooks read: the monotonic origin and the
      oracle-held seconds, not the wall-clock budget snapshot alone. Each case is paired with the
      hook's own verdict on the same state.
  O4. A reducer failure on gather deps with no run state raises (a wiring fault); with a state,
      a refused observability write never fails the command.
  O5/O7. What round 3 deletes is gone (`RunState.start`, lead-0's `_rows_for` and
      `_budget_account`, `QueryCapture._seq_lock`, `hooks/_run_dir`'s two locked JSON helpers),
      and `RunState`'s read accessors: `lead_rows` hands out a tuple of the stored rows,
      `row_count`, `last_row` and `breaker_failures`.

O6 (the summary no longer carries the state; `run_investigation(run_state=…)` is the seam) is
driven in `tests/e2e/test_1235_round3_e2e.py`.

Faults enter through planted entries (a symlink or a directory at the record's name, which
`write_guarded` refuses under any uid) and the injected box; nothing is monkeypatched.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run

import asyncio
import dataclasses
import importlib
import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._query_rules import BASH_SHIM_QUERY_ID  # noqa: E402
from defender.hooks.budget_enforcer import DEFAULT_LIMITS, BudgetKill  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import circuit_breaker as cb  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.box_codec import BoxResult  # noqa: E402
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.runtime.query_tool import QueryCapture  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.runtime.tools import _tool_bash  # noqa: E402
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.test_959_downstream import Box, _gather_scene  # noqa: E402
from defender.tests.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402

LEAD = "l-001"
_PAYLOAD = '{"total": 1, "hits": ["web-1"]}'


def _bare_run(root: Path, name: str = "run") -> tuple[Path, RunState]:
    run_dir = root / name
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    return run_dir, RunState(run_dir, name)


def _append(state: RunState, *, params: dict, lead: str = LEAD) -> dict:
    """One executed row through the production writer."""
    return rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id=lead, system="elastic", verb="query", query_id="elastic.probe",
        params=params, raw_command="elastic query", payload_text=_PAYLOAD, exit_code=0,
        payload_status="ok", payload_digest=rq.payload_digest(_PAYLOAD, "", 0), system_key="")


def _failures(state: RunState, system: str) -> int:
    """`system`'s charged failures, read off the breaker snapshot (the O1 cases read it this
    way so a failure there names O1, not the new accessor O7 adds)."""
    rec = state.breaker_snapshot()["systems"].get(system)
    return rec["failures"] if rec else 0


def _table_rows(run_dir: Path, lead: str = LEAD) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


# ======================================================================================
# O1 — a failing call is charged and recorded whether or not its view could be written.
# ======================================================================================

def _gather_deps(run_dir: Path, state: RunState):
    return dataclasses.replace(
        bind(_tenants1106.fixture_gather_def(), run_dir, defender_dir=DEFENDER),
        lead_id=LEAD, run_state=state)


def _record_failure(deps, *, params: dict) -> tuple[dict, str]:
    """One backend call that failed on the transport (exit 2: an infra failure the breaker
    charges), recorded through the query tool's own recorder."""
    return asyncio.run(QueryCapture(registry=None)._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params=params,
        payload=None, exit_code=2, detail="connection refused", system_key=""))


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_failing_call_whose_view_write_is_refused_is_still_charged_and_recorded(
        tmp_path, kind):
    """O1 at the query tool's recorder: a call that failed on the transport (exit 2) is
    recorded while `executed_queries.jsonl` is squatted (a planted symlink, or a directory). The
    view write's `OSError` propagates — the run is not told the call was viewed — and before it
    does, the failure is charged to the system's breaker and the row is in the run's state.

    Positive control, same folder and deps: with the view writable again the next failing call
    is charged too (the count is the sum, not a reset) and its row lands in both the state and
    the view.

    Observed failing by: round 2's `_record`, which charged the breaker only after the append
    returned — a refused view write cost the breaker its charge and the state its row, so a
    system failing every call while its view is blocked never trips."""
    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "r3-o1")
    deps = _gather_deps(run_dir, state)
    table = RunPaths(run_dir).executed_queries
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    if kind == "symlink":
        table.symlink_to(outside)
    else:
        table.mkdir()

    with pytest.raises(OSError):  # noqa: PT011 — the symlink and the directory refuse in their own words
        _record_failure(deps, params={"q": "a"})
    assert _failures(state, "elastic") == 1, \
        "a failing call whose view write was refused was not charged to its system"
    assert [(r["seq"], r["exit_code"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, 2, {"q": "a"})], "a failing call whose view write was refused left no row"
    assert outside.read_bytes() == b"", "the view write followed the planted link"

    if kind == "symlink":
        table.unlink()
    else:
        table.rmdir()
    row, _text = _record_failure(deps, params={"q": "b"})
    assert row["seq"] == 1, "the recorded row's seq was handed out again"
    assert _failures(state, "elastic") == 2
    assert [(r["seq"], r["params"]) for r in state.lead_rows(LEAD)] == \
        [(0, {"q": "a"}), (1, {"q": "b"})]
    assert [r["seq"] for r in _table_rows(run_dir)] == [1], \
        "the view holds a line other than the one write that landed"


def test_a_succeeding_call_whose_view_write_is_refused_charges_nothing(tmp_path):
    """The charge O1 keeps is the failure's, not a side effect of the refused write: a call that
    SUCCEEDED (exit 0) while the view is squatted is in the state, the write's error propagates,
    and the breaker is untouched."""
    run_dir = tmp_path / "run"
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "r3-o1-ok")
    deps = _gather_deps(run_dir, state)
    RunPaths(run_dir).executed_queries.mkdir()

    with pytest.raises(OSError):  # noqa: PT011 — the directory refuses in its own words
        asyncio.run(QueryCapture(registry=None)._record(
            deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={"q": "a"},
            payload=[{"a": 1}], exit_code=0, detail="", system_key=""))
    assert [(r["seq"], r["exit_code"]) for r in state.lead_rows(LEAD)] == [(0, 0)], \
        "a succeeding call whose view write was refused left no row"
    assert state.breaker_snapshot() == {"systems": {}, "total_failures": 0}, \
        "a succeeding call was charged because its view write failed"


# ======================================================================================
# O2 — a non-enforced role with no run state neither counts nor raises (the enforced role's
# raise is `test_1235_adversary_round2.py`'s).
# ======================================================================================

_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 50, "wall_clock_timeout": 3600,
           "grace_seconds": 600}
_ECHO = [[("bash", {"command": "echo o2"})]]


def test_a_non_enforced_role_whose_deps_carry_no_state_neither_counts_nor_raises(tmp_path):
    """O2's other posture: hooks built with `enforce=False` (a role that is not budget
    enforced) over deps with no run state run the call — no raise, nothing counted anywhere.

    Positive control, same posture: deps carrying a state are counted (`count_call`, no cap), so
    the silence above is the missing state's, not a hook that never counts."""
    run_dir = _run_dir(tmp_path, "o2-open")
    result, _ = drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_LIMITS, enforce=False, state=None)
    returned = [str(part.content) for message in result.all_messages()
                for part in getattr(message, "parts", ()) if part.part_kind == "tool-return"]
    assert len(returned) == 1, f"the unenforced call did not run: {returned}"
    assert "o2" in returned[0], f"the unenforced call did not run: {returned}"

    carried = RunState(run_dir, "o2-open-carried")
    drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_LIMITS, enforce=False, state=carried)
    assert carried.budget_snapshot()["tool_calls"] == 1, \
        "the control: an unenforced role carrying a state did not count its call"


# ======================================================================================
# O3 — lead-0's budget gate reads the clock the budget hooks read.
# ======================================================================================

#: The tail sits at `wall_clock_timeout + grace_seconds` = 120s of investigator time.
_CLOCK_LIMITS = {**DEFAULT_LIMITS, "max_tool_calls": 100, "wall_clock_timeout": 60,
                 "grace_seconds": 60}


def _clocked(run_dir: Path, *, wall_back: float, mono_back: float, credited: float) -> RunState:
    """A run's state whose clock reads as given: the wall-clock origin `wall_back` seconds ago
    (negative: the wall clock has since stepped BACK past the start), the monotonic origin
    `mono_back` seconds ago, and `credited` seconds of closed oracle turns. Set on the state's
    own fields, under its lock — the values a run that long would hold."""
    state = RunState(run_dir, "r3-clock")
    with state.lock:
        origin = (datetime.now(UTC) - timedelta(seconds=wall_back)).isoformat()
        state.budget["created_at"] = state.budget["started_at"] = origin
        state.started_monotonic -= mono_back
        state.oracle_credited = credited
    return state


def _lead_zero_kills(state: RunState) -> bool:
    from defender.hooks.budget_enforcer import enforcement_state, tail_exhausted
    return tail_exhausted(enforcement_state(state), _CLOCK_LIMITS)


def _hook_kills(run_dir: Path, state: RunState) -> bool:
    """The budget hooks' verdict on `state`: MAIN's enforced hook on one bash call."""
    try:
        drive_agent(MAIN_DEF, run_dir, _ECHO, limits=_CLOCK_LIMITS, enforce=True, state=state)
    except BudgetKill:
        return True
    return False


@pytest.mark.parametrize(("wall_back", "mono_back", "credited", "killed"), [
    pytest.param(0, 0, 0, False, id="fresh"),
    pytest.param(1000, 1000, 0, True, id="spent"),
    pytest.param(1000, 1000, 990, False, id="oracle-held-time-is-not-the-investigators"),
    pytest.param(-1000, 1000, 0, True, id="wall-clock-stepped-back"),
])
def test_lead_zeros_budget_gate_agrees_with_the_hooks_on_the_runs_clock(
        tmp_path, wall_back, mono_back, credited, killed):
    """O3: lead-0's gate and the budget hooks answer "is the tail spent?" from one clock — the
    larger of the wall-clock and monotonic deltas, less the seconds an oracle turn held the
    world — so on the same state they agree.

    The discriminating cases are where the budget snapshot alone (a wall-clock origin, no
    monotonic origin, no oracle credit) disagrees with that clock:

      * `oracle-held…`: 1000s of raw time, 990 of them an oracle's — 10s of the investigator's,
        far inside the tail. The snapshot alone says spent: lead-0 would kill a run the hooks
        let continue.
      * `wall-clock-stepped-back`: the wall clock now reads before the run's start, the
        monotonic clock shows 1000s gone. The snapshot alone says fresh: lead-0 would issue a
        backend call on a run the hooks kill at its next tool call.

    `fresh` and `spent` are the controls: both derivations agree there, so a gate that never
    (or always) kills fails one of them."""
    run_dir = _run_dir(tmp_path, "o3")
    state = _clocked(run_dir, wall_back=wall_back, mono_back=mono_back, credited=credited)
    hook = _hook_kills(run_dir, state)
    assert hook is killed, f"the scenario no longer exercises the hooks' clock (hook={hook})"
    assert _lead_zero_kills(state) is hook, (
        "lead-0's budget gate disagrees with the budget hooks on the run's clock: "
        f"hooks kill={hook}, lead-0 kill={not hook}")


# ======================================================================================
# O4 — a reducer failure on deps with no run state raises; a refused write never does.
# ======================================================================================

def test_a_failed_reducer_on_gather_deps_with_no_state_raises(tmp_path):
    """O4: the failed-reducer row (`_record_shim_failure`) needs the run's state; gather deps
    carrying none are a wiring fault and raise `TypeError` — the "never fails the command"
    promise covers a failed observability WRITE, not a missing state.

    Positive control, same scene: the deps carrying their state return the command's output and
    record the shim row."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"Binder Error: o4"))
    command = f"cat {payload} | defender-sql 'SELECT 1'"
    with pytest.raises(TypeError, match="RunState"):
        _tool_bash(dataclasses.replace(deps, run_state=None), command)

    out = _tool_bash(dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"Binder Error: o4"))),
                     command)
    assert "Binder Error: o4" in out
    assert [r["query_id"] for r in deps.run_state.lead_rows(deps.lead_id)] == [BASH_SHIM_QUERY_ID]


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_a_refused_shim_row_write_never_fails_the_command(tmp_path, kind):
    """O4's other half: with the run's state carried and `executed_queries.jsonl` squatted (a
    planted symlink, or a directory), the failed reduce still returns the command's output —
    the refused write is observability, and it never fails the command it observes. The row is
    in the run's state all the same (O1: the state is the record, the file its view), and the
    link's target outside the run is untouched.

    Positive control: the box ran the command once, so the output above is the command's."""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"Binder Error: o4"))
    table = RunPaths(deps.run_dir).executed_queries
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    if kind == "symlink":
        table.symlink_to(outside)
    else:
        table.mkdir()

    out = _tool_bash(deps, f"cat {payload} | defender-sql 'SELECT 1'")
    assert len(box.calls) == 1, "the command never reached the box, so the output is not its"
    assert "Binder Error: o4" in out, "a refused shim-row write cost the command its output"
    assert [r["query_id"] for r in deps.run_state.lead_rows(deps.lead_id)] == \
        [BASH_SHIM_QUERY_ID], "the failed reduce's row is not in the run's state"
    assert outside.read_bytes() == b"", "the shim row's write followed the planted link"


# ======================================================================================
# O5 / O7 — what round 3 deletes is gone; the state's read accessors.
# ======================================================================================

def test_what_round_three_deletes_is_gone():
    """`RunState.start` duplicated the constructor; lead-0's `_rows_for` / `_budget_account`
    wrapped one state call each; `QueryCapture._seq_lock` serialised what the state's own lock
    already does; `hooks/_run_dir`'s `read_json_locked` / `update_json_locked` lost their last
    production caller when the budget left the run folder."""
    from defender.runtime import lead_zero
    from defender.runtime.lead_zero import _capture

    assert not hasattr(RunState, "start"), "RunState.start survived beside the constructor"
    for module in (lead_zero, _capture):
        left = [n for n in ("_rows_for", "_budget_account") if hasattr(module, n)]
        assert left == [], f"{module.__name__} still has {left}"
    assert not hasattr(QueryCapture(registry=None), "_seq_lock"), \
        "the query tool still holds a lock of its own beside the run state's"
    if importlib.util.find_spec("defender.hooks._run_dir") is not None:
        run_dir_mod = importlib.import_module("defender.hooks._run_dir")
        left = [n for n in ("read_json_locked", "update_json_locked")
                if hasattr(run_dir_mod, n)]
        assert left == [], f"hooks/_run_dir still has {left}, with no production caller"


def test_lead_rows_hands_out_a_tuple_of_the_rows_as_they_stood(tmp_path):
    """`lead_rows(lead)` is a tuple of the lead's stored rows, in append order — read-only use,
    no copy of each row. A tuple taken before an append is unchanged by it (it is the rows as
    they stood); an unknown lead is `()`. Its rows are the lines the view holds.

    Positive control: a later read sees the appended row."""
    run_dir, state = _bare_run(tmp_path)
    assert state.lead_rows(LEAD) == ()
    _append(state, params={"q": "a"})
    before = state.lead_rows(LEAD)
    assert isinstance(before, tuple), f"lead_rows handed out a {type(before).__name__}"
    _append(state, params={"q": "b"})
    assert [r["params"] for r in before] == [{"q": "a"}], "an append reached an earlier tuple"
    after = state.lead_rows(LEAD)
    assert [r["params"] for r in after] == [{"q": "a"}, {"q": "b"}]
    assert list(after) == _table_rows(run_dir)
    assert state.lead_rows("l-404") == ()


def test_row_count_and_last_row_read_the_lead_without_listing_it(tmp_path):
    """`row_count(lead)` is how many rows the lead holds, `last_row(lead)` the latest of them
    (`None` for a lead with none) — the two reads lead-0 makes per call, counted over inherited
    and appended rows alike, per lead."""
    run_dir, state = _bare_run(tmp_path)
    assert (state.row_count(LEAD), state.last_row(LEAD)) == (0, None)

    state.inherit_rows([{"lead_id": LEAD, "seq": 0, "params": {"q": "inherited"}},
                        {"lead_id": "l-002", "seq": 0, "params": {"q": "other"}}])
    assert state.row_count(LEAD) == 1
    assert state.last_row(LEAD)["params"] == {"q": "inherited"}

    written = _append(state, params={"q": "mine"})
    assert written["seq"] == 1
    assert state.row_count(LEAD) == 2
    last = state.last_row(LEAD)
    assert (last["seq"], last["params"]) == (1, {"q": "mine"})
    assert last == _table_rows(run_dir)[-1], "the last row is not the view's last line"
    assert state.row_count("l-002") == 1
    assert (state.row_count("l-404"), state.last_row("l-404")) == (0, None)


def test_breaker_failures_counts_a_systems_charged_failures(tmp_path):
    """`breaker_failures(system)` is the failures charged to `system`: 0 before any, one per
    infra failure (exit 2 / 124), nothing for a call that failed on its own terms (exit 1) or
    succeeded, and per system.

    Positive control: it agrees with the breaker snapshot it summarises."""
    _run, state = _bare_run(tmp_path)
    assert state.breaker_failures("elastic") == 0
    cb.record_outcome(state, "elastic", 2)
    cb.record_outcome(state, "elastic", 124)
    cb.record_outcome(state, "elastic", 1)
    cb.record_outcome(state, "elastic", 0)
    cb.record_outcome(state, "cmdb", 2)
    assert state.breaker_failures("elastic") == 2
    assert state.breaker_failures("cmdb") == 1
    assert state.breaker_failures("idp") == 0
    assert state.breaker_failures("elastic") == \
        state.breaker_snapshot()["systems"]["elastic"]["failures"]
