"""#1235: the run's budget counters and circuit breaker live in the run process's memory. Overwriting or deleting a state file in a live run's folder changes no host decision (call cap, tripped system, wall clock); driven through the real driver with the plant made from the scripted model's own turn.

#1235: the repeat guard and the rejection budget read the rows the host recorded in memory, so truncating, deleting or planting rows in executed_queries.jsonl moves neither; the run-to-case link is a sidecar beside the run folder, so a pointer planted inside the folder (or a hand-copied folder) is never followed.

#1235: run-state edge cases: a payload's system is attributed from the run's state not a planted row, a gather at the cap counts no spawn, and budget increments survive thread preemption.

#1235: the correlation lead's calls ride the run's one RunState; an enforced role with no state raises rather than reaching a live run's state; concurrent breaker charges lose no failure.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
import shutil
from dataclasses import replace as _with_fixture_run_1165
import asyncio
from dataclasses import replace
import contextlib
import sys
import threading

import pytest

from defender.hooks.budget_enforcer import (  # noqa: E402
    BUDGET_REFUSAL_MESSAGE,
    DEFAULT_LIMITS,
)
from defender.kit.faults import TransportFault  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    VerbRecorder,
    dispatching_main,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165
from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.investigation import branch  # noqa: E402
from defender.records import session_store  # noqa: E402
from defender.investigation.record_query import REJECTION_BUDGET  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    dispatching_main,
    drive,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.investigation.query_tool import QueryCapture  # noqa: E402
from defender.investigation.run_state import RunState  # noqa: E402
from defender.tests.support.tenancy._tenants1106 import fixture_gather_def  # noqa: E402
from defender.tests.e2e._spec771 import DEFENDER  # noqa: E402
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.hooks import budget_enforcer as be  # noqa: E402
from defender.systems import circuit_breaker  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.tests.runtime.engine.test_budget_seams_631 import _run_dir, drive_agent  # noqa: E402


FLAG = "DEFENDER_BUDGET_ENFORCE"


BUDGET_FILE = "budget.json"


BREAKER_FILE = "circuit_breaker.json"


@pytest.fixture
def enforced(monkeypatch):
    """The enforcing posture, set the way production sets it: the real environment variable."""
    monkeypatch.setenv(FLAG, "true")


def _refusal_stem() -> str:
    """The literal lead-in of the budget refusal, guarded non-empty so a count of it can never
    pass vacuously on an empty needle."""
    stem = BUDGET_REFUSAL_MESSAGE.split("{", 1)[0].strip()
    assert stem, "BUDGET_REFUSAL_MESSAGE opens with a placeholder; its stem is empty"
    return stem


def _refusals(replay: ReplayFn) -> int:
    """How many tool results in the model's final history carried the budget refusal."""
    return replay.seen[-1].count(_refusal_stem())


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class PlantingReplay(ReplayFn):
    """A scripted model that, when it is asked for turn `at` (0-based), first does `plant()` to
    the run folder — in this process, inside the live run, after the driver opened it."""

    def __init__(self, turns: list[Turn], *, at: int, plant) -> None:
        super().__init__(turns)
        self._at, self._plant = at, plant
        self.planted = False

    def __call__(self, messages, info):  # noqa: ANN001 — the FunctionModel callable protocol
        if self.calls == self._at:
            self._plant()
            self.planted = True
        return super().__call__(messages, info)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


_FOUR_BASH = [
    Turn(tool_calls=[("bash", {"command": "echo ran-one"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-two"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-three"})]),
    Turn(tool_calls=[("bash", {"command": "echo ran-four"})]),
    Turn(text="Investigation complete."),
]


_CAP_TWO = {**DEFAULT_LIMITS, "max_tool_calls": 2, "wall_clock_timeout": 3600, "grace_seconds": 600}


def _drive_main(root: Path, main: ReplayFn, *, run_id: str, limits: dict) -> dict:
    """Drive MAIN's script; returns the run's budget snapshot, read off the run's state."""
    run_dir = materialize(root, GOLDEN, run_id=run_id)
    return drive(run_dir, run_id=run_id, main=main, limits=limits)["run_state"].budget_snapshot()


def _zeroed_budget(run_id: str) -> str:
    """A budget record that reads as a fresh, unspent run — what resetting the cap looks like
    on disk."""
    now = _now_iso()
    return json.dumps({"run_id": run_id, "tool_calls": 0, "subagent_spawns": 0,
                       "created_at": now, "started_at": now})


@pytest.mark.e2e
def test_the_call_cap_refuses_at_the_cap(tmp_path, enforced):
    """Positive control for every budget arm below, on the same script and cap."""
    main = ReplayFn(list(_FOUR_BASH))
    budget = _drive_main(tmp_path / "control", main, run_id="b1235-control", limits=_CAP_TWO)

    assert _refusals(main) == 2, "the cap did not refuse the two calls past it"
    history = main.seen[-1]
    assert "ran-one" in history, "a call under the cap did not run"
    assert "ran-two" in history, "a call under the cap did not run"
    assert "ran-three" not in history, "a call past the cap ran"
    assert "ran-four" not in history, "a call past the cap ran"
    assert budget["tool_calls"] == 2


@pytest.mark.e2e
@pytest.mark.parametrize("plant", ["overwrite", "delete"])
def test_a_reset_budget_file_does_not_reopen_the_cap(tmp_path, enforced, plant):
    run_dir = materialize(tmp_path / plant, GOLDEN, run_id='b1235-reset')

    def reset() -> None:
        target = run_dir / BUDGET_FILE
        if plant == "overwrite":
            _write(target, _zeroed_budget(run_dir.name))
        else:
            target.unlink(missing_ok=True)

    main = PlantingReplay(list(_FOUR_BASH), at=2, plant=reset)
    state = drive(run_dir, run_id="b1235-reset", main=main, limits=_CAP_TWO)["run_state"]

    assert main.planted, "the plant never ran — this arm measured nothing"
    history = main.seen[-1]
    assert "ran-one" in history
    assert "ran-two" in history
    assert "ran-three" not in history, f"budget.json ({plant}) reopened the cap: a call past it ran"
    assert "ran-four" not in history, f"budget.json ({plant}) reopened the cap: a call past it ran"
    assert _refusals(main) == 2
    assert state.budget_snapshot()["tool_calls"] == 2


@pytest.mark.e2e
def test_a_planted_clock_origin_does_not_trip_the_wall_clock(tmp_path, enforced):
    """The control: the same script under a zero timeout is refused on every call."""
    roomy = {**DEFAULT_LIMITS, "max_tool_calls": 100, "wall_clock_timeout": 3600,
             "grace_seconds": 600}
    run_dir = materialize(tmp_path / "ancient", GOLDEN, run_id='b1235-clock')

    def ancient() -> None:
        _write(run_dir / BUDGET_FILE, json.dumps({
            "run_id": run_dir.name, "tool_calls": 0, "subagent_spawns": 0,
            "created_at": "2000-01-01T00:00:00+00:00",
            "started_at": "2000-01-01T00:00:00+00:00"}))

    main = PlantingReplay(list(_FOUR_BASH), at=0, plant=ancient)
    summary = drive(run_dir, run_id="b1235-clock", main=main, limits=roomy)

    assert main.planted
    assert summary.get("truncated_by") != "budget", "a planted origin killed the run"
    assert _refusals(main) == 0, "a planted origin tripped the wall clock"
    assert "ran-four" in main.seen[-1]
    assert summary["run_state"].budget_snapshot()["tool_calls"] == 4

    spent = ReplayFn(list(_FOUR_BASH))
    _drive_main(tmp_path / "spent-clock", spent, run_id="b1235-clock-ctl",
                limits={**roomy, "wall_clock_timeout": 0})
    assert _refusals(spent) == 4, "the wall-clock limb never refuses, so the arm above is vacuous"


def _registry(rec: VerbRecorder) -> FakeVerbs:
    def probe(ctx, *, native_query: str = "FROM logs") -> list[dict]:
        rec.record("probe", ctx, {"native_query": native_query})
        raise TransportFault("cmdb unreachable")

    return FakeVerbs({"cmdb": {"probe": probe}})


def _cmdb(n: int) -> Turn:
    return q("cmdb", "probe", {"native_query": f"FROM hosts-{n}"})


def _drive_gather(run_dir: Path, gather: ReplayFn, *, verbs) -> dict:
    """Drive one cmdb lead; returns the run's breaker snapshot, read off the run's state."""
    return drive(run_dir, run_id=run_dir.name, main=dispatching_main("cmdb", "host inventory"),
                 gather=gather, verbs=verbs)["run_state"].breaker_snapshot()


def _down(gather: ReplayFn) -> bool:
    seen = gather.seen[-1]
    return "[circuit-breaker]" in seen and "is DOWN" in seen


@pytest.mark.e2e
def test_a_system_tripped_by_two_infra_failures_answers_down(tmp_path):
    """Positive control for the breaker arms below."""
    rec = VerbRecorder()
    gather = ReplayFn([_cmdb(1), _cmdb(2), _cmdb(3), DONE])
    state = _drive_gather(materialize(tmp_path / "control", GOLDEN_AB3, run_id="k1235-control"),
                          gather, verbs=_registry(rec))

    assert len(rec.calls) == 2, "the tripped system was asked again"
    assert _down(gather)
    assert state["systems"]["cmdb"]["failures"] == 2
    assert "tripped_at" in state["systems"]["cmdb"]
    assert state["total_failures"] == 2


@pytest.mark.e2e
@pytest.mark.parametrize("plant", ["blank", "delete"])
def test_a_reset_breaker_file_does_not_untrip_a_system(tmp_path, plant):
    run_dir = materialize(tmp_path / plant, GOLDEN_AB3, run_id='k1235-reset')

    def reset() -> None:
        target = run_dir / BREAKER_FILE
        if plant == "blank":
            _write(target, json.dumps({"systems": {}, "total_failures": 0}))
        else:
            target.unlink(missing_ok=True)

    rec = VerbRecorder()
    gather = PlantingReplay([_cmdb(1), _cmdb(2), _cmdb(3), DONE], at=2, plant=reset)
    state = _drive_gather(run_dir, gather, verbs=_registry(rec))

    assert gather.planted, "the plant never ran — this arm measured nothing"
    assert len(rec.calls) == 2, f"circuit_breaker.json ({plant}) untripped cmdb: the verb ran again"
    assert _down(gather)
    assert state["systems"]["cmdb"]["failures"] == 2
    assert state["total_failures"] == 2


LEAD = "l-001"


#: The case link's old in-folder name: a pointer planted under it must not be followed.
OLD_POINTER_NAME = "session_store_pointer.json"


def _drive_lead(run_dir: Path, gather: ReplayFn, rec: VerbRecorder, *, run_id: str) -> None:
    """MAIN dispatches one elastic lead; the gather model replays `gather` against the injected
    happy-path registry (`elastic.query`, recorded in `rec`)."""
    drive(run_dir, run_id=run_id, main=dispatching_main("elastic", "auth events"), gather=gather,
          verbs=elastic_ok(rec))


def _lead_lines(run_dir: Path) -> list[dict]:
    """This lead's rows as the file holds them right now (the plants' source)."""
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == LEAD]


def _append_copies(run_dir: Path, row: dict, n: int) -> None:
    with RunPaths(run_dir).executed_queries.open("a", encoding="utf-8") as fh:  # lint-jsonl-io: ok — the plant is a raw write into the live table
        for _ in range(n):
            fh.write(json.dumps(row) + "\n")


_SAME = {"native_query": "FROM logs"}


_THREE_SAME = [q("elastic", "query", _SAME), q("elastic", "query", _SAME),
               q("elastic", "query", _SAME), DONE]


@pytest.mark.e2e
def test_three_identical_requests_trip_the_repeat_guard(tmp_path):
    """Positive control for the repeat arms: with nothing planted, the third identical request
    never reaches the backend."""
    rec = VerbRecorder()
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    _drive_lead(run_dir, ReplayFn(list(_THREE_SAME)), rec, run_id="r1235-control")
    assert len(rec.calls) == 2, "the repeat guard did not refuse the third identical request"


@pytest.mark.e2e
@pytest.mark.parametrize("plant", ["truncate", "delete"])
def test_an_emptied_queries_table_does_not_reset_the_repeat_count(tmp_path, plant):
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    def empty() -> None:
        table = RunPaths(run_dir).executed_queries
        assert len(_lead_lines(run_dir)) == 2, "the plant ran before the two host rows landed"
        if plant == "truncate":
            table.write_text("", encoding="utf-8")
        else:
            table.unlink()

    rec = VerbRecorder()
    gather = PlantingReplay(list(_THREE_SAME), at=2, plant=empty)
    _drive_lead(run_dir, gather, rec, run_id="r1235-empty")

    assert gather.planted, "the plant never ran — this arm measured nothing"
    assert len(rec.calls) == 2, f"a {plant}d queries table reset the repeat count"


@pytest.mark.e2e
def test_planted_rows_do_not_fire_the_repeat_guard(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    def duplicate() -> None:
        rows = _lead_lines(run_dir)
        assert len(rows) == 1, "the plant ran before the first host row landed"
        _append_copies(run_dir, rows[0], 2)

    rec = VerbRecorder()
    gather = PlantingReplay(list(_THREE_SAME), at=1, plant=duplicate)
    _drive_lead(run_dir, gather, rec, run_id="r1235-dup")

    assert gather.planted
    assert len(rec.calls) == 2, \
        "planted rows moved the repeat guard: the second request was refused (or the third ran)"


B = REJECTION_BUDGET


def _rejected(i: int) -> Turn:
    """A call the query tool's argument schema turns back (an extra argument), recorded as an
    above-guard rejection; `verb` varies per call so no two rejections repeat."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": f"ghostverb{i}", "params": _SAME, "bogus_extra_arg": "x"})])


_CORRECTED = q("elastic", "query", {"native_query": "FROM corrected"})


@pytest.mark.e2e
def test_an_emptied_queries_table_does_not_refund_the_rejection_budget(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3)

    def empty() -> None:
        assert len(_lead_lines(run_dir)) == B - 1, "the plant ran at the wrong point"
        RunPaths(run_dir).executed_queries.write_text("", encoding="utf-8")

    rec = VerbRecorder()
    gather = PlantingReplay([*[_rejected(i) for i in range(B + 3)], _CORRECTED, DONE],
                            at=B - 1, plant=empty)
    _drive_lead(run_dir, gather, rec, run_id="j1235-empty")

    assert gather.planted
    assert rec.calls == [], "an emptied queries table refunded the rejection budget"


def _finished_run(root: Path, run_id: str) -> Path:
    """A real, finished run with its own case store."""
    run_dir = materialize(root, GOLDEN, run_id=run_id)
    drive(run_dir, run_id=run_id, main=ReplayFn([Turn(text="Investigation complete.")]))
    return run_dir


def _pointer(run_dir: Path) -> dict:
    return json.loads(RunPaths(run_dir).session_pointer().read_text(encoding="utf-8"))


@pytest.mark.e2e
def test_a_pointer_planted_inside_the_folder_is_not_the_case_link(tmp_path):
    run_a = _finished_run(tmp_path / "a", "o3-a")
    run_b = _finished_run(tmp_path / "b", "o3-b")
    a_link, b_link = _pointer(run_a), _pointer(run_b)
    assert a_link["store_path"] != b_link["store_path"], "the two runs share a store"

    (run_a / OLD_POINTER_NAME).write_text(json.dumps(b_link), encoding="utf-8")

    for open_store in (branch.open_source_store, branch.source_store_if_any):
        with open_store(run_a, source_run=_run_handle_1165(run_a)) as handle:
            assert Path(handle.path).resolve() == Path(a_link["store_path"]).resolve(), \
                f"{open_store.__name__} followed a pointer planted inside the run folder"
    assert session_store.resolve_store_path(_run_handle_1165(run_a)) == Path(a_link["store_path"])
    assert session_store.resolve_session_id(_run_handle_1165(run_a)) == a_link.get("session_id")

    with branch.open_source_store(run_b, source_run=_run_handle_1165(run_b)) as control:
        assert Path(control.path).resolve() == Path(b_link["store_path"]).resolve()
    assert session_store.resolve_store_path(_run_handle_1165(run_b)) == Path(b_link["store_path"])


@pytest.mark.e2e
def test_a_hand_copied_run_folder_carries_no_case_link(tmp_path):
    """The copy opens no store; with an old in-folder pointer planted in it, the open is refused."""
    run_dir = _finished_run(tmp_path / "a", "o3-copied")
    # A run id is a canonical UUID, so the folder is fixture_uuid(<label>).
    copy = tmp_path / "elsewhere" / fixture_uuid("run")
    shutil.copytree(run_dir, copy)

    assert branch.source_store_if_any(copy, source_run=_run_handle_1165(copy)) is None, (
        "a hand-copied folder opened a store through a link carried inside it")

    (copy / OLD_POINTER_NAME).write_text(json.dumps(_pointer(run_dir)), encoding="utf-8")
    with pytest.raises(branch.BranchError):
        branch.source_store_if_any(copy, source_run=_run_handle_1165(copy))

    opened = branch.source_store_if_any(run_dir, source_run=_run_handle_1165(run_dir))
    assert opened is not None, "the original run's sidecar opened no store"
    with opened:
        pass


def test_a_capped_call_whose_view_write_is_refused_is_recorded_once(tmp_path):
    # A run folder's name is its canonical UUID run id.
    run_dir = tmp_path / fixture_uuid("run")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "adv3-capped")
    deps = replace(_with_fixture_run_1165(bind(fixture_gather_def(), run_dir, defender_dir=DEFENDER), run=_fixture_run_1165(run_dir)),
                   run_state=state, lead_id="l-00c", harness_lead=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    RunPaths(run_dir).executed_queries.symlink_to(outside)

    with pytest.raises(OSError, match="alias|link|regular|plain"):
        asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
            deps, system="elastic", verb="query", query_id="elastic.probe", params={},
            payload={"hits": []}, exit_code=0, detail="", system_key=""))

    assert outside.read_bytes() == b""
    rows = state.lead_rows("l-00c")
    assert [(r["seq"], r["verb"], r["exit_code"]) for r in rows] == [(0, "query", 0)]
    assert state.breaker_snapshot()["total_failures"] == 0


# A planted row cannot re-attribute a reducer failure to another system.
@pytest.mark.e2e
def test_1235_payload_attribution_reads_the_runs_state(tmp_path):
    from defender.investigation.run_state import RunState
    from defender.investigation import record_query as rq

    # A run id is a canonical UUID, so the folder is fixture_uuid(<label>).
    run_dir = tmp_path / fixture_uuid("run")
    RunPaths(run_dir).gather_raw.mkdir(parents=True)
    state = RunState(run_dir, "k-x5")
    row = rq.append_query_row(
        state, run=fixture_run(state.run_dir), lead_id="l-001", system="elastic", verb="query", query_id="elastic.q",
        params={"q": "a"}, raw_command="elastic query", payload_text="{}", exit_code=0,
        payload_status="ok", payload_digest="d", system_key="")
    RunPaths(run_dir).executed_queries.write_text(
        json.dumps({**row, "system": "cmdb"}) + "\n", encoding="utf-8")
    operand = run_dir / "gather_raw" / "l-001" / "0.json"
    assert rq.system_for_payload_operands(state, [operand]) == "elastic"


@pytest.mark.e2e
def test_1235_a_gather_at_the_cap_changes_nothing(tmp_path):
    from defender.hooks import budget_enforcer as be
    from defender.investigation.run_state import RunState
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    state = RunState(tmp_path, "r")
    be.account_call(state, "bash", limits=limits, tier="core")
    be.account_call(state, "gather", limits=limits, tier="core")
    assert state.budget_snapshot()["subagent_spawns"] == 0
    assert state.budget_snapshot()["tool_calls"] == 1


@pytest.mark.e2e
def test_1235_increments_survive_fine_grained_preemption(tmp_path):
    import sys
    import threading
    from defender.hooks import budget_enforcer as be
    from defender.investigation.run_state import RunState
    state = RunState(tmp_path, "r")
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 10**9}
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    try:
        def work():
            for _ in range(5000):
                be.account_call(state, "bash", limits=limits, tier="core")
        ts = [threading.Thread(target=work) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    finally:
        sys.setswitchinterval(old)
    assert state.budget_snapshot()["tool_calls"] == 8 * 5000


@pytest.mark.e2e
def test_the_correlation_leads_calls_ride_the_runs_one_state(tmp_path):
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    busy = S.run_alert(tmp_path / "busy",
                       leads={S.L3: [S.query("elastic", "alerts", {"native_query": "k1:1"}),
                                     S.query("elastic", "alerts", {"native_query": "k1:2"}),
                                     S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    idle = S.run_alert(tmp_path / "idle")
    mine = [c for c in busy.backend.rec.calls if "k1:" in str(c.params.get("native_query"))]
    assert len(mine) == 2
    assert len(busy.rows_for(S.L3)) == 2
    assert idle.has_sidecar(S.L3)
    assert all(c.run_state is busy.run_state for c in mine)
    assert list(busy.run_state.lead_rows(S.L3)) == busy.rows_for(S.L3)
    assert busy.budget["tool_calls"] - idle.budget["tool_calls"] == 2


@pytest.mark.e2e
def test_a_deps_with_no_state_raises_and_never_reaches_a_live_runs_state(tmp_path):
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}
    run_dir = _run_dir(tmp_path, "k2")
    live = RunState(run_dir, "k2-live")
    be.account_call(live, "bash", limits=limits, tier="core")
    assert live.budget_snapshot()["tool_calls"] == 1
    script = [[("bash", {"command": "echo k2"})]]

    with pytest.raises(TypeError, match="RunState"):
        drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=None)
    assert live.budget_snapshot()["tool_calls"] == 1, (
        "a deps carrying no state counted its call into the live run's state")

    carried, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=live)
    assert "BUDGET" in str(carried.all_messages()).upper(), (
        "the control: carried, a call on a state at its cap was not refused")


@pytest.mark.e2e
def test_concurrent_breaker_charges_lose_no_failure(tmp_path):
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    per, workers = 2000, 16
    try:
        for trial in range(8):
            state = RunState(tmp_path, f"k7-{trial}")

            def work(w: int, state: RunState = state) -> None:
                for _ in range(per):
                    with contextlib.suppress(circuit_breaker.RunAborted):
                        circuit_breaker.record_outcome(state, f"sys{w % 2}", 2)

            threads = [threading.Thread(target=work, args=(w,)) for w in range(workers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            snap = state.breaker_snapshot()
            assert snap["total_failures"] == per * workers, f"trial {trial} lost a charge"
            assert sum(s["failures"] for s in snap["systems"].values()) == per * workers
    finally:
        sys.setswitchinterval(old)
