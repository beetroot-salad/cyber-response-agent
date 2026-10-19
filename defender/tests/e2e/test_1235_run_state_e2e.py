"""#1235 — one `RunState` per run, driven through the real driver: a branch sibling counts its inherited query rows live from its first turn; no live operation looks state up by path (symlinked folder, shared run id); state is released with the run."""
from __future__ import annotations


import gc
import json
import weakref
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._query_rules import BASH_SHIM_QUERY_ID  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.scripts.gather_tools.record_query import REJECTION_BUDGET  # noqa: E402
from defender.tests.support.runtime.state._1255_view import model_path  # noqa: E402
from defender.tests.support.learning.branch._branch_947 import (  # noqa: E402
    GOLDEN_INVESTIGATION,
    LEGACY_BRANCH_CALL,
    planted_source,
    spec_at,
)
from defender.tests.support.storage._session_store_705 import runs_base  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.tests.e2e.test_pitfalls_input_823 import SQL, _Box  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"
NEW_LEAD = "l-002"
B = REJECTION_BUDGET
_SAME = {"native_query": "FROM logs"}
_OTHER = {"native_query": "FROM other"}
_CORRECTED = q("elastic", "query", {"native_query": "FROM corrected"})


class Asked:
    """What the injected `elastic.query` verb was asked, and what it saw of the run's state."""

    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.queries: list[str] = []
        #: `ctx.run_state.lead_rows(LEAD)` at each call — the state as the call saw it.
        self.inherited_seen: list[list[dict]] = []
        #: The `RunState` object each call's context carried (R2).
        self.states: list[Any] = []

    def registry(self, *, look: bool = False) -> FakeVerbs:
        def query(ctx, *, native_query: str, limit: int = 10) -> list[dict]:
            if look:
                self.states.append(ctx.run_state)
                self.inherited_seen.append(list(ctx.run_state.lead_rows(LEAD)))
            self.queries.append(native_query)
            return [{"run": self.tag, "q": native_query, "n": len(self.queries)}]

        return FakeVerbs({"elastic": {"query": query}})


def _dispatch(lead: str) -> Turn:
    return Turn(tool_calls=[("gather", {
        "lead_id": lead, "system": "elastic", "goal": "measure this lead",
        "what_to_summarize": ["auth events"]})])


def _main(lead: str) -> ReplayFn:
    return ReplayFn([_dispatch(lead), Turn(text="Investigation complete.")])


def _rejected(i: int) -> Turn:
    """A call the query tool's argument schema turns back (an extra argument): an above-guard,
    agent-fixable rejection. The verb varies per call, so no two rejections repeat."""
    return Turn(tool_calls=[("query", {
        "system": "elastic", "verb": f"ghostverb{i}", "params": _SAME, "bogus_extra_arg": "x"})])


def _rows(run_dir: Path, lead: str = LEAD) -> list[dict]:
    return [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == lead]


def _real_rows(root: Path, gather_turns: list[Turn]) -> tuple[list[dict], dict[str, bytes]]:
    """`l-001`'s rows and payload files as a fresh real run writes them for `gather_turns`."""
    run_dir = materialize(root, GOLDEN_AB3, run_id='r1235-v2-source-rows')
    drive(run_dir, run_id="r1235-v2-source-rows", main=_main(LEAD),
          gather=ReplayFn([*gather_turns, DONE]), verbs=Asked("source").registry())
    rows = _rows(run_dir)
    payloads = {r["payload_path"]: (run_dir / r["payload_path"]).read_bytes()
                for r in rows if isinstance(r.get("payload_path"), str)}
    return rows, payloads


#: The planted source's run folder name (`_branch_947.planted_source`'s `name=`), so its files
#: can be written into it before the source is built.
SOURCE_RUN = "run-source-001"


class Branched:
    """A legal source holding `rows` for `l-001`, and a fresh sibling folder to resume it in."""

    def __init__(self, tmp_path: Path, rows: list[dict], payloads: dict[str, bytes]) -> None:
        assert rows, "the source run wrote no l-001 rows — nothing below is inherited"
        self.rows, self.payloads = rows, payloads
        source = runs_base(tmp_path) / SOURCE_RUN
        for rel, data in payloads.items():
            (source / rel).parent.mkdir(parents=True, exist_ok=True)
            (source / rel).write_bytes(data)
        store, planted, _session, path_ids = planted_source(
            tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"),
            queries="".join(json.dumps(r) + "\n" for r in rows), name=SOURCE_RUN)
        assert planted == source, (planted, source)
        assert not (source / "gather_raw" / f"{LEAD}.lead.json").exists(), (
            "the legal source carries a claim for l-001, so the sibling could not re-dispatch it")
        self.spec = spec_at(store, source, path_ids[LEGACY_BRANCH_CALL])
        store.close()
        self.sibling = tmp_path / "defender-runs" / "run-sibling-1235"
        RunPaths(self.sibling).gather_raw.mkdir(parents=True)
        from defender.tests.support.storage._alert_plant import plant_alert
        plant_alert(self.sibling, RunPaths(source).alert.read_bytes())

    def resume(self, *, main: ReplayFn, gather: ReplayFn, verbs: FakeVerbs,
               box: Any = None) -> dict:
        kw = {"box": box} if box is not None else {}
        summary = drive(self.sibling, run_id="r1235-v2-sibling", main=main, gather=gather,
                        verbs=verbs, resume=self.spec, **kw)
        assert summary.get("truncated_by") is None, f"the sibling did not run to its end: {summary}"
        return summary


def _two_same(tmp_path: Path) -> Branched:
    rows, payloads = _real_rows(tmp_path / "rows", [q("elastic", "query", _SAME)] * 2)
    assert [r["seq"] for r in rows] == [0, 1], "the source run did not write two l-001 rows"
    return Branched(tmp_path / "branch", rows, payloads)


def test_the_siblings_state_holds_its_inherited_rows_from_its_first_call(tmp_path):
    branched = _two_same(tmp_path)
    asked = Asked("sibling")
    summary = branched.resume(main=_main(LEAD),
                              gather=ReplayFn([q("elastic", "query", _OTHER), DONE]),
                              verbs=asked.registry(look=True))

    table_rows = _rows(branched.sibling)
    inherited = table_rows[:2]
    assert [(r["seq"], r["params"]) for r in inherited] == [(0, _SAME), (1, _SAME)], (
        "the sibling's table does not open on the two rows it inherited")
    assert asked.inherited_seen == [inherited], (
        "the sibling's first call did not see its inherited rows on the run's state")
    state = summary["run_state"]
    assert asked.states == [state], "the verb context carried a state other than the run's"
    assert list(state.lead_rows(LEAD)) == table_rows, (
        "the run's state and its table disagree about l-001")


def test_the_repeat_guard_counts_inherited_rows(tmp_path):
    """R1: with two identical `l-001` requests inherited, the sibling's first identical request
    is the third occurrence and is refused before it reaches the backend."""
    branched = _two_same(tmp_path)
    asked = Asked("sibling")
    branched.resume(main=_main(LEAD), gather=ReplayFn([q("elastic", "query", _SAME), DONE]),
                    verbs=asked.registry())
    assert asked.queries == [], "the inherited rows did not count toward the repeat guard"

    fresh = Asked("fresh")
    drive(materialize(tmp_path / "fresh", GOLDEN_AB3), run_id="r1235-v2-fresh-repeat",
          main=_main(LEAD), gather=ReplayFn([q("elastic", "query", _SAME), DONE]),
          verbs=fresh.registry())
    assert fresh.queries == ["FROM logs"], "the control's first request never ran"


def test_a_siblings_next_row_takes_the_seq_after_its_inherited_rows(tmp_path):
    """R1: the sibling's first `l-001` row is seq 2 (after the two it inherited), its payload is
    `gather_raw/l-001/2.json`, and the inherited payload files keep the source's bytes."""
    branched = _two_same(tmp_path)
    branched.resume(main=_main(LEAD), gather=ReplayFn([q("elastic", "query", _OTHER), DONE]),
                    verbs=Asked("sibling").registry())

    own = [r for r in _rows(branched.sibling) if r["params"] == _OTHER]
    assert [r["seq"] for r in own] == [2], "the sibling's row did not continue after its inheritance"
    assert own[0]["payload_path"] == f"gather_raw/{LEAD}/2.json"
    for rel, data in branched.payloads.items():
        assert (branched.sibling / rel).read_bytes() == data, (
            f"the sibling's own call overwrote the inherited payload {rel}")
    assert b'"run": "sibling"' in (branched.sibling / own[0]["payload_path"]).read_bytes()

    fresh_dir = materialize(tmp_path / "fresh", GOLDEN_AB3, run_id='r1235-v2-fresh-seq')
    drive(fresh_dir, run_id="r1235-v2-fresh-seq", main=_main(LEAD),
          gather=ReplayFn([q("elastic", "query", _OTHER), DONE]), verbs=Asked("fresh").registry())
    assert [r["seq"] for r in _rows(fresh_dir)] == [0], "the control's first row is not seq 0"


def test_the_rejection_budget_counts_inherited_rejections(tmp_path):
    rows, payloads = _real_rows(tmp_path / "rows",
                                [q("elastic", "query", _SAME), *[_rejected(i) for i in range(B - 1)]])
    assert len(rows) == B, "the source run did not write a capture and B-1 rejections"
    branched = Branched(tmp_path / "branch", rows, payloads)
    asked = Asked("sibling")
    branched.resume(main=_main(LEAD), gather=ReplayFn([_rejected(B), _CORRECTED, DONE]),
                    verbs=asked.registry())
    assert asked.queries == [], "the inherited rejections did not count toward the budget"

    fresh = Asked("fresh")
    drive(materialize(tmp_path / "fresh", GOLDEN_AB3), run_id="r1235-v2-fresh-reject",
          main=_main(LEAD), gather=ReplayFn([_rejected(B), _CORRECTED, DONE]),
          verbs=fresh.registry())
    assert fresh.queries == ["FROM corrected"], "the control's corrected call never ran"


def test_a_failed_reducer_over_an_inherited_payload_is_recorded_with_its_system(tmp_path):
    branched = _two_same(tmp_path)
    sib = branched.sibling
    own_payload = sib / "gather_raw" / NEW_LEAD / "0.json"
    inherited_payload = sib / "gather_raw" / LEAD / "0.json"
    box = _Box()
    branched.resume(
        main=_main(NEW_LEAD),
        gather=ReplayFn([
            q("elastic", "query", _OTHER),
            Turn(tool_calls=[("bash", {
                "command": f"cat {model_path(own_payload, run_dir=sib)} | {SQL} 'SELECT 1'"})]),
            Turn(tool_calls=[("bash", {
                "command": f"cat {model_path(inherited_payload, run_dir=sib)} | {SQL} 'SELECT 2'"})]),
            DONE]),
        verbs=Asked("sibling").registry(), box=box)

    shims = [r for r in _rows(sib, NEW_LEAD) if r.get("query_id") == BASH_SHIM_QUERY_ID]
    by_sql = {("SELECT 1" in r["raw_command"]): r["system"] for r in shims}
    assert len(shims) == 2, f"expected one shim row per failed reduce: {shims}"
    assert by_sql.get(True) == "elastic", "the control: the lead's own payload lost its system"
    assert by_sql.get(False) == "elastic", (
        "a reducer over an inherited payload was recorded without that payload's system")


class Probe:
    """A `cmdb.probe` verb that keeps the `RunState` each call's context carried."""

    def __init__(self) -> None:
        self.states: list[Any] = []

    def registry(self) -> FakeVerbs:
        def probe(ctx, *, native_query: str = "FROM hosts") -> list[dict]:
            self.states.append(ctx.run_state)
            return [{"host": "web-01", "query": native_query}]

        return FakeVerbs({"cmdb": {"probe": probe}})


def _pool_script(run_dir: Path, *, run_id: str, probe: Probe) -> dict:
    """MAIN runs one bash and dispatches one cmdb lead, which probes twice: four tool calls and
    one spawn in the run's one pool. Lead-0 asks `elastic`, which this registry does not hold,
    so it charges nothing."""
    main = ReplayFn([
        Turn(tool_calls=[("bash", {"command": "echo pooled"})]),
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([q("cmdb", "probe", {"native_query": "FROM hosts-1"}),
                       q("cmdb", "probe", {"native_query": "FROM hosts-2"}), DONE])
    return drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=probe.registry())


def test_a_run_driven_through_a_symlinked_folder_counts_one_pool(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    run_dir = materialize(link, GOLDEN_AB3, run_id="r1235-v2-link")
    probe = Probe()

    state = _pool_script(run_dir, run_id="r1235-v2-link", probe=probe)["run_state"]

    assert isinstance(state, RunState)
    assert probe.states, "the lead's verb was never called"
    assert all(s is state for s in probe.states), (
        "the gather lead's verb context carried a state other than the run's")
    assert state.run_id == "r1235-v2-link"
    assert state.run_dir.resolve() == (real / "r1235-v2-link").resolve()
    snapshot = state.budget_snapshot()
    assert (snapshot["tool_calls"], snapshot["subagent_spawns"]) == (5, 2), snapshot
    assert list(state.lead_rows(LEAD)) == _rows(real / "r1235-v2-link"), (
        "the state's rows and the table read through the real spelling disagree")
    assert len(state.lead_rows(LEAD)) == 2


def test_two_runs_with_one_run_id_in_one_process_share_no_state(tmp_path):
    """R2, the positive control: two runs driven one after the other in this process, with the
    SAME run id in different folders, get two states."""
    probe = Probe()
    first = _pool_script(materialize(tmp_path / "a", GOLDEN_AB3), run_id="r1235-v2-same",
                         probe=probe)["run_state"]
    second_main = ReplayFn([Turn(tool_calls=[("bash", {"command": "echo one"})]),
                            Turn(tool_calls=[("bash", {"command": "echo two"})]),
                            Turn(text="Investigation complete.")])
    second = drive(materialize(tmp_path / "b", GOLDEN_AB3), run_id="r1235-v2-same",
                   main=second_main)["run_state"]

    assert first is not second
    a, b = first.budget_snapshot(), second.budget_snapshot()
    assert (a["tool_calls"], a["subagent_spawns"]) == (5, 2), f"the second run moved the first's pool: {a}"
    assert (b["tool_calls"], b["subagent_spawns"]) == (2, 0), f"the second run inherited counts: {b}"
    assert len(first.lead_rows(LEAD)) == 2
    assert list(second.lead_rows(LEAD)) == []


def test_nothing_holds_the_runs_state_once_the_caller_drops_the_result(tmp_path):
    """R4: after the run returns and the caller drops what `drive()` returned, no process-wide
    reference keeps the run's state — a weak reference to it dies at the next collection."""
    answered: list[str] = []

    def probe(ctx, *, native_query: str = "FROM hosts") -> list[dict]:
        answered.append(native_query)
        return [{"host": "web-01"}]

    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"]})]),
        Turn(text="Investigation complete."),
    ])
    result = drive(materialize(tmp_path, GOLDEN_AB3), run_id="r1235-v2-release", main=main,
                   gather=ReplayFn([q("cmdb", "probe", {"native_query": "FROM hosts"}), DONE]),
                   verbs=FakeVerbs({"cmdb": {"probe": probe}}))
    ref = weakref.ref(result["run_state"])
    held = ref()
    assert held is not None
    assert len(held.lead_rows(LEAD)) == 1, "the returned state does not hold the run's row"
    assert held.budget_snapshot()["tool_calls"] == 3
    del held
    del result
    gc.collect()
    assert answered == ["FROM hosts"]
    assert ref() is None, "something in the process still holds the run's state after the run"
