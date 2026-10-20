"""#1235 round 3, through the real run_investigation: a failing query whose view write is refused (box-planted symlink) ends the run holding its row and breaker charge; a run handed no state resolves its own at the boundary; a state for another run is refused before the run starts."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.integrations.faults import TransportFault  # noqa: E402
from defender.tests.support.shared._fixture_uuid import fixture_uuid  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    driver_summary,
    materialize,
)
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e

LEAD = "l-001"


def _main() -> ReplayFn:
    """MAIN dispatches one `cmdb` lead, then closes."""
    return ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": "cmdb", "goal": "measure this lead",
            "what_to_summarize": ["host inventory"]})]),
        Turn(text="Investigation complete."),
    ])


class _Cmdb:
    """`cmdb.probe`, recording what it answered."""

    def __init__(self, run_dir: Path, outside: Path) -> None:
        self.table = RunPaths(run_dir).executed_queries
        self.outside = outside
        self.asked: list[str] = []

    def verbs(self) -> FakeVerbs:
        def probe(ctx, *, native_query: str = "FROM hosts") -> list[dict]:  # noqa: ARG001
            self.asked.append(native_query)
            if native_query == "down":
                self.table.unlink(missing_ok=True)
                self.table.symlink_to(self.outside)
                raise TransportFault("cmdb: connection refused")
            return [{"host": "web-01", "q": native_query}]

        return FakeVerbs({"cmdb": {"probe": probe}})


def _lead(*queries: str) -> ReplayFn:
    return ReplayFn([*(q("cmdb", "probe", {"native_query": n}) for n in queries), DONE])


def test_a_failing_query_whose_view_write_is_refused_ends_the_run_holding_its_row_and_charge(
        tmp_path):
    """O1, driven:"""
    run_dir = materialize(tmp_path / "planted", GOLDEN_AB3, run_id='r3-view-refused')
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(b"")
    cmdb = _Cmdb(run_dir, outside)
    mine = RunState(run_dir, run_dir.name)

    with pytest.raises(OSError):  # noqa: PT011 — the refused append's own errno and words
        drive(run_dir, run_id="r3-view-refused", main=_main(),
              gather=_lead("up", "down", "after"), verbs=cmdb.verbs(), run_state=mine)
    assert cmdb.asked == ["up", "down"], "the run went on after its view write was refused"
    assert [(r["seq"], r["exit_code"], r["params"]) for r in mine.lead_rows(LEAD)] == [
        (0, 0, {"native_query": "up"}), (1, 2, {"native_query": "down"}),
    ], "the run's state does not hold the call whose view write was refused"
    assert mine.breaker_snapshot()["systems"].get("cmdb", {}).get("failures") == 1, \
        "the failed call whose view write was refused was not charged to its system"
    assert outside.read_bytes() == b"", "the append followed the box's planted link"

    clean_dir = materialize(tmp_path / "clean", GOLDEN_AB3, run_id='r3-view-clean')
    clean = _Cmdb(clean_dir, outside)
    summary = drive(clean_dir, run_id="r3-view-clean", main=_main(),
                    gather=_lead("up", "steady", "after"), verbs=clean.verbs())
    assert clean.asked == ["up", "steady", "after"]
    assert [r["seq"] for r in summary["run_state"].lead_rows(LEAD)] == [0, 1, 2]
    assert summary["run_state"].breaker_snapshot()["systems"].get("cmdb") is None


def test_a_run_handed_no_state_resolves_its_own_at_the_boundary(tmp_path):
    """O6, production's path (`run.py` hands no state):"""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='r3-own-state')
    carried: list = []

    def probe(ctx, *, native_query: str = "FROM hosts") -> list[dict]:
        carried.append(ctx.run_state)
        return [{"host": "web-01", "q": native_query}]

    summary = driver_summary(run_dir, run_id="r3-own-state", main=_main(),
                             gather=_lead("one", "two"),
                             verbs=FakeVerbs({"cmdb": {"probe": probe}}))
    assert "run_state" not in summary, "production's summary still hands out the run's state"
    assert len(carried) == 2, "the lead's two calls did not both reach the verb"
    state = carried[0]
    assert isinstance(state, RunState), f"the run's calls carried {state!r}"
    assert all(s is state for s in carried), "the run's calls carried more than one state"
    assert (state.run_dir, state.run_id) == (run_dir, run_dir.name), \
        "the resolved state is not this run's"
    assert [r["params"] for r in state.lead_rows(LEAD)] == \
        [{"native_query": "one"}, {"native_query": "two"}]
    assert state.budget_snapshot()["tool_calls"] >= 3


@pytest.mark.parametrize("other", ["folder", "run-id"])
def test_an_injected_state_for_another_run_is_refused_before_the_run_starts(tmp_path, other):
    """O6:"""
    run_dir = materialize(tmp_path / "run", GOLDEN_AB3, run_id='r3-mismatch')
    elsewhere = tmp_path / "elsewhere" / run_dir.name
    elsewhere.mkdir(parents=True)
    stranger = (RunState(elsewhere, run_dir.name) if other == "folder"
                else RunState(run_dir, fixture_uuid("r3-someone-else")))
    main = _main()
    with pytest.raises(ValueError):  # noqa: PT011 — the wording is the implementation's
        driver_summary(run_dir, run_id="r3-mismatch", main=main, run_state=stranger)
    assert main.calls == 0, "a run handed another run's state drove a turn"
    assert stranger.budget_snapshot()["tool_calls"] == 0, "the stranger's state was counted on"
    assert stranger.breaker_snapshot() == {"systems": {}, "total_failures": 0}

    ok_dir = materialize(tmp_path / "ok", GOLDEN_AB3, run_id='r3-own')
    own = RunState(ok_dir, ok_dir.name)
    ok = driver_summary(ok_dir, run_id="r3-own", main=ReplayFn([Turn(text="done")]),
                        run_state=own)
    assert ok["truncated_by"] is None, ok
