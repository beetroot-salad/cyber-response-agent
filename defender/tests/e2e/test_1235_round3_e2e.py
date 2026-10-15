"""#1235, round 3 — the review's fix list, driven through the real `run_investigation`.

  O1. The run's state is the record of what the run did; `executed_queries.jsonl` is the
      model's view of it. A backend call that fails while its view write is refused (the box
      planted a symlink at the table) is in the run's state and charged to its system's
      breaker, and the refused write ends the run — it does not silently continue.
  O6. Production's summary no longer carries the state. `run_investigation(run_state=…)` is the
      seam: resolved once at the boundary to `RunState(run_dir, run_id)` when handed none, and
      refused (`ValueError`) when handed another run's. The replay harness's `drive()` builds the
      state, injects it, and returns it in its own result; `driver_summary` returns production's
      summary untouched.

The unit half of O1 (the append's order, the recorder's charge) and O2-O7 are in
`tests/test_1235_round3.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import session_store  # noqa: E402
from defender.runtime.run_state import RunState  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests._fixture_uuid import fixture_uuid  # noqa: E402
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
    """`cmdb.probe`, recording what it answered. For the query `"down"` it is the box-side
    fault: it plants a symlink at the run's `executed_queries.jsonl` (the run folder is the
    box's writable mount) and then fails on the transport (exit 2)."""

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


# ======================================================================================
# O1 — a refused view write ends the run, and the run's state holds what happened.
# ======================================================================================

def test_a_failing_query_whose_view_write_is_refused_ends_the_run_holding_its_row_and_charge(
        tmp_path):
    """O1, driven: the lead's first call succeeds; its second fails on the transport after the
    box planted a symlink at `executed_queries.jsonl`. The refused view write ends the run — it
    propagates out of the gather lead and the driver — so the lead's third call is never made.
    The run's state (the one handed to the run, held by the caller because no summary comes
    back) holds both of the lead's rows, the failed one at the next seq with its exit code, and
    the failure is charged to `cmdb`'s breaker. The link's target outside the run is untouched.

    Positive control, same script with no plant: the run completes, all three calls are made,
    and nothing is charged — so the end above is the refused write's, and the charge is the
    failure's.

    Observed failing by: round 2's ordering (the row recorded and the breaker charged only after
    the line was written), under which this run ends holding one row and no charge — the failed
    call invisible to every live decision."""
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


# ======================================================================================
# O6 — the summary carries no state; the state is injected, or resolved at the boundary.
# ======================================================================================

def _store_down(case_id: str, run_dir: Path):  # noqa: ARG001
    raise OSError("r3: no store")


def test_the_production_summary_carries_no_run_state_on_either_exit(tmp_path):
    """O6: `run_investigation`'s summary has no `"run_state"` — on a completed run and on the
    store-setup failure exit (the other `_run_summary` site) alike; nothing in it is a
    `RunState`. The state is what the caller handed in, and the caller still holds it.

    Positive control: the injected state is the one the run used — it holds the lead's row and
    the run's counted calls."""
    run_dir = materialize(tmp_path / "done", GOLDEN_AB3, run_id='r3-summary')
    cmdb = _Cmdb(run_dir, tmp_path / "unused")
    mine = RunState(run_dir, run_dir.name)
    summary = driver_summary(run_dir, run_id="r3-summary", main=_main(), gather=_lead("up"),
                             verbs=cmdb.verbs(), run_state=mine)
    assert "run_state" not in summary, "production's summary still hands out the run's state"
    assert not any(isinstance(v, RunState) for v in summary.values())
    assert [r["params"] for r in mine.lead_rows(LEAD)] == [{"native_query": "up"}], \
        "the injected state is not the one the run recorded into"
    assert mine.budget_snapshot()["tool_calls"] >= 2, "the run did not count on the injected state"

    store_dir = materialize(tmp_path / "store", GOLDEN_AB3, run_id='r3-store')
    cut = driver_summary(store_dir, run_id="r3-store", main=ReplayFn([Turn(text="done")]),
                         store_factory=_store_down, run_state=RunState(store_dir, store_dir.name))
    assert cut["truncated_by"] == session_store.TRUNCATED_BY_STORE, cut
    assert "run_state" not in cut, "the store-setup exit still hands out the run's state"


def test_a_run_handed_no_state_resolves_its_own_at_the_boundary(tmp_path):
    """O6, production's path (`run.py` hands no state): the run resolves one state at its
    boundary — a `RunState` for the run's own folder, as spelled, and its own run id — and
    carries that one object to every call (each verb context the lead's calls are handed holds
    the same object); its summary hands none of it out.

    Positive control: the resolved state is the run's live one — it holds the lead's row and the
    run's counted calls."""
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
    """O6: a state handed to `run_investigation` must be this run's — its `run_dir` and
    `run_id` the run's own. One started for another folder, or under another run id, is a
    `ValueError` at the boundary: no model turn is driven, and the stranger's state is not
    touched.

    Positive control: the same run handed its own state completes (the summary test above), and
    here the drive with a matching state on a fresh folder does too."""
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
