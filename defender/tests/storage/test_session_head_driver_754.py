from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.storage._session_head_754 import (  # noqa: E402
    head_of,
    legacy_v1_store_file,
    log_rows,
    message_ids,
)
from defender.tests.support.storage._session_store_705 import (  # noqa: E402
    runs_base,
    sql,
    store_factory,
    store_mod,
    text_response,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    ReplayFn,
    Turn,
    drive,
    materialize,
)
from defender.run_repository import SessionPaths  # noqa: E402

pytestmark = pytest.mark.e2e

SALT = "0011223344556677"


def test_a_gather_leg_session_carries_its_own_head_like_any_other_session(tmp_path):
    """A dispatched gather leg gets a `session` row of its own, so it carries a head like any"""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='leg-head')
    opened: list = []
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([Turn(text="lead summarised")])

    drive(run_dir, run_id="leg-head", main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {}}),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    sessions = dict(sql(store, "SELECT session_id, agent_id FROM session"))
    legs = [s for s, agent in sessions.items() if agent != "main"]
    mains = [s for s, agent in sessions.items() if agent == "main"]
    assert legs, f"the run must have dispatched a leg; got {sessions}"
    assert mains, f"and recorded the main agent's own session; got {sessions}"

    leg = legs[0]
    leg_rows = message_ids(store, leg)
    assert leg_rows, "the leg really recorded its own turns"
    assert head_of(store, leg) == leg_rows[-1], "a leg's head advances onto its own rows"
    assert store_mod().path_row_ids(store, leg) == leg_rows, "and its path is its own chain"
    assert log_rows(store, leg) == [], "every one of those moves was linear, so none logged"

    main_session = mains[0]
    main_rows = message_ids(store, main_session)
    assert head_of(store, main_session) == main_rows[-1]
    assert head_of(store, main_session) != head_of(store, leg), (
        "two sessions on one shared connection each moved their own head")
    assert set(main_rows).isdisjoint(leg_rows)
    assert log_rows(store, main_session) == []

    recorded = store.append(leg, [text_response("a deliberate recorded move")],
                            agent_id=sessions[leg], parent_id=leg_rows[0],
                            synthesized=True, reason="fold")[0]
    assert head_of(store, leg) == recorded
    assert len(log_rows(store, leg)) == 1, (
        "control: nothing in the schema or the rule distinguishes a leg's session_id — "
        "'legs get no fork/fold semantics' is a statement about what production calls")


def test_a_store_error_during_setup_ends_the_run_through_the_handled_exit(tmp_path):
    """A store failure raised while the run is still being SET UP ends the run through the same"""
    # provenance: c19/C11. This is the one demand in the spec that binds the driver rather than
    # the store.
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN, run_id='stale-setup')
    legacy_v1_store_file(ss.store_path_for("stale-case", sessions=SessionPaths(fixture_runs_base(runs_base(tmp_path)))))
    replay = ReplayFn([Turn(text="never reached")])

    result = drive(run_dir, run_id="stale-setup", main=replay,
                   store_factory=store_factory(tmp_path, case_id="stale-case"))

    assert isinstance(result, dict), result
    assert result["truncated_by"] == "store", (
        f"the run must end through the handled exit, not take the process down; got {result}")
    assert result["output"] is None, "a run that never opened its store has no output"
    assert replay.calls == 0, (
        f"setup failed, so no model turn should have been driven; got {replay.calls}")

    control_dir = materialize(tmp_path / "control", GOLDEN, run_id='fresh-setup')
    control_replay = ReplayFn([Turn(text="Investigation complete.")])
    control = drive(control_dir, run_id="fresh-setup", main=control_replay,
                    store_factory=store_factory(tmp_path, case_id="fresh-case"))
    assert control["truncated_by"] is None, (
        f"control: the same run against a current-version store completes; got {control}")
    assert control["output"], control
