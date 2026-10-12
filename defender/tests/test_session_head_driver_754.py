"""#754 — the demands that bind OUTSIDE `session_store.py`, driven end to end. (The third,
"the pointer path is trusted verbatim across a relocated run dir", retired with the relocation
contract in #1235: the case link is host state beside the run folder, not in a copy of it.)

Flat under `defender/tests/` for the same mechanical reason `test_store_driver_705.py` is:
`check_binds` globs the suite dir non-recursively, so a `discharged_by` pointing into
`tests/e2e/` resolves to nothing and the demands' prose becomes unscannable.
`pytestmark = pytest.mark.e2e` keeps these in the same marker lane as the other replay
scripts.

Every scenario is a few lines of `Turn(...)` against `_replay_harness`: the real agent loop,
the real tools, the real permission gate, the real store — with the store handed in through
the `store_factory` seam, and nothing patched.

**RED AGAINST `1cecad37` IS THE EXPECTED STATE.** `run_investigation` calls its store factory
during SETUP, outside the run loop's `except (sqlite3.Error, StoreError)` handler
(driver.py:520-526, c19/C11), so once the version check moves into `open_store` a stale file
takes the whole `run.py` process down instead of ending the run through the handled
`truncated_by = "store"` exit. That is the one place in this change where a store-level
decision can kill a production process.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests._session_head_754 import (  # noqa: E402
    head_of,
    legacy_v1_store_file,
    log_rows,
    message_ids,
)
from defender.tests._session_store_705 import (  # noqa: E402
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
    """    A dispatched gather leg gets a `session` row of its own, so it carries a head like any
    other session: the leg's head advances linearly onto its own rows as the leg runs, its
    path is its own chain, it contributes NO log entry — and the main agent's head advances
    independently, on the same shared connection, with neither session's head reflecting the
    other's rows.

    Legs get a head like any session; what they do not get is fork/fold semantics. That is a
    statement about what production code calls, NOT a constraint the store enforces — nothing
    in the schema or the rule distinguishes a leg's session_id — which is the control this
    test ends on."""
    # provenance: correction C3 (binding): the design's scope sentence 'gather legs are not
    # sessions and get no head of their own' is false as written — driver.py:428 runs
    # new_session per dispatched leg (c11, refuted). P93, P91 (two sessions moving their own
    # heads on one shared connection cannot cross-contaminate; the seq-collision rider is
    # settled by PR-23, executed, with zero cross-session interference) and P92.
    run_dir = materialize(tmp_path, GOLDEN_AB3)
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
    """    A store failure raised while the run is still being SET UP ends the run through the same
    handled exit the run loop uses: `run_investigation` returns its summary dict carrying
    `truncated_by` of "store" and no output, rather than letting the exception escape and take
    the process down. Not one model turn is driven.

    In production the store is opened during setup, OUTSIDE the run loop's handler whose whole
    purpose is to end a run through that exit — so moving the version check into the opener
    converts a stale file from a partial trace into an unhandled exception. The failure shape
    the design intends is "the run ends cleanly", not "the process dies". The subject is a real
    store file at the version this change refuses, opened through the real opener behind the
    real factory seam."""
    # provenance: c19/C11. This is the one demand in the spec that binds the driver rather than
    # the store.
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN)
    legacy_v1_store_file(ss.store_path_for("stale-case", sessions=SessionPaths(runs_base(tmp_path))))
    replay = ReplayFn([Turn(text="never reached")])

    result = drive(run_dir, run_id="stale-setup", main=replay,
                   store_factory=store_factory(tmp_path, case_id="stale-case"))

    assert isinstance(result, dict), result
    assert result["truncated_by"] == "store", (
        f"the run must end through the handled exit, not take the process down; got {result}")
    assert result["output"] is None, "a run that never opened its store has no output"
    assert replay.calls == 0, (
        f"setup failed, so no model turn should have been driven; got {replay.calls}")

    control_dir = materialize(tmp_path / "control", GOLDEN)
    control_replay = ReplayFn([Turn(text="Investigation complete.")])
    control = drive(control_dir, run_id="fresh-setup", main=control_replay,
                    store_factory=store_factory(tmp_path, case_id="fresh-case"))
    assert control["truncated_by"] is None, (
        f"control: the same run against a current-version store completes; got {control}")
    assert control["output"], control
