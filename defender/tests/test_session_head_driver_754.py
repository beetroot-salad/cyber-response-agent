"""#754 — the three demands that bind OUTSIDE `session_store.py`, driven end to end.

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

import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.scripts.visualize import visualize_run  # noqa: E402
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

    drive(run_dir, run_id="leg-head", salt=SALT, main=main, gather=gather,
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
    legacy_v1_store_file(ss.store_path_for("stale-case", runs_base=runs_base(tmp_path)))
    replay = ReplayFn([Turn(text="never reached")])

    result = drive(run_dir, run_id="stale-setup", salt=SALT, main=replay,
                   store_factory=store_factory(tmp_path, case_id="stale-case"))

    assert isinstance(result, dict), result
    assert result["truncated_by"] == "store", (
        f"the run must end through the handled exit, not take the process down; got {result}")
    assert result["output"] is None, "a run that never opened its store has no output"
    assert replay.calls == 0, (
        f"setup failed, so no model turn should have been driven; got {replay.calls}")

    control_dir = materialize(tmp_path / "control", GOLDEN)
    control_replay = ReplayFn([Turn(text="Investigation complete.")])
    control = drive(control_dir, run_id="fresh-setup", salt=SALT, main=control_replay,
                    store_factory=store_factory(tmp_path, case_id="fresh-case"))
    assert control["truncated_by"] is None, (
        f"control: the same run against a current-version store completes; got {control}")
    assert control["output"], control


def test_the_pointer_path_is_trusted_verbatim_across_a_relocated_run_dir(tmp_path):
    """    The store path a run dir resolves is the one its pointer file records, verbatim: copy a
    finished run dir anywhere else and the copy still resolves the ORIGINAL absolute store
    path, still opens it read-only, and still renders the same transcript — the resolver's
    contract is the pointer file, not a convention about where the run dir sits.

    The lack of confinement is an existing CONTRACT rather than an oversight, in service of the
    allowlist copy and the eval harness's copytree, both of which relocate run dirs that must
    keep resolving their store. This pins it so the confinement question cannot be "fixed" into
    a silent regression later; the paired waiver records what the reader does NOT do and why
    changing it was declined here."""
    # provenance: PR-25 (executed break-attempt); test_store_driver_705.py:191-197 already makes
    # the relocation case explicit.
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN)
    result = drive(run_dir, run_id="relocated", salt=SALT,
                   main=ReplayFn([Turn(text="Investigation complete.")]),
                   store_factory=store_factory(tmp_path))

    original = Path(result["store_path"])
    assert ss.resolve_store_path(run_dir) == original
    here = visualize_run._main_session_analysis(run_dir)
    assert here, "the run must have rendered a transcript from its own run dir"

    relocated = tmp_path / "elsewhere" / "copied-run"
    relocated.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(run_dir, relocated)

    assert ss.resolve_store_path(relocated) == original, (
        "a relocated run dir resolves the ORIGINAL absolute store path, unchanged")
    assert not str(original).startswith(str(relocated)), (
        "the fixture must place the store outside the copy, or the assertion is vacuous")
    reader = ss.open_store_for_read(ss.resolve_store_path(relocated))
    assert sql(reader, "SELECT COUNT(*) FROM session")[0][0] >= 1, (
        "and the reader opens it and serves a live query from there")
    assert [coord for _m, coord in visualize_run._main_session_analysis(relocated)] == [
        coord for _m, coord in here], "the copy renders the same transcript as the original"
