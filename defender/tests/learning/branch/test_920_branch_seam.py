"""#920 PR 1 — the turn-N branch seam: what may be branched from, and where the fork lands."""
from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import importlib
import inspect
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.branch._branch_947 import ALERT_DOC, spec_at  # noqa: E402
from defender.tests.support.storage._session_head_754 import message_ids  # noqa: E402
from defender.tests.support.storage._alert_plant import plant_alert  # noqa: E402
from defender.tests.support.storage._session_store_705 import (  # noqa: E402
    complete_pair,
    make_store,
    mid_pair_session,
    runs_base,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_return_request,
    user_request,
)


def branch_mod():
    """`defender.runtime.branch` — PR 1's new module, imported per test."""
    return importlib.import_module("defender.runtime.branch")


def _sibling_state(sibling_dir: Path):  # noqa: ANN202 — a `RunState` (#1235: not imported at top)
    """A fresh run state for the sibling at `sibling_dir`: what the driver hands seeding as
    its third argument (#1235 round 2, where it was the sibling's run dir)."""
    from defender.runtime.run_state import RunState

    return RunState(sibling_dir, sibling_dir.name)


# the caller contract: fork's seeding and send-role hydration are one number

def test_a_fresh_framework_message_list_underflows_against_a_fork(tmp_path):
    # provenance: issue O1 ("observed failing by: IngestTailUnderflow out of selection.ingest");
    # claim C4 (executed) measured this exact message on a 3-message prefix.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    prefix = [user_request("investigate the alert"), *complete_pair()]
    sel.ingest(store, main, prefix, agent_id="main")
    inherited = ss.path_row_ids(store, main)
    assert len(inherited) == 3, f"the fixture prefix is not three rows: {inherited}"

    child = store.fork(main, at_message_id=inherited[-1])

    with pytest.raises(sel.IngestTailUnderflow, match=r"shorter than the last render"):
        sel.ingest(store, child, [text_response("the model's first resumed turn")],
                   agent_id="main")


def test_the_hydrated_prefix_plus_one_turn_appends_exactly_one_row(tmp_path):
    # provenance: issue O1 / claim C4 — "with the prefix: accepted, path rows [1,2,3,4],
    # exactly one new row". M1 ("hydrates the prefix and passes it as message_history").
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    sel.ingest(store, main, [user_request("investigate the alert"), *complete_pair()],
               agent_id="main")
    inherited = ss.path_row_ids(store, main)

    child = store.fork(main, at_message_id=inherited[-1])
    history = ss.hydrate(store, child, role="send")

    assert len(history) == store.last_render_len(child), (
        "the history handed to the model and the length the fork was charged for disagree; "
        "the tail slice is then off by their difference in whichever direction is worse")
    assert sel.ingest(store, child, list(history), agent_id="main") == [], (
        "re-offering the inherited prefix appended rows — the prefix is stored twice")

    added = sel.ingest(store, child, [*history, text_response("first resumed turn")],
                       agent_id="main")

    assert len(added) == 1, f"exactly the new turn lands; got {added}"
    assert ss.path_row_ids(store, child) == [*inherited, added[0]], (
        "the resumed path is not the inherited prefix plus one")
    assert message_ids(store, child) == added, (
        "the child owns rows beyond the one it added — the prefix was copied, not inherited")
    shas = [row[0] for row in sql(store, "SELECT payload_sha FROM message_payload")]
    assert len(shas) == len(set(shas)), f"byte-identical duplicate rows survive: {shas}"


def test_a_fork_at_a_call_bearing_response_hands_that_response_to_the_framework(tmp_path):
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main, complete_len = mid_pair_session(store)
    inherited = ss.path_row_ids(store, main)
    assert len(inherited) == complete_len + 1, (
        f"the fixture's dangling response is missing: {inherited}")

    child = store.fork(main, at_message_id=inherited[-1])
    history = ss.hydrate(store, child, role="send")

    assert len(history) == complete_len + 1, (
        f"conversation loading handed the resumed run {len(history)} message(s), not the "
        f"{complete_len + 1} through the branch response — the call-bearing response was "
        "dropped, so the framework has no calls to run")
    tail_calls = [p.tool_call_id for p in getattr(history[-1], "parts", ())
                  if getattr(p, "part_kind", "") == "tool-call"]
    assert tail_calls == ["c2"], f"the history does not end on the branch response: {history[-1]!r}"
    assert store.last_render_len(child) == len(history), (
        "the fork's charge and the hydrated history disagree at the branch response — the "
        "first ingest would append the response a second time, or underflow")

    added = sel.ingest(store, child, [*history, tool_return_request("query", tool_call_id="c2")],
                       agent_id="main")

    assert len(added) == 1, f"exactly the answering return lands; got {added}"
    assert ss.path_row_ids(store, child) == [*inherited, added[0]], (
        "the resumed path is not the inherited prefix (through the branch response) plus its answer")
    assert message_ids(store, child) == added, (
        "the child owns more than the one row it added — the branch response was re-appended")


# the store factory: a sibling forks INTO the source run's database

def _source_run(tmp_path, *, case_id: str = "case-source"):
    """A finished run's store and run dir, wired the way `run_investigation` wires them: the
    store under the runs base's own `sessions/`, and a case pointer in the run dir naming it.

    Returns `(store, run_dir, session_id, path_ids)`."""
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path, case_id=case_id)
    run_dir = runs_base(tmp_path) / fixture_uuid("run-source-001")
    run_dir.mkdir(parents=True, exist_ok=True)
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id=case_id, store_path=store.path)
    plant_alert(run_dir, ALERT_DOC.encode("utf-8"))
    session_id = store.new_session(agent_id="main")
    sel.ingest(store, session_id, [user_request("investigate the alert"), *complete_pair()],
               agent_id="main")
    return store, run_dir, session_id, ss.path_row_ids(store, session_id)


def test_the_branch_factory_opens_the_source_runs_own_database(tmp_path):
    # provenance: design M1 ("the store the factory hands back is the SOURCE run's, and the
    # prefix rows live in it"); the seam itself is R12's `run_investigation(store_factory=…)`.
    ss = store_mod()
    branch = branch_mod()
    store, run_dir, session_id, path_ids = _source_run(tmp_path)
    spec = spec_at(store, run_dir, path_ids[-1])

    factory = branch.store_factory_for(spec, source_run=fixture_run(spec.source_run_dir))
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-001"
    sibling_dir.mkdir(parents=True, exist_ok=True)
    handle = factory("a-brand-new-case-id", sibling_dir)

    assert Path(handle.path) == ss.resolve_store_path(_run_handle_1165(run_dir)), (
        f"the sibling opened {handle.path}, not the source run's own store "
        f"({ss.resolve_store_path(_run_handle_1165(run_dir))}) — its fork would inherit nothing")
    assert ss.main_session_id(handle) == session_id, (
        "the source run's own main session is not reachable through the handle the factory "
        "returned, so there is no lineage to branch from")
    assert ss.path_row_ids(handle, session_id) == path_ids, (
        "the prefix rows are not visible through the sibling's handle")


def test_the_branch_factory_wears_the_store_factory_shape(tmp_path):
    # provenance: driver.py's `StoreFactory = Callable[[str, Path], Any]`; design M1 reuses it.
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = _source_run(tmp_path)
    factory = branch.store_factory_for(spec_at(store, run_dir, path_ids[-1]), source_run=fixture_run(run_dir))

    params = list(inspect.signature(factory).parameters.values())
    assert len(params) == 2, f"not (case_id, run_dir)-shaped: {params}"
    assert all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params), (
        f"the driver calls `factory(case_id, run_dir)` positionally: {params}")

    first = factory("case-one", tmp_path / "one")
    second = factory("case-two", tmp_path / "two")
    assert Path(first.path) == Path(second.path), (
        "the factory's answer moved with its arguments; a sibling's own case id and run dir "
        "must not choose which database its prefix lives in")


# the two named seams
