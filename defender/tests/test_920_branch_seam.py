"""#920 PR 1 — the turn-N branch seam: what may be branched from, and where the fork lands."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

from defender.tests._spec1077 import fixture_run

import importlib
import inspect
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests._branch_947 import ALERT_DOC, spec_at  # noqa: E402
from defender.tests._session_head_754 import message_ids  # noqa: E402
from defender.tests._alert_plant import plant_alert  # noqa: E402
from defender.tests._session_store_705 import (  # noqa: E402
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
    """    A fork already carries a `last_render_len` for the prefix it inherited, so an
    `agent.iter` that starts its message list empty — the shape a resume takes if nothing is
    handed back — hands `ingest` a live list SHORTER than the last render, and `ingest`
    refuses it as `IngestTailUnderflow` rather than silently re-appending.

    This is the failure #920's "done when" names by name, and it is the reason the caller
    contract is a contract at all: the store is already right, and only the caller can be
    wrong. Pinned as a NEGATIVE so the positive below is not merely a run that happened to
    work — without this arm, an implementation that never forked at all would satisfy it."""
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
    """    Handing the fork's own `hydrate(role="send")` back as the resumed run's message history
    makes the tail slice exact: re-ingesting the prefix alone appends nothing, and the prefix
    plus one new message appends exactly one row, parented onto the branch point. The prefix
    rows are not re-written under new ids.

    The two numbers are one number. `fork` seeds `last_render_len` from
    `_complete_prefix_len(prefix)` and `hydrate(..., role="send")` truncates by the same
    function, so the symmetry is exact rather than approximate — which is what lets this
    assert a row COUNT rather than a tolerance."""
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
    """    D1 (#1255 — reverses #920's mid-pair rule at two of its three sites): a fork taken AT a
    response whose tool calls are still unanswered — since #1255 the ONLY kind of branch point
    — keeps that response in the conversation the resumed run is handed, and the fork is
    charged for it. So the framework is given the history ENDING in the call-bearing response
    (it runs those calls; P-U2), and the first row the resumed run lands is their answer,
    appended exactly once, with the response itself not appended a second time.

    The two sites, by the design's own list: "conversation loading (which drops a trailing
    call-bearing response)" — `hydrate(role="send")` here — and "the store fork's bookkeeping
    (which would append the response twice)" — `last_render_len`. The third, validation, is
    driven end to end in `tests/e2e/test_1255_snapshot_branch_point.py`.

    Before #1255 this test asserted the opposite: send-role hydration DROPPED the dangling
    response and the fork's charge excluded it, so the resumed model was never shown the call."""
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
    run_dir = runs_base(tmp_path) / "run-source-001"
    run_dir.mkdir(parents=True, exist_ok=True)
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id=case_id, store_path=store.path)
    # Every real run dir holds its alert before anything else happens
    # (`run_common.materialize_run`), and the sibling investigates the same one — so a
    # source run without one is not a shape a branch is ever taken from (#947).
    plant_alert(run_dir, ALERT_DOC.encode("utf-8"))
    session_id = store.new_session(agent_id="main")
    sel.ingest(store, session_id, [user_request("investigate the alert"), *complete_pair()],
               agent_id="main")
    return store, run_dir, session_id, ss.path_row_ids(store, session_id)


def test_the_branch_factory_opens_the_source_runs_own_database(tmp_path):
    """    The factory a resumed run is handed opens the database the SOURCE run wrote — the file
    `session_store.resolve_store_path` names from the source run dir — and the source session
    is readable through the handle it returns.

    Asserted as a path and then as a READ, because neither alone discriminates. `open_store`
    creates the file if it is missing, so a factory that mis-derives its runs base still
    returns a live handle over an empty database; and a handle whose path is right but whose
    lineage query finds nothing would fail at `fork` with an error naming neither the factory
    nor the run dir."""
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
    """    The callable is `StoreFactory`-shaped — two positional parameters, `(case_id, run_dir)`
    — so a resume rides the injection seam `run_investigation` already has rather than growing
    a second one. Neither argument steers it: a resume joins a case, it does not mint one."""
    # provenance: driver.py's `StoreFactory = Callable[[str, Path], Any]`; design M1 reuses it.
    branch = branch_mod()
    store, run_dir, _session_id, path_ids = _source_run(tmp_path)
    factory = branch.store_factory_for(spec_at(store, run_dir, path_ids[-1]), source_run=fixture_run(run_dir))

    params = list(inspect.signature(factory).parameters.values())
    assert len(params) == 2, f"not (case_id, run_dir)-shaped: {params}"
    assert all(p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD for p in params), (
        f"the driver calls `factory(case_id, run_dir)` positionally: {params}")

    # WHICH database it opens is the test above; this one asserts only that the two arguments
    # do not steer it, so the two demands fail separately rather than as one indistinguishable
    # red.
    first = factory("case-one", tmp_path / "one")
    second = factory("case-two", tmp_path / "two")
    assert Path(first.path) == Path(second.path), (
        "the factory's answer moved with its arguments; a sibling's own case id and run dir "
        "must not choose which database its prefix lives in")


# branch-point legality — moved onto driven sources by #1255
#
# Every legality test that stood here built its source by writing store rows directly. After
# #1255 such a store is a run recorded before the change: it has no fork snapshot, and forking
# it is refused for THAT (N4), so a rule checked over it would be checked over nothing. Where
# each went:
#
# - message 0 / an id past the tip / not on MAIN's path -> tests/e2e/test_1255_snapshot_legality.py
#   ::test_d1_a_branch_point_must_be_a_response_on_mains_own_path (now also a gather session's call)
# - a run that captured no queries -> ...::test_a_source_that_captured_no_query_is_refused_at_launch
# - an empty frontier / the frontier read at the branch point, not the end of the run
#   -> ...::test_the_frontier_is_the_one_the_branch_points_snapshot_holds (the frontier is the
#   snapshot's document, P2)
# - a run dir holding evidence / a reused run dir is refused before anything forks
#   -> ...::test_an_arm_folder_already_holding_work_is_refused_before_anything_forks
# - a branch point mid tool pair is refused -> REVERSED (D1): it is now the only branch point;
#   tests/e2e/test_1255_snapshot_branch_point.py::test_d1_only_a_tool_calling_main_response_is_a_branch_point
# - a batched turn counts two fences -> RETIRED with fence counting (P2 replaces it);
#   ...legality.py::test_d1_a_branch_response_that_batches_two_appends_is_rerun_whole
# - a snapped frontier is refused by its own name -> RETIRED: no fence mapping remains to snap
#   (the document is restored by content from the snapshot, P2)
# - the document its history claims / a prefix that would (not) validate -> RETIRED with the
#   fence-boundary seed (P2: content restore); tests/e2e/test_1255_snapshot_restore.py
#   ::test_p2_the_investigation_document_is_restored_by_content and
#   tests/e2e/test_920_branch_resume.py::test_a_resumed_run_appends_onto_the_document_it_inherited
# - the evidence its prefix names (copied, recorded) -> RETIRED with lead selection (G7/P2);
#   tests/e2e/test_1255_snapshot_restore.py::test_p2_append_only_and_write_once_files_are_restored_up_to_the_cut

def test_a_fresh_run_seeds_no_document(tmp_path):
    """    A fresh run writes no `investigation.md` at open: the first `append_block` creates it.

    The negative arm of the seed. A seam that wrote an empty file for every run would hand
    `flagged_diagnostics` and `_check_append_only` a document before the model authored one,
    and `_tool_append_block`'s "an EMPTY append gets no separator" reasoning is written against
    a file that does not exist yet."""
    branch = branch_mod()
    _store, run_dir, _session_id, _ = _source_run(tmp_path)
    fresh = tmp_path / "defender-runs" / "run-fresh"
    fresh.mkdir(parents=True, exist_ok=True)

    assert branch.seed_investigation(None, None, _sibling_state(fresh), run=fixture_run(fresh), source_run=None) == 0
    assert not (fresh / "investigation.md").exists(), (
        "a fresh run's document was created before its first append")


# the two named seams

