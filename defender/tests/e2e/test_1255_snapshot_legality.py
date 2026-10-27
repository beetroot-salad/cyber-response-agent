"""Fork launch refuses stale, altered, or incompatible source state."""
from __future__ import annotations

import dataclasses
import logging

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.tests.support.runtime.state import _1255_snapshot as S
from defender.tests.support.invlang.validation._invlang_warn_836 import (  # noqa: E402
    PROLOGUE,
    REPAIRED_ROW_ATTRS,
    WARN_ROW,
    attr_block,
)
from defender.tests.support.storage._session_store_705 import sql, store_mod  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)
SCRIPT = (S.append(CHUNKS[0]), S.echo("x"), S.append(CHUNKS[1]), S.done())


def _arm_launched(arm: S.Driven) -> None:
    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the control arm was refused at launch ({refused}) — a driven source branched at a "
        "tool-calling MAIN response with an open frontier and a capture")


def _refused(source: S.Driven, arm: S.Driven, forked: int) -> None:
    assert not S.launched(arm), "the arm reached its model"
    assert arm.summary.get("exit_reason") == "BranchError", arm.summary
    assert len(S.child_sessions(source.store)) == forked, (
        "the refusal came after the fork — the source store now carries a child session no run "
        "will ever drive, and every retry adds another")


def _gather_call(store) -> int:
    """A tool-calling response on the correlation lead's own session (not MAIN's)."""
    ss = store_mod()
    session = sql(store, "SELECT session_id FROM session WHERE agent_id = ?",
                  (f"gather:{S.CORRELATION_LEAD}",))[0][0]
    rows = zip(ss.path_row_ids(store, session), ss.hydrate(store, session, role="analysis"),
               strict=True)
    calls = [rid for rid, m in rows if S.calls_of(m)]
    assert calls, "the correlation lead's session holds no tool-calling response"
    return calls[0]


OFF_PATH = {
    "message zero": lambda source: 0,
    "past the tip": lambda source: S.responses(source.store)[-1] + 1000,
    "a gather session's call": lambda source: _gather_call(source.store),
}


@pytest.mark.parametrize("where", sorted(OFF_PATH))
def test_d1_a_branch_point_must_be_a_response_on_mains_own_path(tmp_path, where):
    source = S.drive_source(tmp_path, SCRIPT)
    point = S.tool_calling_responses(source.store)[1]
    spec = S.spec_for(source, point)
    off = dataclasses.replace(spec, branch_message_id=OFF_PATH[where](source))
    forked = len(S.child_sessions(source.store))

    arm = S.drive_arm(tmp_path, off, S.Recorder([S.done()]), name="off", run_id="off-1255")
    _refused(source, arm, forked)

    _arm_launched(S.drive_arm(tmp_path, spec, S.Recorder([S.done()])))


def test_a_source_that_captured_no_query_is_refused_at_launch(tmp_path, caplog):
    bare = S.drive_source(tmp_path / "bare", SCRIPT,
                          leads={S.CORRELATION_LEAD: [Turn(text="nothing to correlate")]})
    assert not S.read_text(bare.paths.executed_queries).strip(), "the bare source captured a query"
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path / "bare", S.spec_for(bare, S.tool_calling_responses(bare.store)[1]),
                      S.Recorder([S.done()]))

    _refused(bare, arm, 0)
    assert "captured no query" in caplog.text, (
        f"the refusal does not name the empty capture: {caplog.text[-400:]!r}")
    source = S.drive_source(tmp_path / "control", SCRIPT)
    _arm_launched(S.drive_arm(tmp_path / "control",
                              S.spec_for(source, S.tool_calling_responses(source.store)[1]),
                              S.Recorder([S.done()])))


C7_SCRIPT = (S.append(CHUNKS[0]), S.echo("x"), S.dispatch("l-001"), S.echo("y"), S.done())
C7_LEAD = (Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                       "params": {"native_query": "user.name:dev.dana"}})]),
           Turn(text="l-001: measured"))


def test_c7_the_capture_is_the_one_the_branch_points_snapshot_holds(tmp_path, caplog):
    source = S.drive_source(tmp_path, C7_SCRIPT,
                            leads={S.CORRELATION_LEAD: [Turn(text="nothing to correlate")],
                                   "l-001": C7_LEAD})
    captured = {r["lead_id"] for r in read_jsonl_rows(source.paths.executed_queries)}
    assert captured == {"l-001"}, (
        f"the source's finished table holds {captured}; this test needs exactly the post-`echo x`"
        " lead's row and no correlation row, or a whole-table reader and a snapshot reader "
        "agree")
    calls = S.tool_calling_responses(source.store)
    x, y = calls[1], calls[3]
    for row, word in ((x, "echo x"), (y, "echo y")):
        (call,) = S.calls_of(S.message_at(source.store, row))
        assert call.tool_name == "bash", f"branch point {row} is not `{word}`: {call}"
        assert call.args_as_dict()["command"] == word, f"branch point {row} is not `{word}`: {call}"
    caplog.set_level(logging.INFO)

    early = S.drive_arm(tmp_path, S.spec_for(source, x), S.Recorder([S.done()]),
                        name="early", run_id="early-1255")

    _refused(source, early, 0)
    assert "captured no query" in caplog.text, (
        f"the refusal does not name the empty capture: {caplog.text[-400:]!r}")
    _arm_launched(S.drive_arm(tmp_path, S.spec_for(source, y), S.Recorder([S.done()])))


def test_the_frontier_is_the_one_the_branch_points_snapshot_holds(tmp_path, caplog):
    source = S.drive_source(tmp_path, SCRIPT)
    first, after = S.tool_calling_responses(source.store)[:2]
    assert S.calls_of(S.message_at(source.store, first))[0].tool_name == "append_block"
    caplog.set_level(logging.INFO)

    early = S.drive_arm(tmp_path, S.spec_for(source, first), S.Recorder([S.done()]),
                        name="early", run_id="early-1255")

    _refused(source, early, 0)
    assert "frontier" in caplog.text, (
        f"the refusal does not name the empty frontier: {caplog.text[-400:]!r}")
    _arm_launched(S.drive_arm(tmp_path, S.spec_for(source, after), S.Recorder([S.done()])))


OPEN_OWNER = PROLOGUE.replace("|bastion-01.corp|kind=physical\n", "|bastion-01.corp|owner=??\n")
REPAIR = Turn(tool_calls=[("fix_row", {"old_row": WARN_ROW, "new_row": REPAIRED_ROW_ATTRS})])
C7_FRONTIER_SCRIPT = (S.append(OPEN_OWNER), S.append(attr_block(WARN_ROW)), S.echo("x"), REPAIR,
                      S.echo("z"), S.done())


def _answers(request: list) -> list[tuple]:
    """Collect the tool-return and retry texts in a request."""
    (*_head, parts), = S.project([request[-1]])
    return [(part[0], part[1], part[3]) if len(part) == 4 else part for part in parts]


def test_c7_the_frontier_is_the_snapshots_not_a_fence_count_cut_of_the_finished_document(
        tmp_path, caplog):
    assert "|owner=??\n" in OPEN_OWNER, "fixture: PROLOGUE's `v-001` row moved; nothing is open"
    source = S.drive_source(tmp_path, C7_FRONTIER_SCRIPT)
    assert REPAIRED_ROW_ATTRS in source.document, "the source's repair did not land"
    assert WARN_ROW not in source.document, "the source's repair did not land in place"
    calls = S.tool_calling_responses(source.store)
    x, repair, z = calls[2], calls[3], calls[4]
    for row, (tool, arg) in ((x, ("bash", "echo x")), (repair, ("fix_row", WARN_ROW)),
                             (z, ("bash", "echo z"))):
        (call,) = S.calls_of(S.message_at(source.store, row))
        assert (call.tool_name, arg in call.args_as_dict().values()) == (tool, True), (
            f"branch point {row} is not `{tool} {arg}`: {call}")
    natural = _answers(source.main.requests[4])  # the repair's answer, as MAIN read it
    assert "repaired 1 flagged row" in repr(natural), (
        f"the source's repair was not answered as a repair: {natural!r}")
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path, S.spec_for(source, x), S.Recorder([REPAIR, S.echo("z"), S.done()]))

    refused = S.refused_at_launch(arm)
    assert refused is None, (
        f"the arm at `echo x` was refused at launch ({refused}) — at that branch point `v-001`'s "
        f"`attrs.owner` was still open; only the finished document's repaired row is closed: "
        f"{caplog.text[-400:]!r}")
    answer = _answers(arm.main.requests[1])
    assert answer == natural, (
        f"the arm's re-run repair was answered {answer!r}, not {natural!r} — the arm did not "
        "hold the document as it stood at `echo x`")
    assert arm.document == source.document

    forked = len(S.child_sessions(source.store))
    caplog.clear()
    late = S.drive_arm(tmp_path, S.spec_for(source, z), S.Recorder([S.done()]), name="late",
                       run_id="late-1255")
    _refused(source, late, forked)
    assert "frontier" in caplog.text, (
        f"the refusal at `echo z` does not name the empty frontier: {caplog.text[-400:]!r}")


_PLANTED = b"someone else's work\n"


def _plant_document(run_dir):
    path = RunPaths(run_dir).investigation
    path.write_bytes(_PLANTED)
    return path


def _plant_evidence(run_dir):
    path = RunPaths(run_dir).payload("l-009", 0)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_PLANTED)
    return path


def _plant_queries(run_dir):
    path = RunPaths(run_dir).executed_queries
    path.write_bytes(b'{"existing": "sibling evidence"}\n')
    return path


def _plant_linked_queries(run_dir):
    path = RunPaths(run_dir).executed_queries
    outside = run_dir.parent / "existing-queries"
    outside.write_bytes(b'{"existing": "sibling evidence"}\n')
    path.unlink(missing_ok=True)
    path.symlink_to(outside)
    return path


PLANTS = {"document": _plant_document, "evidence": _plant_evidence,
          "queries table": _plant_queries, "linked queries table": _plant_linked_queries}


@pytest.mark.parametrize("plant", sorted(PLANTS))
def test_an_arm_folder_already_holding_work_is_refused_before_anything_forks(tmp_path, plant):
    source = S.drive_source(tmp_path, SCRIPT)
    spec = S.spec_for(source, S.tool_calling_responses(source.store)[1])
    planted: dict = {}

    def before(run_dir):
        path = PLANTS[plant](run_dir)
        planted[path] = (path.is_symlink(), path.read_bytes())

    dirty = S.drive_arm(tmp_path, spec, S.Recorder([S.done()]), name="dirty",
                        run_id="dirty-1255", before=before)
    _refused(source, dirty, 0)
    for path, (linked, data) in planted.items():
        assert (path.is_symlink(), path.read_bytes()) == (linked, data), (
            f"the refused arm wrote over its folder's {plant}")

    _arm_launched(S.drive_arm(tmp_path, spec, S.Recorder([S.done()])))


def test_d1_a_branch_response_that_batches_two_appends_is_rerun_whole(tmp_path):
    batched = Turn(tool_calls=[("append_block", {"text": CHUNKS[1]}),
                               ("append_block", {"text": CHUNKS[2]})])
    source = S.drive_source(tmp_path, (S.append(CHUNKS[0]), batched, S.echo("x"), S.done()))
    point = S.tool_calling_responses(source.store)[1]
    assert len(S.calls_of(S.message_at(source.store, point))) == 2, "the batched turn split"
    assert CHUNKS[2].strip() in source.document, "the source's batched appends did not land"

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.echo("x"), S.done()]))

    _arm_launched(arm)
    assert arm.document == source.document


FOLD_SCRIPT = (S.echo("a"), S.echo("b"), S.echo("c"), S.done())


def _plant_folding_document(run_dir) -> None:
    """Seed enough investigation content to force a fold before the branch point."""
    from defender.tests.support.shared.contracts._fold_936 import FOLDING_DOC

    RunPaths(run_dir).investigation.write_text(FOLDING_DOC, encoding="utf-8")


def test_d4_a_source_folded_before_its_branch_point_is_refused_at_launch(
        tmp_path, monkeypatch, caplog):
    from defender.records import session_store

    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    folded = S.drive_source(tmp_path / "folded", FOLD_SCRIPT, before=_plant_folding_document)
    point = S.tool_calling_responses(folded.store)[1]  # `echo b`
    tip = session_store.displaced_tip(folded.store, session_store.main_session_id(folded.store))
    assert tip is not None, (f"the source did not fold at or before its branch point (displaced tip {tip}, branch "
        f"point {point}) — the refusal below would not be about a fold")
    assert tip <= point, (f"the source did not fold at or before its branch point (displaced tip {tip}, branch "
        f"point {point}) — the refusal below would not be about a fold")
    caplog.set_level(logging.INFO)

    arm = S.drive_arm(tmp_path / "folded", S.spec_for(folded, point), S.Recorder([S.done()]))

    _refused(folded, arm, 0)
    assert "fold" in caplog.text.lower(), (
        f"the refusal does not name the fold: {caplog.text[-400:]!r}")

    monkeypatch.delenv("DEFENDER_COMPACTION")
    plain = S.drive_source(tmp_path / "plain", FOLD_SCRIPT, before=_plant_folding_document)
    assert session_store.displaced_tip(
        plain.store, session_store.main_session_id(plain.store)) is None, "the control folded"
    _arm_launched(S.drive_arm(tmp_path / "plain",
                              S.spec_for(plain, S.tool_calling_responses(plain.store)[1]),
                              S.Recorder([S.done()])))
