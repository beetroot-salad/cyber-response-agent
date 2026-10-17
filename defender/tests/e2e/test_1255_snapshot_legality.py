"""#1255 slice A — which branch points a DRIVEN source admits, and what refuses an arm at launch.

These are #920's branch-point legality rules (`tests/test_920_branch_seam.py`), moved onto
driven sources. #920 checked them over hand-planted stores; after #1255 a hand-planted store is
a run recorded before the change — it has no fork snapshot, so every branch from one is refused
for THAT (N4) and a rule checked over it is checked over nothing. Each rule below is asked of
a real run through the arm's real launch (`run_investigation(resume=…)`), at a D1 branch point
(a MAIN response that called tools), with a positive control from the same source.

Rules that #1255 does NOT keep are not here: the fence-count mapping and its "snapped"
refusal, the fence-boundary seed and its validation, the lead-selection copy (all replaced by
the fork snapshot, P2), and the mid-pair refusal (reversed, D1). Their replacements are
`test_1255_snapshot_restore.py` and `test_1255_snapshot_branch_point.py`.

WHAT THESE ARE EVIDENCE FOR (contract review R1-7, recheck RC-2/RC-8c): every test here is a
regression over the new branch point (D1) — each passes once D1 lands, fork snapshot or not —
with four exceptions:

* the D4 pin, which holds today and after;
* `test_c7_the_capture_is_the_one_the_branch_points_snapshot_holds` — C7's capture half. Today's
  `validate` reads the source's WHOLE finished queries table, so a D1-only lift admits a branch
  point that preceded every capture; only a check that reads the branch point's snapshot
  refuses it;
* `test_c7_the_frontier_is_the_snapshots_not_a_fence_count_cut_of_the_finished_document` — C7's
  frontier half (adversary pass 2, F2-C7). Today's frontier is the FINISHED document cut at the
  branch point's fence count, which is the document at the branch point only while no fence
  before the cut is edited later; a `fix_row` after the branch point breaks that, and a D1-only
  lift refuses the legal branch point it leaves behind;
* `test_d1_a_branch_response_that_batches_two_appends_is_rerun_whole` — P2 (the document
  restored by content as of the branch point); a D1-only lift over today's document seed
  failed it (recheck review RC-8c).

The frontier rule (`test_the_frontier_is_the_one_the_branch_points_snapshot_holds`) stays a D1
regression: with no fence edited after the branch point, today's fence-count cut is already the
document at the branch point, so it passes under a D1-only lift (its C7 counterpart above is the
case where the cut and the snapshot disagree). Everything else about the snapshot
is `test_1255_snapshot_restore.py`'s.

RED TODAY (expected): every control arm is taken at a D1 branch point, which today's
`validate` refuses ("unanswered"); a refusal whose REASON is asserted is red today because
today's reason is that one.
"""
from __future__ import annotations

import dataclasses
import logging

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.tests import _1255_snapshot as S  # noqa: E402
from defender.tests._invlang_warn_836 import (  # noqa: E402
    PROLOGUE,
    REPAIRED_ROW_ATTRS,
    WARN_ROW,
    attr_block,
)
from defender.tests._session_store_705 import sql, store_mod  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

CHUNKS = S.chunks(3)
#: A source with one fence landed before its second response — `echo x`, the branch point
#: every control below uses.
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


#: Ids that name no MAIN response of the source, each a different way of being off the path.
OFF_PATH = {
    "message zero": lambda source: 0,
    "past the tip": lambda source: S.responses(source.store)[-1] + 1000,
    "a gather session's call": lambda source: _gather_call(source.store),
}


@pytest.mark.parametrize("where", sorted(OFF_PATH))
def test_d1_a_branch_point_must_be_a_response_on_mains_own_path(tmp_path, where):
    """D1/#920: a branch point is a MAIN response of the source. Message 0 (it precedes every
    payload, so no world can contradict the prefix), an id past the tip (which would otherwise
    read as "everything"), and a tool-calling response of a GATHER session (whose fork would
    inherit a sub-agent's transcript as MAIN's) are each refused at launch, before anything
    forks. Positive control: the same source at a MAIN tool-calling response launches.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
    source = S.drive_source(tmp_path, SCRIPT)
    point = S.tool_calling_responses(source.store)[1]
    spec = S.spec_for(source, point)
    off = dataclasses.replace(spec, branch_message_id=OFF_PATH[where](source))
    forked = len(S.child_sessions(source.store))

    arm = S.drive_arm(tmp_path, off, S.Recorder([S.done()]), name="off", run_id="off-1255")
    _refused(source, arm, forked)

    _arm_launched(S.drive_arm(tmp_path, spec, S.Recorder([S.done()])))


def test_a_source_that_captured_no_query_is_refused_at_launch(tmp_path, caplog):
    """#920 (kept): a source whose queries table holds nothing that reached a system is refused
    — every proposed world agrees with an empty capture. The correlation lead of this source
    answers without querying, so nothing is captured; its D1 branch point is otherwise the
    control's. The refusal names the empty capture. Positive control: a capturing source with
    the same script, at the same branch point, launches.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
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


#: The C7 source: MAIN appends a fence, runs `echo x`, dispatches `l-001` (which queries), runs
#: `echo y`. Its correlation lead answers WITHOUT querying, so the first capture lands between
#: the two echoes.
C7_SCRIPT = (S.append(CHUNKS[0]), S.echo("x"), S.dispatch("l-001"), S.echo("y"), S.done())
C7_LEAD = (Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                       "params": {"native_query": "user.name:dev.dana"}})]),
           Turn(text="l-001: measured"))


def test_c7_the_capture_is_the_one_the_branch_points_snapshot_holds(tmp_path, caplog):
    """C7, the capture half (recheck review RC-2): the legality check "a query that reached a
    system" reads the source's state AS OF THE BRANCH POINT, not the finished source. This
    source captures its first query only after `echo x` (the correlation lead answers without
    querying; `l-001`, dispatched after `echo x`, queries). Branched at `echo x` the arm is
    refused at launch, naming the empty capture — the finished table holds `l-001`'s row, so a
    check reading the whole table (today's `validate`) admits it. Positive control: the same
    source branched at `echo y`, after `l-001`'s query, launches.

    EVIDENCE FOR C7 (legality reads the snapshot): a D1-only lift fails it.

    RED TODAY (class a): the `echo x` arm is refused for D1's reason ("unanswered"), so the
    refusal half passes for the wrong reason and the "captured no query" assertion is red; the
    control is refused on D1 as well."""
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
        assert call.tool_name == "bash" and call.args_as_dict()["command"] == word, (
            f"branch point {row} is not `{word}`: {call}")
    caplog.set_level(logging.INFO)

    early = S.drive_arm(tmp_path, S.spec_for(source, x), S.Recorder([S.done()]),
                        name="early", run_id="early-1255")

    _refused(source, early, 0)
    assert "captured no query" in caplog.text, (
        f"the refusal does not name the empty capture: {caplog.text[-400:]!r}")
    _arm_launched(S.drive_arm(tmp_path, S.spec_for(source, y), S.Recorder([S.done()])))


def test_the_frontier_is_the_one_the_branch_points_snapshot_holds(tmp_path, caplog):
    """#920 (kept) over P2: the frontier a branch point is judged by is the document as it
    stood when that response arrived. At the source's FIRST `append_block` call the document
    held only the harness's lead-0 block — nothing open — so that branch point is refused,
    naming the frontier; one response later (`echo x`, after the first fence landed) the same
    source admits it. An implementation reading the FINISHED document admits both.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
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


#: The F2-C7 source's first fence: `_invlang_warn_836.PROLOGUE` (two declared vertices and one
#: lead, every cell held) with `v-001`'s one attribute OPEN (`owner=??`) — the only open thing in
#: the document (the harness's lead-0 block opens nothing).
OPEN_OWNER = PROLOGUE.replace("|bastion-01.corp|kind=physical\n", "|bastion-01.corp|owner=??\n")
#: The in-place repair: the flagged `owner` row (a key that refines nothing, so the slot stays
#: open) becomes `attrs.owner`, which closes it.
REPAIR = Turn(tool_calls=[("fix_row", {"old_row": WARN_ROW, "new_row": REPAIRED_ROW_ATTRS})])
#: Open slot declared, flagged row landed, `echo x` (the branch point), the repair, `echo z`.
C7_FRONTIER_SCRIPT = (S.append(OPEN_OWNER), S.append(attr_block(WARN_ROW)), S.echo("x"), REPAIR,
                      S.echo("z"), S.done())


def _answers(request: list) -> list[tuple]:
    """The tool answers a request's last message carries, as `S.project` renders them, minus
    the call id: the arm's repair is its OWN call (not the inherited branch response's), so its
    `pyd_ai_<hex>` id is a fresh random one (O4)."""
    (*_head, parts), = S.project([request[-1]])
    return [(part[0], part[1], part[3]) if len(part) == 4 else part for part in parts]


def test_c7_the_frontier_is_the_snapshots_not_a_fence_count_cut_of_the_finished_document(
        tmp_path, caplog):
    """C7, the frontier half (adversary pass 2, F2-C7): "something open in the frontier" reads
    the source's state AS OF THE BRANCH POINT's snapshot, not a cut of the finished document.
    `investigation.md` is rewritable (`fix_row` edits a row in place), so the finished
    document's first n fences are not the document at a branch point when a fence BEFORE the
    cut was repaired after it.

    This source declares `v-001` with one open attribute (`owner=??`), lands a refinement row
    the gate flags (key `owner`, which refines nothing — the slot stays open), runs `echo x`
    (the branch point), and only THEN repairs that row in place to `attrs.owner`, which closes
    the slot; `echo z` follows. At `echo x` the frontier holds the open `attrs.owner`: a legal
    branch point. The repair adds no fence, so the fence-count cut at `echo x` is the WHOLE
    finished document — repaired, nothing open — and a check reading it refuses a legal point.

    Branched at `echo x`, the arm launches; making the source's later calls itself, it makes
    the repair against the document the snapshot holds (the flagged row still there), gets the
    source's own answer, and ends holding the source's finished document. Negative control
    on the same source: branched at `echo z`, after the repair closed the only open slot, the
    arm is refused naming the frontier — the two branch points really differ in what is open.

    EVIDENCE FOR C7 (legality reads the snapshot): a D1 lift that keeps today's fence-count
    frontier refuses the `echo x` arm.

    RED TODAY (class a): both arms are refused at a D1 branch point for D1's reason
    ("unanswered")."""
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


#: What a refused arm's folder held before launch, by plant: (path, bytes) to compare after.
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
    """#920/#1165 (kept): the arm's run folder is restored INTO, never over. A folder that
    already holds an investigation document, evidence under a lead, a queries table with rows,
    or a queries table that is a link out of the folder, is refused at launch, before the fork
    (a refusal after it would leave a child session no run drives, one per retry) and before
    anything is written over what it held. Positive control: the same spec into a clean folder
    launches.

    Regression over the new branch point (D1): it passes once D1 lands, fork snapshot or not,
    so it is not evidence for the snapshot (P2)."""
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
    """D1 + P2 (replaces #920's batched-fence count): a response that calls `append_block`
    twice is one branch point. The arm holds the document as it stood BEFORE both appends and
    re-runs both, so it ends — after the source's own later calls — holding exactly the
    source's document: neither fence lost (a cut counting the response as one fence) nor
    doubled (a cut that already held them).

    EVIDENCE FOR P2 (the document restored by content as of the branch point), not a D1-only
    regression: the recheck review's partial lazy D1 lift, which kept today's document seed,
    failed it (RC-8c) — that seed is not the document as it stood when the branch response
    arrived."""
    batched = Turn(tool_calls=[("append_block", {"text": CHUNKS[1]}),
                               ("append_block", {"text": CHUNKS[2]})])
    source = S.drive_source(tmp_path, (S.append(CHUNKS[0]), batched, S.echo("x"), S.done()))
    point = S.tool_calling_responses(source.store)[1]
    assert len(S.calls_of(S.message_at(source.store, point))) == 2, "the batched turn split"
    assert CHUNKS[2].strip() in source.document, "the source's batched appends did not land"

    arm = S.drive_arm(tmp_path, S.spec_for(source, point), S.Recorder([S.echo("x"), S.done()]))

    _arm_launched(arm)
    assert arm.document == source.document


#: A source that is otherwise branchable at its second response (`echo b`): a capture (the
#: correlation lead), an open frontier (the planted document's open `class` slot), no retry.
FOLD_SCRIPT = (S.echo("a"), S.echo("b"), S.echo("c"), S.done())


def _plant_folding_document(run_dir) -> None:
    """The closed-loop document #936's fold suites fold on (`_fold_936.FOLDING_DOC`): loop 1 is
    closed and loop 2 open, so under compaction the FIRST render folds — before the branch
    point. Planted before the driver starts, as `test_936_fold_lessons_push._fold_run` does."""
    from defender.tests._fold_936 import FOLDING_DOC

    RunPaths(run_dir).investigation.write_text(FOLDING_DOC, encoding="utf-8")


def test_d4_a_source_folded_before_its_branch_point_is_refused_at_launch(
        tmp_path, monkeypatch, caplog):
    """D4 (rev 5 owner decision): a MAIN session compacted (folded) at or before the branch
    point stays unbranchable — refused at launch, before anything forks, naming the fold. The
    source here folds on its first render (`DEFENDER_COMPACTION=1` over a closed-loop
    document), so its `echo b` response is a D1 branch point inside a folded session. Positive
    control: the SAME script over the same document, driven without compaction, launches.

    A REGRESSION PIN: `validate` refuses folded sessions today and D4 keeps that. Today the
    folded arm is refused at a D1 point for D1's reason first ("unanswered"), so only the
    reason assertion is red until D1 lands; the control is red on D1."""
    from defender.runtime import session_store

    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    folded = S.drive_source(tmp_path / "folded", FOLD_SCRIPT, before=_plant_folding_document)
    point = S.tool_calling_responses(folded.store)[1]  # `echo b`
    tip = session_store.displaced_tip(folded.store, session_store.main_session_id(folded.store))
    assert tip is not None and tip <= point, (
        f"the source did not fold at or before its branch point (displaced tip {tip}, branch "
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
