"""#920 PR 1 — a finished investigation resumes at one of its own messages.

Driven end-to-end through the REAL `driver.run_investigation` with a `FunctionModel` replay
(`override_allow_model_requests(False)` makes any provider call raise). Two properties:

**O1 — the prefix is rendered exactly once.** A resumed run forks the source session, is
handed the fork's own send-role hydration as `message_history`, and ingests only what the
model newly produced. Observed failing by `IngestTailUnderflow` — which the driver CATCHES
and reports as `truncated_by="store"` rather than as a crash, so the assertion is on the
summary rather than on a raised exception — or by prefix rows appearing twice under the child.

**A resumed run does not re-orient.** Lead-0 and its correlation lead are turn-0 work: they
read the alert cold to resolve its ancestors, and a branch point is by construction past that.
The discriminator is that the sibling IS handed a verb registry — the same `elastic_backend`
whose recorder catches every call lead-0 makes on the source run — and still issues nothing.
Without that arm the property would be satisfied by a run with no backend to call.

THE SOURCE RUN IS DRIVEN, NOT LOADED. `sessions/` is gitignored, so a store read off disk
would be a store nobody built; and the branch-point checks read the source run's captured
queries and its invlang document, which a hand-planted store would not have. Both come from a
real run through the #808 lead-0 scenario builder, whose lead-0 resolves for real against an
injected elastic backend. The document is authored one `append_block` per fence, because that
is the authoring path `frontier_at` describes and the only one under which the branch point's
message index says anything about how much of the document had landed.

TWO SOURCE RUNS, deliberately. Lead-0's item 3 writes a SYNTHESIZED `ModelRequest` straight
into MAIN's session, landing next to the tool-return `ModelRequest` before it — and pydantic_ai
normalises a history by merging consecutive trailing requests, so a prefix carrying one is a
strictly harder resume than a prefix without. The first scenario has no correlation lead (item
1 resolves no ancestor document, so item 3 never dispatches) and pins the core contract; the
second has one and pins that the contract survives it. Folding them into one test would make
the ordinary case unreachable until the harder one lands.

The unit-level halves — that `fork` and `hydrate(role="send")` truncate through one function,
and which branch points are legal at all — live in `tests/test_920_branch_seam.py`.
"""
from __future__ import annotations

import importlib

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.tests._session_head_754 import message_ids  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory, store_mod  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    L0,
    L3,
    LEAD_ZERO_HEADING,
    VerbRecorder,
    alert_doc,
    answer_hits,
    elastic_backend,
    hit,
    materialize_alert,
    run,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    _split_at_fences,
    drive,
)

pytestmark = pytest.mark.e2e

#: The scaffold `_user_prompt` and `orient.orientation` put in front of MAIN's first message on
#: the SOURCE run. Both strings are inherited by the sibling through `message_history`, so the
#: observable is that each appears EXACTLY ONCE — a second copy is a second orientation.
OPENING_LINE = "Begin the investigation."

CONTINUATION = (
    "Continue this investigation from where it stands. Do not restate what you already hold."
)

#: The ancestor documents item 1's second call returns. `[]` is item 1 resolving nothing, which
#: is what turns item 3's dispatch away (`prepare_correlation_lead` gates on the status), so
#: the two scenarios below differ by this one value and nothing else.
DOCS = [hit(ts="2026-05-25T15:20:00.000Z"), hit(ts="2026-05-25T15:21:00.000Z")]
NO_DOCS: list = []

#: How many `append_block` turns the source run authors its document over — one per fence in
#: the golden, so the run reaches its tip with a document that has genuinely accumulated.
FENCES = 7


def branch_mod():
    """`defender.runtime.branch` — PR 1's new module, imported per test so a missing target is
    one failure per test rather than a collection error for the file."""
    return importlib.import_module("defender.runtime.branch")


def _source_run(tmp_path, sink, *, docs):
    """Drive a real investigation that gathers evidence, writes an invlang document and stops
    WITHOUT closing — the state #920 branches from ("the defender holds a concrete set of
    payloads and has concluded nothing")."""
    return run(
        tmp_path / "source", run_id="branch-920-source",
        answer=answer_hits(docs), stores=sink,
        store_factory=store_factory(tmp_path, sink=sink),
        main_turns=[
            *[Turn(tool_calls=[("append_block", {"text": chunk})])
              for chunk in _split_at_fences(
                  (GOLDEN / "investigation.md").read_text(encoding="utf-8"), FENCES)],
            Turn(text="Holding here; the evidence is in hand and nothing is settled."),
        ],
    )


def _spec(source, store):
    """A `BranchSpec` fixed at the source run's own tip — the last message it produced."""
    ss = store_mod()
    branch = branch_mod()
    prefix_ids = ss.path_row_ids(store, ss.main_session_id(store))
    return branch.BranchSpec(source_run_dir=source.run_dir,
                             branch_message_id=prefix_ids[-1],
                             continuation_prompt=CONTINUATION), prefix_ids


def _resume(spec, sibling_dir, *, main, verbs=None):
    """Drive the sibling, turning an escape out of the driver into the demand it fails.

    `run_investigation` reports the failures it OWNS through `truncated_by`; anything that
    escapes it is a resume the runtime could not start at all, and a bare traceback out of the
    framework names the demand nowhere.

    NO `store_factory=`, deliberately. A resume is supposed to DERIVE its store from the spec —
    `_resolve_store_factory` is the whole of that contract — and handing the factory in
    alongside is what let every arm below stay green over a driver that had lost the derivation
    entirely. Without it, a regression there opens a fresh empty database and dies at
    `main_session_id` with "found 0", which is what these demands should see."""
    kw = {"verbs": verbs} if verbs is not None else {}
    try:
        return drive(sibling_dir, run_id="branch-920-sibling", main=main,
                     resume=spec, **kw)
    except Exception as exc:  # noqa: BLE001 — the class is whatever the resume broke on
        pytest.fail(
            f"the resumed run never reached its own exit: {exc!r}. A branch has to survive "
            "its first request — the inherited prefix is what the framework is handed, and "
            "the store's own render length is what `ingest` measures the live list against.")


def test_a_finished_run_resumes_at_one_of_its_own_messages(tmp_path):
    """    A real run branches at a named message through `run_investigation(resume=…)`: the sibling
    joins the source run's database, its session forks off the branch point, its first model
    request carries the inherited prefix and its own continuation prompt, and everything it
    produces lands as NEW rows — the prefix is not written a second time and no
    `IngestTailUnderflow` ends the run.

    The row assertions are one property seen from three sides. The path check says the
    inherited rows are inherited; the ownership check says the child wrote only its own; the
    `truncated_by` check says the run reached its end rather than being stopped by the store.
    A resume that duplicated the prefix passes the last of those alone, which is why all three
    are here — and the final check refuses a vacuous pass where the sibling appended nothing
    at all."""
    # provenance: issue O1 and its done-when — "a real run branches at a named message from a
    # supported entry point, in every sibling, with no IngestTailUnderflow and no duplicated
    # prefix rows". Claims C4 (executed) and C5.
    ss = store_mod()
    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    assert source.summary_dict.get("truncated_by") is None, (
        f"the SOURCE run did not finish cleanly ({source.summary_dict}); nothing below is "
        "about branching")
    store = sink[0]
    source_session = ss.main_session_id(store)
    spec, prefix_ids = _spec(source, store)

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    sibling = ReplayFn([
        Turn(tool_calls=[("read_file", {"path": str(sibling_dir / "alert.json")})]),
        Turn(text="Resumed and stopping."),
    ])

    summary = _resume(spec, sibling_dir, main=sibling)

    assert summary.get("truncated_by") is None, (
        f"the resumed run was cut short ({summary}) — `store` here is the ingest underflow "
        "O1 names by name")
    assert str(summary.get("store_path")) == str(source.summary_dict.get("store_path")), (
        "the sibling wrote to a different database from the one holding its prefix")

    children = [row[0] for row in sql(
        store, "SELECT session_id FROM session WHERE parent_session_id = ?", (source_session,))]
    assert len(children) == 1, f"the resume did not fork exactly one child session: {children}"
    child = children[0]
    assert ss.branch_point(store, child) == spec.branch_message_id, (
        "the child's recorded branch point is not the message the spec named")
    child_path = ss.path_row_ids(store, child)
    assert child_path[:len(prefix_ids)] == prefix_ids, (
        "the resumed path does not open on the inherited prefix")
    assert message_ids(store, child) == child_path[len(prefix_ids):], (
        "the child owns rows that are not on its path past the branch point — the prefix was "
        "copied into the fork rather than inherited")
    assert message_ids(store, child), (
        "the resumed run appended nothing at all, so 'it appended no duplicates' is vacuous")


def test_a_resumed_run_does_not_orient_again(tmp_path):
    """    A resumed run skips lead-0 entirely: no ancestor resolution, no `l-000` leads row, no
    query rows under a reserved id — even though the sibling is handed the same kind of verb
    registry the source run resolved lead-0 through.

    The source run is the control in the same test, deliberately: it claims `l-000` and issues
    real backend calls through its own recorder, so "the sibling issued none" is measured
    against a demonstrated capability rather than against an assumption. The prompt half is
    the mirror — the ORIENT scaffold and the ancestors heading appear exactly ONCE in the
    sibling's first request, inherited through `message_history`, not rebuilt in front of it.
    """
    # provenance: the discussion's second corrected premise — "`_user_prompt` unconditionally
    # resolves lead-0 and builds a fresh orientation prompt, which is wrong on a resume where
    # the continuation prompt is a parameter and part of the measured instrument".
    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    assert source.rec.calls, (
        "lead-0 issued no backend call on the SOURCE run — the sibling's silence below would "
        "then be the fixture's, not the resume's")
    assert source.has_sidecar(L0), "the source run claimed no l-000 leads row"
    assert source.rows_for(L0), "the source run captured no query rows under l-000"

    spec, _prefix_ids = _spec(source, sink[0])
    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    rec = VerbRecorder()
    sibling = ReplayFn([Turn(text="Resumed and stopping.")])

    _resume(spec, sibling_dir, main=sibling,
            verbs=elastic_backend(rec, answer_hits(DOCS)))

    assert rec.calls == [], (
        f"the resumed run reached the backend {len(rec.calls)} time(s) before its first model "
        f"turn ({rec.verbs}) — lead-0 resolved again over evidence the prefix already holds")
    assert not (sibling_dir / "gather_raw" / f"{L0}.lead.json").is_file(), (
        "the resumed run claimed l-000; a branch point is past turn-0 work by construction")
    rows = read_jsonl_rows(RunPaths(sibling_dir).executed_queries)
    assert [r for r in rows if r.get("lead_id") in (L0, L3)] == [], (
        f"reserved-id query rows survive into the sibling's own table: {rows}")

    assert sibling.seen, "the resumed run never reached the model"
    opening = sibling.seen[0]
    assert CONTINUATION in opening, (
        "the resume's own continuation prompt is not what the model was asked")
    assert opening.count(OPENING_LINE) == 1, (
        f"the ORIENT scaffold appears {opening.count(OPENING_LINE)} time(s): one copy is the "
        "inherited prefix, a second is a fresh orientation built in front of it")
    assert opening.count(LEAD_ZERO_HEADING) == 1, (
        f"the ancestors section appears {opening.count(LEAD_ZERO_HEADING)} time(s) — a "
        "resumed run must not put a second one in front of the history that holds the first")


def test_a_prefix_carrying_a_synthesized_turn_resumes_too(tmp_path):
    """    A branch point whose inherited prefix carries lead-0's SYNTHESIZED correlation turn
    resumes like any other, and the sibling does not re-dispatch that lead.

    This is the ordinary production shape, not an edge case: item 3 writes its summary as a
    `ModelRequest` straight into MAIN's session, and it lands immediately after the
    tool-return `ModelRequest` of the turn before it. pydantic_ai normalises a history it is
    handed by merging consecutive requests, so the list the framework gives the store's render
    processor is SHORTER than the row count `fork` charged the child for — and `ingest`'s tail
    slice then measures the live list against a length that counts rows the framework has
    already folded together. The symmetry between `fork` and `hydrate(role="send")` is exact
    and still does not settle this: both count store rows, and the framework does not.

    The source run is the control again: it DOES claim `l-00c` and it DOES carry the
    synthesized row, so neither half below can pass by the prefix simply not having one."""
    # provenance: `driver._inject_correlation` — "writes the summary DIRECTLY into MAIN's
    # session so the store-hydrated list the next render produces carries it"; #920 O1's
    # done-when is over a REAL run, and this is what real runs' prefixes look like.
    ss = store_mod()
    sink: list = []
    source = _source_run(tmp_path, sink, docs=DOCS)
    assert source.has_sidecar(L3), (
        "the source run dispatched no correlation lead, so its prefix carries no synthesized "
        "turn and this test is a duplicate of the one above")
    store = sink[0]
    source_session = ss.main_session_id(store)
    spec, prefix_ids = _spec(source, store)
    synthesized = ss.synthesized_flags(store, source_session, "send")
    assert any(synthesized), (
        "no synthesized row is on the inherited path; item 3's injection is what this test is "
        "about and it is not there")

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    rec = VerbRecorder()
    sibling = ReplayFn([Turn(text="Resumed and stopping.")])

    summary = _resume(spec, sibling_dir, main=sibling,
                      verbs=elastic_backend(rec, answer_hits(DOCS)))

    assert summary.get("truncated_by") is None, (
        f"the resumed run was cut short ({summary}) over a prefix carrying a synthesized turn")
    children = [row[0] for row in sql(
        store, "SELECT session_id FROM session WHERE parent_session_id = ?", (source_session,))]
    assert len(children) == 1, f"the resume did not fork exactly one child session: {children}"
    child_path = ss.path_row_ids(store, children[0])
    assert child_path[:len(prefix_ids)] == prefix_ids, (
        "the resumed path does not open on the inherited prefix")
    assert message_ids(store, children[0]) == child_path[len(prefix_ids):], (
        "the child owns rows off its own path — the prefix was copied, not inherited")

    assert not (sibling_dir / "gather_raw" / f"{L3}.lead.json").is_file(), (
        "the sibling dispatched its own correlation lead over ancestors the prefix already "
        "carries the answer to")
