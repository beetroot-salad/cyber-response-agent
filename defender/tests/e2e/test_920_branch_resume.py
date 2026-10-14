"""#920 PR 1 — a finished investigation resumes at one of its own messages.

Driven end-to-end through the REAL `driver.run_investigation` with a `FunctionModel` replay
(`override_allow_model_requests(False)` makes any provider call raise). Two properties:

**O1 — the prefix is rendered exactly once.** A resumed run forks the source session, is
handed the fork's own send-role hydration as `message_history`, and ingests only what the
model newly produced. Observed failing by `IngestTailUnderflow` — which the driver CATCHES
and reports as `truncated_by="store"` rather than as a crash, so the assertion is on the
summary rather than on a raised exception — or by prefix rows appearing twice under the child.

**A resumed run does not re-orient.** The correlation lead is turn-0 work: it reads the alert
cold and reports before MAIN's first message, and a branch point is by construction past that.
The discriminator is that the sibling IS handed a verb registry — the same `elastic_backend`
whose recorder catches the call `l-00c` makes on the source run — and still issues nothing.
Without that arm the property would be satisfied by a run with no backend to call.

THE SOURCE RUN IS DRIVEN, NOT LOADED. `sessions/` is gitignored, so a store read off disk
would be a store nobody built; and the branch-point checks read the source run's captured
queries and its invlang document, which a hand-planted store would not have. Both come from a
real run through the #808 scenario builder, whose correlation lead issues one real call
against an injected elastic backend. The document is authored one `append_block` per fence,
because that is the authoring path `frontier_at` describes and the only one under which the
branch point's message index says anything about how much of the document had landed.

Since #1222 the correlation summary rides MAIN's opening message instead of being injected as
a synthesized row, so there is no longer a "prefix carrying a synthesized turn" scenario.

The unit-level halves — that `fork` and `hydrate(role="send")` truncate through one function,
and which branch points are legal at all — live in `tests/test_920_branch_seam.py`.
"""
from __future__ import annotations

import importlib

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime.lead_zero import CORRELATION_HEADING  # noqa: E402
from defender.tests._branch_947 import spec_at  # noqa: E402
from defender.tests._session_head_754 import message_ids  # noqa: E402
from defender.tests._session_store_705 import sql, store_factory, store_mod  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    CORRELATION_SUMMARY,
    L3,
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

#: What the source run's backend returns for `l-00c`'s one call.
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
        # `l-00c` is the only query a source run makes before MAIN: one real call, so the
        # prefix has a query that reached a system (a branch needs one) and the lead's end
        # is its own summary.
        gather_turns=[
            Turn(tool_calls=[("query", {"system": "elastic", "verb": "alerts",
                                        "params": {"native_query": "user.name:dev.dana"}})]),
            Turn(text=CORRELATION_SUMMARY),
        ],
        store_factory=store_factory(tmp_path, sink=sink),
        main_turns=[
            *[Turn(tool_calls=[("append_block", {"text": chunk})])
              for chunk in _split_at_fences(
                  (GOLDEN / "investigation.md").read_text(encoding="utf-8"), FENCES)],
            Turn(text="Holding here; the evidence is in hand and nothing is settled."),
        ],
    )


def _spec(source, store):
    """A `BranchSpec` fixed at the source run's own tip — the last message it produced.

    Built through `spec_at`, which derives the spec's `as_of` (#947) with the runtime's own
    `branch_point_time`: T0 is a coordinate of the branch point rather than of the sibling, and
    `validate` refuses a spec that carries any other moment — so a resume driven with a
    hand-chosen one would be refused before the driver ever reached the seams this file is
    about."""
    ss = store_mod()
    prefix_ids = ss.path_row_ids(store, ss.main_session_id(store))
    return spec_at(store, source.run_dir, prefix_ids[-1], prompt=CONTINUATION), prefix_ids


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


def test_a_resumed_run_appends_onto_the_document_it_inherited(tmp_path):
    """    The sibling's first `append_block` lands ON TOP of the source's document, in the
    sibling's own run dir.

    The session is inherited and the run dir is FRESH, so the document has to be carried across
    or the two halves disagree from turn one: the model's own history says it authored seven
    fences, `_opening_prompt` hands it coordinates into that document, and `_tool_append_block`
    writes `deps.run_dir/"investigation.md"`. Un-seeded, that call reported `(1835 total)`
    against a source document of 13564 bytes, and the model could not read the original back
    either — `permission.decide_read` is rooted at the sibling's run dir, so the source's copy
    is denied.

    Driven end to end rather than asserted at the seam, because everything downstream reads
    this file: `_check_append_only` has no blocks to conserve without it, `_frontier_recall`
    sees a document that never moved, and the close gate's projection reads the sibling's
    verdict against no belief history at all."""
    # provenance: `_opening_prompt`'s own docstring names the problem it cannot solve alone;
    # `branch.seed_investigation` is the other half.
    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    spec, _prefix_ids = _spec(source, sink[0])
    inherited = (source.run_dir / "investigation.md").read_text(encoding="utf-8")
    # `FENCES` counts the model's own `append_block` TURNS; the document also carries the
    # harness-authored lead block in front of them, so the file's own count is the baseline
    # to compare against rather than that constant.
    landed = inherited.count("```invlang")
    assert landed > FENCES, (
        f"the SOURCE run did not author its document ({source.summary_dict}); nothing below "
        "is about inheriting one")

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    # A block the validator accepts ON TOP OF the inherited document — which is itself half
    # the demand: a lead row citing `v-001`/`h-002` only resolves if the seed carried the
    # blocks that declare them.
    own_fence = (
        "```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
        "l-007|3|sibling-probe|v-001|h-002|elastic|15:22-15:40Z\n```")
    _resume(spec, sibling_dir, main=ReplayFn([
        Turn(tool_calls=[("append_block", {"text": own_fence})]),
        Turn(text="Resumed and stopping."),
    ]))

    document = (sibling_dir / "investigation.md").read_text(encoding="utf-8")
    seed = document[: document.index(own_fence)].rstrip("\n")
    assert seed, (
        "the sibling's document does not open on the one its own history says it wrote — its "
        "first append started an empty file in the fresh run dir")
    assert inherited.startswith(seed), (
        "the inherited document is not a byte prefix of the source's — a rebuilt one drops "
        "the prose the author wrote between blocks")
    assert seed.endswith("```"), (
        "the seed does not end on a fence boundary, so it carries prose the source wrote "
        "after its last landed block")
    assert document.count("```invlang") == landed + 1, (
        f"the sibling's document holds {document.count('```invlang')} fences, not the "
        f"{landed} it inherited plus the one it wrote")


def test_a_resumed_run_does_not_orient_again(tmp_path):
    """    A resumed run skips the correlation lead entirely: no new `l-00c` leads row, no new
    query rows under the reserved id — even though the sibling is handed the same kind of verb
    registry the source run dispatched `l-00c` through.

    The source run is the control in the same test, deliberately: it claims `l-00c` and issues
    a real backend call through its own recorder, so "the sibling issued none" is measured
    against a demonstrated capability rather than against an assumption. The prompt half is
    the mirror — the ORIENT scaffold and the correlation heading appear exactly ONCE in the
    sibling's first request, inherited through `message_history`, not rebuilt in front of it.
    """
    # provenance: the discussion's second corrected premise — "`_user_prompt` unconditionally
    # builds a fresh orientation prompt, which is wrong on a resume where the continuation
    # prompt is a parameter and part of the measured instrument".
    sink: list = []
    source = _source_run(tmp_path, sink, docs=DOCS)
    assert source.rec.calls, (
        "the correlation lead issued no backend call on the SOURCE run — the sibling's silence "
        "below would then be the fixture's, not the resume's")
    assert source.has_sidecar(L3), "the source run claimed no l-00c leads row"
    assert source.rows_for(L3), "the source run captured no query rows under l-00c"

    spec, _prefix_ids = _spec(source, sink[0])
    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    rec = VerbRecorder()
    sibling = ReplayFn([Turn(text="Resumed and stopping.")])

    _resume(spec, sibling_dir, main=sibling,
            verbs=elastic_backend(rec, answer_hits(DOCS)))

    assert rec.calls == [], (
        f"the resumed run reached the backend {len(rec.calls)} time(s) before its first model "
        f"turn ({rec.verbs}) — the correlation lead ran again over evidence the prefix holds")
    # The l-00c sidecar is INHERITED, not claimed: a sibling gets the source's captured
    # evidence in its own run dir, and `claim_lead` raises on id reuse — so the inherited
    # claim is itself what stops a resumed run redoing turn-0 work. Byte-identical is the
    # observable that separates the two; a re-claim would rewrite it.
    inherited = sibling_dir / "gather_raw" / f"{L3}.lead.json"
    assert inherited.read_bytes() == (
        source.run_dir / "gather_raw" / f"{L3}.lead.json").read_bytes(), (
        "the resumed run rewrote the l-00c leads row; a branch point is past turn-0 work by "
        "construction")
    rows = read_jsonl_rows(RunPaths(sibling_dir).executed_queries)
    source_rows = read_jsonl_rows(RunPaths(source.run_dir).executed_queries)
    assert [r for r in rows if r.get("lead_id") == L3] == [
        r for r in source_rows if r.get("lead_id") == L3], (
        f"the sibling's reserved-id query rows are not exactly the ones it inherited: {rows}")

    assert sibling.seen, "the resumed run never reached the model"
    opening = sibling.seen[0]
    assert CONTINUATION in opening, (
        "the resume's own continuation prompt is not what the model was asked")
    assert opening.count(OPENING_LINE) == 1, (
        f"the ORIENT scaffold appears {opening.count(OPENING_LINE)} time(s): one copy is the "
        "inherited prefix, a second is a fresh orientation built in front of it")
    assert opening.count(CORRELATION_HEADING) == 1, (
        f"the correlation section appears {opening.count(CORRELATION_HEADING)} time(s) — a "
        "resumed run must not put a second one in front of the history that holds the first")
