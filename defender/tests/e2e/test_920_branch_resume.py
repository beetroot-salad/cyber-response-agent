from __future__ import annotations

import importlib

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.records import RunPaths  # noqa: E402
from defender.investigation.lead_zero import CORRELATION_HEADING  # noqa: E402
from defender.tests.support.runtime.state import _1255_snapshot as S
from defender.tests.support.learning.branch._branch_947 import spec_at  # noqa: E402
from defender.tests.support.storage._session_head_754 import message_ids  # noqa: E402
from defender.tests.support.storage._session_store_705 import sql, store_factory, store_mod  # noqa: E402
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
from defender.tests.support.storage._store_owner import reread

pytestmark = pytest.mark.e2e

OPENING_LINE = "Begin the investigation."

#: What the source run's backend returns for `l-00c`'s one call.
DOCS = [hit(ts="2026-05-25T15:20:00.000Z"), hit(ts="2026-05-25T15:21:00.000Z")]
NO_DOCS: list = []

#: How many `append_block` turns the source run authors its document over — one per fence in
#: the golden, so the run reaches its tip with a document that has genuinely accumulated.
FENCES = 7


def branch_mod():
    """`defender.investigation.branch` — PR 1's new module, imported per test so a missing target is
    one failure per test rather than a collection error for the file."""
    return importlib.import_module("defender.investigation.branch")


def _source_run(tmp_path, sink, *, docs):
    """Drive a real investigation that gathers evidence, writes an invlang document and stops
    WITHOUT closing — the state #920 branches from ("the defender holds a concrete set of
    payloads and has concluded nothing")."""
    return run(
        tmp_path / "source", run_id="branch-920-source",
        answer=answer_hits(docs), stores=sink,
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
    """A `BranchSpec` fixed at the source run's last tool-calling MAIN response — its final
    `append_block` CALL (D1: the tip itself is a text-only response, not a branch point).
    Returns the spec and the main path through that response (the arm's inherited prefix)."""
    ss = store_mod()
    path_ids = ss.path_row_ids(store, ss.main_session_id(store))
    point = S.tool_calling_responses(store)[-1]
    assert S.calls_of(S.message_at(store, point))[0].tool_name == "append_block", (
        "the source's last tool-calling response is not its final append")
    return spec_at(store, source.run_dir, point), path_ids[: path_ids.index(point) + 1]


def _resume(spec, sibling_dir, *, main, verbs=None):
    """Drive the sibling, turning an escape out of the driver into the demand it fails."""
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
    ss = store_mod()
    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    assert source.summary_dict.get("truncated_by") is None, (
        f"the SOURCE run did not finish cleanly ({source.summary_dict}); nothing below is "
        "about branching")
    store = reread(sink[0])
    source_session = ss.main_session_id(store)
    spec, prefix_ids = _spec(source, store)

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    # Pathless (slice B moves the model's view of paths; this file is not about it).
    sibling = ReplayFn([S.echo("resumed"), Turn(text="Resumed and stopping.")])

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
    # provenance: `_opening_prompt`'s own docstring names the problem it cannot solve alone;
    # `ForkSnapshot.restore_files` is the other half.
    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    spec, _prefix_ids = _spec(source, reread(sink[0]))
    inherited = RunPaths(source.run_dir).investigation.read_text(encoding="utf-8")
    landed = inherited.count("```invlang")
    assert landed > FENCES, (
        f"the SOURCE run did not author its document ({source.summary_dict}); nothing below "
        "is about inheriting one")

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    own_fence = (
        "```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
        "l-007|3|sibling-probe|v-001|h-002|elastic|15:22-15:40Z\n```")
    summary = _resume(spec, sibling_dir, main=ReplayFn([
        Turn(tool_calls=[("append_block", {"text": own_fence})]),
        Turn(text="Resumed and stopping."),
    ]))
    assert summary.get("exit_reason") is None, f"the resumed run never started: {summary}"

    document = S.read_text(RunPaths(sibling_dir).investigation)
    assert own_fence in document, f"the sibling's own fence did not land: {document[-300:]!r}"
    seed = document[: document.index(own_fence)]
    assert seed.strip(), (
        "the sibling's document does not open on the one its own history says it wrote — its "
        "first append started an empty file in the fresh run dir")
    assert seed.startswith(inherited), (
        "the sibling's document does not open on the source's finished document: the restore "
        "plus the re-run branch append should re-land exactly what the source held")
    assert document.count("```invlang") == landed + 1, (
        f"the sibling's document holds {document.count('```invlang')} fences, not the "
        f"{landed} it inherited plus the one it wrote")


def test_a_resumed_run_does_not_orient_again(tmp_path):
    sink: list = []
    source = _source_run(tmp_path, sink, docs=DOCS)
    assert source.rec.calls, (
        "the correlation lead issued no backend call on the SOURCE run — the sibling's silence "
        "below would then be the fixture's, not the resume's")
    assert source.has_sidecar(L3), "the source run claimed no l-00c leads row"
    assert source.rows_for(L3), "the source run captured no query rows under l-00c"

    spec, _prefix_ids = _spec(source, reread(sink[0]))
    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    rec = VerbRecorder()
    sibling = S.Recorder([Turn(text="Resumed and stopping.")])

    summary = _resume(spec, sibling_dir, main=sibling,
                      verbs=elastic_backend(rec, answer_hits(DOCS)))
    assert summary.get("exit_reason") is None, f"the resumed run never started: {summary}"

    assert rec.calls == [], (
        f"the resumed run reached the backend {len(rec.calls)} time(s) before its first model "
        f"turn ({rec.verbs}) — the correlation lead ran again over evidence the prefix holds")
    inherited = RunPaths(sibling_dir).lead_claim(L3)
    assert inherited.read_bytes() == RunPaths(source.run_dir).lead_claim(L3).read_bytes(), (
        "the resumed run rewrote the l-00c leads row; a branch point is past turn-0 work by "
        "construction")
    rows = read_jsonl_rows(RunPaths(sibling_dir).executed_queries)
    source_rows = read_jsonl_rows(RunPaths(source.run_dir).executed_queries)
    assert [r for r in rows if r.get("lead_id") == L3] == [
        r for r in source_rows if r.get("lead_id") == L3], (
        f"the sibling's reserved-id query rows are not exactly the ones it inherited: {rows}")

    assert sibling.seen, "the resumed run never reached the model"
    opening = sibling.seen[0]
    source_opening = [p for p in S.user_prompts(sibling.requests[0]) if OPENING_LINE in p]
    assert len(source_opening) == 1, "the inherited prefix lost the source's opening message"
    assert S.user_prompts(sibling.requests[0]) == source_opening, (
        "the resumed run's first request carries a user message the source never sent (D1/P4: "
        f"an arm resumes with none): {S.user_prompts(sibling.requests[0])[1:]!r}")
    assert opening.count(OPENING_LINE) == 1, (
        f"the ORIENT scaffold appears {opening.count(OPENING_LINE)} time(s): one copy is the "
        "inherited prefix, a second is a fresh orientation built in front of it")
    assert opening.count(CORRELATION_HEADING) == 1, (
        f"the correlation section appears {opening.count(CORRELATION_HEADING)} time(s) — a "
        "resumed run must not put a second one in front of the history that holds the first")


# --- #1108 P4 OD21 (owner ruling 2026-10-23): a resume never hands the box the source's page --


def _bash_answers(recorder) -> list[str]:
    """What each of MAIN's `bash` calls was answered (a tool return, or the refusal it was
    handed back as a retry prompt), in call order, from the sibling's last request (the
    inherited prefix holds none: the source run called no `bash`)."""
    from pydantic_ai.messages import RetryPromptPart, ToolReturnPart

    return [str(part.content) for message in recorder.requests[-1]
            for part in getattr(message, "parts", ())
            if isinstance(part, (ToolReturnPart, RetryPromptPart))
            and getattr(part, "tool_name", None) == "bash"]


def _files_holding(root, text: str) -> list[str]:
    """Every regular file under `root` (relative names) whose bytes hold `text`."""
    from pathlib import Path

    root = Path(root)
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file() and not p.is_symlink()
                  and text.encode("utf-8") in p.read_bytes())


def test_od21_a_resumed_box_sees_neither_the_source_run_page_nor_its_raw_knowledge_reason(tmp_path):
    """#1108 P4 OD21/U12 consequence (owner ruling 2026-10-23): the source run's saved
    `runtime.html` is an operator page written after its box stopped and may show the raw
    knowledge reason. A sibling resumed over that source re-binds the source run dir (its
    folder is restored from it), and its box must see neither that page nor the reason in
    anything mounted to it.

    Two channels, each with its positive control:
    - INSIDE the sibling's box, MAIN's own `bash` (`cat` is the one opener MAIN's lane allows):
      `/runs/current/runtime.html` does not answer with the page, while
      `/runs/current/investigation.md` answers with the document inherited from the source.
    - Host-side, the box's run-folder bind source (the sibling's run dir, its alert input
      directory included) holds the reason in no file, while the same walk over the source run
      dir finds it in the planted page (so the page was there to be carried).
    The agent half the box mounts is the tenant's export, not derived from the source run."""
    import uuid

    sink: list = []
    source = _source_run(tmp_path, sink, docs=NO_DOCS)
    spec, _prefix_ids = _spec(source, reread(sink[0]))
    inherited_word = "dev.dana"
    assert inherited_word in RunPaths(source.run_dir).investigation.read_text(encoding="utf-8"), (
        f"the SOURCE run wrote no document naming {inherited_word!r} ({source.summary_dict}); "
        "the in-box control below is vacuous")
    # Minted per run, so the checkout (this file) never holds it.
    reason = f"od21-raw-knowledge-reason-{uuid.uuid4().hex}"
    page = RunPaths(source.run_dir).runtime_html
    page.write_text(
        "<html><body><div class=\"knowledge-banner\">knowledge stale (operator): "
        f"{reason}</div></body></html>\n", encoding="utf-8")

    sibling_dir = materialize_alert(tmp_path / "sibling", alert_doc())
    sibling = S.Recorder([
        Turn(tool_calls=[("bash", {"command": "cat /runs/current/runtime.html"})]),
        Turn(tool_calls=[("bash", {"command": "cat /runs/current/investigation.md"})]),
        Turn(text="Resumed and stopping."),
    ])
    summary = _resume(spec, sibling_dir, main=sibling)
    assert summary.get("exit_reason") is None, f"the resumed run never started: {summary}"

    answers = _bash_answers(sibling)
    assert len(answers) == 2, f"the sibling's box answered {len(answers)} of its 2 reads: {answers}"
    page_read, doc_read = answers
    assert inherited_word in doc_read, (
        f"control: the box does not show the document the sibling inherited, so its silence "
        f"about the page proves nothing: {doc_read[:300]!r}")
    for needle in (reason, "knowledge-banner"):
        assert needle not in page_read, (
            f"OD21: the resumed box can read the source's saved run page (an operator surface "
            f"carrying the raw knowledge reason): {page_read[:300]!r}")
    assert _files_holding(source.run_dir, reason) == [RunPaths(source.run_dir).runtime_html.name], (
        "control: the host walk does not find the planted page in the source run dir, so its "
        "silence over the sibling's run folder proves nothing")
    assert _files_holding(sibling_dir, reason) == [], (
        f"OD21/U12: the raw knowledge reason was carried into the resumed box's run folder: "
        f"{_files_holding(sibling_dir, reason)}")
