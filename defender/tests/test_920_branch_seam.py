"""#920 PR 1 — the turn-N branch seam: what may be branched from, and where the fork lands.

`defender/runtime/branch.py` does not exist at the base this spec forks from, so the module
is reached through `branch_mod()` (the `_session_store_705.store_mod()` idiom) rather than a
top-level import: a missing target then produces one failure *per test* instead of one
collection error for the whole file.

WHAT THIS FILE OWNS, AND WHAT IT DELIBERATELY DOES NOT
------------------------------------------------------
Three things, matching the three halves of the runtime PR:

1. **The caller contract around `fork`** (issue O1, claim C4). `session_store.fork()` is NOT
   under test here and is NOT re-pinned: `tests/test_session_head_fork_754.py:311`
   (`test_a_fresh_fork_renders_its_inherited_prefix_exactly_once`) already owns its
   `last_render_len` seeding, and #920's own first trap is "do not fix `fork`". What is
   demanded here is the OTHER half of the same number — that `hydrate(role="send")` produces
   exactly the list `fork` already charged the child for, so an `agent.iter` handed that list
   as `message_history` ingests one row per genuinely new message and none for the prefix.
   The negative arm (a fresh, empty framework list underflowing) is what makes the positive
   arm mean something, and #754 pins neither.

2. **The store factory** (design M1). A sibling gets its own run dir but must fork INTO the
   source run's database — the prefix rows are there and `fork` walks parents inside one
   transaction. The observable is a PATH, compared against `session_store.resolve_store_path`
   of the source run dir, because "it opened a store" is satisfied by opening the wrong one:
   `open_store` creates-if-missing, so a factory that mis-derives `runs_base` succeeds, hands
   back an empty database, and fails much later with an error naming neither.

3. **Branch-point legality** (design M1's precondition). A branch point exists to carry a pair
   of worlds that are both consistent with the captured evidence and that differ on something
   still open. With no capture the consistency claim is vacuous — that is the generated-world
   design #920 rejected, reached by branching too early — and with an empty frontier there is
   nothing for the pair to divide. The frontier is read AT THE BRANCH POINT, not at the end of
   the run, and that arm is what separates a real implementation from one that reads the
   finished document and calls it the frontier.

The driver wiring itself (`resume=`, `message_history=`) is driven end-to-end in
`tests/e2e/test_920_branch_resume.py`; only the two named seams are checked here, and only as
signatures, so a rename is loud rather than silently uncovered.
"""
from __future__ import annotations

import dataclasses
import importlib
import inspect
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests._branch_947 import ALERT_DOC, spec_at  # noqa: E402
from defender.tests._session_head_754 import message_ids  # noqa: E402
from defender.tests._session_store_705 import (  # noqa: E402
    DEFENDER,
    complete_pair,
    make_store,
    mid_pair_session,
    runs_base,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)

#: The document every legality fixture branches over. Read off the tree rather than authored
#: inline: an invlang document whose frontier is non-empty is not a string one can improvise —
#: it needs vertices carrying live `??` cells — and the golden is the same corpus
#: `_invlang_corpus` parametrizes every other invlang rule over.
GOLDEN_INVESTIGATION = DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md"


def branch_mod():
    """`defender.runtime.branch` — PR 1's new module, imported per test."""
    return importlib.import_module("defender.runtime.branch")


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


def test_a_mid_pair_branch_point_hydrates_to_what_the_fork_was_charged_for(tmp_path):
    """    Branching at a response whose tool call is still unanswered — the shape a raw row count
    over-counts by one — leaves the fork's `last_render_len` and its send-role hydration
    still equal, and the first resumed turn still appends exactly one row.

    The mid-pair case is where a caller that rebuilds the prefix any other way (a row count, a
    `role="live"` read) diverges from the store: `fork` deliberately does not count the
    dangling response, so a history that DOES count it makes the live list one longer than the
    render and the dangling call is silently re-sent."""
    # provenance: claim C5 — session_store.py:327's docstring states the SEND-role seeding and
    # why the raw row count over-counts; this is the caller half of that same statement.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main, complete_len = mid_pair_session(store)
    inherited = ss.path_row_ids(store, main)
    assert len(inherited) == complete_len + 1, (
        f"the fixture's dangling response is missing: {inherited}")

    child = store.fork(main, at_message_id=inherited[-1])
    history = ss.hydrate(store, child, role="send")

    assert len(history) == complete_len, (
        "send-role hydration did not drop the unanswered call, so the resumed model is "
        "handed a tool call it can neither answer nor withdraw")
    assert store.last_render_len(child) == len(history), (
        "the fork's charge and the hydrated history disagree on the mid-pair boundary")

    added = sel.ingest(store, child, [*history, tool_return_request("query", tool_call_id="c2")],
                       agent_id="main")

    assert len(added) == 1, f"exactly the answering return lands; got {added}"
    assert message_ids(store, child) == added, (
        "the child owns more than the one row it added")


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
    ss.write_case_pointer(run_dir, case_id=case_id, store_path=store.path)
    # Every real run dir holds its alert before anything else happens
    # (`run_common.materialize_run_dir`), and the sibling investigates the same one — so a
    # source run without one is not a shape a branch is ever taken from (#947).
    (run_dir / "alert.json").write_text(ALERT_DOC, encoding="utf-8")
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

    factory = branch.store_factory_for(spec)
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-001"
    sibling_dir.mkdir(parents=True, exist_ok=True)
    handle = factory("a-brand-new-case-id", sibling_dir)

    assert Path(handle.path) == ss.resolve_store_path(run_dir), (
        f"the sibling opened {handle.path}, not the source run's own store "
        f"({ss.resolve_store_path(run_dir)}) — its fork would inherit nothing")
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
    factory = branch.store_factory_for(spec_at(store, run_dir, path_ids[-1]))

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


# branch-point legality

def _legal_source(tmp_path, *, investigation: str | None, queries: str | None = "row"):
    """A source run whose session carries an `append_block` turn — a branch point past which
    at least one invlang fence has landed.

    `investigation` is the document body (`None` writes no file); `queries` is the captured
    evidence (`None` writes no table). Returns `(store, run_dir, path_ids)` where `path_ids`
    is the session path — `path_ids[2]` is the last row BEFORE the `append_block` turn and
    `path_ids[-1]` the last row after it.
    """
    ss = store_mod()
    store, run_dir, session_id, _ = _source_run(tmp_path)
    # The call carries the DOCUMENT as its `text`, which is what a real `append_block` that
    # authored this file would have sent. `fence_count_at` reads the appended text, so a
    # placeholder here would land a document the store says holds no fences — a fixture
    # asserting a convention (one fence per append) that nothing in the runtime enforces.
    store.append(session_id, [tool_call_response("append_block",
                                                 {"text": investigation or ""},
                                                 tool_call_id="ab1")], agent_id="main")
    store.append(session_id, [tool_return_request("append_block", "ok", tool_call_id="ab1")],
                 agent_id="main")
    if investigation is not None:
        (run_dir / "investigation.md").write_text(investigation, encoding="utf-8")
    if queries is not None:
        (run_dir / "executed_queries.jsonl").write_text(
            '{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", '
            '"query_id": "elastic.sshd-failed-by-srcip", "params": {}, '
            '"payload_status": "ok"}\n', encoding="utf-8")
    return store, run_dir, ss.path_row_ids(store, session_id)


def _append_document(store, session_id, text, chunks):
    """Author `text` through `chunks` `append_block` turns, cut on fence boundaries.

    The document a run ends with is the concatenation of what its appends sent, and a fixture
    that writes one text to disk while sending another asserts a mapping neither half has.
    Cut on fence starts so every running concatenation is a valid prefix document — and NOT
    one fence per chunk, because that is the convention nothing enforces and the reason
    `fence_count_at` counts blocks rather than calls.

    Returns `(chunks, return_row_ids)`.
    """
    import re
    ss = store_mod()
    starts = [m.start() for m in re.finditer(r"(?m)^```invlang", text)]
    picks = ([0] + [starts[round(i * len(starts) / chunks)] for i in range(1, chunks)]
             + [len(text)])
    pieces = [text[a:b] for a, b in zip(picks, picks[1:], strict=False)]
    returns = []
    for i, piece in enumerate(pieces):
        store.append(session_id, [tool_call_response("append_block", {"text": piece},
                                                     tool_call_id=f"doc-{i}")], agent_id="main")
        store.append(session_id, [tool_return_request("append_block", "ok",
                                                      tool_call_id=f"doc-{i}")], agent_id="main")
        returns.append(ss.path_row_ids(store, session_id)[-1])
    return pieces, returns


def _one_fence(marker: str) -> str:
    """One ````invlang` block, distinct per marker — the text one `append_block` sends."""
    return f"```invlang\n:L findings [id]\n{marker}\n```"


def _fence_turns(store, session_id, batches):
    """Append one `append_block` turn per entry in `batches`, each landing that many fences.

    A batch of 2 is ONE `ModelResponse` carrying two `ToolCallPart`s and ONE `ModelRequest`
    carrying both returns — the shape the framework produces when a turn calls the fence verb
    twice, which `tools.py`'s `sequential=True` orders and does not prevent. Returns the row id
    of each turn's RETURN message, in order."""
    from pydantic_ai.messages import (
        ModelRequest, ModelResponse, ToolCallPart, ToolReturnPart,
    )
    ss = store_mod()
    returns = []
    for turn, width in enumerate(batches):
        ids = [f"ab-{turn}-{i}" for i in range(width)]
        store.append(session_id, [ModelResponse(parts=[
            ToolCallPart(tool_name="append_block", args={"text": _one_fence(i)},
                         tool_call_id=i)
            for i in ids])], agent_id="main")
        store.append(session_id, [ModelRequest(parts=[
            ToolReturnPart(tool_name="append_block", content="ok", tool_call_id=i)
            for i in ids])], agent_id="main")
        returns.append(ss.path_row_ids(store, session_id)[-1])
    return returns


def test_a_turn_that_batches_two_appends_counts_two_fences(tmp_path):
    """    A turn carrying two `append_block` calls lands two fences and is counted as two.

    The `actor` projection cannot say "twice": `session_store._tool_name` publishes every
    DISTINCT tool a message names, comma-joined, so a count taken from it reads one batched
    turn as one fence. That under-count is the SILENT direction — `FrontierAt.snapped` fires
    only when a caller asks PAST the document's end — so the branch was admitted at a frontier
    the run had already moved past, with `validate` reporting nothing wrong. Nothing forbids
    the turn: `tools.py` sets `sequential=True`, which orders two calls inside one response
    rather than preventing them, and nothing sets `parallel_tool_calls=False`.

    Asserted against the DOCUMENT's own fence count, not against a literal, so the two halves
    of the mapping are pinned to each other rather than to a number this test chose."""
    # provenance: `fence_count_at`'s contract — "a caller holding a message index maps it to a
    # fence itself" (`frontier_at`); `session_store._tool_name`'s distinct-name join.
    branch = branch_mod()
    store, run_dir, session_id, _ = _source_run(tmp_path)
    returns = _fence_turns(store, session_id, [1, 2])
    document = "\n\n".join(_one_fence(f"ab-{t}-{i}") for t, i in ((0, 0), (1, 0), (1, 1)))
    (run_dir / "investigation.md").write_text(document, encoding="utf-8")

    counted = branch.fence_count_at(store, session_id, returns[-1], document)

    assert counted == 3, (
        f"the batched turn's second fence was dropped: {counted} counted against 3 landed")
    from defender.skills.invlang.frontier import frontier_at
    assert not frontier_at(document, counted).snapped, (
        "the count ran past the document, which is the loud direction and not this bug")


def test_a_resumed_run_inherits_the_document_its_history_claims(tmp_path):
    """    A sibling's run dir gets `investigation.md` seeded from the source's, cut at the branch.

    The session is inherited and the run dir is FRESH, so without this the model reads an
    inherited history saying it authored N fences while `_tool_append_block` starts an empty
    file in the new run dir — and it cannot even read the source's copy, because
    `permission.decide_read` is rooted at the sibling's run dir.

    CUT AT THE BRANCH, not copied whole: the source ran on past the fork, and its later fences
    carry the conclusions the pair exists to not share. Asserted as a byte PREFIX of the source
    and as a fence count, because either alone passes something wrong — a prefix check alone
    admits the empty file, and a count alone admits a rebuilt document that dropped the
    author's prose between blocks."""
    # provenance: `_opening_prompt`'s own docstring (a model re-reading `<source>/…` is denied);
    # `_tool_append_block` writes `_investigation_path(deps)`, rooted at the sibling's run_dir.
    branch = branch_mod()
    document = GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    store, run_dir, session_id, _ = _source_run(tmp_path)
    pieces, returns = _append_document(store, session_id, document, 3)
    landed = sum(piece.count("```invlang") for piece in pieces[:2])
    (run_dir / "investigation.md").write_text(document, encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text(
        '{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", '
        '"query_id": "elastic.sshd-failed-by-srcip", "params": {}, "payload_status": "ok"}\n',
        encoding="utf-8")
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-doc"
    sibling_dir.mkdir(parents=True, exist_ok=True)

    branch.open_main_session(store, spec_at(store, run_dir, returns[1]), sibling_dir)

    seeded = (sibling_dir / "investigation.md").read_text(encoding="utf-8")
    from defender.skills.invlang.parser import INVLANG_FENCE_RE
    assert len(INVLANG_FENCE_RE.findall(seeded)) == landed, (
        f"the seed holds {len(INVLANG_FENCE_RE.findall(seeded))} fences, not the {landed} "
        "that had landed at the branch point")
    assert document.startswith(seeded), (
        "the seed is not a byte prefix of the source document — a rebuilt document drops the "
        "prose the author wrote between blocks")
    assert len(INVLANG_FENCE_RE.findall(document)) > landed, (
        "the fixture no longer runs on past the branch, so this pins nothing")
    assert "\n" in seeded.strip("\n").replace("```", ""), (
        "the seed carries no prose at all, so the byte-prefix arm above pins nothing")


def test_a_resumed_run_inherits_the_evidence_its_prefix_names(tmp_path):
    """    The sibling gets the source's captured evidence in its OWN run dir, copied not shared.

    The inherited message prefix is full of absolute paths into the run dir that produced it —
    a gather return names `gather_raw/{lead_id}/{seq}.json`, a lead claim names its sidecar —
    and `permission.decide_read` roots the sibling at its own run dir, so every one of them is
    denied to a model reading back its own history. The queries table comes for the mirror
    reason: `validate` refuses a branch whose source captured nothing, so those rows ARE the
    sibling's evidence.

    COPIED, because the sibling appends to both. A link would put the sibling's new rows into
    the source run's own table — corrupting the base of the comparison the branch exists to
    produce."""
    branch = branch_mod()
    document = GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    store, run_dir, session_id, _ = _source_run(tmp_path)
    _pieces, returns = _append_document(store, session_id, document, 3)
    (run_dir / "investigation.md").write_text(document, encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text(
        '{"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", '
        '"query_id": "elastic.sshd-failed-by-srcip", "params": {}, "payload_status": "ok"}\n',
        encoding="utf-8")
    (run_dir / "gather_raw" / "l-001").mkdir(parents=True)
    (run_dir / "gather_raw" / "l-001" / "0.json").write_text('{"hits": []}', encoding="utf-8")
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-evidence"
    sibling_dir.mkdir(parents=True, exist_ok=True)

    branch.open_main_session(store, spec_at(store, run_dir, returns[1]), sibling_dir)

    assert (sibling_dir / "executed_queries.jsonl").read_text(encoding="utf-8") == (
        run_dir / "executed_queries.jsonl").read_text(encoding="utf-8")
    assert (sibling_dir / "gather_raw" / "l-001" / "0.json").is_file(), (
        "the payload sidecar the inherited prefix names is not in the sibling's run dir")
    # Copied, not shared: writing to the sibling's table leaves the source's alone.
    (sibling_dir / "executed_queries.jsonl").write_text("{}\n", encoding="utf-8")
    assert "sshd-failed-by-srcip" in (
        run_dir / "executed_queries.jsonl").read_text(encoding="utf-8")


def test_a_run_dir_holding_evidence_is_refused_before_anything_forks(tmp_path):
    """    A sibling dir that already carries evidence is refused BEFORE the fork, not after.

    `store.fork` commits its own transaction and this module cannot undo one, so a refusal
    raised after it leaves a child session in the SOURCE database with no run behind it — and
    this refusal is the repeatable kind (a retried resume), so every retry would add another.

    An EMPTY `gather_raw/` is not evidence: the run scaffolding creates it for every run before
    a resume reaches this check, so refusing on existence would refuse every branch."""
    ss = store_mod()
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    session_id = ss.main_session_id(store)
    before = len(sql(store, "SELECT session_id FROM session WHERE parent_session_id = ?",
                     (session_id,)))
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-dirty"
    (sibling_dir / "gather_raw" / "l-009").mkdir(parents=True)
    (sibling_dir / "gather_raw" / "l-009" / "0.json").write_text("{}", encoding="utf-8")
    spec = spec_at(store, run_dir, path_ids[-1])

    with pytest.raises(branch.BranchError, match="already holds"):
        branch.open_main_session(store, spec, sibling_dir)

    assert len(sql(store, "SELECT session_id FROM session WHERE parent_session_id = ?",
                   (session_id,))) == before, (
        "the refusal came after the fork — the source store now carries a child session no "
        "run will ever drive, and every retry adds another")


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

    assert branch.seed_investigation(None, None, fresh) == 0
    assert not (fresh / "investigation.md").exists(), (
        "a fresh run's document was created before its first append")


def test_a_reused_run_dir_is_refused_rather_than_seeded_over(tmp_path):
    """    A run dir that already holds a document is refused, not appended to.

    `investigation.md` is append-only and one run's. Seeding a source's prefix onto another
    run's work log would interleave two investigations in the one artifact whose whole contract
    forbids it — and it would pass every later append-only check, because the result only
    grows."""
    branch = branch_mod()
    store, run_dir, session_id, _ = _source_run(tmp_path)
    returns = _fence_turns(store, session_id, [1])
    (run_dir / "investigation.md").write_text(
        GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), encoding="utf-8")
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-used"
    sibling_dir.mkdir(parents=True, exist_ok=True)
    (sibling_dir / "investigation.md").write_text("someone else's work\n", encoding="utf-8")

    with pytest.raises(branch.BranchError, match="already holds"):
        branch.seed_investigation(store, spec_at(store, run_dir, returns[0]), sibling_dir)


def test_a_prefix_that_would_not_validate_is_refused_rather_than_seeded(tmp_path):
    """    A fence-boundary prefix that does not pass invlang validation is refused, even though the
    SOURCE document passes whole.

    The premise this seam rested on — a valid source gives a valid prefix — is false, and not
    by a technicality. `_check_lead_refs` asks whether a cited lead is declared ANYWHERE in the
    document, not whether it was declared first, so a source whose `:R` block cites a lead its
    `:L findings` block declares one fence LATER is well-formed as a whole and `undeclared
    lead` when cut between the two. That is exactly the cut this function makes.

    REFUSED rather than seeded, and refused rather than repaired: the sibling would receive a
    document it did not write, cannot fix — append-only puts the committed bytes out of reach —
    and every subsequent append of which is refused for a fault that is not its own. It is the
    same answer, for the same reason, that the fence-count mismatch above already gives: a seed
    cut wrong is not a seed.

    The third site of #961/#964's class, found by `lint_ungated_artifact_write` on its first
    run rather than by either issue.
    """
    branch = branch_mod()
    store, run_dir, session_id, _ = _source_run(tmp_path)
    returns = _fence_turns(store, session_id, [1, 1, 1])

    from defender.skills.invlang.validate import diagnose
    from defender.tests._invlang_amendment_954 import (
        VERTICES, attr_block, findings_block,
    )
    source_doc = (
        VERTICES
        + attr_block("l-001|v-001|class|server")
        + findings_block("l-001|1|probe|v-001||cmdb|n/a")
    )
    assert [d for d in diagnose(source_doc, None) if d.severity != "warning"] == [], (
        "the fixture's premise: the SOURCE document is well-formed"
    )
    (run_dir / "investigation.md").write_text(source_doc, encoding="utf-8")

    sibling_dir = tmp_path / "defender-runs" / "run-sibling-prefix"
    sibling_dir.mkdir(parents=True, exist_ok=True)

    with pytest.raises(branch.BranchError, match="does not pass validation"):
        branch.seed_investigation(
            store, spec_at(store, run_dir, returns[1]), sibling_dir)

    assert not (sibling_dir / "investigation.md").exists(), (
        "the refusal came after the write — the sibling holds a document it can never repair"
    )


def test_a_prefix_that_validates_is_still_seeded(tmp_path):
    """    POSITIVE CONTROL for the check above: the ordinary source, cut at the same kind of
    boundary, still seeds. Without it an implementation that refused every branch would pass."""
    branch = branch_mod()
    store, run_dir, session_id, _ = _source_run(tmp_path)
    returns = _fence_turns(store, session_id, [1, 1])
    (run_dir / "investigation.md").write_text(
        GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), encoding="utf-8")
    sibling_dir = tmp_path / "defender-runs" / "run-sibling-ok"
    sibling_dir.mkdir(parents=True, exist_ok=True)

    # The fence COUNT is a fixture detail (`_source_run`'s own opening turn carries the whole
    # document, so the branch point maps past it); the claim is that a well-formed prefix is
    # still seeded rather than refused.
    assert branch.seed_investigation(
        store, spec_at(store, run_dir, returns[0]), sibling_dir) > 0
    assert (sibling_dir / "investigation.md").is_file()


def test_message_zero_is_refused_as_a_branch_point(tmp_path):
    """    Message 0 is refused. It precedes every payload the run captured, so both siblings are
    consistent with the prefix by construction and the captured base constrains nothing —
    which is the generated-world design the redesign rejected, reached by branching too early
    rather than by choosing it."""
    # provenance: design §The captured base world ("the base is captured, not authored");
    # the branch point is defined as "when the defender holds a concrete set of payloads".
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError):
        branch.validate(store, dataclasses.replace(
            spec_at(store, run_dir, path_ids[-1]), branch_message_id=0))


def test_a_run_that_captured_no_queries_is_refused(tmp_path):
    """    A source run whose queries table is empty is refused, however far into the conversation
    the branch point sits. "A world consistent with the evidence" is vacuous when there is no
    evidence: every proposed sibling agrees with an empty capture."""
    # provenance: design §The captured base world — "base = executed_queries.jsonl +
    # gather_raw/ from the source run"; claim C14 records the same emptiness one level up.
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), queries=None)

    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(store, run_dir, path_ids[-1]))


def test_a_branch_point_with_an_empty_frontier_is_refused(tmp_path):
    """    A branch point over a document with no invlang blocks is refused even though the run
    captured evidence: an empty frontier is nothing open, so the pair of worlds has no
    question to divide and the episode grades nothing.

    Paired with the capture check above rather than folded into it: an implementation that
    tests only the capture passes that one and fails this, which is the point."""
    # provenance: design M8 ("the invlang frontier at the branch turn, frontier_at, shipped by
    # #919"); frontier.frontier_at answers the empty frontier for a fence-less document.
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(tmp_path, investigation=None)

    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(store, run_dir, path_ids[-1]))


def test_the_frontier_is_read_at_the_branch_point_not_at_the_end_of_the_run(tmp_path):
    """    The same finished run admits a branch point and refuses an earlier one: after its
    `append_block` turn the frontier is open, before it the document had not started and the
    frontier is empty.

    This is the demand that separates reading the frontier AT the branch from reading the
    terminal document. Both arms run against ONE source run whose investigation.md is the
    full golden — so an implementation that derives the frontier from the finished file
    accepts both and fails here, while one that maps the message id onto the fences that had
    landed by then splits them."""
    # provenance: design M8 + `frontier_at`'s own docstring — "a caller holding a message
    # index maps it to a fence itself, because only the run's trace can do that".
    branch = branch_mod()
    document = GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    assert "```invlang" in document, (
        f"{GOLDEN_INVESTIGATION} carries no invlang fence — the fixture moved and both arms "
        "below would be asserting over an empty document")
    store, run_dir, path_ids = _legal_source(tmp_path, investigation=document)

    def at(message_id: int):
        return spec_at(store, run_dir, message_id)

    assert branch.validate(store, at(path_ids[-1])) is None, (
        "a branch point past the run's own append_block was refused; nothing here is left "
        "to accept and the refusals above are vacuous")

    with pytest.raises(branch.BranchError):
        branch.validate(store, at(path_ids[2]))


def test_a_message_that_is_not_on_mains_path_is_refused(tmp_path):
    """    An id past the source run's tip is refused rather than read as "every fence".

    `fence_count_at` scores rows with `row_id <= branch_message_id`, so a number no row of
    MAIN's path carries silently reads as the WHOLE document — and `fork` walks parents from
    whatever id it is handed, so the fault surfaces far away (or not at all) instead of here."""
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError, match="MAIN path"):
        branch.validate(store, dataclasses.replace(
            spec_at(store, run_dir, path_ids[-1]), branch_message_id=path_ids[-1] + 1000))


def test_a_branch_point_mid_tool_pair_is_refused(tmp_path):
    """    A branch point that is a response whose tool call is still unanswered is refused.

    `fork` hides that row from `hydrate(role="send")` — so the FIRST `message_history` looks
    clean — while still making it the child's HEAD. `ingest` then parents the continuation
    prompt onto it, the next `hydrate(role="send")` ends on a `ModelRequest` and therefore
    stops truncating, and the dangling `tool_use` goes on the wire with no matching result.
    Every provider rejects that, so the resumed run dies on its first request with a 400 that
    names nothing about branching.

    `path_ids[3]` is the `append_block` CALL and `path_ids[4]` its return, so the two arms
    below are one message apart: the accepted one is the same branch point, taken at the
    boundary the store's own `_complete_prefix_len` puts it at."""
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError, match="unanswered"):
        branch.validate(store, spec_at(store, run_dir, path_ids[3]))

    assert branch.validate(store, spec_at(store, run_dir, path_ids[4])) is None, (
        "the tool RETURN one row later was refused too, so the arm above is satisfied by a "
        "guard that refuses every branch point rather than by the pair rule")


def test_a_snapped_frontier_is_refused_by_its_own_name(tmp_path):
    """    A branch point whose fence count runs past the document is refused AS SNAPPED.

    `frontier_at` clamps an out-of-range index and answers the TERMINAL frontier — the state
    with everything settled and nothing open — so a `validate` that asks "is anything open?"
    first reports "branched too late" for a run whose real fault is that the message-to-fence
    mapping cannot be trusted at all. The refusal has to name the clamp, or the operator is
    sent to fix the wrong thing.

    The document here holds ONE fence against a session whose appends carry the whole golden,
    which is the shape a truncated or rewritten document leaves behind."""
    ss = store_mod()
    branch = branch_mod()
    store, run_dir, path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))
    session_id = ss.main_session_id(store)
    # A second landed append, carrying no block of its own — the count that over-runs the
    # document comes from `_legal_source`'s first append, which sent the whole golden.
    store.append(session_id, [tool_call_response("append_block", {"text": "..."},
                                                 tool_call_id="ab2")], agent_id="main")
    store.append(session_id, [tool_return_request("append_block", "ok", tool_call_id="ab2")],
                 agent_id="main")
    document = GOLDEN_INVESTIGATION.read_text(encoding="utf-8")
    one_fence = document[: document.index("```", document.index("```invlang") + 10) + 3]
    (run_dir / "investigation.md").write_text(one_fence, encoding="utf-8")
    tip = ss.path_row_ids(store, session_id)[-1]
    assert tip != path_ids[-1], "the two extra rows did not land"

    with pytest.raises(branch.BranchError, match="snapped"):
        branch.validate(store, spec_at(store, run_dir, tip))


# the two named seams

def test_branch_spec_carries_the_four_branch_coordinates():
    """    `BranchSpec` is the whole of what a resume is told: which run to read the capture and
    the document from, which of its messages to fork at, what to say on arrival, and WHEN the
    branch point was.

    `continuation_prompt` is a FIELD rather than something the seam composes because the
    08-16 experiment's own caveat was that its continuation wording biased the run toward
    closing over gathering — the prompt is part of the measured instrument.

    `as_of` joined them in #947 and is required for the mirror reason: it is the moment every
    payload of the episode is stamped and every open window is closed at, so a resume that
    could be spelled without one would stamp the afternoon it happened to run. Its own
    demands — the derivation, and `validate`'s cross-check — are `test_947_clock.py`."""
    # provenance: design M1 — "takes (session, branch_message_id, continuation_prompt, verbs)";
    # `verbs` is the oracle registry and lands with the oracle, not with the runtime half.
    branch = branch_mod()
    names = [f.name for f in dataclasses.fields(branch.BranchSpec)]
    assert names == ["source_run_dir", "branch_message_id", "continuation_prompt", "as_of"], (
        f"BranchSpec's coordinates are not the four the design names: {names}")


def test_the_driver_carries_the_two_resume_seams():
    """    `run_investigation` accepts `resume`, and `_drive_agent` accepts `message_history` — the
    two parameters #920's discussion corrected the issue on ("no driver change is needed is
    wrong; three are").

    A signature check, deliberately: what those parameters DO is driven end-to-end in
    `tests/e2e/test_920_branch_resume.py`, and this exists so a rename fails loudly here
    rather than leaving the e2e file the only thing that names them."""
    # provenance: claim C3 (executed) — "agent.iter(prompt, deps=deps, usage_limits=...) — no
    # message_history"; the discussion's three corrected driver sites.
    driver = importlib.import_module("defender.runtime.driver")
    assert "resume" in inspect.signature(driver.run_investigation).parameters, (
        "run_investigation has no `resume` parameter — a branch has no supported entry point")
    assert "message_history" in inspect.signature(driver._drive_agent).parameters, (
        "_drive_agent cannot be handed an inherited prefix, so a resumed run's first request "
        "starts from an empty framework list and underflows at ingest")
