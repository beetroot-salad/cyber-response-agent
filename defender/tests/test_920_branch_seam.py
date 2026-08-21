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


# ==========================================================================
# the caller contract: fork's seeding and send-role hydration are one number
# ==========================================================================

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


# ==========================================================================
# the store factory: a sibling forks INTO the source run's database
# ==========================================================================

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
    spec = branch.BranchSpec(source_run_dir=run_dir, branch_message_id=path_ids[-1],
                             continuation_prompt="continue")

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
    _store, run_dir, _session_id, path_ids = _source_run(tmp_path)
    factory = branch.store_factory_for(
        branch.BranchSpec(source_run_dir=run_dir, branch_message_id=path_ids[-1],
                          continuation_prompt="continue"))

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


# ==========================================================================
# branch-point legality
# ==========================================================================

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
    store.append(session_id, [tool_call_response("append_block", {"text": "..."},
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


def test_message_zero_is_refused_as_a_branch_point(tmp_path):
    """    Message 0 is refused. It precedes every payload the run captured, so both siblings are
    consistent with the prefix by construction and the captured base constrains nothing —
    which is the generated-world design the redesign rejected, reached by branching too early
    rather than by choosing it."""
    # provenance: design §The captured base world ("the base is captured, not authored");
    # the branch point is defined as "when the defender holds a concrete set of payloads".
    branch = branch_mod()
    store, run_dir, _path_ids = _legal_source(
        tmp_path, investigation=GOLDEN_INVESTIGATION.read_text(encoding="utf-8"))

    with pytest.raises(branch.BranchError):
        branch.validate(store, branch.BranchSpec(
            source_run_dir=run_dir, branch_message_id=0, continuation_prompt="continue"))


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
        branch.validate(store, branch.BranchSpec(
            source_run_dir=run_dir, branch_message_id=path_ids[-1],
            continuation_prompt="continue"))


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
        branch.validate(store, branch.BranchSpec(
            source_run_dir=run_dir, branch_message_id=path_ids[-1],
            continuation_prompt="continue"))


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

    def spec_at(message_id: int):
        return branch.BranchSpec(source_run_dir=run_dir, branch_message_id=message_id,
                                 continuation_prompt="continue")

    assert branch.validate(store, spec_at(path_ids[-1])) is None, (
        "a branch point past the run's own append_block was refused; nothing here is left "
        "to accept and the refusals above are vacuous")

    with pytest.raises(branch.BranchError):
        branch.validate(store, spec_at(path_ids[2]))


# ==========================================================================
# the two named seams
# ==========================================================================

def test_branch_spec_carries_the_three_branch_coordinates():
    """    `BranchSpec` is the whole of what a resume is told: which run to read the capture and
    the document from, which of its messages to fork at, and what to say on arrival.

    `continuation_prompt` is a FIELD rather than something the seam composes because the
    08-16 experiment's own caveat was that its continuation wording biased the run toward
    closing over gathering — the prompt is part of the measured instrument."""
    # provenance: design M1 — "takes (session, branch_message_id, continuation_prompt, verbs)";
    # `verbs` is the oracle registry and lands with the oracle, not with the runtime half.
    branch = branch_mod()
    names = [f.name for f in dataclasses.fields(branch.BranchSpec)]
    assert names == ["source_run_dir", "branch_message_id", "continuation_prompt"], (
        f"BranchSpec's coordinates are not the three the design names: {names}")


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
