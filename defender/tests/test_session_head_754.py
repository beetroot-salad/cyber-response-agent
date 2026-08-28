"""#754 — the recorded head pointer and the head-move log: the WRITE side.

The executable form of the demands in `spec_graph_754.yaml` that bind `head_message_id`,
`session_head_log`, `append`, `reason.domain` and the fold. Each test carries its demand's
observable-outcome prose in its docstring (that docstring is what `check_binds` scans in
place of a demand `outcome`); the ledger ids each rests on sit in a `# provenance:` comment
beneath it, and the design history lives in the frontiers, not here.

**RED AGAINST `1cecad37` IS THE EXPECTED STATE.** `session.head_message_id` does not exist,
`session_head_log` does not exist, `append` takes no `reason`, and `path_row_ids` derives the
path from insertion order. This suite pins the demanded CORRECTION, never today's behaviour —
B1/B2 (executed) measured today's insertion-order path and PR-24 (executed) measured `ingest`
duplicating all N messages of an inherited prefix; both are the defect, not the contract.

The three rules the whole file turns on, since two of them are counter-intuitive:

  * **When a head move is recorded.** The log is written iff the move is NON-LINEAR **or** an
    explicit `reason` was supplied. A degenerate fold — root already equal to head — is linear
    and still logs, because the caller minted a frontier and said why. An append into a
    session that holds rows but whose head is NULL RAISES rather than silently orphaning them.
  * **Who may supply a reason.** Membership is validated by exact match whenever `reason` is
    not None, before the linearity classification and before the empty-batch short-circuit. On
    a NON-linear move any caller may supply one; on a LINEAR move only a caller minting a
    frontier row (`synthesized=True`) may, and every other caller is refused. `'fork'` has no
    legitimate caller through `append` at all, because `fork()` writes its own entry.
  * **What the log records.** Six columns. `from_message_id` is the DISPLACED head and
    `attached_to_message_id` is the first inserted row's own parent; they are different
    questions and a multi-message non-linear append answers both differently.

Two ledger refutations govern what must NOT be asserted here: PR-6 refuted the `IndexError`
premise behind P95 (the fold path already reads `root = ids[0] if ids else None`), and
PR-16/PR-21/PR-19 refuted the premises that a live run folds and that the judge or the
learning loop reads the log. No test below asserts any of them.
"""
from __future__ import annotations

import inspect

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests._session_head_754 import (  # noqa: E402
    DELIBERATE,
    NotSerializable,
    head_of,
    linear_turns,
    log_rows,
    message_ids,
    raised_by,
)
from defender.tests._session_store_705 import (  # noqa: E402
    complete_pair,
    make_store,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    user_request,
)


# #0 — the signal contract

def test_head_move_signal_contract(tmp_path):
    """    The head-move surface is exactly this: `append` takes a keyword `reason` drawn from the
    module-level closed set `HEAD_MOVE_REASONS`, naming fork and fold; every head move lands
    in `session.head_message_id`; every recorded move lands in `session_head_log`; and three
    module-level readers project the log — `displaced_tip(store, session_id)` returning the
    MOST RECENT fold's displaced tip, `fold_history(store, session_id)` returning every fold's
    displaced tip in head-move order with `displaced_tip` as its last element, and
    `branch_point(store, session_id)` returning the session's branch point. All three answer
    `None` (or the empty history) for a session with no matching entry AND for a session_id
    that does not exist, rather than raising.

    "Most recent" alone would make the FIRST fold's displaced tip unreachable through the
    helper, which is the addressability the log exists to provide, so the ordered accessor
    sits beside it. Nothing here projects an off-path id to its message CONTENT:
    `session/agent#seq` translation is the caller's own `message`-row lookup, out of scope."""
    # provenance: demand #0, FK-A(a)-(d). PR-21/PR-19 (censuses): these readers have no
    # consumer anywhere, on either side of this change, so the test drives them directly and
    # asserts nothing about a consumer.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)

    assert ss.HEAD_MOVE_REASONS == ("fork", "fold"), (
        "the closed set is a module-level constant naming exactly the two reasons")

    main = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, main, 3)
    assert head_of(store, main) == r3
    f1 = sel.fold(store, main, agent_id="main", boundary=3)
    r4 = store.append(main, [text_response("after the fold")], agent_id="main")[0]
    f2 = sel.fold(store, main, agent_id="main", boundary=4)

    assert ss.displaced_tip(store, main) == r4, "the MOST RECENT fold's displaced tip"
    assert ss.fold_history(store, main) == [r3, r4], "every fold's tip, in head-move order"
    assert ss.fold_history(store, main)[-1] == ss.displaced_tip(store, main)
    assert head_of(store, main) == f2
    assert ss.path_row_ids(store, main) == [r1, f2], (
        "the reader projects the path from the recorded head")
    assert f1 != f2

    fork = store.fork(main, at_message_id=f1)
    assert ss.branch_point(store, fork) == f1
    assert ss.displaced_tip(store, fork) is None, "no fold of its own yet"

    empty = store.new_session(agent_id="main")
    for absent in (empty, "no-such-session-id"):
        assert ss.displaced_tip(store, absent) is None
        assert ss.branch_point(store, absent) is None
        assert ss.fold_history(store, absent) == []


# the path reads from head

def test_path_follows_head_not_insertion_order(tmp_path):
    """    The path a reader projects is the parent walk from the session's RECORDED head, not from
    the highest-id row the session happens to hold: a fork whose head was set to an ancestor
    reads back as the prefix ending at that ancestor — neither the empty path insertion order
    gives it (it owns no rows at all) nor the parent's full path — and it stays that prefix
    while the parent keeps appending.

    The assertion is about the anchor rather than the tip because that is where the two
    disagree: with the path derived from insertion order, an append parented off the tip
    evicted a turn from the conversation, and a higher-id append after a fold silently UNDID
    the fold."""
    # provenance: B1/B2 (executed) measured both defects; F5/B13 established the off-path
    # append has a live production shape (a gather leg's row landing in the main session).
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, main, 3)

    fork = store.fork(main, at_message_id=r1)
    assert head_of(store, fork) == r1, "fork records the branch point as the fork's head"
    assert message_ids(store, fork) == [], (
        "the fixture must give the fork no rows of its own, or insertion order and head "
        "cannot disagree")
    assert ss.path_row_ids(store, fork) == [r1], (
        "the walk starts from the recorded head — not [] (insertion order over the fork's "
        "own rows) and not the parent's [r1, r2, r3]")

    r4 = store.append(main, [text_response("the parent moves on")], agent_id="main")[0]
    assert ss.path_row_ids(store, main) == [r1, r2, r3, r4]
    assert ss.path_row_ids(store, fork) == [r1], (
        "the fork's path is anchored to a recorded value, never re-derived from the tree")

    f1 = store.append(fork, [text_response("the fork's own first")], agent_id="main")[0]
    assert ss.path_row_ids(store, fork) == [r1, f1]
    assert ss.path_row_ids(store, main) == [r1, r2, r3, r4], (
        "the fork's higher-id row must not join the parent's path")


def test_path_row_ids_is_empty_when_head_is_null(tmp_path):
    """    A session whose `head_message_id` is SQL NULL reads as an empty path even when the
    session still holds rows: the reader has no `ORDER BY id DESC LIMIT 1` fallback left with
    which to re-derive a tip, so the rows are unreachable rather than silently re-attached.

    The rows-but-no-head state is built with a raw UPDATE because the WRITE side of the same
    state is an error rather than a silent orphaning; this is the READ contract, and it is
    unchanged by that. The positive control is the same reader over the same rows once head
    names one of them, so "empty" is never satisfiable by a reader that returns nothing."""
    # provenance: P116; the write side is `an_append_into_a_rows_but_null_head_session_raises`.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)

    store.connection.execute(
        "UPDATE session SET head_message_id = NULL WHERE session_id = ?", (session_id,))
    assert head_of(store, session_id) is None
    assert message_ids(store, session_id) == [r1, r2], "the rows are still there"

    assert ss.path_row_ids(store, session_id) == [], (
        "with no head there is no tip to walk from, and no fallback that invents one")
    assert ss.hydrate(store, session_id, role="analysis") == []

    store.connection.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?", (r2, session_id))
    assert ss.path_row_ids(store, session_id) == [r1, r2], (
        "positive control: the identical reader over the identical rows returns them once "
        "head names one")


def test_session_head_is_a_column_read_with_no_fork_fallback(tmp_path):
    """    The implicit append parent is a read of `session.head_message_id`: a fork's head is
    already set when the fork is constructed, so its first append parents onto it with no
    `fork_at_message_id` column left to consult, and its SECOND append parents onto the row
    the first one moved head to rather than onto the branch point again. An explicit parent
    still wins over the column.

    That second append is what makes the column read observable: a fallback consulted once
    per fork session and a live head column agree on the first append and disagree on every
    one after it."""
    # provenance: R5 substitute for the removed `_session_tip`. C1 (census): the removed
    # column had no live reader outside it. B4 (executed) measured the once-per-session read.
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)

    fork = store.fork(main, at_message_id=r1)
    assert head_of(store, fork) == r1
    f1 = store.append(fork, [text_response("first")], agent_id="main")[0]
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (f1,)) == [(r1,)]
    f2 = store.append(fork, [text_response("second")], agent_id="main")[0]
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (f2,)) == [(f1,)], (
        "the second append reads the moved head, not the branch point a second time")
    assert ss.path_row_ids(store, fork) == [r1, f1, f2]

    # an explicit parent still wins over the column — with a reason, since naming a row
    # that is not head is a non-linear move under the rule
    off = store.append(main, [text_response("explicit wins")], agent_id="main",
                       parent_id=r1, reason="fold")[0]
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (off,)) == [(r1,)], (
        f"the explicit parent must win over head ({r2}), or the caller cannot re-parent")
    assert head_of(store, main) == off


# the fold

def test_fold_moves_head_to_frontier_and_logs_fold(tmp_path):
    """    A fold moves the session's head to the frontier row it mints and leaves exactly ONE
    `session_head_log` entry behind: `from_message_id` the tip the fold displaced,
    `to_message_id` the frontier, `attached_to_message_id` the row the frontier parented
    onto, and the reason `fold`. The path afterwards is the lineage root plus the frontier.

    Exactly one row per fold holds without exception, including the degenerate fold whose
    root already IS head."""
    # provenance: issue obligation 2.
    # rejected: the call site does not decide to log. `_fold_impl` issues no INSERT into
    # session_head_log at all — the entry appears because `append` applied the rule to the
    # parent and the reason it was handed (test_the_store_writes_the_log_not_its_call_sites).
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)
    assert log_rows(store, session_id) == [], "no ordinary turn logged anything"

    frontier = sel.fold(store, session_id, agent_id="main", boundary=3)

    assert head_of(store, session_id) == frontier, "the fold moves head to the frontier"
    entries = log_rows(store, session_id)
    assert len(entries) == 1, f"exactly one entry per fold; got {entries}"
    entry = entries[0]
    assert entry.from_message_id == r3, "the displaced tip"
    assert entry.to_message_id == frontier, "the new head"
    assert entry.attached_to_message_id == r1, "the row the frontier parented onto"
    assert entry.reason == "fold"
    assert ss.path_row_ids(store, session_id) == [r1, frontier]
    assert r2 not in ss.path_row_ids(store, session_id), "the folded turn is off-path"


def test_consecutive_folds_chain_their_log_entries(tmp_path):
    """    Two folds with no ordinary turn between them leave two entries that chain: the first
    displaces the original tip onto frontier one, the second displaces frontier one onto
    frontier two, and each states what IT alone displaced. That is what makes "walk
    `parent_id` back from the second entry's `from_message_id`" a real reconstruction rather
    than a guess.

    This is also the positive control for the log's append-only property: every subsequent
    head move ADDS a row alongside the ones already there."""
    # provenance: P100 + P77.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)

    first = sel.fold(store, session_id, agent_id="main", boundary=3)
    second = sel.fold(store, session_id, agent_id="main", boundary=4)

    entries = log_rows(store, session_id)
    assert [(e.from_message_id, e.to_message_id, e.reason) for e in entries] == [
        (r3, first, "fold"), (first, second, "fold")], entries
    assert head_of(store, session_id) == second
    # the reconstruction P77 names: walk back from the second entry's displaced tip
    assert ss._walk_parents(store.connection, entries[1].from_message_id)[-1] == r1
    assert r2 in ss._walk_parents(store.connection, entries[0].from_message_id), (
        "the first entry's displaced tip still reaches the turns the fold cut")


def test_fold_reuse_leaves_head_and_the_log_untouched(tmp_path):
    """    A second fold at a boundary that already holds a frontier returns the existing frontier
    row: no new `message` row, head unchanged, and the log gains no second entry.

    The reuse branch returns BEFORE any append, so no reason is ever supplied on that path
    and the rule's reason arm cannot fire — which is why this is the one legitimate no-log
    fold, and why it survives a trigger that records every reason-bearing move."""
    # provenance: P97, raised from claim c18 (read) rather than from the doc.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 3)

    frontier = sel.fold(store, session_id, agent_id="main", boundary=3)
    head_after_fold = head_of(store, session_id)
    log_after_fold = log_rows(store, session_id)
    rows_after_fold = sql(store, "SELECT COUNT(*) FROM message")

    for _ in range(3):
        assert sel.fold(store, session_id, agent_id="main", boundary=3) == frontier, (
            "the frontier for one boundary is reused, not re-minted")

    assert head_of(store, session_id) == head_after_fold, "reuse moves no head"
    assert log_rows(store, session_id) == log_after_fold, "reuse logs nothing"
    assert len(log_after_fold) == 1, "the control: the FIRST fold did log"
    assert sql(store, "SELECT COUNT(*) FROM message") == rows_after_fold


def test_the_fold_reuse_lookup_is_scoped_by_session_and_agent(tmp_path):
    """    Two folds at one boundary under DIFFERENT `agent_id`s miss each other's reuse lookup:
    each mints its own frontier and its own non-linear head move with its own log entry, so
    one session ends up holding two live "boundary N" frontiers and head lands on whichever
    ran last. A fork cannot reach the same shape from the other direction: its fold is
    refused, because the row its frontier would parent onto belongs to the parent session.

    The reuse key is scoped by session and agent and is not changed here, so the two-frontier
    shape is the behaviour this pins — not the behaviour it endorses. Nobody has decided it
    is wanted."""
    # provenance: P98 + P106, grounded in PR-23 (executed): `(session_id, agent_id,
    # synthesized)` scopes `_next_seq` cleanly and a synthesized row at seq 0 coexists with an
    # ordinary seq-0 row, so the two frontiers can and do coexist. P106's premise is what the
    # two-agent arm observes; its two-frontiers-per-lineage consequence is closed by the
    # cross-session fold refusal rather than by the key.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)

    mine = sel.fold(store, session_id, agent_id="main", boundary=3)
    theirs = sel.fold(store, session_id, agent_id="gather-l1", boundary=3)

    assert theirs != mine, "a different agent_id misses the reuse lookup"
    frontiers = sql(store, "SELECT id, agent_id, seq FROM message WHERE synthesized = 1 "
                           "AND session_id = ? ORDER BY id", (session_id,))
    assert frontiers == [(mine, "main", 3), (theirs, "gather-l1", 3)], frontiers
    assert head_of(store, session_id) == theirs, "head lands on whichever ran last"
    assert [(e.from_message_id, e.to_message_id, e.reason)
            for e in log_rows(store, session_id)] == [
        (r3, mine, "fold"), (mine, theirs, "fold")], "each move logged once"

    fork = store.fork(session_id, at_message_id=theirs)
    store.append(fork, [text_response("the fork's own turn")], agent_id="main")
    assert sel.path_row_ids(store, fork)[0] not in message_ids(store, fork), (
        "the fixture must put the fork's lineage root in the PARENT's session, or V4's "
        "refusal is not what is being observed")

    refused = raised_by(sel.fold, store, fork, agent_id="main", boundary=3)

    assert refused is not None, (
        "the fold would have parented the fork's frontier onto another session's row")
    assert not isinstance(refused, DELIBERATE), f"{refused!r}"
    assert sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ? AND synthesized = 1",
               (fork,)) == [(0,)], "the refused fold minted no frontier"
    assert [e.reason for e in log_rows(store, fork)] == ["fork"], (
        "and recorded nothing beyond the entry fork() itself wrote")
    assert r2 not in (mine, theirs)


def test_a_degenerate_fold_still_writes_its_log_entry(tmp_path):
    """    Folding a session whose path is a single row — so the frontier's parent already IS the
    session's head and the move is LINEAR — still writes its `fold` entry, because the caller
    minted a frontier row and said why.

    The exemption is the frontier-minting caller's, not every reason-bearer's, and this test
    carries both controls that make that observable: the SAME linear move carrying the SAME
    reason from an ordinary caller is REFUSED, and the same move with no reason writes
    nothing. Without the first control, "anything carrying a reason gets logged" would pass."""
    # provenance: P94 (a one-row path folds with root == head) and P96 (the same shape by
    # another route); P85 measured the cost of leaving it unlogged — a consumer walking the
    # log to reconstruct the run's compaction history does not see the fold at all.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    (r1,) = linear_turns(store, session_id, 1)
    assert head_of(store, session_id) == r1
    assert log_rows(store, session_id) == []

    frontier = sel.fold(store, session_id, agent_id="main", boundary=1)

    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (frontier,)) == [(r1,)], (
        "the fixture must be the degenerate shape: the frontier parents onto head itself")
    entries = log_rows(store, session_id)
    assert len(entries) == 1, f"the degenerate fold must record its move; got {entries}"
    assert (entries[0].from_message_id, entries[0].to_message_id) == (r1, frontier)
    assert entries[0].reason == "fold"
    assert head_of(store, session_id) == frontier

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("an ordinary turn, but explained")],
                     agent_id="main", reason="fold")
    assert len(log_rows(store, session_id)) == 1, (
        "control: the identical linear move from an ordinary caller is REFUSED, so the "
        "exemption is the frontier-minting caller's and not every reason-bearer's")

    control = store.append(session_id, [text_response("an ordinary turn")], agent_id="main")[0]
    assert head_of(store, session_id) == control
    assert len(log_rows(store, session_id)) == 1, (
        "control: a linear move carrying NO reason still writes nothing")


# the non-linearity rule

def test_a_linear_turn_writes_no_log_entry(tmp_path):
    """    An ordinary turn — the first inserted row parenting onto the session's own current head,
    with no reason supplied — writes no `session_head_log` row, whichever writer issues it:
    the renderer's ingest path, a fold's reuse return, a fresh fork's first append, and a
    gather leg's session all leave the log exactly as they found it.

    Bound to every writer that could reach the log so the negative is not silently scoped to
    the one someone thought of. The test supplies no reason at all: a linear move that DOES
    carry one is either a frontier-minting call (and is recorded) or refused, both visible
    events rather than an absent row. The positive control is the same channel under the
    complementary condition — one non-linear append into each session DOES produce exactly
    one row — so an empty log is never mistaken for a blind observation channel."""
    # provenance: issue obligation 6; P63 (a sibling child appended into the parent session
    # after a fork is linear against the parent's own head and adds nothing).
    sel = selection_mod()
    store = make_store(tmp_path)

    ingested = store.new_session(agent_id="main")
    live = [user_request("orientation"), *complete_pair()]
    sel.ingest(store, ingested, live, agent_id="main")
    sel.render(store, ingested, live, agent_id="main", fold=False)
    assert log_rows(store, ingested) == [], "ingest's linear appends log nothing"

    r1 = message_ids(store, ingested)[0]
    fork = store.fork(ingested, at_message_id=r1)
    fork_entries = log_rows(store, fork)
    store.append(fork, [text_response("the fork's first turn")], agent_id="main")
    assert log_rows(store, fork) == fork_entries, (
        "the fork's first append is linear against the head fork() set, and adds nothing")

    # the gather leg, as `gather_dispatch` builds it: its own session row, then ingest
    leg = store.new_session(agent_id="gather-l1")
    sel.ingest(store, leg, [user_request("lead brief"), text_response("lead summarised")],
               agent_id="gather-l1")
    assert log_rows(store, leg) == [], "a leg's linear turns log nothing either"

    for session_id, agent_id in ((ingested, "main"), (fork, "main"), (leg, "gather-l1")):
        before = len(log_rows(store, session_id))
        path = sel.path_row_ids(store, session_id)
        assert len(path) > 1, (
            f"every control here must be a genuinely NON-linear move: a reason on a LINEAR move "
            f"from an ordinary caller is refused — got {path}")
        store.append(session_id, [text_response("a recorded move")], agent_id=agent_id,
                     parent_id=path[0], reason="fold")
        assert len(log_rows(store, session_id)) == before + 1, (
            f"positive control: the same channel on {session_id} DOES see a non-linear move")


def test_first_append_into_a_fresh_session_is_linear(tmp_path):
    """    The first append into a session that holds no rows and whose head is SQL NULL is LINEAR:
    it requires no reason, writes no log row, and moves head onto the row it inserted.

    This is also the control that keeps the rows-but-NULL-head refusal from over-reaching. A
    NULL head with ROWS is an error and a NULL head with NO rows is the ordinary first turn;
    the two states differ ONLY in whether the session already holds rows, so the refusal has
    to be written against that predicate and the pair has to be tested together."""
    # provenance: P116 + P52 — rule case 1, previous head NULL and the first row's parent NULL.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    assert head_of(store, session_id) is None, "a fresh session starts with no head"
    assert message_ids(store, session_id) == []

    first = store.append(session_id, [user_request("the first turn")], agent_id="main")[0]

    assert head_of(store, session_id) == first
    assert log_rows(store, session_id) == [], "rule case 1 is linear: nothing to record"
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (first,)) == [(None,)]
    assert ss.path_row_ids(store, session_id) == [first]


def test_an_append_into_a_rows_but_null_head_session_raises(tmp_path):
    """    An append into a session that holds rows but whose `head_message_id` is SQL NULL is
    REFUSED: the caller gets a `StoreAppendError`, no message row lands, head stays NULL and
    the log stays untouched — rather than the row being accepted as a linear first turn and
    every pre-existing row silently orphaned with no recorded reason.

    Silent orphaning is the one outcome the design's own principle forbids: reachable lineage
    may be derived, unreachable lineage must be recorded. The raise is written against "the
    session holds rows", so the same test drives the fresh, no-rows session as its control
    and shows it stays legal."""
    # provenance: P55, promoted out of consensus — all three answering copies converged on the
    # old mechanism correctly and none flagged that it contradicts that principle.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)
    store.connection.execute(
        "UPDATE session SET head_message_id = NULL WHERE session_id = ?", (session_id,))

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("would orphan r1 and r2")], agent_id="main")

    assert message_ids(store, session_id) == [r1, r2], "nothing new landed"
    assert head_of(store, session_id) is None, "head did not move"
    assert log_rows(store, session_id) == []

    control = store.new_session(agent_id="main")
    accepted = store.append(control, [user_request("ordinary first turn")], agent_id="main")[0]
    assert head_of(store, control) == accepted, (
        "control: a NULL head with NO rows is the ordinary first turn and stays legal")


def test_an_unexplained_non_linear_append_raises_and_writes_nothing(tmp_path):
    """    An append whose first row parents onto a row that is not the session's current head, with
    no reason supplied, is refused on all three surfaces at once: the caller gets a
    `StoreAppendError`, no message row survives, head is unmoved and no log row is written.
    Supplying a reason from the closed set is what makes the same move legal."""
    # provenance: issue obligation 7.
    # rejected: FK-K, accepted and DOCUMENTED rather than fixed — a retried IDENTICAL append
    # genuinely IS non-linear the second time, because head has already advanced to the row
    # the first call inserted, so its unchanged explicit parent_id no longer equals the new
    # previous head. `ingest` threads each new id as the next parent, so a retried ingest
    # append — the shape an at-least-once dispatch or a timeout produces — hits exactly this
    # and gets StoreAppendError on a call the caller believes is a harmless retry. That is
    # the rule working, not a bug: no dedup key is added, because the design deliberately
    # does not have one, and the error is legible here so a caller that meets it can read it.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("off head, unexplained")],
                     agent_id="main", parent_id=r1)

    assert message_ids(store, session_id) == [r1, r2, r3], "the refusal left no row"
    assert head_of(store, session_id) == r3, "head is unmoved"
    assert log_rows(store, session_id) == [], "and nothing was recorded"

    explained = store.append(session_id, [text_response("off head, explained")],
                             agent_id="main", parent_id=r1, reason="fold")[0]
    assert head_of(store, session_id) == explained, (
        "control: the identical move with a reason from the closed set is legal")
    assert len(log_rows(store, session_id)) == 1

    # FK-K's shape, driven: the identical call issued twice raises the second time
    payload = [text_response("an at-least-once retry")]
    store.append(session_id, payload, agent_id="main", parent_id=explained)
    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, payload, agent_id="main", parent_id=explained)


def test_a_multi_message_non_linear_append_writes_exactly_one_log_entry(tmp_path):
    """    A multi-message batch whose FIRST row parents off head is one non-linear move: every
    message in the batch lands, head moves to the LAST inserted id, and exactly ONE log row
    is written — `from_message_id` the previous head, `to_message_id` that new head, and
    `attached_to_message_id` the first inserted row's own parent. All three are different
    ids, which is the whole point of the third column.

    `from_message_id` is the DISPLACED head and reads misleadingly as the attachment point;
    the third column is what makes that misreading unavailable rather than merely wrong."""
    # provenance: P50 (the rule inspects only the first row's parent); FK-J minted
    # attached_to_message_id after one of three answering copies read from_message_id as the
    # attachment point and was wrong against the schema.
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)

    batch = [user_request("graft"), *complete_pair()]
    landed = store.append(session_id, batch, agent_id="main", parent_id=r1, reason="fold")

    assert len(landed) == 3, f"every message in the batch lands; got {landed}"
    assert head_of(store, session_id) == landed[-1], "head moves to the LAST inserted id"
    entries = log_rows(store, session_id)
    assert len(entries) == 1, f"the rule inspects only the first row; got {entries}"
    entry = entries[0]
    assert entry.from_message_id == r3, "the displaced head"
    assert entry.to_message_id == landed[-1], "the new head"
    assert entry.attached_to_message_id == r1, "the first inserted row's own parent"
    assert len({entry.from_message_id, entry.to_message_id,
                entry.attached_to_message_id}) == 3, (
        f"the fixture must make all three differ, or the misreading reads as correct: {entry}")
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (landed[0],)) == [(r1,)]
    assert r2 not in (entry.from_message_id, entry.attached_to_message_id)


def test_an_ingest_that_fails_partway_leaves_head_on_the_last_committed_message(tmp_path):
    """    When the third message of an ingested turn cannot be stored, messages one and two are
    already durable, head is parked on message two, message three leaves no trace, the log is
    untouched, and the next render sees the conversation through message two only.

    Each per-message append is its own transaction and each is linear, so head advances
    stepwise and durably, once per committed call. The failure is real and induced in the
    test — the third message is an object the REAL serializer refuses — so no exception class
    is authored here and the taxonomy assumption ceases to exist rather than being pinned."""
    # provenance: P52 + P53; the fault object cites B8 (executed).
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    live = [user_request("one"), text_response("two"), NotSerializable()]
    failure = raised_by(sel.ingest, store, session_id, live, agent_id="main")

    assert failure is not None, "the third message must really fail to store"
    landed = message_ids(store, session_id)
    assert len(landed) == 2, f"messages one and two are durable, three is not; got {landed}"
    assert head_of(store, session_id) == landed[-1], "head is parked on message two"
    assert log_rows(store, session_id) == [], "every committed append was linear"
    assert len(ss.hydrate(store, session_id, role="analysis")) == 2, (
        "the next render sees the conversation through message two only")
    assert store.connection.in_transaction is False


def test_one_round_of_ingest_then_fold_contributes_exactly_one_log_row(tmp_path):
    """    One round that ingests a turn and then folds moves head TWICE — first onto the ingest
    tail's tip, then onto the frontier — and contributes exactly ONE log row, from the fold.

    The two moves are observed as two rather than inferred: head is read after the ingest and
    again after the fold, and the single entry's `from_message_id` is the tip the ingest had
    just established."""
    # provenance: P54.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    ingested = sel.ingest(store, session_id, [user_request("orientation"), text_response("a")],
                          agent_id="main")
    after_ingest = head_of(store, session_id)
    assert after_ingest == ingested[-1]
    assert log_rows(store, session_id) == []

    frontier = sel.fold(store, session_id, agent_id="main", boundary=2)

    assert head_of(store, session_id) == frontier != after_ingest, "head moved twice"
    entries = log_rows(store, session_id)
    assert len(entries) == 1, f"the round contributes exactly one row; got {entries}"
    assert (entries[0].from_message_id, entries[0].reason) == (after_ingest, "fold")


def test_the_store_writes_the_log_not_its_call_sites(tmp_path):
    """    A bare `store.append` naming a parent that is not head and handing over a reason produces
    the log entry on its own, with no fold machinery anywhere in the call: the rule lives
    inside `append`, so neither the fold path nor `ingest` has to know the log exists.

    The observable that separates the two designs: the row appears with no synthesized
    frontier row in the store at all, and the entry's reason is the one the caller handed
    over rather than one the call site chose."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)

    landed = store.append(session_id, [text_response("hand-rolled fold")], agent_id="main",
                          parent_id=r1, reason="fold")[0]

    entries = log_rows(store, session_id)
    assert len(entries) == 1, f"append wrote the entry itself; got {entries}"
    assert (entries[0].from_message_id, entries[0].to_message_id) == (r2, landed)
    assert entries[0].reason == "fold"
    assert sql(store, "SELECT COUNT(*) FROM message WHERE synthesized = 1") == [(0,)], (
        "no fold machinery ran: there is no frontier row in the store")
    assert head_of(store, session_id) == landed


def test_append_accepts_reason_as_a_keyword(tmp_path):
    """    `reason` is a keyword-only argument with a `None` default, so every call site that
    predates it keeps working unchanged — including the full existing coordinate set — and
    only a caller that means to record a head move passes it.

    The seam is not "a member reason is accepted whenever it is a member". On a NON-linear
    move any caller may hand one over; on a LINEAR move only a caller minting a frontier row
    may, and both sides are driven here rather than leaving the accepting half to imply the
    rest. A non-string reason reaches the membership check rather than being rejected at the
    call boundary, so the check owes a semantic refusal of its own rather than leaking a
    container's `TypeError`."""
    # provenance: PR-5 (executed) — no pydantic validate_call, no typeguard and no runtime
    # decorator anywhere in the store, so the `str | None` annotation is unenforced.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    plain = store.append(session_id, [user_request("no reason at all")], agent_id="main")
    assert len(plain) == 1, "the pre-existing call shape still works"

    full = store.append(session_id, [tool_call_response(tool_call_id="c1")],
                        agent_id="main", parent_id=plain[0], synthesized=False, seq=1,
                        run_step=3, duration_ms=12.5, wire_sha="abc")
    assert len(full) == 1, "#705's full coordinate set is unchanged"

    signature = inspect.signature(store.append)
    assert signature.parameters["reason"].kind is inspect.Parameter.KEYWORD_ONLY
    assert signature.parameters["reason"].default is None, (
        "None is the absent sentinel; `is not None` is what tests it, never `if reason:`")

    recorded = store.append(session_id, [text_response("recorded")], agent_id="main",
                            parent_id=plain[0], reason="fold")
    assert len(log_rows(store, session_id)) == 1
    assert head_of(store, session_id) == recorded[0]

    refused = raised_by(store.append, session_id, [text_response("x")], agent_id="main",
                        reason=123)
    assert isinstance(refused, ss.StoreAppendError), (
        f"a non-string reason must get the store's own semantic refusal; got {refused!r}")

    # the seam's discriminator: on a LINEAR move the same member reason turns on the caller
    linear = raised_by(store.append, session_id, [text_response("ordinary turn")],
                       agent_id="main", reason="fold")
    assert isinstance(linear, ss.StoreAppendError), (
        f"an ordinary caller may not hand a reason to a linear move; got {linear!r}")
    minted = store.append(session_id, [user_request("FRONTIER: boundary 9")], agent_id="main",
                          synthesized=True, seq=9, reason="fold")
    assert head_of(store, session_id) == minted[0], (
        "control: the identical linear move from a frontier-minting caller is accepted")
    assert len(log_rows(store, session_id)) == 2


def test_reason_membership_is_validated_before_linearity_classification(tmp_path):
    """    `reason` membership is checked by exact match whenever it is not None, before the move's
    linearity is classified: `'rewind'`, `'Fork'`, `''` and a non-string `123` all raise
    `StoreAppendError` on a LINEAR move and on a NON-LINEAR one alike, and each refusal
    leaves no message row, no head move and no log entry.

    The linear arm is what discriminates: with validation running only inside the non-linear
    branch, a linear append would silently IGNORE a meaningless reason. `''` and `123` are
    the discriminating values because the annotation is unenforced and `is not None` — never
    `if reason:` — is what the absent sentinel requires. Membership is not checked against
    the move's SHAPE: the store cannot tell a compaction from a rewind."""
    # provenance: FK-C's single unconditional rule, replacing seven doc-silent cases; PR-5
    # (executed) for the two discriminating values.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)
    before = message_ids(store, session_id)

    for bad in ("rewind", "Fork", "", 123):
        for parent, arm in ((r2, "linear"), (r1, "non-linear")):
            with pytest.raises(ss.StoreAppendError):
                store.append(session_id, [text_response(f"{bad!r} on a {arm} move")],
                             agent_id="main", parent_id=parent, reason=bad)
    assert message_ids(store, session_id) == before, "no refusal left a row behind"
    assert head_of(store, session_id) == r2, "and none moved head"
    assert log_rows(store, session_id) == []

    accepted = store.append(session_id, [text_response("fold is a member")],
                            agent_id="main", parent_id=r1, reason="fold")[0]
    assert head_of(store, session_id) == accepted, (
        "control: an exact member is accepted on the same channel")
    assert [e.reason for e in log_rows(store, session_id)] == ["fold"]
    # `fork` is a member too, and is refused here for a DIFFERENT reason: it has no caller
    # through `append` at all. That is why the membership control uses `fold` — this demand is
    # about membership, not about who may write a fork entry.
    assert "fork" in ss.HEAD_MOVE_REASONS


def test_an_empty_batch_with_a_reason_validates_before_the_short_circuit(tmp_path):
    """    An append of an EMPTY message list validates its reason before short-circuiting: an
    out-of-set reason raises `StoreAppendError` even though no row would have been written,
    while a valid reason returns the empty id list, moves no head and writes no log row —
    there is no move to record.

    The short-circuit returns before any row exists to classify, so the linearity rule has
    nothing to inspect; validating first means the caller learns immediately that it passed a
    meaningless or out-of-set argument instead of getting a silent no-op."""
    # provenance: P39.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    (r1,) = linear_turns(store, session_id, 1)

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [], agent_id="main", reason="rewind")

    assert store.append(session_id, [], agent_id="main", reason="fold") == []
    assert store.append(session_id, [], agent_id="main") == []
    assert head_of(store, session_id) == r1, "no move happened, so head did not move"
    assert log_rows(store, session_id) == [], "and nothing was recorded"
    assert message_ids(store, session_id) == [r1]


# who may hand `append` a reason at all

def test_a_reason_on_a_linear_move_is_refused_unless_the_caller_mints_a_frontier(tmp_path):
    """    A member reason handed to a LINEAR move is accepted only from a caller minting a frontier
    row and REFUSED from any other: the fold's own append is exempted by the `synthesized`
    flag it already carries, an ordinary turn handing over the same reason gets a
    `StoreAppendError` with nothing written, and a NON-linear move still requires and accepts
    a reason from any caller at all.

    The discriminator has to be a property of the ROW being inserted rather than of the
    caller's identity, which the store has no way to check: a bare caller reaching the
    exemption must flag its row synthesized, which moves it into the synthesized keyspace the
    message identity already keys on and the reader surface projects as a frontier. The three
    arms are the whole rule — a spurious reason on an ordinary turn is a refusal rather than
    a silently-written log row, the degenerate fold still records, and obligation 7's
    requirement that a non-linear move carry a reason is untouched."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("ordinary turn, spurious reason")],
                     agent_id="main", reason="fold")
    assert message_ids(store, session_id) == [r1, r2], "the refusal left no row"
    assert head_of(store, session_id) == r2, "and moved no head"
    assert log_rows(store, session_id) == [], "and wrote nothing"

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("explicitly onto head, same reason")],
                     agent_id="main", parent_id=r2, reason="fold")
    assert log_rows(store, session_id) == [], (
        "naming head explicitly is the same linear move and gets the same refusal")

    frontier = store.append(session_id, [user_request("FRONTIER: boundary 2")],
                            agent_id="main", synthesized=True, seq=2, reason="fold")[0]
    assert head_of(store, session_id) == frontier
    assert [(e.from_message_id, e.to_message_id, e.reason)
            for e in log_rows(store, session_id)] == [(r2, frontier, "fold")], (
        "control: the identical linear move from a frontier-minting caller is accepted and "
        "recorded — that is the degenerate fold's exemption, made explicit")

    off_head = store.append(session_id, [text_response("a genuine non-linear move")],
                            agent_id="main", parent_id=r1, reason="fold")[0]
    assert head_of(store, session_id) == off_head
    assert len(log_rows(store, session_id)) == 2, (
        "control: a NON-linear move still takes a reason from any caller — obligation 7 "
        "requires one, and nothing here narrows that")


def test_a_bare_append_cannot_mint_a_fork_entry(tmp_path):
    """    `append` refuses the fork reason outright, from every caller and on every move shape:
    `fork()` writes its own entry and never goes through `append`, so a fork-reasoned append
    has no legitimate caller at all. In particular a bare append into a session that holds no
    rows — where the move is linear and the previous head is NULL — cannot mint a row that
    `branch_point` would hand back as a branch point.

    Without the refusal the two rules compose into an escape: the move is linear so the
    unexplained-non-linear refusal does not fire, the reason is a member so membership does
    not fire, the reason arm records it, and its `from_message_id` is the previous head —
    NULL. That row is indistinguishable from a genuine fork entry by origin alone. The
    ordinary reason-less first turn into the same session stays legal, and this test drives
    it as the control rather than closing the escape by narrowing it."""
    ss = store_mod()
    store = make_store(tmp_path)
    fresh = store.new_session(agent_id="main")

    with pytest.raises(ss.StoreAppendError):
        store.append(fresh, [user_request("an unearned branch point")], agent_id="main",
                     reason="fork")
    assert message_ids(store, fresh) == [], "the refusal left no row"
    assert head_of(store, fresh) is None, "and no head"
    assert log_rows(store, fresh) == [], "and no entry for branch_point to find"
    assert ss.branch_point(store, fresh) is None, (
        "the escape closed: a never-forked session has no branch point")

    first = store.append(fresh, [user_request("the ordinary first turn")], agent_id="main")[0]
    assert head_of(store, fresh) == first, (
        "control: the reason-less first append into the same session is still legal")

    r2 = store.append(fresh, [text_response("second")], agent_id="main")[0]
    with pytest.raises(ss.StoreAppendError):
        store.append(fresh, [text_response("off head, fork-reasoned")], agent_id="main",
                     parent_id=first, reason="fork")
    assert log_rows(store, fresh) == [], (
        "the refusal holds on a NON-linear move too: fork() is the only writer of a fork "
        "entry, whatever the move's shape")
    assert head_of(store, fresh) == r2

    child = store.fork(fresh, at_message_id=first)
    assert [e.reason for e in log_rows(store, child)] == ["fork"], (
        "control: fork() itself still writes the entry, through its own path")
    assert ss.branch_point(store, child) == first


def test_a_fold_refuses_to_parent_a_frontier_outside_the_folding_session(tmp_path):
    """    A fold refuses to mint a frontier parented onto a row belonging to another session:
    folding a forked session — whose lineage root always lies in its parent — is refused
    whether or not the fork has appends of its own, and nothing is written by the refusal. A
    fold whose root is the folding session's own row still succeeds.

    An append of its own is not enough to make the frontier's parent this session's row,
    because the path walk crosses session boundaries by design; refusing on the session an
    append of its own would leave exactly that case parenting across the boundary. Scoped to
    the fold: a bare `append` naming a parent in another session stays legal, which
    `test_the_path_walk_crosses_session_boundaries_and_head_is_not_confined` pins."""
    # provenance: P102; B12 (executed) established the walk crosses session boundaries.
    sel = selection_mod()
    store = make_store(tmp_path)
    parent = store.new_session(agent_id="main")
    p1, p2 = linear_turns(store, parent, 2)

    appendless = store.fork(parent, at_message_id=p2)
    refused_bare = raised_by(sel.fold, store, appendless, agent_id="main", boundary=2)
    assert refused_bare is not None, "a fork with no append of its own must be refused"
    assert not isinstance(refused_bare, DELIBERATE), (
        f"the refusal must be deliberate, not an incidental error: {refused_bare!r}")

    with_appends = store.fork(parent, at_message_id=p2)
    own = store.append(with_appends, [text_response("the fork's own turn")], agent_id="main")[0]
    assert sel.path_row_ids(store, with_appends)[0] == p1, (
        "the fixture must leave the fork's lineage root in the parent session — a fork WITH "
        "an append of its own is the case a session-scoped rule would miss")

    refused = raised_by(sel.fold, store, with_appends, agent_id="main", boundary=3)

    assert refused is not None, (
        "an append of its own does not make the frontier's parent this session's row")
    assert not isinstance(refused, DELIBERATE), f"{refused!r}"
    for session_id in (appendless, with_appends):
        assert sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ? AND "
                          "synthesized = 1", (session_id,)) == [(0,)], "no frontier minted"
        assert [e.reason for e in log_rows(store, session_id)] == ["fork"], (
            "and nothing recorded beyond the entry fork() wrote")
    assert head_of(store, with_appends) == own, "the refused fold moved no head"

    frontier = sel.fold(store, parent, agent_id="main", boundary=2)
    assert sql(store, "SELECT session_id FROM message WHERE id = ?", (frontier,)) == [
        (parent,)], "control: a fold whose root is its own session's row still succeeds"
    assert head_of(store, parent) == frontier


def test_a_fold_on_an_empty_path_is_refused(tmp_path):
    """Folding a session whose path is empty is refused: there is no row for the frontier to
    parent onto, and a frontier with no parent is not a fold. Nothing is written by the
    refusal — no frontier row, no head move, no log entry — and the same fold on the same
    session succeeds as soon as it holds a row of its own.

    Refusing to parent a frontier outside the folding session does not decide this case on its
    own: with no row to parent onto there is no session to compare. The parentless frontier
    the empty path would otherwise mint is also the one shape that writes a head-move entry
    with no origin from an ordinary fold, which is why the reader is specified on the reason
    as well as on the origin."""
    # provenance: PR-6 (executed) records today's behaviour — `root = ids[0] if ids else None`
    # mints a parentless frontier and raises no IndexError — so this test is red against the
    # base because the refusal is missing, not because the fold path is.
    sel = selection_mod()
    store = make_store(tmp_path)
    empty = store.new_session(agent_id="main")
    assert sel.path_row_ids(store, empty) == [], "the fixture is a session with an empty path"

    refused = raised_by(sel.fold, store, empty, agent_id="main", boundary=0)

    assert refused is not None, "a frontier with no parent is not a fold"
    assert not isinstance(refused, DELIBERATE), (
        f"the refusal must be deliberate, not an incidental error: {refused!r}")
    assert message_ids(store, empty) == [], "the refused fold minted no frontier"
    assert head_of(store, empty) is None, "and moved no head"
    assert log_rows(store, empty) == [], "and recorded nothing"

    r1 = store.append(empty, [user_request("a turn of its own")], agent_id="main")[0]
    frontier = sel.fold(store, empty, agent_id="main", boundary=1)
    assert head_of(store, empty) == frontier, (
        "control: the same fold succeeds once there is a row to parent onto")
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (frontier,)) == [(r1,)]


# the cycle guard (correction R3, binding)

def test_append_still_refuses_a_cyclic_parent_chain_at_write_time(tmp_path):
    """    `append` still refuses a cyclic `parent_id` chain at WRITE time — before anything is
    durable — whether the cycle is reachable through the implicit parent it reads off head or
    only through a caller-supplied explicit parent that sits off this session's own chain.
    The refusal rolls back the row and the head move with it, exactly as obligation 7's raise
    does.

    The guard is a bounded walk from the row's OWN parent, implicit or explicit: a depth cap
    on the head walk covers only the implicit shape, and the invariant at stake — one walk
    both the reader and the writer go through, so a corrupted chain cannot stay invisible at
    write time — is preserved only by the parent-anchored form. Both shapes are driven here,
    each asserting that the check participates in the same rollback as the row and the head
    move, and that the caller observes a raise with nothing left durably inserted."""
    # provenance: corrections R3 (binding), P25/P26 (one demand, not two), P27, P35. COR-R3
    # (executed) is today's behaviour that must not regress; the only shipped cycle test
    # drives the read path, so the write-time guarantee would have vanished silently.
    ss = store_mod()
    store = make_store(tmp_path)
    implicit = store.new_session(agent_id="main")
    a, b = linear_turns(store, implicit, 2)
    store.connection.execute("UPDATE message SET parent_id = ? WHERE id = ?", (b, a))

    with pytest.raises(ss.CyclicParentChain):
        store.append(implicit, [text_response("onto a looped head")], agent_id="main")
    assert message_ids(store, implicit) == [a, b], "nothing durable was left behind"
    assert head_of(store, implicit) == b, "and head did not move"
    assert log_rows(store, implicit) == []

    # the explicit shape: a cycle that head's own walk would never trip over
    clean = store.new_session(agent_id="main")
    c1, c2 = linear_turns(store, clean, 2, label="clean")
    elsewhere = store.new_session(agent_id="main")
    e1, e2 = linear_turns(store, elsewhere, 2, label="elsewhere")
    store.connection.execute("UPDATE message SET parent_id = ? WHERE id = ?", (e2, e1))
    assert ss.path_row_ids(store, clean) == [c1, c2], (
        "the fixture must leave this session's own chain clean, or the explicit arm proves "
        "nothing the implicit arm did not")

    with pytest.raises(ss.CyclicParentChain):
        store.append(clean, [text_response("onto a looped explicit parent")],
                     agent_id="main", parent_id=e2, reason="fold")
    assert message_ids(store, clean) == [c1, c2]
    assert head_of(store, clean) == c2
    assert log_rows(store, clean) == []


# D4 / survival, and the end-to-end walk

def test_deleting_default_boundary_leaves_every_fold_caller_working(tmp_path):
    """    With `_default_boundary` no longer standing in as the fold's placeholder default, every
    surviving fold caller still works: `selection.fold_boundary` still resolves its boundary
    and still reuses the frontier row at it, a fold handed an explicit boundary still mints
    exactly one frontier, and `selection.fold` called with no boundary now FAILS CLOSED with
    a `ValueError` instead of silently counting rows off the path."""
    # provenance: correction R2 (binding). D4's census was refuted — `selection.fold_boundary`
    # has one green, committed, spec-bound caller (C2/c10) and `_default_boundary` has two
    # callers, not one (C3) — so only the fold's `if boundary is None` fallback goes.
    # rejected: keeping `_default_boundary` as `_fold_impl`'s default. It counts
    # non-synthesized rows in the SESSION with no path predicate, so after a fold it
    # over-counts the rows the fold displaced (B3, executed: the path holds 2 rows and it
    # returns 4), and `_fold_impl`'s own comment already says no production path should take
    # the placeholder. The over-count itself stays INHERITED by `fold_boundary` and
    # explicitly unfixed here — path-scoped counting is FK16 / #753 — which is why this test
    # pins the over-count as the current contract rather than asserting the fix.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 4)

    assert sel.fold_boundary(store, session_id) == 4, (
        "the surviving caller still resolves a boundary from the session's row count")
    frontier = sel.fold(store, session_id, agent_id="main", boundary=2)
    assert sql(store, "SELECT id FROM message WHERE synthesized = 1") == [(frontier,)], (
        "an explicit boundary still mints exactly one frontier row")

    assert len(sel.path_row_ids(store, session_id)) == 2, "the path after the fold"
    assert sel._default_boundary(store, session_id) == 4, (
        "B3's over-count is inherited and NOT fixed here (FK16 / #753): the count is over "
        "the session, not over the path")
    assert sel.fold_boundary(store, session_id) == 4

    reused = sel.fold(store, session_id, agent_id="main", boundary=2)
    assert reused == frontier, "the reuse lookup still keys on the boundary it was handed"

    refused = raised_by(sel.fold, store, session_id, agent_id="main")
    assert isinstance(refused, ValueError), (
        f"fold(boundary=None) fails closed rather than counting off the path; got {refused!r}")
    assert raised_by(sel._fold_impl, store, session_id, agent_id="main") is not None, (
        "boundary is required on _fold_impl: there is no placeholder left to fall back to")


def test_the_full_lifecycle_walk_new_session_two_folds_and_a_fork(tmp_path):
    """    The seven-point walk, end to end in one store file: (1) a fresh session's head is NULL,
    its path empty and its log empty; (2) the first append is linear — head is the new row,
    the log still empty; (3) the next turn advances head linearly, still nothing logged; (4)
    the first fold moves head to frontier one and writes entry one; (5) an ordinary turn off
    frontier one advances head with no new entry; (6) the second fold moves head to frontier
    two and writes entry two, naming what IT displaced; (7) forking off frontier two gives
    the child head at frontier two, a path that is the parent's prefix through it — NOT empty
    — and a single `fork` entry with a NULL origin, after which the child's own first append
    is linear and adds nothing. Session A is untouched throughout."""
    # provenance: P118, asserted point by point rather than re-derived. Point (7) is F4/B11
    # (executed): under a recorded head a forked-but-unappended session's path is the
    # inherited prefix, where today it reads empty.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)

    a = store.new_session(agent_id="main")
    assert (head_of(store, a), ss.path_row_ids(store, a), log_rows(store, a)) == (None, [], [])

    r1 = store.append(a, [user_request("one")], agent_id="main")[0]
    assert (head_of(store, a), ss.path_row_ids(store, a)) == (r1, [r1])
    assert log_rows(store, a) == []

    r2 = store.append(a, [text_response("two")], agent_id="main")[0]
    assert (head_of(store, a), log_rows(store, a)) == (r2, [])

    f1 = sel.fold(store, a, agent_id="main", boundary=2)
    assert head_of(store, a) == f1
    assert [(e.from_message_id, e.to_message_id, e.reason) for e in log_rows(store, a)] == [
        (r2, f1, "fold")]

    r3 = store.append(a, [text_response("three")], agent_id="main")[0]
    assert (head_of(store, a), len(log_rows(store, a))) == (r3, 1)

    f2 = sel.fold(store, a, agent_id="main", boundary=3)
    assert head_of(store, a) == f2
    assert [(e.from_message_id, e.to_message_id) for e in log_rows(store, a)] == [
        (r2, f1), (r3, f2)]

    b = store.fork(a, at_message_id=f2)
    assert head_of(store, b) == f2
    assert ss.path_row_ids(store, b) == [r1, f2], "the parent's prefix, not []"
    assert [(e.from_message_id, e.to_message_id, e.reason) for e in log_rows(store, b)] == [
        (None, f2, "fork")]

    b1 = store.append(b, [text_response("the child's first")], agent_id="main")[0]
    assert head_of(store, b) == b1
    assert len(log_rows(store, b)) == 1, "the child's first append is linear"
    assert ss.path_row_ids(store, b) == [r1, f2, b1]

    assert head_of(store, a) == f2, "session A is untouched throughout"
    assert len(log_rows(store, a)) == 2
    assert ss.path_row_ids(store, a) == [r1, f2]
