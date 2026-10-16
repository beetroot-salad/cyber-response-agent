"""The recorded head pointer and head-move log: the write side (append, fold, reason validation)."""
from __future__ import annotations


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
    user_request,
)


# #0 — the signal contract

def test_head_move_signal_contract(tmp_path):
    """The head-move surface is exactly this: `append` takes a keyword `reason` drawn from the"""
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
    """The path a reader projects is the parent walk from the session's RECORDED head, not from"""
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
    """A session whose `head_message_id` is SQL NULL reads as an empty path even when the"""
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


# the fold

def test_fold_moves_head_to_frontier_and_logs_fold(tmp_path):
    """A fold moves the session's head to the frontier row it mints and leaves exactly ONE"""
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
    """Two folds with no ordinary turn between them leave two entries that chain: the first"""
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
    """A second fold at a boundary that already holds a frontier returns the existing frontier"""
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
    """Two folds at one boundary under DIFFERENT `agent_id`s miss each other's reuse lookup:"""
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
    """Folding a session whose path is a single row — so the frontier's parent already IS the"""
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
    """An ordinary turn — the first inserted row parenting onto the session's own current head,"""
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
    """The first append into a session that holds no rows and whose head is SQL NULL is LINEAR:"""
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
    """An append into a session that holds rows but whose `head_message_id` is SQL NULL is"""
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
    """An append whose first row parents onto a row that is not the session's current head, with"""
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
    """A multi-message batch whose FIRST row parents off head is one non-linear move: every"""
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
    """When the third message of an ingested turn cannot be stored, messages one and two are"""
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
    """One round that ingests a turn and then folds moves head TWICE — first onto the ingest"""
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


def test_reason_membership_is_validated_before_linearity_classification(tmp_path):
    """`reason` membership is checked by exact match whenever it is not None, before the move's"""
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


# who may hand `append` a reason at all

def test_a_reason_on_a_linear_move_is_refused_unless_the_caller_mints_a_frontier(tmp_path):
    """A member reason handed to a LINEAR move is accepted only from a caller minting a frontier"""
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
    """`append` refuses the fork reason outright, from every caller and on every move shape:"""
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
    """A fold refuses to mint a frontier parented onto a row belonging to another session:"""
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
    """Folding a session whose path is empty is refused: there is no row for the frontier to parent onto, and a frontier with no parent is not a fold."""
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
    """`append` still refuses a cyclic `parent_id` chain at WRITE time — before anything is"""
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

def test_the_full_lifecycle_walk_new_session_two_folds_and_a_fork(tmp_path):
    """The seven-point walk, end to end in one store file: (1) a fresh session's head is NULL,"""
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
