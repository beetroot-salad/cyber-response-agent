"""fork's recorded branch point, the log readers, and the all-or-nothing transaction."""
from __future__ import annotations

import inspect
import sqlite3

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests._session_head_754 import (  # noqa: E402
    NotSerializable,
    fresh_process_readback,
    head_of,
    linear_turns,
    log_rows,
    message_ids,
    raised_by,
)
from defender.tests._session_store_705 import (  # noqa: E402
    FaultStore,
    StoreFault,
    complete_pair,
    make_store,
    runs_base,
    selection_mod,
    sql,
    store_mod,
    text_response,
    user_request,
)
from defender.run_repository import SessionPaths  # noqa: E402


# fork: the branch point becomes a log entry

def test_fork_logs_null_to_branch_point(tmp_path):
    """Constructing a fork sets the new session's head to the branch point and records that move"""
    # provenance: issue obligation 4a.
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)

    fork = store.fork(main, at_message_id=r2)

    entries = log_rows(store, fork)
    assert len(entries) == 1, f"one entry, under the child's own session_id; got {entries}"
    assert entries[0].from_message_id is None, (
        "a fork displaces nothing, and the NULL origin is what makes it recognisable")
    assert entries[0].to_message_id == r2
    assert entries[0].reason == "fork"
    assert head_of(store, fork) == r2
    assert log_rows(store, main) == [], "the parent's own head never moved"
    assert ss.path_row_ids(store, fork) == [r1, r2]


def test_branch_point_survives_the_parent_folding_past_it(tmp_path):
    """After the parent folds past the branch point, the fork's branch point is still answerable"""
    # provenance: issue obligation 4b (D2), reproduced from B5 (executed).
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, main, 3)

    fork = store.fork(main, at_message_id=r2)
    store.append(fork, [text_response("the fork continues")], agent_id="main")
    sel.fold(store, main, agent_id="main", boundary=3)

    parent_path = ss.path_row_ids(store, main)
    fork_path = ss.path_row_ids(store, fork)
    shared = set(parent_path) & set(fork_path)
    assert shared == {r1}, (
        f"the fixture must make derivation WRONG, not merely unavailable: {shared}")
    assert r2 not in parent_path, "the parent folded past the branch point"

    assert ss.branch_point(store, fork) == r2, (
        f"the recorded branch point survives; derivation would answer {r1}")
    assert ss.branch_point(store, fork) != max(shared)
    assert r3 not in fork_path


def test_a_fresh_fork_renders_its_inherited_prefix_exactly_once(tmp_path):
    """`fork` sets the child's `last_render_len` to the length of the prefix it inherits, so the"""
    # provenance: PR-24 (executed) measured it — three inherited messages became ids [4,5,6]
    # beside [1,2,3]. Driven through fork plus ingest, not through the store alone.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    live = [user_request("orientation"), *complete_pair()]
    sel.ingest(store, main, live, agent_id="main")
    inherited = ss.path_row_ids(store, main)
    assert len(inherited) == 3

    fork = store.fork(main, at_message_id=inherited[-1])

    assert store.last_render_len(fork) == 3, (
        "the fork has already rendered what it inherited; anything less re-ingests it")
    assert ss.path_row_ids(store, fork) == inherited

    again = sel.ingest(store, fork, live, agent_id="main")
    assert again == [], f"the inherited prefix must not be re-appended; got {again}"
    assert message_ids(store, fork) == [], "the fork still owns no rows of its own"

    grown = [*live, text_response("genuinely new")]
    added = sel.ingest(store, fork, grown, agent_id="main")
    assert len(added) == 1, f"exactly the new tail lands; got {added}"
    assert ss.path_row_ids(store, fork) == [*inherited, added[0]]

    shas = [row[0] for row in sql(store, "SELECT payload_sha FROM message_payload")]
    assert len(shas) == len(set(shas)), (
        f"PR-24's byte-identical duplicates must not appear anywhere; got {shas}")


# the log readers


def test_the_full_fold_history_is_readable_in_order(tmp_path):
    """Over a session that folded three times, the fold history returns all three displaced tips"""
    # provenance: FK-A(a) and (d); P77 is the reconstruction case.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 2)

    tips: list[int] = []
    for boundary in (2, 3, 4):
        tips.append(head_of(store, session_id))
        sel.fold(store, session_id, agent_id="main", boundary=boundary)
        store.append(session_id, [text_response(f"after fold {boundary}")], agent_id="main")

    history = ss.fold_history(store, session_id)
    assert history == tips, f"every fold's displaced tip, in head-move order; got {history}"
    assert history[-1] == ss.displaced_tip(store, session_id)
    assert history[0] != history[-1], (
        "the fixture must fold more than once, or the accessor proves nothing")

    never = store.new_session(agent_id="main")
    assert ss.fold_history(store, never) == []
    assert ss.displaced_tip(store, never) is None
    assert ss.fold_history(store, "no-such-session-id") == []
    assert ss.displaced_tip(store, "no-such-session-id") is None


def test_branch_point_ignores_a_log_row_with_a_non_null_from_message_id(tmp_path):
    """A `fork`-reasoned entry whose `from_message_id` is not NULL is not a branch point and the"""
    # provenance: P48, the sharpest single observation in the measurement; P32 for the raw
    # route. The writer-side refusal and the reader-side filter are two independent guards.
    ss = store_mod()
    store = make_store(tmp_path)
    unearned = store.new_session(agent_id="main")
    u1, u2 = linear_turns(store, unearned, 2)
    with pytest.raises(ss.StoreAppendError):
        store.append(unearned, [text_response("unearned")], agent_id="main",
                     parent_id=u1, reason="fork")
    store.connection.execute(
        "INSERT INTO session_head_log (session_id, from_message_id, to_message_id, reason) "
        "VALUES (?, ?, ?, 'fork')", (unearned, u2, u1))

    entries = log_rows(store, unearned)
    assert len(entries) == 1, entries
    assert entries[0].reason == "fork", entries
    assert entries[0].from_message_id == u2, (
        "the fixture must reproduce P48: a real, logged, fork-reasoned, NON-NULL-origin row")

    assert ss.branch_point(store, unearned) is None, (
        "only a NULL origin marks a genuine branch point")

    store.connection.execute(
        "INSERT INTO session_head_log (session_id, from_message_id, to_message_id, reason) "
        "VALUES (?, NULL, ?, 'fold')", (unearned, u1))
    assert ss.branch_point(store, unearned) is None, (
        "nor does a NULL-origin row that is not fork-reasoned: neither decoy in this session "
        "makes a branch point, and the reader needs both halves of the predicate to say so")

    genuine = store.fork(unearned, at_message_id=u1)
    assert ss.branch_point(store, genuine) == u1, (
        "control: the same reader on the same store resolves a real fork's branch point")
    assert ss.branch_point(store, unearned) is None


def test_branch_point_requires_a_fork_reason_not_just_a_null_origin(tmp_path):
    """A branch point is a log row that is BOTH origin-less and fork-reasoned: the reader"""
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    decoy = store.new_session(agent_id="main")
    d1, d2 = linear_turns(store, decoy, 2, label="decoy")
    store.connection.execute(
        "INSERT INTO session_head_log (session_id, from_message_id, to_message_id, reason) "
        "VALUES (?, NULL, ?, 'fold')", (decoy, d2))
    assert log_rows(store, decoy)[0].from_message_id is None, (
        "the fixture must reproduce the shape: a NULL-origin row that is NOT a fork")

    assert ss.branch_point(store, decoy) is None, (
        "a NULL origin alone does not make a branch point — the reason has to say fork")
    assert ss.displaced_tip(store, decoy) is None, (
        "and a fold that displaced nothing reads exactly like a session that never folded")

    never = store.new_session(agent_id="main")
    linear_turns(store, never, 1, label="never")
    assert ss.displaced_tip(store, never) == ss.displaced_tip(store, decoy)
    assert ss.fold_history(store, decoy) == ss.fold_history(store, never), (
        "indistinguishable through every reader, not only through one")

    genuine = store.fork(decoy, at_message_id=d1)
    assert ss.branch_point(store, genuine) == d1, (
        "control: the same reader on the same store resolves a real fork's branch point")
    real_tip = head_of(store, never)
    sel.fold(store, never, agent_id="main", boundary=1)
    assert ss.displaced_tip(store, never) == real_tip, (
        "control: a fold that DID displace something is still recoverable")


# obligation 8 — the one transaction, in every failure shape

def test_head_and_log_move_in_one_transaction(tmp_path):
    """The head UPDATE and the conditional log INSERT ride inside the same transaction as the"""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)
    assert log_rows(store, session_id) == []

    linear_batch = [text_response("would land"), NotSerializable()]
    assert raised_by(store.append, session_id, linear_batch, agent_id="main") is not None
    assert message_ids(store, session_id) == [r1, r2, r3], "the earlier row rolled back too"
    assert head_of(store, session_id) == r3
    assert log_rows(store, session_id) == []

    # the same fault on a move that WAS going to write a log row
    non_linear = [text_response("would land"), NotSerializable()]
    assert raised_by(store.append, session_id, non_linear, agent_id="main",
                     parent_id=r1, reason="fold") is not None
    assert message_ids(store, session_id) == [r1, r2, r3]
    assert head_of(store, session_id) == r3, "head did not move"
    assert log_rows(store, session_id) == [], "and its log entry was not written either"
    assert store.connection.in_transaction is False

    landed = store.append(session_id, [text_response("a"), text_response("b")],
                          agent_id="main", parent_id=r1, reason="fold")
    assert message_ids(store, session_id) == [r1, r2, r3, *landed]
    assert head_of(store, session_id) == landed[-1]
    assert len(log_rows(store, session_id)) == 1, (
        "control: rows, head and the entry commit together or not at all")

    assert not inspect.iscoroutinefunction(store.append), (
        "P11/F3: the head UPDATE and the log INSERT go inside the EXISTING synchronous "
        "BEGIN IMMEDIATE block — an await there reintroduces interleaved-transaction "
        "corruption across concurrently dispatched gather sessions on one connection")


def test_a_failed_append_reads_back_as_the_pre_append_state_in_a_fresh_process(tmp_path):
    """A refused append is invisible to a later reader, whatever refused it: when the wait for a"""
    ss = store_mod()
    base = runs_base(tmp_path)
    real = ss.open_store(case_id="case-alpha", sessions=SessionPaths(base))
    session_id = real.new_session(agent_id="main")
    r1, r2 = linear_turns(real, session_id, 2)
    real.append(session_id, [text_response("recorded move")], agent_id="main",
                parent_id=r1, reason="fold")
    expected_head = head_of(real, session_id)
    expected_log = log_rows(real, session_id)
    expected_rows = message_ids(real, session_id)
    assert len(expected_log) == 1, expected_log
    assert expected_head not in (r1, r2), "the recorded move really moved head"

    blocker = sqlite3.connect(str(real.path), isolation_level=None, timeout=0.0)
    blocker.execute("BEGIN EXCLUSIVE")
    real.connection.execute("PRAGMA busy_timeout = 50")
    contended = raised_by(real.append, session_id, [text_response("contended")],
                          agent_id="main", parent_id=r1, reason="fold")
    blocker.rollback()
    blocker.close()
    real.connection.execute("PRAGMA busy_timeout = 30000")
    assert contended is not None, "the second writer must really have held the lock"
    assert head_of(real, session_id) == expected_head, "the wait expired before BEGIN"
    assert log_rows(real, session_id) == expected_log
    assert message_ids(real, session_id) == expected_rows

    handle = FaultStore(real, StoreFault(on="append", after=0, mode="disk-full"))
    exhausted = raised_by(handle.append, session_id, [text_response("x" * 64_000)],
                          agent_id="main", parent_id=r1, reason="fold")
    assert exhausted is not None, "the database must really have stopped growing"
    real.close()

    reopened = ss.open_store(case_id="case-alpha", sessions=SessionPaths(base))
    assert head_of(reopened, session_id) == expected_head
    assert log_rows(reopened, session_id) == expected_log
    assert message_ids(reopened, session_id) == expected_rows

    # a writer that dies mid-transaction: a real second connection, really abandoned
    dying = sqlite3.connect(str(reopened.path), isolation_level=None)
    dying.execute("PRAGMA foreign_keys = ON")
    dying.execute("BEGIN IMMEDIATE")
    dying.execute("INSERT INTO message (session_id, agent_id, parent_id, seq, synthesized, "
                  "kind) VALUES (?, 'main', ?, 99, 0, 'response')", (session_id, expected_head))
    dying.execute("UPDATE session SET head_message_id = ? WHERE session_id = ?",
                  (r1, session_id))
    dying.close()

    final = fresh_process_readback(reopened.path, session_id)[session_id]
    assert final["head"] == expected_head, "COMMIT never ran, so the head move never happened"
    assert [tuple(row) for row in final["log"]] == [tuple(e) for e in expected_log]
    assert message_ids(reopened, session_id) == expected_rows


def test_a_unique_seq_collision_rolls_back_the_head_move_and_the_log(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1 = store.append(session_id, [user_request("root")], agent_id="main", seq=0)[0]
    r2 = store.append(session_id, [text_response("second")], agent_id="main", seq=1)[0]
    payload_rows = sql(store, "SELECT COUNT(*) FROM message_payload")

    with pytest.raises(sqlite3.IntegrityError):
        store.append(session_id, [text_response("colliding")], agent_id="main",
                     parent_id=r1, reason="fold", seq=0)

    assert message_ids(store, session_id) == [r1, r2], "no message row survived"
    assert sql(store, "SELECT COUNT(*) FROM message_payload") == payload_rows
    assert head_of(store, session_id) == r2, "the head move rolled back with the row"
    assert log_rows(store, session_id) == [], "and so did the log entry it was going to write"

    survivor = store.append(session_id, [text_response("after")], agent_id="main",
                            parent_id=r1, reason="fold", seq=2)[0]
    assert head_of(store, session_id) == survivor, "the connection stays usable"
    assert len(log_rows(store, session_id)) == 1


def test_foreign_key_violations_on_the_head_and_log_writes_raise_and_roll_back(tmp_path):
    """Every foreign key this change relies on is enforced at write time and every violation"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)

    with pytest.raises(sqlite3.IntegrityError):
        store.append("no-such-session-id", [user_request("orphan")], agent_id="main")
    assert sql(store, "SELECT COUNT(*) FROM message") == [(2,)]

    with pytest.raises(sqlite3.IntegrityError):
        store.append(session_id, [text_response("orphan parent")], agent_id="main",
                     parent_id=777777, reason="fold")
    assert message_ids(store, session_id) == [r1, r2]
    assert head_of(store, session_id) == r2
    assert log_rows(store, session_id) == []

    with pytest.raises(sqlite3.IntegrityError):
        store.connection.execute(
            "UPDATE session SET head_message_id = 999999 WHERE session_id = ?", (session_id,))
    assert head_of(store, session_id) == r2
    store.connection.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?", (r1, session_id))
    assert head_of(store, session_id) == r1, (
        "control: the same UPDATE to a real row succeeds, so the refusal is the key firing")

    insert_log = ("INSERT INTO session_head_log (session_id, from_message_id, "
                  "to_message_id, reason) VALUES (?, NULL, ?, 'fork')")
    with pytest.raises(sqlite3.IntegrityError):
        store.connection.execute(insert_log, (session_id, 999999))
    with pytest.raises(sqlite3.IntegrityError):
        store.connection.execute(insert_log, ("no-such-session-id", r1))
    assert log_rows(store) == [], "no refused log row survived"
    assert ss.path_row_ids(store, session_id) == [r1]


def test_the_path_walk_crosses_session_boundaries_and_head_is_not_confined(tmp_path):
    """The key on `head_message_id` requires only that SOME message row with that id exists,"""
    # provenance: P21, P28 and P33, grounded in B12/B13 (executed): the walk follows parent_id
    # regardless of session_id, and agent_id does not scope it either.
    ss = store_mod()
    store = make_store(tmp_path)
    donor = store.new_session(agent_id="main")
    d1, d2 = linear_turns(store, donor, 2, label="donor")
    borrower = store.new_session(agent_id="gather-l1")

    store.connection.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?", (d2, borrower))
    assert head_of(store, borrower) == d2, "the key accepts a row from another session"
    assert ss.path_row_ids(store, borrower) == [d1, d2], (
        "the walk returns the donor's rows as the borrower's path")
    assert len(ss.hydrate(store, borrower, role="analysis")) == 2
    assert message_ids(store, borrower) == [], "none of which the borrower owns"

    # the ordinary shape of the same permissiveness: an append whose explicit parent is a
    # row in another session lands under THIS session and is a non-linear move here
    landed = store.append(borrower, [text_response("grafted")], agent_id="gather-l1",
                          parent_id=d1, reason="fold")[0]
    assert sql(store, "SELECT session_id FROM message WHERE id = ?", (landed,)) == [(borrower,)]
    assert ss.path_row_ids(store, borrower) == [d1, landed]
    assert [(e.from_message_id, e.to_message_id) for e in log_rows(store, borrower)] == [
        (d2, landed)], "recorded under the borrower, naming the head it displaced"
    assert ss.path_row_ids(store, donor) == [d1, d2], "the donor is untouched"
