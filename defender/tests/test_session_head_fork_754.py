"""#754 — fork's recorded branch point, the log readers, and the one transaction.

The executable form of the `spec_graph_754.yaml` demands that bind `fork_constructor`, the
three log readers (`displaced_tip`, `branch_point`, `fold_history`) and obligation 8's
all-or-nothing guarantee. Each test's docstring carries its demand's prose; the ledger ids
sit in a `# provenance:` comment beneath it.

**RED AGAINST `1cecad37` IS THE EXPECTED STATE**, and `store.fork()` has NO production caller
(C6/c15: zero production call sites, eight test ones), so the fork half of this change is
spec-only by construction until #696 — every test below drives the store API directly, and
none asserts a driver path that does not exist.

Faults here stay on the author charge's hierarchy. The mid-transaction failure is a real
object the REAL serializer refuses (`_session_head_754.NotSerializable`, ledger claim B8);
the contention failure is a real second connection really holding the write lock with the
store's own `busy_timeout` lowered so the real wait really expires; the exhaustion failure is
the real database really taken to its real growth ceiling (`FaultStore`'s `disk-full` mode,
ledger claim `rp-c1`); the process-death failure is a real abandoned transaction. No
exception class below is authored, and where a class is deliberately unpinned the assertion
is the rollback.
"""
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


# fork: the branch point becomes a log entry

def test_fork_logs_null_to_branch_point(tmp_path):
    """    Constructing a fork sets the new session's head to the branch point and records that move
    as a `fork` entry whose `from_message_id` is SQL NULL — the fork came from nowhere, it
    displaced nothing — and whose `to_message_id` is the branch point itself. The entry lands
    under the CHILD's session_id: it is the child's head that moved."""
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


def test_a_fork_entry_records_no_attachment_point(tmp_path):
    """    A `fork` entry's `attached_to_message_id` is SQL NULL: `fork()` inserts no message row, so
    there is no first-inserted row whose parent could be recorded, and in particular the
    column does not repeat `to_message_id`.

    Left unpinned, an implementer could write the branch point into it and stay green, which
    would re-create one column over exactly the conflation that column exists to prevent. The
    control is the multi-message non-linear append, whose entry DOES carry an attachment
    point: the column is not simply always NULL."""
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)

    fork = store.fork(main, at_message_id=r2)

    entry = log_rows(store, fork)[0]
    assert entry.attached_to_message_id is None, (
        f"a fork grafts no row on, so it records no attachment point; got {entry}")
    assert entry.to_message_id == r2, "the branch point stays where it belongs"

    landed = store.append(main, [text_response("a"), text_response("b")], agent_id="main",
                          parent_id=r1, reason="fold")
    grafted = log_rows(store, main)[0]
    assert grafted.attached_to_message_id == r1, (
        "control: an append that DOES graft a row on records where — so NULL on the fork "
        "entry is a fact about fork(), not a column nothing ever fills")
    assert grafted.to_message_id == landed[-1]


def test_branch_point_survives_the_parent_folding_past_it(tmp_path):
    """    After the parent folds past the branch point, the fork's branch point is still answerable
    exactly: `branch_point` returns the recorded row even though the parent's own path no
    longer reaches it, and a merge-base derivation over the two live paths would return a
    DIFFERENT, wrong answer.

    That is the whole case for recording the branch point rather than deriving it: derivation
    does not fail, it answers the lineage root while the true branch point is elsewhere."""
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


def test_two_forks_one_branch_point_two_entries(tmp_path):
    """    Two forks taken from one branch point are two sessions with two `fork` entries naming the
    same `to_message_id`, each under its own session_id — nothing dedupes them, and nothing
    refuses the second.

    No idempotency is added on the way in: two forks from one point coexist by design, and a
    uniqueness constraint over the branch point would break this outright."""
    # provenance: issue obligation 5; P24 (the end state holds regardless of dispatch timing);
    # PR-18 (executed): the only unique index on `session` is its primary key over session_id.
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)

    left = store.fork(main, at_message_id=r2)
    right = store.fork(main, at_message_id=r2)

    assert left != right, "each fork mints its own session_id"
    entries = log_rows(store)
    assert [(e.session_id, e.from_message_id, e.to_message_id, e.reason) for e in entries] == [
        (left, None, r2, "fork"), (right, None, r2, "fork")], entries
    assert head_of(store, left) == head_of(store, right) == r2
    assert ss.branch_point(store, left) == ss.branch_point(store, right) == r2
    assert ss.path_row_ids(store, left) == ss.path_row_ids(store, right) == [r1, r2]


def test_fork_accepts_any_at_message_id_and_records_it_unmodified(tmp_path):
    """    Nothing restricts which row a fork may branch from: an ancestor short of the current head,
    a row an earlier fold displaced off the path, a synthesized frontier row, and a row
    belonging to another session are all accepted, and each fork's log entry names the id it
    was handed, unmodified, with head set to exactly that row."""
    # provenance: P59 (an off-path at_message_id), P61 (an ancestor short of head), P56 (a row
    # from another session — B12 establishes the walk crosses sessions anyway) and P57 (a
    # synthesized frontier row — fork treats every id uniformly).
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, main, 3)
    frontier = sel.fold(store, main, agent_id="main", boundary=3)
    other = store.new_session(agent_id="gather-l1")
    (o1,) = linear_turns(store, other, 1, agent_id="gather-l1", label="leg")

    assert r3 not in ss.path_row_ids(store, main), "r3 is off-path after the fold"
    for label, at in (("ancestor", r2), ("off-path", r3), ("frontier", frontier),
                      ("foreign", o1)):
        child = store.fork(main, at_message_id=at)
        entries = log_rows(store, child)
        assert [(e.from_message_id, e.to_message_id, e.reason) for e in entries] == [
            (None, at, "fork")], f"{label}: {entries}"
        assert head_of(store, child) == at, label
        assert ss.path_row_ids(store, child)[-1] == at, label
    assert r1 in ss.path_row_ids(store, main)


def test_a_forks_head_is_independent_of_the_parents_later_appends(tmp_path):
    """    A fork's head never moves as a side effect of the parent's later appends, and the parent's
    head never moves as a side effect of the fork's: every head UPDATE and every log INSERT
    targets exactly one session_id, so the shared message-id space affects id VALUES and never
    which session's head column moved."""
    # provenance: P60 (the 'recorded, not derived' point), with P119 and P120.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)
    fork = store.fork(main, at_message_id=r2)
    assert head_of(store, fork) == head_of(store, main) == r2, (
        "both heads name the same id at fork time — they are still separate columns")

    r3 = store.append(main, [text_response("the parent moves on")], agent_id="main")[0]
    parent_frontier = sel.fold(store, main, agent_id="main", boundary=3)

    assert head_of(store, fork) == r2, "the parent's appends and fold left the fork's head"
    assert [e.reason for e in log_rows(store, fork)] == ["fork"]

    f1 = store.append(fork, [text_response("the fork moves on")], agent_id="main")[0]
    assert head_of(store, main) == parent_frontier, "and the fork's append left the parent's"
    assert [e.reason for e in log_rows(store, main)] == ["fold"]
    assert ss.path_row_ids(store, fork) == [r1, r2, f1]
    assert r3 not in ss.path_row_ids(store, fork)


def test_a_forks_first_append_is_linear_and_adds_no_second_entry(tmp_path):
    """    A fresh fork's first append parents onto the head the fork already set, so the rule reads
    it as LINEAR: it requires no reason, adds no second log row, and the session's only entry
    stays the `fork` one written when the fork was constructed.

    The complementary condition is driven too: the same append routed off head instead needs a
    reason and is refused without one, so "no second entry" is a property of linearity rather
    than of a log the fork cannot reach."""
    # provenance: a fresh fork's hydrate IS the parent's prefix — the point of setting head at
    # fork time. B11 (executed) is the fact the design never stated; today the read is [].
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)
    fork = store.fork(main, at_message_id=r2)

    first = store.append(fork, [text_response("the fork's first")], agent_id="main")[0]

    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (first,)) == [(r2,)]
    assert head_of(store, fork) == first
    assert [e.reason for e in log_rows(store, fork)] == ["fork"], (
        "the fork entry is still the session's only one")
    assert ss.path_row_ids(store, fork) == [r1, r2, first]

    with pytest.raises(ss.StoreAppendError):
        store.append(fork, [text_response("off the fork's head")], agent_id="main",
                     parent_id=r1)
    assert [e.reason for e in log_rows(store, fork)] == ["fork"]
    store.append(fork, [text_response("off the fork's head, explained")], agent_id="main",
                 parent_id=r1, reason="fold")
    assert [e.reason for e in log_rows(store, fork)] == ["fork", "fold"], (
        "control: the same channel records a move that IS non-linear")


def test_fork_writes_head_and_log_in_one_transaction(tmp_path):
    """    `fork`'s two writes — the `session` row carrying the new head, and the `fork` log entry —
    ride ONE `BEGIN IMMEDIATE … COMMIT`, so a failure of either leaves neither: a fork from a
    session_id that does not exist raises and leaves no session row AND no log row, where an
    autocommit pair would have left the log entry behind.

    A fault between the two writes would leave a session with a head and NO branch-point
    record: the unreachable-lineage-without-a-record state the design's own principle forbids,
    and the state derivation gets wrong."""
    # provenance: B10 (executed): fork runs on an autocommit connection today and its single
    # INSERT is atomic BY ACCIDENT — one write was accidentally atomic, two are not. PR-20
    # (executed) supplies the real fault: parent_session_id is a LIVE foreign key, so the
    # INSERT raises before the Python-computed fallback can ever become visible.
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    (r1,) = linear_turns(store, main, 1)
    sessions_before = sql(store, "SELECT COUNT(*) FROM session")

    statements: list[str] = []
    store.connection.set_trace_callback(statements.append)
    try:
        child = store.fork(main, at_message_id=r1)
    finally:
        store.connection.set_trace_callback(None)

    ordered = [" ".join(s.split()).upper() for s in statements]
    begins = [i for i, s in enumerate(ordered) if s.startswith("BEGIN IMMEDIATE")]
    commits = [i for i, s in enumerate(ordered) if s.startswith("COMMIT")]
    log_writes = [i for i, s in enumerate(ordered)
                  if s.startswith("INSERT INTO SESSION_HEAD_LOG")]
    row_writes = [i for i, s in enumerate(ordered)
                  if s.startswith("INSERT INTO SESSION") and i not in log_writes]
    assert len(begins) == len(commits) == 1, f"one transaction, not two: {ordered}"
    assert len(log_writes) == len(row_writes) == 1, (
        f"both of fork's writes must be visible in the trace: {ordered}")
    writes = log_writes + row_writes
    assert begins[0] < min(writes), f"a write landed before BEGIN IMMEDIATE: {ordered}"
    assert max(writes) < commits[0], f"a write landed after COMMIT: {ordered}"

    assert head_of(store, child) == r1
    assert len(log_rows(store, child)) == 1

    failed = raised_by(store.fork, "this-session-id-does-not-exist", r1)
    assert isinstance(failed, sqlite3.IntegrityError), (
        f"PR-20's real fault: the parent_session_id foreign key refuses it; got {failed!r}")
    assert sql(store, "SELECT COUNT(*) FROM session") == [(sessions_before[0][0] + 1,)], (
        "the refused fork left no session row")
    assert len(log_rows(store)) == 1, (
        "and no orphan log entry survived it — the two writes are one transaction")


def test_a_fresh_fork_renders_its_inherited_prefix_exactly_once(tmp_path):
    """    `fork` sets the child's `last_render_len` to the length of the prefix it inherits, so the
    first ingest into a fresh fork appends NOTHING for the messages the prefix already covers
    and appends exactly one row for the first genuinely new message. No message is stored
    twice.

    Leaving the render length behind is not a silent inefficiency but a duplication: the tail
    slice reads zero regardless of how many rows the effective history already covers, so the
    whole live list is re-appended as byte-identical rows, and the underflow guard cannot
    catch it because it only fires when the live list is SHORTER than the last render."""
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

def test_displaced_tip_survives_later_appends(tmp_path):
    """    The tip a fold displaced stays answerable after the conversation moves on: ordinary turns
    after the fold do not disturb it, and walking `parent_id` back from it still reaches every
    turn the fold cut, so the log plus the message tree is a real reconstruction surface
    rather than a marker."""
    # provenance: issue obligation 3; P77. Which fold's tip a single reader returns — the most
    # recent — is why the ordered accessor exists beside it.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, session_id, 3)

    sel.fold(store, session_id, agent_id="main", boundary=3)
    assert ss.displaced_tip(store, session_id) == r3

    for _ in range(3):
        store.append(session_id, [text_response("life goes on")], agent_id="main")
    assert ss.displaced_tip(store, session_id) == r3, (
        "later linear appends move head but displace nothing, so they record nothing")
    assert r3 not in ss.path_row_ids(store, session_id), "the tip really is off-path now"

    cut = ss._walk_parents(store.connection, ss.displaced_tip(store, session_id))
    assert cut == [r3, r2, r1], (
        f"the folded turns are reachable by walking back from the displaced tip; got {cut}")


def test_the_full_fold_history_is_readable_in_order(tmp_path):
    """    Over a session that folded three times, the fold history returns all three displaced tips
    in head-move order, and its last element is what the single-value reader returns. Both
    answer emptily — the empty history, and `None` — for a session that never folded and for a
    session_id that does not exist, rather than raising.

    "Most recent" alone makes the FIRST fold's tip unreachable through the helper, which is
    precisely the addressability the log was built for and precisely what the reconstruction
    case needs every entry for. Ids only: nothing projects an off-path id to its content."""
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
    """    A `fork`-reasoned entry whose `from_message_id` is not NULL is not a branch point and the
    reader ignores it: `branch_point` answers `None` for the session that holds it — and still
    answers `None` once a NULL-origin row carrying a different reason sits beside it — while a
    genuine fork's branch point on the same store still resolves.

    A row like this records an ordinary non-linear move that happened to carry the fork
    reason, and its origin is the head it displaced. It is distinguishable from a real branch
    point — but only if the reader is specified to look, and without that the helper returns a
    plausible, wrong branch point for any session someone reached that way.

    The fixture is built through a raw connection, because `append` refuses the fork reason
    from every caller and the schema constrains nothing: an out-of-band writer is the case the
    reader's filter actually has to survive."""
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
    """A branch point is a log row that is BOTH origin-less and fork-reasoned: the reader
    answers `None` for a session whose only NULL-origin row carries the fold reason, while a
    genuine fork's branch point on the same store still resolves. On that same session
    `displaced_tip` answers `None` too — a fold that displaced nothing is indistinguishable
    from never having folded.

    Filtering on a NULL origin alone is sound only while a NULL origin means "fork". It does
    not: a session whose path is empty has no previous head, so any move recorded there —
    including a fold — carries a NULL origin. A reader that checks only the origin hands that
    row back as the branch point of a session nobody forked, which is exactly the wrong-answer
    failure the branch point is recorded rather than derived to avoid.

    The row is written through a raw connection because that is the route that survives every
    writer-side rule: the schema constrains the reason column not at all, so the reader is the
    guard that holds regardless of who wrote the row."""
    # provenance: the premise this closes was implicit in FK-A(c) and never written down —
    # a NULL origin was unreachable except through fork() until a linear reason-bearing move
    # became legal. PR-6 (executed) is what makes the fold-shaped route real.
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
    """    The head UPDATE and the conditional log INSERT ride inside the same transaction as the
    message rows: when a message partway through a batch cannot be stored, the whole call
    leaves nothing — no message row, head unmoved, and no log entry — and the identical batch
    with a storable payload commits all three effects together. **There is no state in which
    head moved and its log entry is missing.**

    The fault is real and lands mid-transaction: the second message of the batch is an object
    the REAL serializer refuses, after the first message's row has already been inserted. A
    fault at two further points inside one call cannot be addressed from outside it, so the
    non-linear arm is what covers the log INSERT specifically — a log row was due on that
    call, and wherever inside the transaction the fault lands, a fresh read shows no new row,
    head unmoved and no entry.

    The block stays synchronous: adding an `await` inside it reintroduces
    interleaved-transaction corruption across concurrently-dispatched gather sessions sharing
    one connection, which is why the new statements go inside the existing block rather than
    beside it."""
    # provenance: issue obligation 8; P11-P14 and P16. The fault object cites B8 (executed).
    # The coroutine-shape assertion records the no-await constraint; it is true of today's
    # code and does not discriminate on its own.
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
    """    A refused append is invisible to a later reader, whatever refused it: when the wait for a
    contended write expires before the transaction ever begins, when the database can no
    longer grow, and when a writer abandons an open transaction without committing, the file
    read back from scratch shows the complete pre-append state — head at its prior value, the
    log exactly as it was, no message row — and head and log agree with each other and with
    that state. A refusal for an unrelated reason leaves every previously recorded move
    intact.

    All three faults are real and no exception class is authored: a genuine second connection
    really holds the write lock with the store's own `busy_timeout` lowered so the real wait
    really expires; the database is really taken to its real growth ceiling; a real open
    transaction is really abandoned on a real second connection."""
    # provenance: P1, P2 (the class is deliberately unpinned — the assertion is the rollback),
    # P7, P8 and P86. rp-c1 (executed) measured the exhaustion failure: SQLITE_FULL with
    # already-committed rows still readable. What a contention outlasting the timeout raises
    # is unprobed, which is why nothing here names its class.
    ss = store_mod()
    base = runs_base(tmp_path)
    real = ss.open_store(case_id="case-alpha", runs_base=base)
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

    reopened = ss.open_store(case_id="case-alpha", runs_base=base)
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
    """    A caller-supplied `seq` that collides with an existing row drives the UNIQUE constraint
    and rolls the whole call back identically to a payload failure: head and log are left
    exactly where they were, and the connection stays usable afterwards."""
    # provenance: P37, the one failure shape a probe drove end to end. PR-9 (executed, on the
    # real append): zero message and message_payload rows survive, the tip is unchanged, a
    # subsequent append succeeds — and the organic case cannot arise, since _next_seq
    # recomputes MAX(seq)+1 before every insert, so the explicit coordinate is the only route.
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
    """    Every foreign key this change relies on is enforced at write time and every violation
    rolls the whole call back: an append into a session_id that does not exist raises and
    leaves no row, an append naming a parent id that does not exist raises inside the
    transaction and leaves head unmoved with nothing logged, a head UPDATE naming a message
    that does not exist raises the identical error an INSERT-time violation does — while the
    same UPDATE to a real row succeeds — and a log row naming a message or a session that does
    not exist is refused by the log's own keys.

    A head naming a row that does not exist is unreachable through the store's own API, which
    is what the raw UPDATE arm establishes from the other side."""
    # provenance: P3, P4, P22, P34 and P36. PR-8 (executed) probed the UPDATE path B9 had not
    # and confirmed PRAGMA foreign_keys is ON on the real connection; PR-4: message.session_id
    # does carry a key to session; PR-10: a nonexistent parent raises at the INSERT inside
    # BEGIN IMMEDIATE. P29 collapses onto this.
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
    """    The key on `head_message_id` requires only that SOME message row with that id exists,
    never that its session_id matches: a head pointed at another session's row is accepted, and
    the walk from it returns that session's rows as this one's path and hydrate output.
    Nothing catches it — no CHECK, no trigger, no application guard — and the fork case makes
    the same permissiveness ordinary rather than pathological.

    This pins the PERMISSIVENESS as the contract, so a later change that quietly adds
    confinement is caught and the absence stays examined rather than assumed."""
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
