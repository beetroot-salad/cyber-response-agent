"""#754 — the log as a record, the schema version, the two openers, and the readers.

The executable form of the `spec_graph_754.yaml` demands that bind `session_head_log` as a
table, `session` as a shape, `user_version`, `open_store_for_read`, the role-scoped reader
surface and the visualizer's session pick. Each test's docstring carries its demand's prose;
the ledger ids sit in a `# provenance:` comment beneath it.

**RED AGAINST `1cecad37` IS THE EXPECTED STATE.** `SCHEMA_VERSION` is 1, `_check_schema_version`
is wired exclusively to `hydrate` (C4/OC-1), `_migrate_session_columns` silently re-shapes a
pre-existing file (B7, executed) and `visualize_run.py:328` still carries the bare rowid
fallback the design never mentions (c12).

The version-refusal tests build their subject by hand — a real SQLite file carrying the shape
shipped before this change, stamped `PRAGMA user_version = 1`, left in the default `delete`
journal mode (`_session_head_754.legacy_v1_store_file`). That is what makes both halves of the
refusal observable rather than inferred: a refusal that had run the DDL would have left new
tables behind, and one that had run the WAL pragma would have left the file in WAL with
`-wal`/`-shm` sidecars beside it (PR-11 and PR-12, both executed).
"""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("pydantic_ai")

from defender.scripts.visualize import visualize_run  # noqa: E402
from defender.tests._session_head_754 import (  # noqa: E402
    DELIBERATE,
    file_shape,
    fresh_process_readback,
    head_of,
    legacy_v1_store_file,
    linear_turns,
    log_rows,
    message_ids,
    raised_by,
    sidecars,
)
from defender.tests._session_store_705 import (  # noqa: E402
    complete_pair,
    make_store,
    runs_base,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    user_request,
)


# the two tables' declared shape

def test_session_head_log_has_the_declared_shape(tmp_path):
    """    `session_head_log` is one STRICT table with SIX columns — an integer primary key, the
    `session_id` it belongs to, a NULLABLE `from_message_id` (the displaced head), a NOT NULL
    `to_message_id` (the new head), a nullable `attached_to_message_id` (the first inserted
    row's own parent) and a NOT NULL `reason` — and both head-move kinds land in it, a fold
    and a fork side by side, distinguished only by that reason."""
    # provenance: B9 (executed) verified the DDL is satisfiable verbatim on this connection —
    # STRICT accepts a NULL origin and refuses a bogus destination.
    # rejected: D1's alternative of three narrow columns — head_message_id plus
    # branch_point_message_id on `session`, and displaces_message_id on `message`. The one
    # table is chosen instead because it makes fork and fold ONE operation with two reasons
    # rather than two mechanisms sharing a substrate, which is what this test observes: the
    # two entries below differ in their reason and in nothing else structural.
    sel = selection_mod()
    store = make_store(tmp_path)

    columns = {row[1]: row for row in sql(store, "PRAGMA table_info(session_head_log)")}
    assert set(columns) == {"id", "session_id", "from_message_id", "to_message_id",
                            "attached_to_message_id", "reason"}, sorted(columns)
    assert columns["id"][5] == 1, "id is the table's primary key"
    assert [columns[c][2].upper() for c in ("id", "from_message_id", "to_message_id",
                                            "attached_to_message_id")] == ["INTEGER"] * 4
    assert columns["session_id"][2].upper() == columns["reason"][2].upper() == "TEXT"
    not_null = {name for name, row in columns.items() if row[3]}
    assert not_null == {"session_id", "to_message_id", "reason"}, (
        f"only the origin and the attachment point may be NULL; got {not_null}")

    ddl = sql(store, "SELECT sql FROM sqlite_master WHERE name = 'session_head_log'")[0][0]
    assert "STRICT" in ddl.upper(), ddl
    keys = {row[3]: (row[2], row[4]) for row in
            sql(store, "PRAGMA foreign_key_list(session_head_log)")}
    assert keys["session_id"][0] == "session"
    assert keys["from_message_id"] == keys["to_message_id"] == ("message", "id")
    assert keys["attached_to_message_id"] == ("message", "id")

    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)
    sel.fold(store, session_id, agent_id="main", boundary=2)
    fork = store.fork(session_id, at_message_id=r1)
    assert {e.reason for e in log_rows(store)} == {"fold", "fork"}, (
        "one table carries both head-move kinds")
    assert [e.session_id for e in log_rows(store)] == [session_id, fork]
    assert log_rows(store, fork)[0].from_message_id is None
    assert log_rows(store, session_id)[0].from_message_id == r2


def test_session_carries_head_message_id_and_no_fork_at_message_id(tmp_path):
    """    `session` carries `head_message_id`, an integer keyed to `message(id)`, and no longer
    carries `fork_at_message_id` at all; its other columns are unchanged and the table is
    still STRICT. The workflow that depended on the removed column — a fork's first append
    finding its branch point without the caller re-supplying it — still completes, now through
    the head column."""
    # provenance: R5 substitute for the removal. C1 (census): the column had no live reader
    # outside `_session_tip`, which this change also removes, so the removal's whole dependent
    # set is inside the delta.
    ss = store_mod()
    store = make_store(tmp_path)

    columns = {row[1]: row for row in sql(store, "PRAGMA table_info(session)")}
    assert set(columns) == {"session_id", "case_id", "parent_session_id", "agent_id",
                            "head_message_id", "truncated_by", "last_render_len"}, (
        sorted(columns))
    assert columns["head_message_id"][2].upper() == "INTEGER"
    assert not columns["head_message_id"][3], "a session with no head is the ordinary state"
    ddl = sql(store, "SELECT sql FROM sqlite_master WHERE name = 'session'")[0][0]
    assert "STRICT" in ddl.upper(), ddl
    keys = {row[3]: (row[2], row[4]) for row in sql(store, "PRAGMA foreign_key_list(session)")}
    assert keys["head_message_id"] == ("message", "id")
    assert keys["parent_session_id"][0] == "session"
    assert "fork_at_message_id" not in keys

    main = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, main, 2)
    fork = store.fork(main, at_message_id=r1)
    first = store.append(fork, [text_response("no re-supplied parent")], agent_id="main")[0]
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (first,)) == [(r1,)], (
        "the substitute carries the workflow the removed column used to")
    assert ss.path_row_ids(store, fork) == [r1, first]
    assert head_of(store, main) == r2


# the log as an append-only record

def test_no_head_log_row_is_ever_updated_or_deleted(tmp_path):
    """    No head move the store's own API can make ever rewrites or removes an entry already in the
    log: driving a long mixed run of folds, forks and ordinary turns leaves every earlier row
    byte-identical and still present, each new move only ADDING a row beside the ones already
    there.

    Append-only is a property of the WRITE SURFACE, not a SQL-enforced guarantee — the handle
    exposes no mutator for these rows — so the second half of this test shows a raw connection
    mutating and deleting one unopposed. Pinning "SQLite forbids it" would pin a guarantee
    nothing provides."""
    # provenance: P87, scoped by PR-22 (executed census): the only two production UPDATEs
    # anywhere target session.truncated_by and session.last_render_len; no trigger, no
    # constraint and no STRICT mechanism forbids a direct write.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 2)

    seen: list[tuple] = []
    counts: list[int] = []
    for boundary in (2, 3):
        sel.fold(store, session_id, agent_id="main", boundary=boundary)
        store.fork(session_id, at_message_id=head_of(store, session_id))
        store.append(session_id, [text_response(f"turn {boundary}")], agent_id="main")
        current = log_rows(store)
        assert current[:len(seen)] == seen, (
            f"an earlier row changed under a later head move: {current[:len(seen)]} != {seen}")
        seen = current
        counts.append(len(current))
    assert counts == sorted(set(counts)), f"the log only ever grew; got {counts}"
    assert counts[0] < counts[-1], (
        f"every move ADDS a row beside the ones already there; got {counts}")
    assert len(seen) == 4, seen

    store.connection.execute(
        "UPDATE session_head_log SET reason = 'rewind' WHERE id = ?", (seen[0].id,))
    store.connection.execute("DELETE FROM session_head_log WHERE id = ?", (seen[1].id,))
    after = log_rows(store)
    assert len(after) == 3, (
        "SQLite forbids the DELETE no more than the UPDATE: append-only is a property of "
        "the store's write surface, which exposes no mutator, not a constraint")
    assert after[0].reason == "rewind", after


def test_head_log_row_order_by_id_reproduces_head_move_order(tmp_path):
    """    Read in `id` order, the log reproduces the true order of the head moves that were made —
    folds and forks interleaved — skipping the gaps left by the linear turns between them, so
    a reader can replay the sequence without a timestamp column.

    Scoped to the documented single-writer, no-rollback shape and not beyond it."""
    # provenance: P88. PR-7 (executed): rowid reuse after a ROLLBACK is confirmed, but id order
    # never diverged from commit order in any construction tried, including a genuine second
    # writer connection — which BLOCKED on the first's held lock rather than racing it. PR-13
    # (census) then establishes two independent production writers cannot exist at all.
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 2)

    made: list[tuple[str, int]] = []
    for boundary in (2, 3, 4):
        displaced = head_of(store, session_id)
        frontier = sel.fold(store, session_id, agent_id="main", boundary=boundary)
        made.append(("fold", frontier))
        linear_turns(store, session_id, 2, label=f"quiet-{boundary}")
        fork = store.fork(session_id, at_message_id=displaced)
        made.append(("fork", displaced))
        assert head_of(store, fork) == displaced

    replayed = [(e.reason, e.to_message_id) for e in log_rows(store)]
    assert replayed == made, f"id order must replay head-move order; got {replayed}"
    assert len(replayed) == 6, (
        "the six recorded moves only: the six quiet turns between them left no row")
    ids = [e.id for e in log_rows(store)]
    assert ids == sorted(ids)


def test_a_message_id_named_by_both_a_fold_and_a_fork_entry_stays_independently_recoverable(
        tmp_path):
    """    One message id named by a fold entry as the tip it displaced AND by a fork entry as the
    branch point it opened stays independently recoverable from both sides: the two are
    distinct entries, nothing merges or dedupes by message id, and each reader answers from
    its own side of the log."""
    # provenance: P78, asserted against the raw log as well as through the helpers so it holds
    # whatever either reader does.
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1, r2, r3 = linear_turns(store, main, 3)

    fork = store.fork(main, at_message_id=r3)
    sel.fold(store, main, agent_id="main", boundary=3)

    entries = log_rows(store)
    named_by = [(e.session_id, e.reason) for e in entries
                if r3 in (e.from_message_id, e.to_message_id)]
    assert sorted(named_by) == sorted([(fork, "fork"), (main, "fold")]), named_by
    assert len(entries) == 2, f"two entries, neither merged into the other; got {entries}"

    assert ss.displaced_tip(store, main) == r3, "recoverable as the fold's displaced tip"
    assert ss.branch_point(store, fork) == r3, "and as the fork's branch point"
    assert ss.branch_point(store, main) is None
    assert ss.displaced_tip(store, fork) is None
    assert r2 not in ss.path_row_ids(store, main), "the fold displaced it"
    assert r1 in ss.path_row_ids(store, main), "and the lineage root survived it"


def test_the_log_reads_back_identically_from_a_second_process(tmp_path):
    """    After the run ends, a second process holding only the run dir resolves the store through
    the pointer file, opens it read-only and reads back exactly the same state:
    `head_message_id`, the path and every log row are identical for a head-set session AND for
    a NULL-head one.

    The log is ordinary committed SQLite state, which is what makes this true — so the test
    really runs a second interpreter rather than opening a second handle in this one."""
    # provenance: P83 + P121, grounded in F6/C11 (census): the visualizer opens the store
    # read-only after the fact through the run-dir pointer, and is the only cross-process
    # reader.
    ss = store_mod()
    sel = selection_mod()
    base = runs_base(tmp_path)
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    ss.write_case_pointer(run_dir, case_id="case-alpha", store_path=store.path)

    live_session = store.new_session(agent_id="main")
    linear_turns(store, live_session, 2)
    sel.fold(store, live_session, agent_id="main", boundary=2)
    store.fork(live_session, at_message_id=head_of(store, live_session))

    headless = store.new_session(agent_id="main")
    linear_turns(store, headless, 1, label="orphaned")
    store.connection.execute(
        "UPDATE session SET head_message_id = NULL WHERE session_id = ?", (headless,))

    expected = {
        session_id: (head_of(store, session_id), ss.path_row_ids(store, session_id),
                     [tuple(e) for e in log_rows(store, session_id)])
        for session_id in (live_session, headless)
    }
    store.close()

    resolved = ss.resolve_store_path(run_dir)
    elsewhere = fresh_process_readback(resolved, live_session, headless)

    for session_id, (head, path, entries) in expected.items():
        seen = elsewhere[session_id]
        assert seen["head"] == head, session_id
        assert seen["path"] == path, session_id
        assert [tuple(row) for row in seen["log"]] == entries, session_id
    assert expected[live_session][0] is not None, "the fixture carries a head-set session"
    assert expected[headless][0] is None, "and a NULL-head one"
    assert expected[headless][1] == []


# the reason domain has no SQL enforcement behind it

def test_reason_is_a_python_closed_set_not_a_sql_check(tmp_path):
    """    SQLite objects to nothing about a reason outside the closed set: a raw connection inserts
    a `rewind` entry into `session_head_log` and it lands, and a reader can still read it. The
    store's own module-level closed set is the entire enforcement — which is why adding a third
    reason later is a Python edit and not a migration, and why an out-of-set reason through
    `append` is refused by that check and by nothing else.

    A reason is not checked against the MOVE's shape either: the store cannot tell a
    compaction from a rewind, so a `fold` entry written over an arbitrary rewind is
    indistinguishable in the log from a genuine one, and pretending otherwise would invent a
    semantics the log does not carry."""
    # provenance: P47/P32.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)

    with pytest.raises(ss.StoreAppendError):
        store.append(session_id, [text_response("rewound")], agent_id="main",
                     parent_id=r1, reason="rewind")
    assert log_rows(store, session_id) == [], "the Python check refused it"

    store.connection.execute(
        "INSERT INTO session_head_log (session_id, from_message_id, to_message_id, reason) "
        "VALUES (?, ?, ?, 'rewind')", (session_id, r1, r2))
    smuggled = log_rows(store, session_id)
    assert [e.reason for e in smuggled] == ["rewind"], (
        "SQLite has no CHECK behind the closed set; a raw writer's third reason lands")
    assert smuggled[0].to_message_id == r2

    ddl = sql(store, "SELECT sql FROM sqlite_master WHERE name = 'session_head_log'")[0][0]
    assert "CHECK" not in ddl.upper(), (
        f"the enforcement is the Python constant, not the schema: {ddl}")
    assert ss.HEAD_MOVE_REASONS == ("fork", "fold"), (
        "control: the closed set the check reads is a module-level constant, so a third "
        "reason is a one-line Python edit")


# every role-scoped reader over a NULL-head session

def test_every_role_scoped_reader_returns_empty_for_a_null_head_session(tmp_path):
    """    Every role-scoped read of a session whose head is NULL returns empty — `send`, `analysis`
    and `actor` projections and the synthesized-flag projection alike — because all four derive
    from the same path walk, and the walk from no head yields no rows.

    The enumeration is how the four subjects are picked, not what is asserted about them: each
    reader is DRIVEN over the same session, first with head cleared and then with head
    restored, and the restored read is what makes "empty" a fact about the head rather than
    about a reader that returns nothing to anybody."""
    # provenance: P117 (2/2 after discounting one copy) and P116, settled by C7: all four
    # surfaces go through path_row_ids, so an empty path yields nothing on every one.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    live = [user_request("orientation"), *complete_pair()]
    landed = store.append(session_id, live, agent_id="main")
    store.append(session_id, [tool_call_response(tool_call_id="dangling")], agent_id="main")

    store.connection.execute(
        "UPDATE session SET head_message_id = NULL WHERE session_id = ?", (session_id,))

    empty = {
        "send": ss.hydrate(store, session_id, role="send"),
        "analysis": ss.hydrate(store, session_id, role="analysis"),
        "actor": ss.hydrate(store, session_id, role="actor"),
        "synthesized-flags": ss.synthesized_flags(store, session_id, role="analysis"),
    }
    assert empty == {via: [] for via in empty}, empty
    assert ss.path_row_ids(store, session_id) == []

    store.connection.execute(
        "UPDATE session SET head_message_id = ? WHERE session_id = ?", (landed[-1], session_id))
    restored = {
        "send": ss.hydrate(store, session_id, role="send"),
        "analysis": ss.hydrate(store, session_id, role="analysis"),
        "actor": ss.hydrate(store, session_id, role="actor"),
        "synthesized-flags": ss.synthesized_flags(store, session_id, role="analysis"),
    }
    for via, rows in restored.items():
        assert len(rows) == len(landed), (
            f"control: {via} returns the same rows once head names one; got {rows}")


def test_hydrate_fails_closed_on_an_unresolvable_path_element(tmp_path):
    """    When the walked path contains an id no `message` row resolves, every role-scoped read
    raises a NAMED `StoreError` rather than dying on an uncaught `KeyError` — the read path
    fails closed the way the write path already does.

    The walk terminates cleanly on such an id and returns it as the path's OLDEST element
    rather than raising or dropping it, so the failure surfaces one layer later, in a dict
    lookup, as an error no caller can classify. The exception's own class is not pinned beyond
    the family: what is demanded is that it is the store's, not the interpreter's. The live
    route is a corrupted chain rather than an API call — the foreign key keeps a phantom id
    out of both `parent_id` and `head_message_id` — which is why the fixture corrupts one
    through a raw connection."""
    # provenance: PR-3 (executed) measured the uncaught KeyError on the send and actor roles.
    # P29's consensus ('unreachable through the store's own API') is true of the WRITE path
    # only. This change makes it more reachable, not less: the walk's anchor stops being a
    # derived tip and becomes a plain column carrying no application guard.
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)
    assert len(ss.hydrate(store, session_id, role="analysis")) == 2, (
        "control: the same reads return the conversation while the chain resolves")

    # Direct file damage is the only route left: the foreign key on `parent_id` refuses this
    # on any connection the store hands out, so the corruption goes through a raw connection
    # that never issued the pragma — which is the shape #705's
    # `test_every_store_connection_sets_the_foreign_keys_pragma_itself` describes and the one
    # PR-3 drove.
    raw = sqlite3.connect(str(store.path))
    raw.execute("UPDATE message SET parent_id = 999999 WHERE id = ?", (r1,))
    raw.commit()
    raw.close()
    assert 999999 in ss.path_row_ids(store, session_id), (
        "the fixture must put the unresolvable id ON the walked path, as PR-3 measured")

    for role in ("send", "analysis", "actor"):
        failure = raised_by(ss.hydrate, store, session_id, role)
        assert isinstance(failure, ss.StoreError), (
            f"role {role}: the read must fail closed with the store's own error, not an "
            f"uncaught KeyError from a dict lookup; got {failure!r}")
    flags = raised_by(ss.synthesized_flags, store, session_id, "analysis")
    assert isinstance(flags, ss.StoreError), (
        f"the flag projection walks the same path and fails the same way; got {flags!r}")

    raw = sqlite3.connect(str(store.path))
    raw.execute("UPDATE message SET parent_id = NULL WHERE id = ?", (r1,))
    raw.commit()
    raw.close()
    assert [m for m in ss.hydrate(store, session_id, role="analysis")], (
        "control: with the chain repaired the same reader returns the conversation again")
    assert ss.path_row_ids(store, session_id) == [r1, r2]


# the schema version, and where the refusal lands

def test_a_fresh_store_stamps_schema_version_2(tmp_path):
    """    Opening a store on a path that does not exist yet SUCCEEDS and leaves the file stamped at
    the schema version this change ships — the new check cannot refuse the file it is itself
    creating — and reopening that same, now non-fresh, file succeeds too.

    This is the positive control for both the version-1 refusal and the deleted-shim negative."""
    # provenance: P67. PR-11 (executed, SQL-trace confirmed): today all the DDL runs and commits
    # BEFORE the fresh-only user_version stamp, which is the very last statement the opener
    # issues, so a check placed after the DDL meets an unstamped fresh file and refuses it.
    # PR-14 (executed): executescript commits per statement, so a partially built, unstamped
    # file can exist on disk.
    ss = store_mod()
    base = runs_base(tmp_path)

    assert ss.SCHEMA_VERSION == 2, "the bump this change ships"
    store = ss.open_store(case_id="case-fresh", runs_base=base)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 1)
    assert store.connection.execute("PRAGMA user_version").fetchone()[0] == 2
    assert ss.hydrate(store, session_id, role="analysis"), "the fresh file reads normally"
    store.close()

    shape = file_shape(store.path)
    assert shape["user_version"] == 2
    assert "session_head_log" in shape["objects"], shape["objects"]
    assert "head_message_id" in shape["session_columns"], shape["session_columns"]

    again = ss.open_store(case_id="case-fresh", runs_base=base)
    assert ss.path_row_ids(again, session_id) == message_ids(again, session_id), (
        "a non-fresh file at the current version reopens and reads")


def test_open_store_refuses_a_user_version_1_file(tmp_path):
    """    A store file stamped `PRAGMA user_version = 1` — the shape shipped before this change — is
    refused at `open_store` with `UnknownSchemaVersion` naming the version it found, rather
    than opened, migrated or read anyway.

    Version 1 is pinned as a NAMED case, not as a member of a computed pair: the shipped
    test's `(0, SCHEMA_VERSION + 1)` arithmetic becomes (0, 3) after the bump and leaves the
    exact case the obligation names covered by nothing. The refusal deliberately stops at the
    store boundary here; what the driver does with it is
    `test_a_store_error_during_setup_ends_the_run_through_the_handled_exit`."""
    # provenance: issue obligation 9, as narrowed by correction C2.
    ss = store_mod()
    base = runs_base(tmp_path)
    stale = legacy_v1_store_file(ss.store_path_for("case-stale", runs_base=base))
    assert file_shape(stale)["user_version"] == 1

    refusal = raised_by(ss.open_store, case_id="case-stale", runs_base=base)

    assert isinstance(refusal, ss.UnknownSchemaVersion), (
        f"a version-1 file must be refused at open; got {refusal!r}")
    assert "1" in str(refusal), f"the refusal names the version it found: {refusal}"

    fresh = ss.open_store(case_id="case-fresh", runs_base=base)
    assert fresh.path != stale, "control: a file at the current version opens"
    assert fresh.new_session(agent_id="main")


def test_open_store_refuses_before_any_ddl_or_wal_pragma(tmp_path):
    """    The refusal fires immediately after connecting and before anything else: a refused
    version-1 file is left byte-identical — no new table, no altered column, still in its
    original journal mode — and no `-wal`/`-shm` sidecar is left beside it, because the gate
    closes the connection before re-raising.

    A refusal that reshapes the file it refuses is not failing closed. The fixture is a
    hand-built file in the default journal mode precisely so both halves are observable rather
    than inferred: a refusal that had run the DDL would have left new tables behind, and one
    that had run the WAL pragma would have rewritten the header of the file it refuses."""
    # provenance: PR-11 (the DDL runs and commits before the stamp) and PR-12 (executed): with
    # the connection closed the refused file is byte-identical, but a raise propagating out
    # without the caller ever getting a handle to close LEAKS the connection and its sidecars
    # until process exit.
    ss = store_mod()
    base = runs_base(tmp_path)
    stale = legacy_v1_store_file(ss.store_path_for("case-stale", runs_base=base))
    before_bytes = stale.read_bytes()
    before = file_shape(stale)
    assert before["journal_mode"] == "delete", before
    assert "session_head_log" not in before["objects"], before

    refusal = raised_by(ss.open_store, case_id="case-stale", runs_base=base)

    assert isinstance(refusal, ss.StoreError), refusal
    assert stale.read_bytes() == before_bytes, (
        "the refused file must be byte-identical: nothing ran before the check")
    after = file_shape(stale)
    assert after["objects"] == before["objects"], (
        f"the DDL ran on a file the open was about to refuse: {after['objects']}")
    assert after["journal_mode"] == "delete", (
        "the WAL pragma ran before the check — it rewrites the header of the very file the "
        "open refuses")
    assert sidecars(stale) == [], (
        "PR-12's leak: the connection and its -wal/-shm sidecars must be closed before the "
        "raise, not left until process exit")


def test_open_store_for_read_refuses_a_stale_version_too(tmp_path):
    """    The reader refuses a stale file at the same point the writer does: `open_store_for_read` on
    a version-1 file raises rather than handing back a handle that fails one call later, so the
    refusal holds on EVERY via that reaches the store rather than on the writer's alone.

    The reader is the only opener that ever meets a file it did not create — the writer always
    mints its own fresh case_id file — so leaving it unchecked was exactly backwards. Both
    openers are driven against the same file, with a current-version file both of them open as
    the control."""
    # provenance: OC-1 (census) refuted 'open_store_for_read version-checks': the check is
    # wired exclusively to hydrate. C11 for the asymmetry, OC-2 for the writer's fresh file.
    ss = store_mod()
    base = runs_base(tmp_path)
    stale = legacy_v1_store_file(ss.store_path_for("case-stale", runs_base=base))

    reader_refusal = raised_by(ss.open_store_for_read, stale)
    writer_refusal = raised_by(ss.open_store, case_id="case-stale", runs_base=base)
    assert isinstance(reader_refusal, ss.UnknownSchemaVersion), (
        f"the reader is the opener that MEETS a stale file; got {reader_refusal!r}")
    assert isinstance(writer_refusal, ss.UnknownSchemaVersion), writer_refusal
    assert sidecars(stale) == [], "neither refusal leaks its connection"

    current = ss.open_store(case_id="case-current", runs_base=base)
    session_id = current.new_session(agent_id="main")
    linear_turns(current, session_id, 1)
    current.close()
    reader = ss.open_store_for_read(ss.store_path_for("case-current", runs_base=base))
    assert ss.path_row_ids(reader, session_id), (
        "control: the same reader opens and serves a file at the current version")


def test_an_unknown_user_version_is_still_refused_at_the_new_raise_point(tmp_path):
    """    A store whose `PRAGMA user_version` the store does not recognise is still refused — and the
    refusal now arrives at `open_store` itself, not one call later at the first read. Below the
    known version (0, the un-set sentinel), above it (3), and at a value nobody enumerated (99)
    alike, so the check is a general inequality and not a named-member list."""
    # provenance: correction C1 (binding), re-expressing #705's reader_refuses_an_unknown_user_
    # version at the new raise point; B16 (executed simulation) confirmed the shipped test
    # ERRORS once the check moves, because it calls open_store outside its pytest.raises block.
    # P64 (version 0 was never at risk) and P65/P66 via B6 (executed): an unenumerated 99 was
    # refused.
    ss = store_mod()
    base = runs_base(tmp_path)
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = store.new_session(agent_id="main")
    linear_turns(store, session_id, 1)
    path = store.path
    assert ss.hydrate(store, session_id, role="analysis"), "control: the known version reads"
    store.close()

    for bogus in (0, ss.SCHEMA_VERSION + 1, 99):
        raw = sqlite3.connect(str(path))
        raw.execute(f"PRAGMA user_version = {bogus}")
        raw.commit()
        raw.close()
        with pytest.raises(ss.UnknownSchemaVersion):
            ss.open_store(case_id="case-alpha", runs_base=base)
        with pytest.raises(ss.UnknownSchemaVersion):
            ss.open_store_for_read(path)

    raw = sqlite3.connect(str(path))
    raw.execute(f"PRAGMA user_version = {ss.SCHEMA_VERSION}")
    raw.commit()
    raw.close()
    reopened = ss.open_store(case_id="case-alpha", runs_base=base)
    assert ss.hydrate(reopened, session_id, role="analysis"), (
        "control: restored to the known version, the same file opens and reads again")


def test_no_alter_shim_reshapes_an_existing_store(tmp_path):
    """    No migration shim reshapes a pre-existing store: a file carrying the ORIGINAL five-column
    `session` table opens to a refusal and keeps all five columns, and its version is not
    re-stamped either. The recorded lineage is never falsely reported absent — it is simply
    inaccessible — and no migration path forward is named.

    The positive control is the fresh path on the same runs base, so "nothing was reshaped"
    cannot be satisfied by an opener that reshapes nothing because it creates nothing."""
    # provenance: D3, and the R5 substitute for the removal. B7 (executed): the shim grew that
    # table from five columns to seven with no version check and no error, so 'silently
    # re-shaped' is literal. P84.
    ss = store_mod()
    base = runs_base(tmp_path)
    legacy = legacy_v1_store_file(ss.store_path_for("case-legacy", runs_base=base),
                                  migrated=False)
    before = file_shape(legacy)
    assert before["session_columns"] == ["session_id", "case_id", "parent_session_id",
                                         "truncated_by", "last_render_len"], before

    refusal = raised_by(ss.open_store, case_id="case-legacy", runs_base=base)

    assert isinstance(refusal, ss.UnknownSchemaVersion), refusal
    after = file_shape(legacy)
    assert after["session_columns"] == before["session_columns"], (
        f"a shim ALTERed the table the open refused: {after['session_columns']}")
    assert "agent_id" not in after["session_columns"]
    assert "head_message_id" not in after["session_columns"]
    assert after["user_version"] == 1, "and its version was not re-stamped either"

    fresh = ss.open_store(case_id="case-fresh", runs_base=base)
    assert "head_message_id" in file_shape(fresh.path)["session_columns"], (
        "control: the fresh path still builds the current shape")


# the visualizer's pick

def _rendered_run(tmp_path, *, case_id: str = "case-alpha"):
    """A run dir whose pointer resolves a real store — the only thing `_main_session_analysis`
    is given."""
    ss = store_mod()
    base = runs_base(tmp_path)
    run_dir = tmp_path / f"run-{case_id}"
    run_dir.mkdir()
    store = ss.open_store(case_id=case_id, runs_base=base)
    ss.write_case_pointer(run_dir, case_id=case_id, store_path=store.path)
    return run_dir, store


def test_the_visualizer_picks_the_root_of_lineage_main_session(tmp_path):
    """    The transcript the visualizer renders is the ROOT-OF-LINEAGE main session's — the one whose
    `parent_session_id` is NULL — so a fork of main, which inherits `agent_id`, and a gather
    leg's session are both excluded from the pick even when the row ordering favours them.

    The counterfactual is what separates the predicate from the ordering: a forked main session
    is given a LOWER rowid than the session it forked from, which the API cannot produce but
    which a rowid-ordered pick would follow straight into the wrong transcript. The pick runs
    in the VISUALIZER'S process, and a wrong pick renders the wrong run silently — no error,
    just the wrong transcript."""
    # provenance: P113, grounded in B14 (executed): today's picker returns the true main only
    # because rowid ordering happens to favour it, and a fork of main is a second agent_id
    # 'main' row.
    run_dir, store = _rendered_run(tmp_path)
    leg = store.new_session(agent_id="gather-l1")
    linear_turns(store, leg, 1, agent_id="gather-l1", label="leg")
    main = store.new_session(agent_id="main")
    linear_turns(store, main, 2, label="the real conversation")
    fork = store.fork(main, at_message_id=head_of(store, main))
    store.append(fork, [text_response("only the fork said this")], agent_id="main")

    store.connection.execute(
        "UPDATE session SET rowid = -1 WHERE session_id = ?", (fork,))
    ordered = [r[0] for r in sql(store, "SELECT session_id FROM session ORDER BY rowid")]
    assert ordered[0] == fork, (
        "the counterfactual must make rowid order favour the fork, or the assertion is "
        "about ordering and not about the predicate")
    store.close()

    picked = visualize_run._main_session_analysis(run_dir)

    coords = [coord for _message, coord in picked]
    assert coords, "the pick must resolve a session and render its path"
    assert {c.split("/")[0] for c in coords} == {main}, (
        f"the root-of-lineage main session's own path, not the fork's or the leg's: {coords}")
    flat = " ".join(str(p.content) for message, _c in picked
                    for p in getattr(message, "parts", []) if hasattr(p, "content"))
    assert "only the fork said this" not in flat, flat
    assert "the real conversation" in flat, flat


def test_the_root_of_lineage_query_raises_on_zero_or_multiple_matches(tmp_path):
    """    When the root-of-lineage query does not resolve to exactly one session the visualizer
    RAISES instead of picking one: a store with no root-of-lineage main session at all fails
    loudly rather than falling back to whatever row happens to sort first, and a store with TWO
    independently-created main sessions fails loudly rather than rendering one of them
    silently.

    A second, independently created non-forked main session also satisfies the predicate, so
    the pick's uniqueness is a breakable presupposition rather than a guarantee; limiting the
    ambiguity away would turn it into a silently wrong transcript, which is the one failure
    this reader cannot afford. The raised class is deliberately unpinned; what is pinned is
    that a deliberate refusal happens instead of a transcript."""
    # provenance: P111 (the bare rowid fallback the design never mentions — a branch no test
    # can reach is worse than none) and P90 (the new finding the measurement surfaced).
    empty_dir, empty_store = _rendered_run(tmp_path, case_id="case-nomain")
    leg = empty_store.new_session(agent_id="gather-l1")
    linear_turns(empty_store, leg, 1, agent_id="gather-l1", label="leg")
    empty_store.close()

    missing = raised_by(visualize_run._main_session_analysis, empty_dir)
    assert missing is not None, (
        "with no root-of-lineage row the deleted fallback would have rendered the gather "
        "leg's transcript as the run's own")
    assert not isinstance(missing, DELIBERATE), (
        f"the refusal must be deliberate, not an incidental programming error: {missing!r}")

    two_dir, two_store = _rendered_run(tmp_path, case_id="case-twomain")
    first = two_store.new_session(agent_id="main")
    linear_turns(two_store, first, 1, label="first main")
    second = two_store.new_session(agent_id="main")
    linear_turns(two_store, second, 1, label="second main")
    assert sql(two_store, "SELECT COUNT(*) FROM session WHERE parent_session_id IS NULL "
                          "AND agent_id = 'main'") == [(2,)]
    two_store.close()

    ambiguous = raised_by(visualize_run._main_session_analysis, two_dir)
    assert ambiguous is not None, "two roots of lineage must be a caught error"
    assert not isinstance(ambiguous, DELIBERATE), f"{ambiguous!r}"

    one_dir, one_store = _rendered_run(tmp_path, case_id="case-onemain")
    only = one_store.new_session(agent_id="main")
    linear_turns(one_store, only, 1, label="the only main")
    one_store.close()
    assert visualize_run._main_session_analysis(one_dir), (
        "control: exactly one root of lineage renders its transcript")
