"""The head log's schema, version refusal on stale stores, the two openers, and role-scoped readers."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import sqlite3

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.storage._session_head_754 import (  # noqa: E402
    DELIBERATE,
    file_shape,
    head_of,
    legacy_v1_store_file,
    linear_turns,
    log_rows,
    raised_by,
    session_analysis,
    sidecars,
)
from defender.tests.support.storage._session_store_705 import (  # noqa: E402
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
from defender.run_repository import SessionPaths  # noqa: E402


# the two tables' declared shape

def test_session_head_log_has_the_declared_shape(tmp_path):
    """`session_head_log` is one STRICT table with SIX columns — an integer primary key, the"""
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


# the log as an append-only record

def test_no_head_log_row_is_ever_updated_or_deleted(tmp_path):
    """No head move the store's own API can make ever rewrites or removes an entry already in the"""
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


def test_a_message_id_named_by_both_a_fold_and_a_fork_entry_stays_independently_recoverable(
        tmp_path):
    """One message id named by a fold entry as the tip it displaced AND by a fork entry as the"""
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


# the reason domain has no SQL enforcement behind it


# every role-scoped reader over a NULL-head session

def test_every_role_scoped_reader_returns_empty_for_a_null_head_session(tmp_path):
    """Every role-scoped read of a session whose head is NULL returns empty — `send`, `analysis`"""
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
    """When the walked path contains an id no `message` row resolves, every role-scoped read"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1, r2 = linear_turns(store, session_id, 2)
    assert len(ss.hydrate(store, session_id, role="analysis")) == 2, (
        "control: the same reads return the conversation while the chain resolves")

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

def test_open_store_refuses_a_user_version_1_file(tmp_path):
    """A store file stamped `PRAGMA user_version = 1` — the shape shipped before this change — is"""
    # provenance: issue obligation 9, as narrowed by correction C2.
    ss = store_mod()
    base = runs_base(tmp_path)
    stale = legacy_v1_store_file(ss.store_path_for("case-stale", sessions=SessionPaths(base)))
    assert file_shape(stale)["user_version"] == 1

    refusal = raised_by(ss.open_store, case_id="case-stale", sessions=SessionPaths(base))

    assert isinstance(refusal, ss.UnknownSchemaVersion), (
        f"a version-1 file must be refused at open; got {refusal!r}")
    assert "1" in str(refusal), f"the refusal names the version it found: {refusal}"

    fresh = ss.open_store(case_id="case-fresh", sessions=SessionPaths(base))
    assert fresh.path != stale, "control: a file at the current version opens"
    assert fresh.new_session(agent_id="main")


def test_open_store_for_read_refuses_a_stale_version_too(tmp_path):
    """The reader refuses a stale file at the same point the writer does: `open_store_for_read` on"""
    # provenance: OC-1 (census) refuted 'open_store_for_read version-checks': the check is
    # wired exclusively to hydrate. C11 for the asymmetry, OC-2 for the writer's fresh file.
    ss = store_mod()
    base = runs_base(tmp_path)
    stale = legacy_v1_store_file(ss.store_path_for("case-stale", sessions=SessionPaths(base)))

    reader_refusal = raised_by(ss.open_store_for_read, stale)
    writer_refusal = raised_by(ss.open_store, case_id="case-stale", sessions=SessionPaths(base))
    assert isinstance(reader_refusal, ss.UnknownSchemaVersion), (
        f"the reader is the opener that MEETS a stale file; got {reader_refusal!r}")
    assert isinstance(writer_refusal, ss.UnknownSchemaVersion), writer_refusal
    assert sidecars(stale) == [], "neither refusal leaks its connection"

    current = ss.open_store(case_id="case-current", sessions=SessionPaths(base))
    session_id = current.new_session(agent_id="main")
    linear_turns(current, session_id, 1)
    current.close()
    reader = ss.open_store_for_read(ss.store_path_for("case-current", sessions=SessionPaths(base)))
    assert ss.path_row_ids(reader, session_id), (
        "control: the same reader opens and serves a file at the current version")


# the store's session pick

def _rendered_run(tmp_path, *, case_id: str = "case-alpha"):
    """A run dir whose pointer resolves a real store — the only thing the pick is given."""
    ss = store_mod()
    base = runs_base(tmp_path)
    run_dir = tmp_path / fixture_uuid(f"run-{case_id}")
    run_dir.mkdir()
    store = ss.open_store(case_id=case_id, sessions=SessionPaths(base))
    ss.write_case_pointer(_run_handle_1165(run_dir), case_id=case_id, store_path=store.path)
    return run_dir, store



def test_the_session_pick_resolves_the_root_of_lineage_main_session(tmp_path):
    """The session the pick resolves is the ROOT-OF-LINEAGE main session — the one whose"""
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

    picked = session_analysis(run_dir)

    coords = [coord for _message, coord in picked]
    assert coords, "the pick must resolve a session and render its path"
    assert {c.split("/")[0] for c in coords} == {main}, (
        f"the root-of-lineage main session's own path, not the fork's or the leg's: {coords}")
    flat = " ".join(str(p.content) for message, _c in picked
                    for p in getattr(message, "parts", []) if hasattr(p, "content"))
    assert "only the fork said this" not in flat, flat
    assert "the real conversation" in flat, flat


def test_the_root_of_lineage_query_raises_on_zero_or_multiple_matches(tmp_path):
    """When the root-of-lineage query does not resolve to exactly one session the pick"""
    # provenance: P111 (the bare rowid fallback the design never mentions — a branch no test
    # can reach is worse than none) and P90 (the new finding the measurement surfaced).
    empty_dir, empty_store = _rendered_run(tmp_path, case_id="case-nomain")
    leg = empty_store.new_session(agent_id="gather-l1")
    linear_turns(empty_store, leg, 1, agent_id="gather-l1", label="leg")
    empty_store.close()

    missing = raised_by(session_analysis, empty_dir)
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

    ambiguous = raised_by(session_analysis, two_dir)
    assert ambiguous is not None, "two roots of lineage must be a caught error"
    assert not isinstance(ambiguous, DELIBERATE), f"{ambiguous!r}"

    one_dir, one_store = _rendered_run(tmp_path, case_id="case-onemain")
    only = one_store.new_session(agent_id="main")
    linear_turns(one_store, only, 1, label="the only main")
    one_store.close()
    assert session_analysis(one_dir), (
        "control: exactly one root of lineage renders its transcript")
