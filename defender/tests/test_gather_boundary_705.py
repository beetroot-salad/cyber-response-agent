"""gather_boundary SQL view over model-authored args: malformed/over-deep args null their own row, session and fold scoping, cyclic parent chains, inert SQL-shaped content."""
from __future__ import annotations

import json
import sqlite3

import pytest

from defender.tests._session_store_705 import (
    make_store,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)


def _append_gather_call(store, session_id: str, args, *, tool_call_id: str,
                        tool_name: str = "gather") -> int:
    """One model-authored tool call, through the real append path."""
    return store.append(session_id, [tool_call_response(tool_name, args,
                                                        tool_call_id=tool_call_id)],
                        agent_id="main")[0]


def test_gather_boundary_extracts_lead_id_across_all_three_args_shapes(tmp_path):
    """The view returns the `lead_id` for dict-shaped args and for JSON-string args, and NULL for a
    malformed args string, in ONE query over a table holding all three."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    dict_row = _append_gather_call(store, session_id, {"lead_id": "l-003"}, tool_call_id="d")
    string_row = _append_gather_call(store, session_id, json.dumps({"lead_id": "l-004"}),
                                     tool_call_id="s")
    bad_row = _append_gather_call(store, session_id, '{"lead_id": "l-005"',
                                  tool_call_id="m")

    rows = dict(sql(store, "SELECT message_id, lead_id FROM gather_boundary"))
    assert rows.get(dict_row) == "l-003", rows
    assert rows.get(string_row) == "l-004", (
        "the JSON-string shape is production's; a single json_extract returns NULL here")
    assert rows.get(bad_row) is None, rows


def test_a_malformed_args_row_nulls_itself_without_aborting_the_query(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    healthy = [_append_gather_call(store, session_id, {"lead_id": f"l-{i:03d}"},
                                  tool_call_id=f"h{i}") for i in range(9)]
    poison = _append_gather_call(
        store, session_id,
        "not json at all — <script>; DROP TABLE message; -- \x01\x02",
        tool_call_id="poison")

    rows = dict(sql(store, "SELECT message_id, lead_id FROM gather_boundary"))
    assert len(rows) == len(healthy) + 1, (
        f"the query must survive and return every row; got {len(rows)}")
    assert rows[poison] is None
    assert [rows[m] for m in healthy] == [f"l-{i:03d}" for i in range(9)]


def test_args_shapes_outside_the_enumerated_three_null_without_aborting(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    cases = {
        "not-an-object": json.dumps(["l-001", "l-002"]),
        "scalar": json.dumps("l-001"),
        "none": json.dumps(None),
        "absent-key": json.dumps({"system": "elastic"}),
        "double-encoded": json.dumps(json.dumps({"lead_id": "deep"})),
    }
    ids = {label: _append_gather_call(store, session_id, value, tool_call_id=label)
           for label, value in cases.items()}
    ids["duplicate-key"] = _append_gather_call(
        store, session_id, '{"lead_id": "first", "lead_id": "second"}',
        tool_call_id="duplicate-key")
    ids["object-lead-id"] = _append_gather_call(
        store, session_id, {"lead_id": {"nested": "oops"}}, tool_call_id="object-lead-id")
    ids["array-lead-id"] = _append_gather_call(
        store, session_id, {"lead_id": ["a", "b"]}, tool_call_id="array-lead-id")
    control = _append_gather_call(store, session_id, {"lead_id": "l-ok"},
                                  tool_call_id="control")

    rows = dict(sql(store, "SELECT message_id, lead_id FROM gather_boundary"))
    assert rows[control] == "l-ok", "positive control: the query still works at all"
    for label in ("not-an-object", "scalar", "none", "absent-key", "double-encoded"):
        assert rows[ids[label]] is None, f"{label} must null cleanly, got {rows[ids[label]]!r}"
    assert rows[ids["duplicate-key"]] == "first", (
        "PR5: json_each yields both members; the extraction takes the first occurrence")
    assert rows[ids["object-lead-id"]] == '{"nested":"oops"}', (
        "PR5: a substructure comes back as compact JSON TEXT, not NULL and not an error")
    assert rows[ids["array-lead-id"]] == '["a","b"]', rows[ids["array-lead-id"]]


def test_over_depth_args_does_not_abort_the_whole_gather_boundary_query(tmp_path):
    """One `args` value nested past SQLite's JSON parser depth ceiling nulls its own row and every
    other row in the same query still returns its `lead_id` — the whole view does not abort."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    healthy = [_append_gather_call(store, session_id, {"lead_id": f"l-{i:03d}"},
                                  tool_call_id=f"h{i}") for i in range(9)]
    depth = 5000
    over_deep = "[" * depth + "1" + "]" * depth
    poison = _append_gather_call(store, session_id, '{"lead_id": ' + over_deep + "}",
                                 tool_call_id="over-depth")

    assert store.connection.execute(
        "SELECT json_valid(?)", ("[" * 1001 + "1" + "]" * 1001,)).fetchone()[0] == 0, (
        "the depth ceiling this demand exists for is not present on this build — "
        "re-probe adv:PO2 before trusting the assertion below")

    try:
        rows = dict(sql(store, "SELECT message_id, lead_id FROM gather_boundary"))
    except sqlite3.OperationalError as exc:  # the shipped behaviour adv:PO2 measured
        pytest.fail(f"one crafted args row aborted the whole boundary query: {exc}")
    assert rows[poison] is None
    assert [rows[m] for m in healthy] == [f"l-{i:03d}" for i in range(9)], (
        "the healthy rows must survive the poison row")


def test_gather_boundary_stays_narrowed_to_kind_response(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    response_row = _append_gather_call(store, session_id, {"lead_id": "l-visible"},
                                       tool_call_id="r1")
    store.append(session_id, [tool_return_request(
        "gather", json.dumps({"lead_id": "l-hidden-in-a-request"}), tool_call_id="r1")],
        agent_id="main")
    store.append(session_id, [user_request(
        "investigate", instructions=json.dumps({"args": {"lead_id": "l-instructions"}}))],
        agent_id="main")

    lead_ids = {row[0] for row in sql(store, "SELECT lead_id FROM gather_boundary")}
    assert lead_ids == {"l-visible"}, lead_ids
    kinds = {row[0] for row in sql(store, "SELECT kind FROM gather_boundary")}
    assert kinds <= {"response"}, kinds
    assert sql(store, "SELECT message_id FROM gather_boundary") == [(response_row,)]


def test_gather_boundary_is_scoped_to_one_session(tmp_path):
    store = make_store(tmp_path)
    first = store.new_session(agent_id="main")
    first_row = _append_gather_call(store, first, {"lead_id": "l-first"}, tool_call_id="a")
    second = store.new_session(agent_id="main")
    _append_gather_call(store, second, {"lead_id": "l-second"}, tool_call_id="b")
    fork = store.fork(first, at_message_id=first_row)
    _append_gather_call(store, fork, {"lead_id": "l-fork"}, tool_call_id="c")

    for session_id, expected in ((first, {"l-first"}), (second, {"l-second"}),
                                 (fork, {"l-first", "l-fork"})):
        got = {row[0] for row in sql(
            store, "SELECT lead_id FROM gather_boundary WHERE session_id = ?", (session_id,))}
        assert got == expected, (
            f"session {session_id} saw {got}; the view must scope by the session's path")

    ss = store_mod()
    unscoped = sql(store, "SELECT session_id, message_id FROM gather_boundary")
    assert unscoped, "positive control: the unscoped read is not empty"
    for session_id, message_id in unscoped:
        assert message_id in ss.path_row_ids(store, session_id), (
            f"the unscoped read paired session {session_id} with message {message_id}, "
            "which is not on that session's path — the guarantee a caller-side "
            "predicate could not give")


def test_gather_boundary_drops_the_leads_a_fold_displaced(tmp_path):
    """A session that has folded stops serving the leads on the turns the fold cut."""
    ss, selection = store_mod(), selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    root_row = _append_gather_call(store, session_id, {"lead_id": "l-root"},
                                   tool_call_id="r")
    store.append(session_id, [tool_return_request("gather", "summary", tool_call_id="r")],
                 agent_id="main")
    gather_row = _append_gather_call(store, session_id, {"lead_id": "l-displaced"},
                                     tool_call_id="d")
    store.append(session_id, [tool_return_request("gather", "summary", tool_call_id="d")],
                 agent_id="main")

    def leads(sid: str) -> set:
        return {row[0] for row in sql(
            store, "SELECT lead_id FROM gather_boundary WHERE session_id = ?", (sid,))}

    assert leads(session_id) == {"l-root", "l-displaced"}, (
        "control: both leads are served before the fold")
    assert gather_row in ss.path_row_ids(store, session_id)

    selection.fold(store, session_id, agent_id="main", boundary=4)
    assert gather_row not in ss.path_row_ids(store, session_id), (
        "the fixture must actually displace the lead-bearing turn")
    assert root_row in ss.path_row_ids(store, session_id), (
        "the fixture must also leave a lead-bearing turn ON the path, or the assertion "
        "below cannot tell 'displaced' from 'the view went blank'")

    assert leads(session_id) == {"l-root"}, (
        "the fold displaced one lead-bearing turn and kept the other; the boundary must "
        "not still serve a lead off a row the conversation can no longer reach, and must "
        "still serve the one it can")
    assert gather_row not in {row[0] for row in sql(
        store, "SELECT message_id FROM gather_boundary")}, (
        "and it must be reachable from NO session, not merely filtered out of this "
        "one — an unscoped read is what the caller-side predicate never constrained")
    assert sql(store, "SELECT COUNT(*) FROM message WHERE session_id = ? AND kind = 'response'",
               (session_id,)) == [(2,)], (
        "and the displaced row is still IN the file — the view excludes it by path, "
        "not because anything deleted it")


def test_a_cyclic_parent_chain_ends_the_boundarys_walk_instead_of_hanging(tmp_path):
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    rows = [_append_gather_call(store, session_id, {"lead_id": f"l-{i}"}, tool_call_id=f"c{i}")
            for i in range(3)]

    raw = sqlite3.connect(str(store.path))
    raw.execute("UPDATE message SET parent_id = ? WHERE id = ?", (rows[-1], rows[0]))
    raw.commit()
    raw.close()

    seen = sql(store, "SELECT message_id FROM gather_boundary WHERE session_id = ?",
               (session_id,))
    assert sorted(r[0] for r in seen) == sorted(rows), seen
    assert len(seen) == len(set(seen)), f"the walk revisited a row: {seen}"

    with pytest.raises(ss.CyclicParentChain):
        ss.path_row_ids(store, session_id)


def test_a_thinking_part_shaped_like_a_sql_fragment_round_trips_inert(tmp_path):
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    hostile = "'; DROP TABLE message; --"
    store.append(session_id, [text_response(hostile)], agent_id="main")
    control = _append_gather_call(store, session_id, {"lead_id": "l-control"},
                                  tool_call_id="ctl")

    tables = {row[0] for row in sql(store, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "message" in tables, "the fragment executed"
    bodies = "".join(row[0] for row in sql(store, "SELECT payload FROM message_payload"))
    assert hostile in json.loads(json.dumps(bodies)), "the content must survive as inert text"
    rows = dict(sql(store, "SELECT message_id, lead_id FROM gather_boundary"))
    assert rows[control] == "l-control", "positive control: the boundary still extracts"
