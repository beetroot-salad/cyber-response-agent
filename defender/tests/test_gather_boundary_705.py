"""#705 — `gather_boundary`, the danger-lens surface.

`args` is 100% model-authored (`ToolCallPart.args`), and a retried tool call leaves its
original response in the history, so a malformed `args` string is REACHABLE in production
rather than hypothetical. Every fixture here is real input through the real primitive:
the crafted `args` value is written into a real store through the real append path and the
real SQLite view is queried — no fake stands between the test and the engine, so the
taxonomy assumption ceases to exist rather than being pinned once.

The governing refutation:

  * **adv:PO2** — the guarded double `json_extract` does NOT survive all malformed JSON.
    `args` nested past SQLite's ~1000-level parser ceiling raises
    `OperationalError: malformed JSON` and aborts the ENTIRE query (measured: 1 poison row
    among 99 healthy → all 100 lost). O12/C17/M9's guard guarantee holds for garbage text
    and fails here, so `test_a_malformed_args_row_nulls_itself_without_aborting_the_query`
    is scoped to garbage text and the depth case is its own demand, red against HEAD
    because the design owes a depth guard nothing currently states.
"""
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
    """The view returns the `lead_id` for dict-shaped args and for JSON-string args, and
    NULL for a malformed args string, in ONE query over a table holding all three.

    A single `json_extract(p.value,'$.args.lead_id')` returns NULL on the production
    (Fireworks-served GLM) JSON-string shape — the guarded double extraction is what makes
    all three work, and the three shapes must be in one query or the guard's ordering is
    untested (C17)."""
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
    """A malformed args string of arbitrary GARBAGE TEXT nulls its own row only; the
    well-formed rows in the same query still return their `lead_id`, and SQLite raises no
    `malformed JSON` error.

    Positive control: `test_gather_boundary_extracts_lead_id_across_all_three_args_shapes`.
    SCOPE, per adv:PO2: this holds for garbage text and is REFUTED for over-depth nesting,
    which is `test_over_depth_args_does_not_abort_the_whole_gather_boundary_query`."""
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
    """Every `args` shape outside O12's enumerated three resolves without aborting the
    query: an array, a bare scalar, JSON null and an absent key all yield a clean NULL;
    a duplicate `lead_id` key resolves to the FIRST occurrence; an object- or
    array-valued `lead_id` returns that substructure's compact JSON serialization AS
    TEXT; and a double-encoded args string fails safe to NULL.

    Probed, not assumed — `dep:PO5`, `PR5` and `adv:PO3` (all executed) established each
    of these against SQLite 3.46.1, and this demand extends the domain past the three the
    design enumerated (FK16/R17)."""
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
    """One `args` value nested past SQLite's JSON parser depth ceiling nulls its own row
    and every other row in the same query still returns its `lead_id` — the whole view
    does not abort.

    adv:PO2 (executed) REFUTES the design's own guard claim: at depth 1000+ the guarded
    double `json_extract` raises `OperationalError: malformed JSON` out of the ENTIRE
    query — 1 poison row among 99 healthy lost all 100, not one. A single crafted tool
    argument is therefore a denial of service on the whole boundary. RED against HEAD is
    this demand's expected state: the design owes a depth guard it does not state."""
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
    """The view scans only `kind='response'` rows, so request payloads carrying the
    resolved `instructions` blob are never walked — the predicate C16 measured at
    21.6 ms → 0.4 ms over 2200 messages, asserted as a contract rather than as a timing.

    The discriminating fixture is a REQUEST row whose payload contains a `lead_id`-shaped
    value: an unnarrowed view would surface it."""
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
    """The boundary carries the scoping predicate ITSELF: a per-case file holding a
    second execution and a fork never serves one session another's leads, and the
    caller's `WHERE session_id = ?` chooses a session rather than repairing the view.

    FK16's second half, closed by #753. The discriminating half is the row an
    unscoped read must NOT be able to reach: `l-second` belongs to a session that is
    not on `first`'s path or `fork`'s, so a view that returned every response row in
    the file — the shape #744 shipped — would serve it to both. The fork DOES see the
    prefix it inherited (`l-first`): those turns are on its conversation, its
    defender genuinely holds them, and #696 has to be able to fork at one of them.

    The `session_id` column therefore names the session whose path the row is on, not
    the session that owns the row, so a shared prefix row appears once per descendant."""
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
    """A session that has folded stops serving the leads on the turns the fold cut.

    This is the half of #753 that only exists once compaction is on, and the half a
    session predicate alone cannot reach: the displaced rows still carry the folding
    session's `session_id`, so `WHERE session_id = ?` returns them. They are simply no
    longer reachable from the session's head — the fold reparents its frontier onto the
    lineage root — and a #696 boundary picker that saw them would fork the source
    defender from a state it no longer occupies.

    The positive control is the lead on the ROOT turn, which the fold reparents its
    frontier onto rather than displacing: the post-fold read must still serve `l-root`.
    Without a lead surviving the fold, "the displaced lead is gone" would be satisfied
    just as well by a view that returned nothing at all for a folded session."""
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
    """A `parent_id` chain that loops — reachable only by direct file damage, since the
    foreign key keeps a phantom id out of every write the store's own API can make —
    terminates the view's recursive walk and returns each row in the ring once.

    #753 put a recursion where the view previously had none, so a corrupted file gained a
    way to hang a reader. `UNION` is the guard: the repeated triple is discarded. The
    contract is deliberately WEAKER than the Python walk's on the same shape — the view
    degrades, `path_row_ids` raises — because a danger lens that never returns is worse
    than one that over-reports, while the reader that projects the conversation into a
    prompt must refuse outright."""
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
    """Model-authored content shaped like a SQL fragment is stored and returned as inert
    text: the reader never concatenates payload content into a query, so a
    `'; DROP TABLE message; --` ThinkingPart survives the round trip AND leaves the
    schema intact.

    Positive control: an ordinary lead still extracts through the same view in the same
    call, so the negative is not passing because the query stopped working."""
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
