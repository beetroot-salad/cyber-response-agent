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
    sql,
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
    """The boundary is asked for one session's leads and returns only that session's
    rows, so a per-case file holding a second execution AND a fork does not serve one
    session another's leads.

    FK16's second half is a design gap, not a probe question: O3 keys rows by
    `session_id`, O1 keys the FILE by `case_id`, and O11 puts a fork's rows in the same
    file — so the view as published cannot be correct for a forked case. The positive
    control is that each session's own lead IS reachable."""
    store = make_store(tmp_path)
    first = store.new_session(agent_id="main")
    _append_gather_call(store, first, {"lead_id": "l-first"}, tool_call_id="a")
    second = store.new_session(agent_id="main")
    _append_gather_call(store, second, {"lead_id": "l-second"}, tool_call_id="b")
    fork = store.fork(first, at_message_id=sql(store, "SELECT id FROM message LIMIT 1")[0][0])
    _append_gather_call(store, fork, {"lead_id": "l-fork"}, tool_call_id="c")

    for session_id, expected in ((first, {"l-first"}), (second, {"l-second"}),
                                 (fork, {"l-fork"})):
        got = {row[0] for row in sql(
            store, "SELECT lead_id FROM gather_boundary WHERE session_id = ?", (session_id,))}
        assert got == expected, (
            f"session {session_id} saw {got}; the view must carry a session predicate")


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
