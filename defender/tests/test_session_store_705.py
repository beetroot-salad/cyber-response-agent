"""#705 — the per-case session store: schema, identity, durability, payloads, lineage.

The executable form of the demands in `spec_graph_705.yaml` that bind `session_store`,
`message`, `message_payload`, `session`, `config` and the path walk. Each test carries
its demand's observable-outcome prose in its docstring (that docstring is what
`check_binds` scans in place of a demand `outcome`).

Two ledger refutations govern this file and are pinned as CORRECTIONS, never as
today's behaviour:

  * **PR1** — a `STRICT INTEGER` column does *not* reject a Python `bool`, a numeric
    `str` or an integer-valued `float`; all three silently coerce. Only a fractional
    `float` and `bytes` are rejected. So `test_store_connection_is_strict_fk_wal_with_a_busy_timeout`
    pins that STRICT/FK/WAL/busy_timeout are SET and says nothing about type rejection,
    and the coordinate type guard is a separate, application-level demand
    (`test_the_store_refuses_a_wrong_typed_coordinate_at_its_own_boundary`, FK21(ii)).
  * **adv:PO4 / dep:PO7** — `dump_python` silently coerces `set`→`list`, `bytes`→base64,
    `NaN`/`Inf`→`None`, and an unrecognized field is accepted then dropped on re-dump.
    O5's "verbatim" is therefore already false with no writer at fault (R9), so the
    round-trip demands compare against the ORIGINAL value and state the coercion set.

Red against `4e4645aa` is the expected state: `runtime/session_store.py` does not exist.
"""
from __future__ import annotations

import json
import math
import sqlite3
import threading

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolReturnPart,
)

from defender.tests._session_store_705 import (
    complete_pair,
    make_store,
    nine_row_fixture,
    part_kind_zoo,
    runs_base,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)


# ==========================================================================
# the handle, the connection, the schema version
# ==========================================================================

def test_open_store_returns_a_per_case_handle(tmp_path):
    """Opening the store on a case_id returns a handle bound to that case's database
    file, and two sessions of the same case — including two separate executions of one
    investigation — open the same file and land in it together."""
    ss = store_mod()
    base = runs_base(tmp_path)

    first = ss.open_store(case_id="case-alpha", runs_base=base)
    s1 = first.new_session(agent_id="main")
    first.append(s1, [user_request("execution one")], agent_id="main")
    first.close()

    second = ss.open_store(case_id="case-alpha", runs_base=base)
    s2 = second.new_session(agent_id="main")
    second.append(s2, [user_request("execution two")], agent_id="main")

    other = ss.open_store(case_id="case-beta", runs_base=base)

    assert second.path == first.path, "two executions of one case must share one file"
    assert other.path != first.path, "a different case must not share the file"
    assert s1 != s2, "each execution mints its own session_id"
    sessions = {row[0] for row in sql(second, "SELECT session_id FROM session")}
    assert sessions == {s1, s2}, (
        f"both executions' sessions must live in the one per-case file; got {sessions}")


def test_store_connection_is_strict_fk_wal_with_a_busy_timeout(tmp_path):
    """A freshly opened store reports STRICT tables, foreign_keys on, journal_mode wal,
    and a non-zero busy_timeout, so a contended write waits instead of failing a
    fail-closed append.

    Deliberately silent about type rejection: PR1 refuted the 3/3 consensus that STRICT
    is a type guard. What STRICT buys here is pinned by what it DOES reject (a BLOB in
    an INTEGER column), never by what the consensus wrongly believed it rejects."""
    store = make_store(tmp_path)
    conn = store.connection

    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] > 0, (
        "a zero busy_timeout turns every fork contention into a fail-closed abort")

    ddl = {row[0]: row[1] for row in sql(
        store, "SELECT name, sql FROM sqlite_master WHERE type='table' AND sql IS NOT NULL")}
    assert ddl, "the store must create its own tables"
    for name, text in ddl.items():
        assert "STRICT" in text.upper(), f"table {name} is not STRICT: {text}"

    # what STRICT really does buy, re-probed live rather than inherited (PR1)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO message (session_id, agent_id, synthesized, seq, kind) "
                     "VALUES (?, ?, ?, ?, ?)", ("s", "main", 0, b"5", "request"))


def test_the_store_refuses_a_wrong_typed_coordinate_at_its_own_boundary(tmp_path):
    """A coordinate value of the wrong Python type — a bool, a numeric string or an
    integer-valued float where `seq` is required — is refused by the store's own
    validation before it reaches SQLite, because PR1 proved STRICT silently coerces all
    three (FK21(ii): the design has no coordinate type guard to fall back on).

    The positive control is the same append with a real `int`, which succeeds."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    ok = store.append(session_id, [user_request("well typed")], agent_id="main", seq=0)
    assert ok, "positive control: an int seq is accepted"

    for bad in (True, "1", 1.0):
        with pytest.raises((ss.StoreAppendError, TypeError, ValueError)) as caught:
            store.append(session_id, [user_request("badly typed")], agent_id="main", seq=bad)
        assert caught.value is not None, f"{bad!r} must be refused, not coerced"

    stored = sql(store, "SELECT seq, typeof(seq) FROM message ORDER BY id")
    assert stored == [(0, "integer")], (
        f"a coerced coordinate must never reach the table; got {stored}")


def test_reader_refuses_an_unknown_user_version(tmp_path):
    """A store whose `PRAGMA user_version` the reader does not know is refused with an
    error rather than migrated or read anyway; the version the writer stamps reads
    normally.

    `is:PO1` established that a never-versioned file reads 0, so the refusal is
    symmetric: below the known version (0, the un-set sentinel) and above it alike."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("hello")], agent_id="main")
    path = store.path

    known = store.connection.execute("PRAGMA user_version").fetchone()[0]
    assert known == ss.SCHEMA_VERSION, (
        "the writer must stamp the schema version it claims to write")
    assert ss.SCHEMA_VERSION != 0, (
        "0 is the un-set sentinel (is:PO1) — a fresh, never-stamped file must not read "
        "as a valid version")
    assert ss.hydrate(store, session_id, role="analysis"), "positive control: known version reads"
    store.close()

    for bogus in (0, ss.SCHEMA_VERSION + 1):
        raw = sqlite3.connect(str(path))
        raw.execute(f"PRAGMA user_version = {bogus}")
        raw.commit()
        raw.close()
        reopened = ss.open_store(case_id="case-alpha", runs_base=runs_base(tmp_path))
        with pytest.raises(ss.UnknownSchemaVersion):
            ss.hydrate(reopened, session_id, role="analysis")


def test_every_store_connection_sets_the_foreign_keys_pragma_itself(tmp_path):
    """Every connection the store hands out issues `PRAGMA foreign_keys` itself, as its
    first statement and outside any transaction, so a second connection reaching the
    rows — the reader, the visualizer subprocess, an ad hoc script — enforces the
    foreign keys instead of getting them silently inert.

    `dep:PO2` (executed): `foreign_keys` is per-connection state, never persisted in the
    file; a fresh connection that skipped the pragma read `(0,)` and the identical
    FK-violating INSERT SUCCEEDED."""
    ss = store_mod()
    base = runs_base(tmp_path)
    writer = ss.open_store(case_id="case-alpha", runs_base=base)
    writer.new_session(agent_id="main")

    second = ss.open_store(case_id="case-alpha", runs_base=base)
    assert second.connection is not writer.connection, (
        "this demand is about a SECOND connection; sharing one hides the defect")
    assert second.connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    def _orphan_payload_insert() -> None:
        second.connection.execute(
            "INSERT INTO message_payload (message_id, payload) VALUES (?, ?)",
            (999999, "{}"))
        second.connection.commit()

    with pytest.raises(sqlite3.IntegrityError):
        _orphan_payload_insert()


def test_the_ddl_loads_on_the_sqlite_the_gate_actually_runs(tmp_path):
    """The published DDL executes with STRICT and foreign keys on against the sqlite3
    the test process is actually running, and the store refuses to open below STRICT's
    3.37 floor with a clear diagnostic rather than a syntax error.

    G18/X6 reframed U10: CI's interpreter is uv-managed python-build-standalone bundling
    its own libsqlite3, so a version NUMBER is the wrong assertion — making the DDL
    execute in-suite turns the gate itself into the standing probe."""
    ss = store_mod()
    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(ss.DDL)

    tables = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert {"config", "session", "message", "message_payload"} <= tables, tables
    views = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='view'").fetchall()}
    assert "gather_boundary" in views, views

    floor = (3, 37, 0)
    running = tuple(int(x) for x in sqlite3.sqlite_version.split("."))
    assert running >= floor, (
        f"STRICT needs sqlite >= 3.37; this interpreter runs {sqlite3.sqlite_version}")


# ==========================================================================
# append-only: the negative and its positive control
# ==========================================================================

def test_message_rows_are_never_updated_or_deleted(tmp_path):
    """Driving a fold and a fork issues no UPDATE and no DELETE against `message`; every
    row present after the first append is byte-identical at the end.

    Observed through SQLite's own authorizer callback, not through the writer's promise:
    a re-parent is always a NEWLY APPENDED row choosing its parent, which is why folded
    turns survive as an orphaned branch rather than being edited out (O4)."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("root")], agent_id="main")
    before = sql(store, "SELECT id, session_id, agent_id, seq, parent_id, kind FROM message")

    seen: list[tuple[int, str]] = []

    def authorizer(action, arg1, arg2, dbname, source):
        if arg1 == "message":
            seen.append((action, arg2 or ""))
        return sqlite3.SQLITE_OK

    store.connection.set_authorizer(authorizer)
    fixture = nine_row_fixture(store)
    store.fork(fixture["main"], at_message_id=fixture["row_ids"][5])
    store.connection.set_authorizer(None)

    mutations = [s for s in seen if s[0] in (sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE)]
    assert mutations == [], f"message must be append-only; saw {mutations}"

    after = sql(store, "SELECT id, session_id, agent_id, seq, parent_id, kind FROM message "
                       "WHERE id <= ?", (before[-1][0],))
    assert after == before, "an existing row changed under a fold/fork"


def test_message_rows_are_appended_by_every_writer(tmp_path):
    """Both the renderer's append path and the ingest path add new `message` rows, so
    the append-only negative above is not passing because nothing ever wrote."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    rendered = store.append(session_id, [user_request("rendered")],
                            agent_id="main", synthesized=True)
    ingested = store.append(session_id, complete_pair(), agent_id="main")

    assert len(rendered) == 1, rendered
    assert len(ingested) == 2, ingested
    rows = sql(store, "SELECT id, synthesized FROM message ORDER BY id")
    assert [r[0] for r in rows] == rendered + ingested
    assert [r[1] for r in rows] == [1, 0, 0], (
        "the synthesized flag must distinguish the two writers' rows")


# ==========================================================================
# payloads — round-trip, coercion, unknown fields, the encoding
# ==========================================================================

def test_ingested_payload_round_trips_verbatim(tmp_path):
    """Every ingested row's stored payload re-validates into a ModelMessage that
    re-dumps byte-identically to the dump of the ORIGINAL object, ThinkingParts and the
    `instructions` blob included.

    Compared against the original, never stored-to-stored: adv:PO4 showed a
    stored-to-stored comparison passes `None == None` on a value dump_python silently
    coerced."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    originals = part_kind_zoo()
    store.append(session_id, originals, agent_id="main")

    original_dump = ModelMessagesTypeAdapter.dump_python(originals, mode="json")
    stored = [json.loads(row[0]) for row in
              sql(store, "SELECT payload FROM message_payload ORDER BY message_id")]
    assert stored == original_dump, "the stored payload is not the original dump"

    revalidated = ModelMessagesTypeAdapter.validate_python(stored)
    assert ModelMessagesTypeAdapter.dump_python(revalidated, mode="json") == original_dump

    kinds = [p.get("part_kind") for msg in stored for p in msg.get("parts", [])]
    assert "thinking" in kinds, "the ThinkingPart must survive, not be dropped in setup"


def test_a_silently_coerced_payload_value_is_not_reported_as_a_verbatim_round_trip(tmp_path):
    """A payload value `dump_python` silently coerces — `set`→`list`, `bytes`→base64,
    `NaN`/`Inf`→`None` — is either refused at append or surfaced as a coercion; it is
    never reported back as a verbatim round trip of the original.

    adv:PO4 (executed) BREACHED O5 here with no writer at fault: dump_python raises only
    on a genuinely unknown Python type and on a circular reference, neither reachable
    from this tree's tools. The assertion is taken against the ORIGINAL value."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    coercions = [
        ("set", {1, 2, 3}),
        ("bytes", b"\x00\x01raw"),
        ("nan", float("nan")),
        ("inf", float("inf")),
    ]
    for label, value in coercions:
        message = ModelRequest(parts=[ToolReturnPart(
            tool_name="query", content=value, tool_call_id=f"c-{label}")])
        try:
            store.append(session_id, [message], agent_id="main")
        except ss.PayloadNotRepresentable:
            continue  # refused at append — the fail-closed reading, also acceptable
        row = sql(store, "SELECT payload FROM message_payload ORDER BY message_id DESC LIMIT 1")
        recovered = ModelMessagesTypeAdapter.validate_json(f"[{row[0][0]}]")[0]
        got = recovered.parts[0].content
        if isinstance(value, float) and math.isnan(value):
            assert got is None or (isinstance(got, float) and math.isnan(got))
            assert got is not None, (
                "NaN silently became None (adv:PO4) — the store must not call that a "
                "verbatim round trip")
        else:
            assert got == value, (
                f"{label}: stored value {got!r} is not the original {value!r}; "
                "adv:PO4's coercion must be refused or reported, not silently accepted")


def test_a_payload_field_the_installed_adapter_does_not_recognize_is_dropped_on_re_dump(tmp_path):
    """A stored payload carrying a field the installed adapter does not recognize is
    detected by the store rather than silently accepted and dropped, while a
    ThinkingPart's six real fields — content, id, signature, provider_name,
    provider_details, part_kind — round-trip byte-identically including nested
    provider_details.

    dep:PO7 / is:PO2 (executed): validation does NOT raise on an unrecognized field at
    either message or part level; the field is silently accepted and DROPPED on re-dump,
    so a version skew is invisible through the payload."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    real = ModelResponse(parts=[ThinkingPart(
        content="weighing", id="th-1", signature="sig",
        provider_name="anthropic", provider_details={"nested": {"a": [1, 2]}})])
    store.append(session_id, [real], agent_id="main")
    dumped = ModelMessagesTypeAdapter.dump_python([real], mode="json")
    stored = json.loads(sql(store, "SELECT payload FROM message_payload ORDER BY message_id")[0][0])
    assert stored == dumped[0], "ThinkingPart's real fields must round-trip byte-identically"

    skewed = json.loads(json.dumps(dumped[0]))
    skewed["totally_unknown_message_field"] = 1
    skewed["parts"][0]["totally_unknown_part_field"] = 2
    with pytest.raises(ss.PayloadSchemaSkew):
        ss.load_payload(json.dumps(skewed))


def test_the_store_append_encoding_is_pinned_against_a_lone_surrogate(tmp_path):
    """A payload carrying a lone surrogate — reachable through `json.loads('"\\ud800"')`
    on a provider body, with no decoder involved — produces the same, stated outcome
    every time, because the store names its `ensure_ascii` rather than inheriting it.

    R9 pins this: adv:PO4 found the only content-triggered halt that really exists sits
    at the SQLite bind, and whether it fires is decided entirely by an unstated keyword.
    A security-relevant availability property must not rest on a default nobody wrote
    down; the positive control is ordinary non-BMP text (PR3), which must survive."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    assert ss.PAYLOAD_ENSURE_ASCII is True, (
        "the encoding must be stated; with ensure_ascii=False the same content raises "
        "UnicodeEncodeError at the bind (adv:PO4)")

    control = ModelRequest(parts=[ToolReturnPart(
        tool_name="query", content="before\x00mid\U0001F4A9after", tool_call_id="ok")])
    store.append(session_id, [control], agent_id="main")
    got = ModelMessagesTypeAdapter.validate_json(
        f"[{sql(store, 'SELECT payload FROM message_payload ORDER BY message_id')[0][0]}]")[0]
    assert got.parts[0].content == "before\x00mid\U0001F4A9after", (
        "PR3: NUL and non-BMP survive as escapes; the control must not be the thing "
        "that breaks")

    lone = json.loads('"\\ud800"')
    hostile = ModelRequest(parts=[ToolReturnPart(
        tool_name="query", content=lone, tool_call_id="surrogate")])
    store.append(session_id, [hostile], agent_id="main")
    rows = sql(store, "SELECT payload FROM message_payload ORDER BY message_id")
    assert len(rows) == 2, (
        "with the encoding pinned, a lone surrogate must not halt the append — a "
        "zero-privilege availability attack on the defender via alert text")


def test_payload_sha_digests_the_stored_payload_text_at_write_time(tmp_path):
    """`message_payload.payload_sha` is the digest of the payload TEXT as stored, taken
    at write time — an integrity check, never an identity and never a diffing key.

    R15 resolved the dangling bind by keeping the column and minting this demand: two
    rows with identical payload text carry identical `payload_sha` and are still two
    distinct rows, so nothing may use the digest to deduplicate or to match on ingest
    (invariant 3)."""
    import hashlib

    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    twin = text_response("identical body")
    store.append(session_id, [twin], agent_id="main")
    store.append(session_id, [twin], agent_id="main")

    rows = sql(store, "SELECT message_id, payload, payload_sha FROM message_payload "
                      "ORDER BY message_id")
    assert len(rows) == 2, "identical payloads must remain two rows"
    for _mid, payload, sha in rows:
        assert sha == hashlib.sha256(payload.encode("utf-8")).hexdigest(), (
            "payload_sha must digest the payload text exactly as stored")
    assert rows[0][2] == rows[1][2], "identical text, identical digest — by construction"
    assert rows[0][0] != rows[1][0], "the digest is not an identity"


# ==========================================================================
# lineage: the path walk, ordering, cycles
# ==========================================================================

def test_path_exactness_nine_row_fixture(tmp_path):
    """Over the nine-row fixture `fork-a`'s tip walks to exactly 1,5,6,8,9 and `main`'s
    to exactly 1,5,6,7; rows 2,3,4 lie on no path from any tip; and re-parenting the
    frontier to row 4 instead of the root makes `fork-a` walk to a strict superset —
    the counterfactual that proves the assertion is about the parent chain and not about
    row ordering."""
    ss = store_mod()
    store = make_store(tmp_path)
    fx = nine_row_fixture(store)
    ids = fx["row_ids"]

    main_path = ss.path_row_ids(store, fx["main"])
    fork_path = ss.path_row_ids(store, fx["fork_a"])
    assert main_path == [ids[1], ids[5], ids[6], ids[7]], main_path
    assert fork_path == [ids[1], ids[5], ids[6], ids[8], ids[9]], fork_path

    on_a_path = set(main_path) | set(fork_path)
    assert {ids[2], ids[3], ids[4]}.isdisjoint(on_a_path), (
        "the folded turns must lie on no path from any tip")

    # counterfactual: a frontier parented to row 4 drags the folded turns back on
    other = make_store(tmp_path, case_id="case-counterfactual")
    fx2 = nine_row_fixture(other)
    ids2 = fx2["row_ids"]
    other.connection.execute("UPDATE message SET parent_id = ? WHERE id = ?",
                             (ids2[4], ids2[5]))
    other.connection.commit()
    dragged = ss.path_row_ids(other, fx2["fork_a"])
    assert ids2[4] in dragged, (
        "re-parenting the frontier to row 4 must make fork-a walk a superset")
    assert {ids2[2], ids2[3], ids2[4]} <= set(dragged)
    assert len(dragged) > len(fork_path), (dragged, fork_path)


def test_order_comes_from_the_parent_chain_not_from_seq(tmp_path):
    """A fork that restarts `seq` at 0 still reads back in true send order, because order
    is the parent chain and nothing records membership separately (O9).

    The discriminating fixture is a fork whose own rows carry seq 0,1 while the prefix it
    inherits carries higher seq values: an implementation that sorted by seq would emit
    the fork's rows first."""
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1 = store.append(main, [user_request("root")], agent_id="main", seq=0)[0]
    r2 = store.append(main, [tool_call_response(tool_call_id="a")], agent_id="main",
                      seq=1, parent_id=r1)[0]
    r3 = store.append(main, [tool_return_request(tool_call_id="a")], agent_id="main",
                      seq=2, parent_id=r2)[0]

    fork = store.fork(main, at_message_id=r3)
    f1 = store.append(fork, [text_response("fork first")], agent_id="main",
                      seq=0, parent_id=r3)[0]
    f2 = store.append(fork, [user_request("fork second")], agent_id="main",
                      seq=1, parent_id=f1)[0]

    assert ss.path_row_ids(store, fork) == [r1, r2, r3, f1, f2]
    seqs = [row[0] for row in sql(store,
            "SELECT seq FROM message WHERE session_id = ? ORDER BY id", (fork,))]
    assert seqs == [0, 1], f"the fork must be free to restart seq at 0; got {seqs}"

    messages = ss.hydrate(store, fork, role="analysis")
    texts = [p.content for m in messages for p in m.parts if isinstance(p, TextPart)]
    assert texts == ["fork first"], texts


def test_the_path_walk_refuses_a_cyclic_parent_chain(tmp_path):
    """A cyclic `parent_id` chain is refused by the walk with a loud error rather than
    walked forever: `hydrate` carries its own depth cap or cycle guard.

    dep:PO1 (executed): SQLite's recursive CTE does NOT detect a cycle, does NOT error
    and does NOT truncate — it alternated between two mutually-parented rows for
    2,000,000 rows before the probe broke out manually. There is no free lunch from the
    engine, and the design does not name the gap."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    a = store.append(session_id, [user_request("a")], agent_id="main")[0]
    b = store.append(session_id, [text_response("b")], agent_id="main", parent_id=a)[0]
    store.connection.execute("UPDATE message SET parent_id = ? WHERE id = ?", (b, a))
    store.connection.commit()

    with pytest.raises(ss.CyclicParentChain):
        ss.hydrate(store, session_id, role="analysis")


# ==========================================================================
# identity: sessions, forks, case_id, config
# ==========================================================================

def test_a_fork_is_a_branch_with_no_prefix_copy_and_no_id_remap(tmp_path):
    """Constructing a fork writes one `session` row and sets its first message's
    `parent_id` to the fork point; the source's rows are not copied, no id is remapped,
    and no `forked_at_message` column exists."""
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1 = store.append(main, [user_request("root")], agent_id="main")[0]
    r2 = store.append(main, [text_response("branch here")], agent_id="main", parent_id=r1)[0]
    before = sql(store, "SELECT id, session_id, parent_id FROM message ORDER BY id")

    fork = store.fork(main, at_message_id=r2)
    f1 = store.append(fork, [user_request("fork continues")], agent_id="main", parent_id=r2)[0]

    after_source = sql(store, "SELECT id, session_id, parent_id FROM message "
                              "WHERE session_id = ? ORDER BY id", (main,))
    assert after_source == before, "a fork must not copy or remap the source's rows"
    assert sql(store, "SELECT parent_id FROM message WHERE id = ?", (f1,)) == [(r2,)]

    session_cols = {row[1] for row in sql(store, "PRAGMA table_info(session)")}
    assert "parent_session_id" in session_cols
    assert "forked_at_message" not in session_cols, (
        "lineage is the message parent chain; a second bookkeeping column is the drift "
        "finding 2 is about")
    parent = sql(store, "SELECT parent_session_id FROM session WHERE session_id = ?", (fork,))
    assert parent == [(main,)]


def test_two_forks_from_one_point_share_a_parent_id_and_differ_only_in_session_id(tmp_path):
    """Two forks taken from the same message are two rows with the same `parent_id` and
    different `session_id`s, each walking back through the shared prefix exactly once,
    and their two seq-0 rows are never conflated."""
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1 = store.append(main, [user_request("root")], agent_id="main", seq=0)[0]
    r2 = store.append(main, [text_response("fork point")], agent_id="main",
                      seq=1, parent_id=r1)[0]

    fa = store.fork(main, at_message_id=r2)
    fb = store.fork(main, at_message_id=r2)
    a1 = store.append(fa, [user_request("a")], agent_id="main", seq=0, parent_id=r2)[0]
    b1 = store.append(fb, [user_request("b")], agent_id="main", seq=0, parent_id=r2)[0]

    assert fa != fb
    assert sql(store, "SELECT parent_id FROM message WHERE id IN (?, ?) ORDER BY id",
               (a1, b1)) == [(r2,), (r2,)]
    assert ss.path_row_ids(store, fa) == [r1, r2, a1]
    assert ss.path_row_ids(store, fb) == [r1, r2, b1]
    assert ss.path_row_ids(store, fa).count(r1) == 1, "the shared prefix is walked once"


def test_case_id_is_inherited_by_a_fork_and_the_eval_join_key_is_not(tmp_path):
    """A fork's `session` row carries the source's `case_id` and a freshly minted
    `session_id`, so ticket screening still refuses the source's own ticket, while the
    eval dir-name join key does not follow the fork.

    FK1b/R17 correct O13's clause: `ticket_screen.self_case_key` returns `deps.run_id`
    today and its docstring pins that deliberately, so this demand asserts what the store
    carries — the inheritance — and records the screen's key as #696's gap, never
    asserting a keying the code contradicts."""
    store = make_store(tmp_path, case_id="case-alpha")
    main = store.new_session(agent_id="main")
    r1 = store.append(main, [user_request("root")], agent_id="main")[0]
    fork = store.fork(main, at_message_id=r1)

    rows = dict(sql(store, "SELECT session_id, case_id FROM session"))
    assert rows[fork] == rows[main] == "case-alpha", (
        f"case_id must be inherited by the fork; got {rows}")
    assert fork != main, "session_id is minted, not derived"

    from defender.tests._session_store_705 import runs_base as _rb
    other = store_mod().open_store(case_id="case-beta", runs_base=_rb(tmp_path))
    assert other.path != store.path, "case_id is what selects the file"


def test_config_row_is_content_addressed_over_the_reproducibility_set(tmp_path):
    """Two runs with identical models, corpus git_sha, prompt digests and library
    versions produce the same `config_sha`, and changing any one of the four changes it.

    FK19/R17: the serialization is canonical JSON — sorted keys, no whitespace — and all
    four fields are required, so the digest cannot depend on dict insertion order across
    two code paths (which would defeat O14's purpose with no warning signal)."""
    ss = store_mod()
    store = make_store(tmp_path)
    base = {"models": {"main": "m1"}, "corpus": {"git_sha": "abc"},
            "prompts": {"main": "p1"}, "versions": {"pydantic_ai": "1.107.0"}}

    sha = store.write_config(base)
    reordered = {k: base[k] for k in reversed(list(base))}
    assert store.write_config(reordered) == sha, (
        "insertion order must not change the digest — canonical JSON, sorted keys")

    for field in base:
        changed = {**base, field: {**base[field], "extra": "x"}}
        assert store.write_config(changed) != sha, f"changing {field} must change the sha"

    for field in base:
        incomplete = {k: v for k, v in base.items() if k != field}
        with pytest.raises(ss.IncompleteConfig):
            store.write_config(incomplete)

    stored = sql(store, "SELECT sha256 FROM config WHERE sha256 = ?", (sha,))
    assert stored == [(sha,)], "the config row is addressed by its own digest"


# ==========================================================================
# retention, absences, the session row's bookkeeping
# ==========================================================================

def test_payload_lives_in_its_own_table_and_retention_drops_only_bodies(tmp_path):
    """`DELETE FROM message_payload` for one session drops the bodies while leaving that
    session's coordinates, parent chain and `gather_boundary` rows intact and queryable —
    and X9's consequence is pinned with it: every per-response `model_name`, `usage`,
    `provider` and `finish_reason` fact lives ONLY in the payload and goes with it."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [
        user_request("investigate"),
        tool_call_response("gather", {"lead_id": "l-001"}, tool_call_id="g1"),
        tool_return_request("gather", "summary", tool_call_id="g1"),
    ], agent_id="main")

    message_cols = {row[1] for row in sql(store, "PRAGMA table_info(message)")}
    for absent in ("payload", "model_name", "usage", "provider", "finish_reason"):
        assert absent not in message_cols, (
            f"{absent} must live only in message_payload (O33/X9); found on message")

    before_boundary = sql(store, "SELECT lead_id FROM gather_boundary")
    before_path = sql(store, "SELECT id, parent_id, seq, kind FROM message ORDER BY id")

    store.connection.execute(
        "DELETE FROM message_payload WHERE message_id IN "
        "(SELECT id FROM message WHERE session_id = ?)", (session_id,))
    store.connection.commit()

    assert sql(store, "SELECT id, parent_id, seq, kind FROM message ORDER BY id") == before_path
    assert sql(store, "SELECT COUNT(*) FROM message_payload") == [(0,)]
    after_boundary = sql(store, "SELECT lead_id FROM gather_boundary")
    assert before_boundary != [], "the fixture recorded no boundary row to lose"
    assert after_boundary == [], (
        "the boundary view derives from the payload — retention taking it with the "
        "bodies is the fact X9 pins, not a bug the test hides")


def test_raw_gather_payloads_are_not_stored_in_the_message_payload_table(tmp_path):
    """A run whose gather leg wrote a large raw payload to `gather_raw/` stores only the
    summary the model saw; the raw bytes appear in no `message_payload` row.

    Positive control: `test_ingested_payload_round_trips_verbatim` — the summary the
    model DID see is stored, so this negative is not passing on an empty table."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    raw_marker = "RAW-ELASTIC-HIT-" + ("x" * 4096)
    summary = "3 hits, 2 hosts; details by ref"

    gather_raw = tmp_path / "run" / "gather_raw" / "l-001"
    gather_raw.mkdir(parents=True)
    (gather_raw / "0.json").write_text(json.dumps({"hits": raw_marker}))

    store.append(session_id, [tool_return_request("gather", summary, tool_call_id="g1")],
                 agent_id="main")

    bodies = "".join(row[0] for row in sql(store, "SELECT payload FROM message_payload"))
    assert summary in bodies, "positive control: the summary the model saw IS stored"
    assert raw_marker not in bodies, "the raw payload must stay by-ref in gather_raw/"


def test_no_maintained_tool_call_table_and_no_epoch_marker(tmp_path):
    """The schema contains no maintained `tool_call` projection table and no epoch-marker
    table or column; tool calls are derived with `json_each` at read time.

    Positive control: the store must actually be open and populated with its real tables
    (`message`, `session`) before the negative below means anything — otherwise an empty
    `names` set (a broken `store` handle, a wrong DB, a schema that failed to load) makes
    every `not any(...)` below pass vacuously, discriminating nothing."""
    store = make_store(tmp_path)
    names = {row[0].lower() for row in
             sql(store, "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"message", "session"} <= names, (
        f"the store must expose its real, populated schema, or the negative checks "
        f"below are vacuous; got {names}")
    assert not any("tool_call" in n for n in names), (
        f"a maintained second copy drifting from its source IS finding 2; got {names}")
    assert not any("epoch" in n for n in names), names

    all_cols: set[str] = set()
    for name in names:
        all_cols |= {row[1].lower() for row in sql(store, f"PRAGMA table_info({name})")}
    assert all_cols, "table_info over a real schema must yield real columns"
    assert not any("epoch" in c for c in all_cols), all_cols


def test_synthesized_rows_occupy_their_own_seq_address_space(tmp_path):
    """After a fold, the synthesized frontier and the next real message can both hold
    their own `seq` without collision, and `main#5` still names the fifth non-synthesized
    thing main produced."""
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    for i in range(5):
        store.append(session_id, [text_response(f"real {i}")], agent_id="main", seq=i)
    store.append(session_id, [user_request("FRONTIER")], agent_id="main",
                 synthesized=True, seq=0)
    store.append(session_id, [text_response("real 5")], agent_id="main", seq=5)

    rows = sql(store, "SELECT seq, synthesized FROM message ORDER BY id")
    coexist = "a synthesized seq 0 and a real seq 0 must coexist — separate address spaces"
    assert (0, 1) in rows, coexist
    assert (0, 0) in rows, coexist

    fifth = sql(store, "SELECT id FROM message WHERE session_id = ? AND agent_id = 'main' "
                       "AND synthesized = 0 AND seq = 4", (session_id,))
    assert len(fifth) == 1, "main#4 still names one row"

    def _collide() -> None:
        store.connection.execute(
            "INSERT INTO message (session_id, agent_id, synthesized, seq, kind) "
            "VALUES (?, 'main', 0, 0, 'response')", (session_id,))
        store.connection.commit()

    with pytest.raises(sqlite3.IntegrityError):
        _collide()


def test_a_session_ends_on_an_incomplete_pair_only_when_truncated_by_is_set(tmp_path):
    """A session whose last row is an unanswered response has `truncated_by` set, and a
    session with `truncated_by` unset always ends on a complete pair.

    G13/F6 found this FALSE of today's driver — `truncated_by` is written only inside
    `except BudgetKill` — so R11 widens the write to all three caught exits and this
    demand pins the widened rule, not the shipped one."""
    ss = store_mod()
    store = make_store(tmp_path)

    clean = store.new_session(agent_id="main")
    store.append(clean, [user_request("go"), *complete_pair()], agent_id="main")
    assert sql(store, "SELECT truncated_by FROM session WHERE session_id = ?", (clean,)) \
        == [(None,)]
    assert ss.ends_on_complete_pair(store, clean) is True

    for reason in ("budget", "request-limit", "aborted"):
        cut = store.new_session(agent_id="main")
        store.append(cut, [user_request("go"), tool_call_response(tool_call_id="x")],
                     agent_id="main")
        store.set_truncated_by(cut, reason)
        assert sql(store, "SELECT truncated_by FROM session WHERE session_id = ?",
                   (cut,)) == [(reason,)]
        assert ss.ends_on_complete_pair(store, cut) is False


def test_the_last_render_length_is_persisted_on_the_session_row(tmp_path):
    """The length of the last render (or the id of the last appended row) is persisted on
    the `session` row, so a fresh process recomputes the ingest tail from the store
    instead of from a number that lived only in the previous process's memory.

    FK18/R17: `PR4` confirmed a live list SHORTER than `last_render` silently slices to
    `[]` and never raises, so a restart that recomputed from nothing would ingest NOTHING
    with no diagnostic possible from the slice."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("root"), *complete_pair()], agent_id="main")
    store.set_last_render_len(session_id, 3)

    cols = {row[1] for row in sql(store, "PRAGMA table_info(session)")}
    assert cols & {"last_render_len", "last_message_id"}, (
        f"the session row must carry the render cursor; columns are {cols}")

    store.close()
    reopened = ss.open_store(case_id="case-alpha", runs_base=runs_base(tmp_path))
    assert reopened.last_render_len(session_id) == 3, (
        "a fresh process must recover the cursor from the store")


def test_an_append_is_one_commit_per_render_boundary(tmp_path):
    """One append is one transaction: the `message` row and its `message_payload` row
    commit together, and no transaction spans more than one render boundary.

    FK15/R17 settles the granularity the design left unstated. Observed through a real
    second connection sampling mid-append (life:po7 shape (3): an uncommitted row is
    NEVER visible), so a torn (row, payload) pair is observable if it exists."""
    ss = store_mod()
    base = runs_base(tmp_path)
    store = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = store.new_session(agent_id="main")
    observer = ss.open_store(case_id="case-alpha", runs_base=base)

    samples: list[tuple[int, int]] = []

    def sample(*_a):
        samples.append((
            observer.connection.execute("SELECT COUNT(*) FROM message").fetchone()[0],
            observer.connection.execute("SELECT COUNT(*) FROM message_payload").fetchone()[0],
        ))
        return sqlite3.SQLITE_OK

    store.connection.set_trace_callback(lambda stmt: sample())
    store.append(session_id, [user_request("a"), text_response("b")], agent_id="main")
    store.connection.set_trace_callback(None)

    assert samples, "the observation channel never fired"
    torn = [s for s in samples if s[0] != s[1]]
    assert torn == [], f"a (message, payload) pair was observable torn: {torn}"
    assert samples[-1] == (2, 2)


def test_message_writes_from_concurrent_gather_legs_do_not_collide_or_lose_rows(tmp_path):
    """Two gather legs appending concurrently against one store, each under its own
    `agent_id`, both land every row: no lost write, no collision under `message`'s
    composite key, and each leg's rows read back complete.

    `auth:P2` (executed) confirms this concurrency is reachable in THIS PR from ordinary
    gather fan-out — not only from #696's parallel forks — and `life:po7` (executed)
    observed the WAL behaviour (leg-a=20, leg-b=10, no lost writes, monotonic
    cross-visibility) that this demand pins as a test rather than as a probe."""
    ss = store_mod()
    base = runs_base(tmp_path)
    owner = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = owner.new_session(agent_id="main")

    counts = {"gather-a": 20, "gather-b": 10}
    errors: list[BaseException] = []
    barrier = threading.Barrier(len(counts))

    def leg(agent_id: str, n: int) -> None:
        try:
            handle = ss.open_store(case_id="case-alpha", runs_base=base)
            barrier.wait(timeout=10)
            for i in range(n):
                handle.append(session_id, [text_response(f"{agent_id}-{i}")],
                              agent_id=agent_id, seq=i)
            handle.close()
        except BaseException as exc:  # noqa: BLE001 — the assertion is "no error at all"
            errors.append(exc)

    threads = [threading.Thread(target=leg, args=(a, n)) for a, n in counts.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == [], f"a concurrent leg failed: {errors!r}"
    landed = dict(sql(owner, "SELECT agent_id, COUNT(*) FROM message "
                             "WHERE agent_id LIKE 'gather-%' GROUP BY agent_id"))
    assert landed == counts, f"lost writes across concurrent legs: {landed}"
    for agent_id, n in counts.items():
        seqs = [row[0] for row in sql(owner, "SELECT seq FROM message WHERE agent_id = ? "
                                             "ORDER BY seq", (agent_id,))]
        assert seqs == list(range(n)), f"{agent_id} lost or collided rows: {seqs}"


def test_one_writer_racing_itself_under_one_agent_id_allocates_distinct_seqs(tmp_path):
    """One writer racing ITSELF — the same `session_id` and the same `agent_id`, appending
    concurrently, with no caller-supplied `seq` — loses no row and collides on none: the
    store allocates the coordinate under contention, so the rows land with the full
    contiguous `seq` range and every row is readable afterwards.

    `test_message_writes_from_concurrent_gather_legs_do_not_collide_or_lose_rows` races two
    DISTINCT `agent_id`s and hands each leg its own pre-computed `seq`, so `message`'s
    composite key separates them by construction and the allocation is never contended.
    This is the case that leaves: `life:po7` observed WAL cross-visibility and `auth:P2`
    that ordinary gather fan-out reaches concurrent appends in THIS PR, but nothing observed
    one writer's own two legs competing for the same next coordinate. Positive control: the
    row count under a single-threaded append of the same shape, so "no collision" is not
    satisfied by an empty table."""
    ss = store_mod()
    base = runs_base(tmp_path)
    owner = ss.open_store(case_id="case-alpha", runs_base=base)
    session_id = owner.new_session(agent_id="main")

    per_leg = 15
    agent_id = "gather-a"
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def leg(tag: str) -> None:
        try:
            handle = ss.open_store(case_id="case-alpha", runs_base=base)
            barrier.wait(timeout=10)
            for i in range(per_leg):
                handle.append(session_id, [text_response(f"{tag}-{i}")], agent_id=agent_id)
            handle.close()
        except BaseException as exc:  # noqa: BLE001 — the assertion is "no error at all"
            errors.append(exc)

    threads = [threading.Thread(target=leg, args=(tag,)) for tag in ("self-a", "self-b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert errors == [], f"a self-racing leg failed: {errors!r}"
    seqs = [row[0] for row in sql(owner, "SELECT seq FROM message WHERE agent_id = ? "
                                         "AND session_id = ? ORDER BY seq",
                                  (agent_id, session_id))]
    assert len(seqs) == 2 * per_leg, (
        f"one writer racing itself lost rows: {len(seqs)} of {2 * per_leg} landed")
    assert len(set(seqs)) == len(seqs), f"two of the writer's own appends collided: {seqs}"
    assert seqs == list(range(2 * per_leg)), (
        f"the allocated coordinates are not the contiguous range the composite key needs: "
        f"{seqs}")

    # positive control: the same shape, uncontended, is what the counts above are measured
    # against — a store that silently dropped every append would satisfy "no collision".
    quiet = owner.new_session(agent_id="main")
    for i in range(3):
        owner.append(quiet, [text_response(f"quiet-{i}")], agent_id=agent_id)
    assert len(sql(owner, "SELECT seq FROM message WHERE session_id = ?", (quiet,))) == 3
