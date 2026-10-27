"""The per-case session store: schema, identity, durability, payloads, lineage, concurrency."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

import gc
import json
import re
import sqlite3
import warnings
import threading

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelRequest,
    TextPart,
    ToolReturnPart,
)

from defender.tests.support.storage._session_store_705 import (
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
from defender.records import SessionPaths
from defender.tests.support.storage._store_owner import owned_store


# the handle, the connection, the schema version

def test_store_connection_is_strict_fk_wal_with_a_busy_timeout(tmp_path):
    """A freshly opened store reports STRICT tables, foreign_keys on, journal_mode wal,"""
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
    """A coordinate value of the wrong Python type — a bool, a numeric string or an"""
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


def test_a_store_dropped_while_open_warns_and_one_closed_first_does_not(tmp_path):
    """A handle collected while its connection is still open names its file in an
    `UnclosedStoreWarning`: the leak is reported where it happens, not left for SQLite to
    clean up whenever the collector runs (#1324). A closed handle is collected silently."""
    ss = store_mod()
    # Opened bare, not through `make_store`: the test's own stack would hold it open.
    leaked = ss.open_store(  # lint-store-ownership: ok — the leak under test
        case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(runs_base(tmp_path))))
    path = re.escape(str(leaked.path))
    with pytest.warns(ss.UnclosedStoreWarning, match=path):
        del leaked

    closed = make_store(tmp_path / "closed")
    closed.close()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        del closed
        gc.collect()
    assert not [w for w in caught if issubclass(w.category, ss.UnclosedStoreWarning)], (
        f"a closed store still warned: {[str(w.message) for w in caught]}")


def test_reader_refuses_an_unknown_user_version(tmp_path):
    """A store whose `PRAGMA user_version` the reader does not know is refused with an"""
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
        with pytest.raises(ss.UnknownSchemaVersion), ss.open_store(
                case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(runs_base(tmp_path)))):
            pass


# append-only: the negative and its positive control


# payloads — round-trip, coercion, unknown fields, the encoding

def test_ingested_payload_round_trips_verbatim(tmp_path):
    """Every ingested row's stored payload re-validates into a ModelMessage that"""
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


def test_payload_sha_digests_the_stored_payload_text_at_write_time(tmp_path):
    """`message_payload.payload_sha` is the digest of the payload TEXT as stored, taken"""
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


# lineage: the path walk, ordering, cycles

def test_path_exactness_nine_row_fixture(tmp_path):
    """Over the nine-row fixture `fork-a`'s tip walks to exactly 1,5,6,8,9 and `main`'s"""
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
    """A fork that restarts `seq` at 0 still reads back in true send order, because order is the parent chain and nothing records membership separately (O9)."""
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
    """A cyclic `parent_id` chain is refused by the walk with a loud error rather than walked forever: `hydrate` carries its own depth cap or cycle guard."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    a = store.append(session_id, [user_request("a")], agent_id="main")[0]
    b = store.append(session_id, [text_response("b")], agent_id="main", parent_id=a)[0]
    store.connection.execute("UPDATE message SET parent_id = ? WHERE id = ?", (b, a))
    store.connection.commit()

    with pytest.raises(ss.CyclicParentChain):
        ss.hydrate(store, session_id, role="analysis")


# identity: sessions, forks, case_id, config

def test_a_fork_is_a_branch_with_no_prefix_copy_and_no_id_remap(tmp_path):
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


def test_config_row_is_content_addressed_over_the_reproducibility_set(tmp_path):
    """Two runs with identical models, corpus git_sha, prompt digests and library"""
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


# retention, absences, the session row's bookkeeping

def test_payload_lives_in_its_own_table_and_retention_drops_only_bodies(tmp_path):
    """`DELETE FROM message_payload` for one session drops the bodies while leaving that"""
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
    """A run whose gather leg wrote a large raw payload to `gather_raw/` stores only the"""
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


def test_synthesized_rows_occupy_their_own_seq_address_space(tmp_path):
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
    """A session whose last row is an unanswered response has `truncated_by` set, and a session with `truncated_by` unset always ends on a complete pair."""
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


def test_an_append_is_one_commit_per_render_boundary(tmp_path):
    """One append is one transaction: the `message` row and its `message_payload` row"""
    base = runs_base(tmp_path)
    store = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    session_id = store.new_session(agent_id="main")
    observer = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))

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
    """Two gather legs appending concurrently against one store, each under its own"""
    ss = store_mod()
    base = runs_base(tmp_path)
    owner = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    session_id = owner.new_session(agent_id="main")

    counts = {"gather-a": 20, "gather-b": 10}
    errors: list[BaseException] = []
    barrier = threading.Barrier(len(counts))

    def leg(agent_id: str, n: int) -> None:
        try:
            with ss.open_store(case_id="case-alpha",
                               sessions=SessionPaths(fixture_runs_base(base))) as handle:
                barrier.wait(timeout=10)
                for i in range(n):
                    handle.append(session_id, [text_response(f"{agent_id}-{i}")],
                                  agent_id=agent_id, seq=i)
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
    """One writer racing ITSELF — the same `session_id` and the same `agent_id`, appending"""
    ss = store_mod()
    base = runs_base(tmp_path)
    owner = owned_store(case_id="case-alpha", sessions=SessionPaths(fixture_runs_base(base)))
    session_id = owner.new_session(agent_id="main")

    per_leg = 15
    agent_id = "gather-a"
    errors: list[BaseException] = []
    barrier = threading.Barrier(2)

    def leg(tag: str) -> None:
        try:
            with ss.open_store(case_id="case-alpha",
                               sessions=SessionPaths(fixture_runs_base(base))) as handle:
                barrier.wait(timeout=10)
                for i in range(per_leg):
                    handle.append(session_id, [text_response(f"{tag}-{i}")], agent_id=agent_id)
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


@pytest.mark.parametrize("bad", [
    True, "12.5", float("nan"), float("inf"), float("-inf"),
    pytest.param(__import__("decimal").Decimal("1.5"), id="Decimal"),
    pytest.param(__import__("fractions").Fraction(1, 2), id="Fraction"),
])
def test_duration_ms_is_refused_at_the_boundary_unless_a_finite_real_number(tmp_path, bad):
    """`duration_ms` is bound straight into the INSERT and never meets the payload's"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    message = ModelRequest(parts=[ToolReturnPart(tool_name="query", content="x",
                                                 tool_call_id="c-1")])
    with pytest.raises(ss.PayloadNotRepresentable):
        store.append(session_id, [message], agent_id="main", duration_ms=bad)
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] == 0
    # The accepted shapes: `None`, a real `int`, a finite `float`.
    store.append(session_id, [message], agent_id="main", duration_ms=None)
    store.append(session_id, [message], agent_id="main", duration_ms=3)
    store.append(session_id, [message], agent_id="main", duration_ms=12.5)
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] == 3
