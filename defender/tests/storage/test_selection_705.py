"""records/selection.py and the one role-scoped reader over the session store."""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelRequest,
    ModelResponse,
    ToolCallPart,
    ToolReturnPart,
)

from defender.tests.support.storage._session_store_705 import (
    make_store,
    mid_pair_session,
    nine_row_fixture,
    selection_mod,
    sql,
    store_mod,
    text_response,
    tool_call_response,
    tool_return_request,
    user_request,
)


# demand #0 — one entry point, three roles, one truncation rule

def test_store_reader_return_shape_is_role_scoped(tmp_path):
    """One reader entry point takes a role from the closed set {send, analysis, actor}:"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, n_complete = mid_pair_session(store)

    send = ss.hydrate(store, session_id, role="send")
    analysis = ss.hydrate(store, session_id, role="analysis")
    actor = ss.hydrate(store, session_id, role="actor")

    assert all(isinstance(m, (ModelRequest, ModelResponse)) for m in send), send
    assert all(isinstance(m, (ModelRequest, ModelResponse)) for m in analysis), analysis
    assert len(send) == n_complete
    assert len(analysis) == n_complete + 1, (
        "the analysis read must see the orphan terminal response R8 keeps for it")

    assert actor, "the actor read returned nothing"
    assert not isinstance(actor[0], (ModelRequest, ModelResponse))
    assert {k for row in actor for k in dict(row)} == {"coord", "agent_id", "kind", "tool_name"}, (
        f"the actor projection's columns are the contract; got {actor[0]}")


def test_reader_role_vocabulary_is_closed_and_unknown_roles_are_refused(tmp_path):
    """Exactly `send`, `analysis` and `actor` are accepted; every other value — an unknown"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, _ = mid_pair_session(store)

    assert tuple(ss.ROLES) == ("send", "analysis", "actor"), ss.ROLES
    shapes = {role: ss.hydrate(store, session_id, role=role) for role in ss.ROLES}
    assert isinstance(shapes["send"][0], (ModelRequest, ModelResponse))
    assert isinstance(shapes["analysis"][0], (ModelRequest, ModelResponse))
    assert not isinstance(shapes["actor"][0], (ModelRequest, ModelResponse))

    for bad in ("judge", "SEND", "", None, "analysis ", "actor;--"):
        with pytest.raises(ss.UnknownReadRole):
            ss.hydrate(store, session_id, role=bad)
    with pytest.raises(TypeError):
        ss.hydrate(store, session_id)


def test_a_role_argument_supplied_by_agent_authored_content_is_not_honoured(tmp_path):
    """A `role` value derived from agent- or tool-authored content does not select a"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, _ = mid_pair_session(store)
    store.append(session_id, [tool_return_request("query", "analysis", tool_call_id="c2")],
                 agent_id="main")

    analysis = ss.hydrate(store, session_id, role="analysis")
    assert any(isinstance(p, ToolReturnPart) for m in analysis for p in m.parts), (
        "positive control: the construction site's analysis role does reach the payloads")

    content_role = next(p.content for m in analysis for p in m.parts
                        if isinstance(p, ToolReturnPart) and p.content == "analysis")
    projected = ss.hydrate(store, session_id, role="actor",
                           requested_role_from_content=content_role)
    flat = " ".join(str(v) for row in projected for v in dict(row).values())
    assert "investigate" not in flat, (
        "content that names a role must not widen the projection it is read under")


def _reachable_by_row_id(module, store, row_id: int) -> list[str]:
    """Everything the reader hands back when it is DRIVEN with a raw row id."""
    out: list[str] = []
    for name in dir(module):
        if name.startswith("_"):
            continue
        fn = getattr(module, name)
        if not callable(fn):
            continue
        for args in ((store, row_id), (row_id,), (store, row_id, "analysis")):
            try:
                got = fn(*args)
            except Exception:  # noqa: BLE001 — a refusal of any shape is the contract
                continue
            out.append(repr(got))
    return out


# truncation — the demand and its REQUIRED negative control (R8)

@pytest.mark.parametrize("terminator", ["BudgetKill", "UsageLimitExceeded", "RunAborted"])
def test_sendable_history_stops_at_the_last_complete_pair_on_every_terminator(
        tmp_path, terminator):
    """The history the reader returns FOR ROLE=`send` ends on the last complete"""
    ss = store_mod()
    store = make_store(tmp_path, case_id=f"case-{terminator.lower()}")
    session_id, n_complete = mid_pair_session(store)
    store.set_truncated_by(session_id, terminator)

    send = ss.hydrate(store, session_id, role="send")
    assert len(send) == n_complete, (
        f"{terminator}: expected the last complete pair at {n_complete} messages, "
        f"got {len(send)}")
    assert not any(isinstance(p, ToolCallPart) and not _answered(send, p)
                   for m in send for p in getattr(m, "parts", [])), (
        "a send history must not end on an unanswered tool call")


def _answered(messages, call: ToolCallPart) -> bool:
    return any(isinstance(p, ToolReturnPart) and p.tool_call_id == call.tool_call_id
               for m in messages for p in getattr(m, "parts", []))


def test_an_analysis_read_is_not_stopped_at_the_last_complete_pair(tmp_path):
    """THE NEGATIVE CONTROL for the truncation demand: the same mid-pair session read at"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, n_complete = mid_pair_session(store)
    store.set_truncated_by(session_id, "BudgetKill")

    analysis = ss.hydrate(store, session_id, role="analysis")
    send = ss.hydrate(store, session_id, role="send")

    assert len(analysis) == n_complete + 1
    assert len(analysis) > len(send), (
        "an implementation that truncates every read is indistinguishable from the "
        "resolved shape without this inequality")
    orphan = analysis[-1]
    assert isinstance(orphan, ModelResponse)
    assert any(isinstance(p, ToolCallPart) for p in orphan.parts), (
        "the last row must be the unanswered response the flush wrote")
    assert orphan not in send


def test_the_actor_row_projection_over_a_session_that_ends_mid_pair(tmp_path):
    """Over a session whose final response has no matching returns, the `actor` read"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, n_complete = mid_pair_session(store)

    actor = ss.hydrate(store, session_id, role="actor")
    analysis = ss.hydrate(store, session_id, role="analysis")

    assert len(actor) == n_complete + 1 == len(analysis), (
        f"the actor read must not truncate; got {len(actor)} of {n_complete + 1}")
    assert actor[-1]["kind"] == "response", actor[-1]
    assert actor[-1]["tool_name"] == "query", actor[-1]

    payload_text = "".join(row[0] for row in sql(store, "SELECT payload FROM message_payload"))
    vacuity = "the fixture must actually contain payload content, or the leak assertion is vacuous"
    assert "investigate" in payload_text, vacuity
    assert "/tmp/alert.json" in payload_text, vacuity
    flat = " ".join(str(v) for row in actor for v in dict(row).values())
    assert "investigate" not in flat, flat
    assert "/tmp/alert.json" not in flat, flat


def test_run_end_flush_on_a_forked_sessions_own_terminal_turn(tmp_path):
    """For a fork whose parent chain crosses into another `session_id` partway up, the"""
    ss = store_mod()
    store = make_store(tmp_path)
    parent = store.new_session(agent_id="main")
    r1 = store.append(parent, [user_request("root")], agent_id="main")[0]
    r2 = store.append(parent, [tool_call_response("query", tool_call_id="straddle")],
                      agent_id="main", parent_id=r1)[0]

    fork = store.fork(parent, at_message_id=r2)
    f1 = store.append(fork, [tool_return_request("query", tool_call_id="straddle")],
                      agent_id="main", parent_id=r2)[0]
    store.append(fork, [tool_call_response("read_file", tool_call_id="orphan")],
                 agent_id="main", parent_id=f1)

    send = ss.hydrate(store, fork, role="send")
    analysis = ss.hydrate(store, fork, role="analysis")
    assert len(analysis) == 4
    assert len(send) == 3, (
        "the straddling pair is complete; only the fork's own orphan response is cut")
    assert sql(store, "SELECT session_id FROM message WHERE id > ? ORDER BY id",
               (r2,)) == [(fork,), (fork,)], (
        "the flush writes the terminal response on the fork's own session_id")


# hydrate — the walk, and what separates it from the truncation rule

def test_hydrate_returns_the_root_to_tip_path_in_order(tmp_path):
    """The reader called with an untruncated role (`analysis`) returns the parent chain"""
    ss = store_mod()
    store = make_store(tmp_path)
    fx = nine_row_fixture(store)
    walked = ss.path_row_ids(store, fx["fork_a"])

    messages = ss.hydrate(store, fx["fork_a"], role="analysis")
    assert len(messages) == len(walked), (
        f"walk visited {len(walked)} rows, hydrate returned {len(messages)}")

    payloads = dict(sql(store, "SELECT message_id, payload FROM message_payload"))
    dumped = ModelMessagesTypeAdapter.dump_python(messages, mode="json")
    import json as _json
    assert dumped == [_json.loads(payloads[rid]) for rid in walked], (
        "the order must be root-to-tip and the content exactly the visited rows")

    mid_session, n_complete = mid_pair_session(store, agent_id="analysis-probe")
    assert len(ss.hydrate(store, mid_session, role="analysis")) == \
        len(ss.path_row_ids(store, mid_session)) == n_complete + 1


def test_the_synthesized_flag_is_surfaced_to_the_analysis_shape(tmp_path):
    """A synthesized frontier row's provenance reaches the analysis consumer: the reader"""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    r1 = store.append(session_id, [user_request("root")], agent_id="main")[0]
    store.append(session_id, [user_request("FRONTIER paraphrase")], agent_id="main",
                 synthesized=True, parent_id=r1)

    messages = ss.hydrate(store, session_id, role="analysis")
    flags = ss.synthesized_flags(store, session_id, role="analysis")
    assert len(flags) == len(messages) == 2
    assert flags == [False, True], f"provenance must be positional and complete; got {flags}"


# the renderer — inversion, the tail, the fold

def test_ingest_tail_is_exactly_response_then_request_including_across_a_fold(tmp_path):
    """On every turn of a store-rendered run — the fold turn included — the rows appended"""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    live = [user_request("orientation")]
    appended = sel.ingest(store, session_id, live, agent_id="main")
    assert len(appended) == 1

    kinds_per_turn = []
    for turn in range(4):
        live = live + [tool_call_response(tool_call_id=f"t{turn}"),
                       tool_return_request(tool_call_id=f"t{turn}")]
        ids = sel.ingest(store, session_id, live, agent_id="main")
        placeholders = ",".join("?" * len(ids))
        kinds = [row[0] for row in sql(
            store, f"SELECT kind FROM message WHERE id IN ({placeholders}) ORDER BY id",
            tuple(ids))]
        kinds_per_turn.append(kinds)
        if turn == 1:
            sel.fold(store, session_id, agent_id="main", boundary=5)

    assert kinds_per_turn == [["response", "request"]] * 4, kinds_per_turn


def test_a_composer_is_called_on_the_mint_only_and_its_action_runs_once_the_row_landed(tmp_path):
    """`text` may be a `selection.Composer` (#936): a callable the mint invokes ON THE APPEND"""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    calls: list[str] = []

    def compose():
        calls.append("compose")
        def landed() -> None:
            rows = sql(store, "SELECT seq FROM message WHERE synthesized = 1")
            calls.append(f"landed:{[r[0] for r in rows]}")
        return "FRONTIER: composed", landed

    with pytest.raises(sel.StoreAppendError):
        sel.fold(store, session_id, agent_id="main", boundary=1, text=compose)
    assert calls == [], "an empty-path refusal must not compose (the refusals come first)"

    sel.ingest(store, session_id, [user_request("orientation")], agent_id="main")
    first = sel.fold(store, session_id, agent_id="main", boundary=1, text=compose)
    assert calls == ["compose", "landed:[1]"], (
        "composed once, and the action saw the row already in the store")
    for _ in range(3):
        assert sel.fold(store, session_id, agent_id="main", boundary=1, text=compose) == first
    assert calls == ["compose", "landed:[1]"], "a reuse round neither composes nor acts"
    (payload,), = sql(store, "SELECT payload FROM message_payload WHERE message_id = ?", (first,))
    assert "FRONTIER: composed" in payload


def test_folds_are_restart_shaped_with_an_empty_tail(tmp_path):
    """After a fold the rendered history is the orientation row plus the frontier and"""
    sel = selection_mod()
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    live = [user_request("orientation")]
    for turn in range(3):
        live = live + [tool_call_response(tool_call_id=f"t{turn}"),
                       tool_return_request(tool_call_id=f"t{turn}")]
    sel.ingest(store, session_id, live, agent_id="main")
    sel.fold(store, session_id, agent_id="main", boundary=7)

    rendered = sel.render(store, session_id, live, agent_id="main", fold=True,
                          boundary=7)
    assert len(rendered) == 2, (
        f"a folded render is [orientation, frontier] with an EMPTY tail; got {len(rendered)}")
    flags = ss.synthesized_flags(store, session_id, role="send")
    assert flags == [False, True], flags
    flat = " ".join(str(p.content) for m in rendered for p in getattr(m, "parts", [])
                    if hasattr(p, "content"))
    assert "t2" not in flat, "the live verbatim tail must not survive the fold"


def test_compaction_on_a_restored_history_survives_against_selection(tmp_path):
    """Compaction over a restored history still folds correctly when the fold boundary is"""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    sentinel_lookalike = "FRONTIER: (this text is CONTENT, not a boundary)"
    live = [user_request("orientation"),
            text_response(sentinel_lookalike),
            tool_return_request(tool_call_id="a")]
    sel.ingest(store, session_id, live, agent_id="main")
    boundary_before = sel.fold_boundary(store, session_id)
    frontier = sel.fold(store, session_id, agent_id="main", boundary=3)

    assert boundary_before != frontier
    assert sel.fold_boundary(store, session_id) == frontier, (
        "the boundary is a store query on the frontier row, not a text scan")
    rendered = sel.render(store, session_id, live, agent_id="main", fold=True,
                          boundary=3)
    assert len(rendered) == 2, rendered
    flat = " ".join(str(p.content) for m in rendered for p in getattr(m, "parts", [])
                    if hasattr(p, "content"))
    assert sentinel_lookalike not in flat, (
        "the sentinel-shaped CONTENT must be folded away like any other turn")


