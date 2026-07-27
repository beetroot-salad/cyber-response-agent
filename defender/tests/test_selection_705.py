"""#705 — `runtime/selection.py` and the ONE role-scoped reader.

This file carries demand #0 — the return-value contract — as amended by **R8**:

  * one reader entry point takes a role from the closed set `{send, analysis, actor}`;
  * `send` and `analysis` return `list[ModelMessage]`; `actor` returns a payload-free
    `(coord, agent_id, kind, tool_name)` row projection;
  * **sendability truncation applies to `send` alone** — an `analysis` read sees the full
    path including an orphan terminal response;
  * `hydrate` IS that reader called with a role, not a third entry point;
  * the `PRAGMA user_version` refusal applies to every shape (unchanged from R5).

**Ratified at the phase-E repair round (93-verify-resolutions.md R21, finding F6):** R8's own
text permitted *either* "three roles" *or* "an equivalent `truncate` flag defaulting on for
send and off for analysis", and this file closes the second off by asserting the role tuple
outright. That narrowing is now an explicit decision rather than an assumption made by writing
a test — **the three roles are the contract and the flag variant is out of it**. The ground:
the flag formulation leaves the `actor` shape's default unstated (75-reclassification red flag
2 recorded exactly that and left it undecided), while a closed role vocabulary carries
FK14/R17's refusal of an unknown value naturally. The assertions below are unchanged; only
their status is — an implementation of the flag variant is non-conforming, not merely awkward.

R8 **rejects** R5's clause "sendability truncation … applies to both shapes". Nothing here
may be written one-sided: `75-reclassification.md`'s sharpest output is that
`test_sendable_history_stops_at_the_last_complete_pair_on_every_terminator` is
NON-DISCRIMINATING without an analysis-role negative control, because an implementation
that truncates EVERY read — the shape §7 rejected — passes the send-side half exactly as
the resolved shape does. Every truncation assertion here is therefore paired.
"""
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

from defender.tests._session_store_705 import (
    complete_pair,
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


# ==========================================================================
# demand #0 — one entry point, three roles, one truncation rule
# ==========================================================================

def test_store_reader_return_shape_is_role_scoped(tmp_path):
    """One reader entry point takes a role from the closed set {send, analysis, actor}:
    `send` and `analysis` return a `list[ModelMessage]`, `actor` returns a payload-free
    `(coord, agent_id, kind, tool_name)` row projection — from the same call with a
    different role argument, over the same session_id.

    Truncation belongs to `send` alone (R8), so over a mid-pair session the three shapes
    differ in EXTENT as well as in type: a reader that ignored its role argument entirely
    would be caught by the length, not by the shape."""
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


def test_reader_serves_three_roles_against_the_same_session_id_back_to_back(tmp_path):
    """`send`, `analysis` and `actor` reads of one session_id against one open handle, in
    immediate succession, each return their own role's shape and extent with no state
    carried between calls; over a mid-pair session `len(analysis) > len(send)`, and the
    actor result is payload-free at both extents.

    Under R5-as-worded the back-to-back calls differed only in shape; under R8 they also
    differ in LENGTH, which is the stronger discriminator (P7)."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id, _ = mid_pair_session(store)

    first_send = ss.hydrate(store, session_id, role="send")
    analysis = ss.hydrate(store, session_id, role="analysis")
    actor = ss.hydrate(store, session_id, role="actor")
    second_send = ss.hydrate(store, session_id, role="send")

    assert ModelMessagesTypeAdapter.dump_python(first_send, mode="json") == \
           ModelMessagesTypeAdapter.dump_python(second_send, mode="json"), (
        "an interleaved analysis/actor read must carry no state into the next send read")
    assert len(analysis) > len(first_send)
    assert len(actor) == len(analysis), (
        "the actor read is not truncated either (R8 scopes truncation to `send`)")
    flat = " ".join(str(v) for row in actor for v in dict(row).values())
    assert "investigate" not in flat, "the actor projection must carry no payload text"


def test_reader_role_vocabulary_is_closed_and_unknown_roles_are_refused(tmp_path):
    """Exactly `send`, `analysis` and `actor` are accepted; every other value — an unknown
    string, `None`, a missing argument, an empty string — is refused with an error rather
    than defaulted to either the restrictive or the permissive projection.

    The positive control enumerates all THREE accepted values and asserts each returns its
    own shape: without it, "refuses everything" passes. R8 widened the closed set from two
    names to three, and a reader that refused `send` would break the renderer — the one
    caller whose output reaches a provider (P8/FK14/R17). The role tuple is asserted as an
    exact equality because the role-only formulation is RATIFIED (F6, this file's module
    docstring): the equivalent-`truncate`-flag variant R8 also offered is out of the
    contract, so an implementation carrying a flag instead of these three names is
    non-conforming rather than an accepted alternative."""
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
    """A `role` value derived from agent- or tool-authored content does not select a
    projection: the role comes from the caller's construction site, never from content.

    The leak-relevant role is `analysis` (the payload-carrying one), so the discriminating
    fixture is a tool result whose text IS the string "analysis" reaching the reader as a
    role. Positive control: the same reader, called with `analysis` from the construction
    site, does return the payloads (FK14/R17)."""
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
    """Everything the reader hands back when it is DRIVEN with a raw row id.

    The observation channel for the negative below. It calls every public callable the
    module exposes with the row id in each argument position a by-row-id door could
    plausibly take, and flattens whatever comes back into strings. A door under any name
    — `peek`, `fetch_one`, `get_message` — is caught by what it RETURNS, which a scan of
    `dir()` for the substrings `by_id`/`row_id` is not.
    """
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


def test_the_reader_exposes_no_row_id_entry_point(tmp_path):
    """There is no by-row-id read: driven with a raw row id, no path through the reader
    returns that row's stored body — an audit read takes the `analysis` role and walks the
    path, so a folded row lying off every path is not addressable at all, under any name.

    FK14/R17: a fail-open second door would put a security boundary on a caller-supplied
    row id with no role enumeration behind it. Two positive controls, because a negative
    over a channel that can see nothing is not a negative: the same body IS returned by
    the reader when it lies on a real path, and the row-id probe itself DOES surface that
    body when it is run against a deliberately-leaky stand-in — so a door that existed
    would be caught rather than merely unnamed."""
    ss = store_mod()
    store = make_store(tmp_path)
    folded_body = "OFF-PATH-FOLDED-BODY-705-d4e5f6"
    fx = nine_row_fixture(store, folded_body=folded_body)
    orphaned = fx["row_ids"][4]

    # positive control 1 — the same body, ON a path, IS returned by the reader
    on_path_session = store.new_session(agent_id="main")
    store.append(on_path_session, [text_response(folded_body)], agent_id="main")
    reachable = repr(ss.hydrate(store, on_path_session, role="analysis"))
    assert folded_body in reachable, (
        "positive control: the reader must be able to return this body at all, or the "
        "absence assertions below measure nothing")

    # positive control 2 — the probe itself detects a by-row-id door when one exists
    class LeakyReader:
        def read_message(self, handle, row_id):
            return sql(handle, "SELECT payload FROM message_payload WHERE message_id = ?",
                       (row_id,))

    assert any(folded_body in got
               for got in _reachable_by_row_id(LeakyReader(), store, orphaned)), (
        "the row-id probe cannot see a door it is pointed straight at — it would report "
        "the real reader clean for the wrong reason")

    # the negative: no path through the real reader returns the row by its raw id
    for got in _reachable_by_row_id(ss, store, orphaned):
        assert folded_body not in got, (
            "a reader path returned an off-path row's body from its raw row id — that is "
            "the fail-open second door FK14 names")

    # and it is off every path, under every role, which is what makes the door matter
    for role in ss.ROLES:
        for session_id in (fx["main"], fx["fork_a"], on_path_session):
            if session_id == on_path_session:
                continue
            assert folded_body not in repr(ss.hydrate(store, session_id, role=role)), (
                f"the folded row surfaced through a role-scoped read at role {role}")
    assert orphaned not in ss.path_row_ids(store, fx["fork_a"])


# ==========================================================================
# truncation — the demand and its REQUIRED negative control (R8)
# ==========================================================================

@pytest.mark.parametrize("terminator", ["BudgetKill", "UsageLimitExceeded", "RunAborted"])
def test_sendable_history_stops_at_the_last_complete_pair_on_every_terminator(
        tmp_path, terminator):
    """The history the reader returns FOR ROLE=`send` ends on the last complete
    (response, tool-returns) pair after a `BudgetKill`, a `UsageLimitExceeded` and a
    `RunAborted` alike — one rule, in the reader, once, reached only through the `send`
    role.

    Its negative control is
    `test_an_analysis_read_is_not_stopped_at_the_last_complete_pair`: without it an
    implementation that truncates EVERY read — the shape §7 rejected — passes this
    assertion exactly as the resolved shape does. R11 replaces `ForkStop` with
    `RunAborted` in the observable terminator set; `ForkStop` stays design-provenance
    owned by #696 (G12: zero hits repo-wide)."""
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
    """THE NEGATIVE CONTROL for the truncation demand: the same mid-pair session read at
    role=`analysis` returns the FULL root-to-tip path including the orphan terminal
    response, and is strictly longer than the same session read at role=`send`.

    R8 amends R5: truncation is a property of the `send` role only. Under the rejected
    reading an analysis read could not observe the orphan terminal response M3's run-end
    flush exists to capture, so the moved `transcript.html` would silently drop the last
    response of every truncated run — a live equivalence break (P1/P5)."""
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
    """Over a session whose final response has no matching returns, the `actor` read
    returns a `(coord, agent_id, kind, tool_name)` row for EVERY row on the path — the
    orphan terminal response included — nothing is truncated, and every returned row is
    payload-free.

    This is the outright flip R8 produced: two of three phase-C answers asserted the actor
    projection truncates, both citing R5's rejected "applies to both shapes" clause as
    their sole ground. Truncation and payload-exclusion are two INDEPENDENT properties and
    neither may stand in for the other, so both are asserted here (P3)."""
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


def test_actor_role_read_over_a_session_containing_only_synthesized_frontier_rows(tmp_path):
    """An `actor` read over a session whose every row is a synthesized frontier returns a
    NON-EMPTY row set — one row per synthesized row — each payload-free: the exclusion
    branch is not conditioned on `synthesized`.

    Non-emptiness is the load-bearing half. Under the clause R8 rejected the actor read
    truncated to the last complete pair, and a session with no complete pair could
    legitimately return EMPTY, making the payload-absence assertion pass vacuously — the
    same failure `test_actor_role_read_against_a_session_with_zero_rows` was minted to
    guard, arriving through a different door (P11)."""
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    secret = "FRONTIER: the defender is chasing the sshd pivot hypothesis"
    parent = None
    for i in range(3):
        parent = store.append(session_id, [user_request(f"{secret} #{i}")],
                              agent_id="main", synthesized=True, parent_id=parent)[0]

    actor = ss.hydrate(store, session_id, role="actor")
    assert len(actor) == 3, f"the actor read must return every synthesized row; got {actor}"
    flat = " ".join(str(v) for row in actor for v in dict(row).values())
    assert "defender" not in flat, flat
    assert "sshd pivot" not in flat, flat


def test_actor_role_read_against_a_session_with_zero_rows(tmp_path):
    """An `actor` read of a session with no rows returns an empty projection without
    raising — the vacuity control that makes the leak assertions above informative.

    On its own this test carries no information; it exists so that "the actor sees no
    payload" is never satisfiable by a reader that simply returns nothing, and it is
    paired with the non-empty synthesized-only read above (consensus, O31)."""
    ss = store_mod()
    store = make_store(tmp_path)
    empty = store.new_session(agent_id="main")

    assert ss.hydrate(store, empty, role="actor") == []
    assert ss.hydrate(store, empty, role="analysis") == []

    populated = store.new_session(agent_id="main")
    store.append(populated, [user_request("real"), *complete_pair()], agent_id="main")
    assert len(ss.hydrate(store, populated, role="actor")) == 3, (
        "the same reader over a non-empty session must return rows")


def test_run_end_flush_on_a_forked_sessions_own_terminal_turn(tmp_path):
    """For a fork whose parent chain crosses into another `session_id` partway up, the
    run-end flush writes the terminal response on the FORK's own session_id, and a
    role=`send` read stops at the last complete pair OF THE ASSEMBLED PATH regardless of
    which session each row of that pair belongs to.

    The discriminating fixture is a fork whose fork point is a `ModelResponse` in the
    parent and whose own first row carries the matching tool returns: that pair STRADDLES
    the session boundary and must count as complete. An implementation computing
    completeness within the fork's own rows would wrongly truncate it away (P4, settled by
    derivation from R8's "one rule, in the reader, once" over a path-shaped input)."""
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


# ==========================================================================
# hydrate — the walk, and what separates it from the truncation rule
# ==========================================================================

def test_hydrate_returns_the_root_to_tip_path_in_order(tmp_path):
    """The reader called with an untruncated role (`analysis`) returns the parent chain
    from tip to root, reversed into send order, as a `list[ModelMessage]` carrying
    EXACTLY the rows the walk visited — no row it did not visit, and no row it did visit
    omitted.

    The "no row omitted" half is only assertable under R8, and it is what separates the
    WALK from the TRUNCATION RULE; exercised over a mid-pair session, or the distinction
    is untested (D3)."""
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
    """A synthesized frontier row's provenance reaches the analysis consumer: the reader
    returns, alongside the messages, which of them the store recorded as synthesized —
    a frontier row is the model's own paraphrase of turns that may carry attacker-derived
    content, and `list[ModelMessage]` has nowhere to carry the flag.

    FK20/R17: decide whether the analysis shape carries provenance; if it does not, say so
    explicitly so a downstream consumer cannot assume otherwise. This demand pins that it
    DOES."""
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


# ==========================================================================
# the renderer — inversion, the tail, the fold
# ==========================================================================

def test_render_ignores_its_input_and_returns_the_store_render(tmp_path):
    """The ProcessHistory processor discards the list it is handed and returns
    `hydrate(store, path)` for role=`send`, so a caller that passes a deliberately wrong
    list still gets the store's render back.

    R10: the renderer ALWAYS returns the store's render; `DEFENDER_COMPACTION` gates only
    whether a fold is applied inside it — branching the renderer on the flag would leave
    every store assertion exercised only under a flag CI does not set."""
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    store.append(session_id, [user_request("real root"), *complete_pair()], agent_id="main")

    wrong = [user_request("THIS LIST IS NOT THE HISTORY")]
    rendered = sel.render(store, session_id, wrong, agent_id="main", fold=False)
    expected = ss.hydrate(store, session_id, role="send")

    assert ModelMessagesTypeAdapter.dump_python(rendered, mode="json") == \
           ModelMessagesTypeAdapter.dump_python(expected, mode="json")
    flat = " ".join(str(p.content) for m in rendered for p in getattr(m, "parts", [])
                    if hasattr(p, "content"))
    assert "THIS LIST IS NOT THE HISTORY" not in flat


def test_the_renderer_applies_no_truncation_of_its_own(tmp_path):
    """The history the renderer hands to the provider is exactly what the reader returns
    for `(session, role="send")`: the renderer applies no truncation of its own, and the
    last-complete-pair rule has exactly one implementation, reached only through the
    reader.

    The discriminating fixture is a mid-pair session, where a renderer that skipped the
    rule would emit one message MORE than the reader does and a renderer that re-applied
    it locally would still pass a shape-only check (P2)."""
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id, n_complete = mid_pair_session(store)

    rendered = sel.render(store, session_id, [], agent_id="main", fold=False)
    assert len(rendered) == n_complete == len(ss.hydrate(store, session_id, role="send"))
    assert len(rendered) < len(ss.hydrate(store, session_id, role="analysis"))
    assert sel.hydrate is ss.hydrate, (
        "selection must reach the rule through the reader, not carry a second copy")


def test_ingest_tail_is_exactly_response_then_request_including_across_a_fold(tmp_path):
    """On every turn of a store-rendered run — the fold turn included — the rows appended
    past the previous render are exactly one `ModelResponse` followed by one
    `ModelRequest`.

    C5 measured `appended 1,2,2,2` across a fold with a store-rendering processor; dep:PO6
    then confirmed the processor fires once per logical request node and that a real
    `ModelRetry` builds a NEW node, so the retried pair appends as new rows rather than
    re-ingesting the old one."""
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
            sel.fold(store, session_id, agent_id="main")

    assert kinds_per_turn == [["response", "request"]] * 4, kinds_per_turn


def test_no_position_or_payload_hash_diffing_on_ingest(tmp_path):
    """Ingest computes its tail from the render length alone: feeding it a history whose
    earlier rows have identical payload hashes appends nothing extra and drops nothing,
    and a live list SHORTER than the last render is refused loudly rather than silently
    ingesting nothing.

    Positive control:
    `test_ingest_tail_is_exactly_response_then_request_including_across_a_fold`. PR4
    (executed) confirmed `live[len(last_render):]` on a shorter live list returns `[]` and
    never raises, so no diagnostic is possible from the slice alone — FK18's silent
    no-ingest, which the render cursor on the session row exists to make impossible."""
    ss = store_mod()
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    twin = text_response("identical body")
    live = [user_request("root"), twin, tool_return_request(tool_call_id="a"), twin]
    first = sel.ingest(store, session_id, live, agent_id="main")
    assert len(first) == 4, "duplicate payloads must not be diffed away"

    live = live + [tool_call_response(tool_call_id="b"), tool_return_request(tool_call_id="b")]
    second = sel.ingest(store, session_id, live, agent_id="main")
    assert len(second) == 2, f"the tail is the render-length slice only; got {len(second)}"

    with pytest.raises(ss.IngestTailUnderflow):
        sel.ingest(store, session_id, live[:2], agent_id="main")
    assert sql(store, "SELECT COUNT(*) FROM message") == [(6,)], (
        "a refused ingest must append nothing")


def test_one_frontier_row_per_fold_boundary(tmp_path):
    """A run that crosses one fold boundary several times over produces exactly ONE
    synthesized frontier row for that boundary, looked up and reused rather than re-minted
    per render; a SECOND boundary produces a second, distinct frontier row.

    Identity is assigned by construction at creation, never by content-diffing, and the
    lookup is a store query keyed on `(session_id, boundary)` — not an in-process cache
    (FK10/R17). C13 measured the naive shape: `_compact_messages` minted 4 distinct
    frontiers in one 6-request run and only 1 reached the log."""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    sel.ingest(store, session_id, [user_request("orientation")], agent_id="main")

    first = sel.fold(store, session_id, agent_id="main")
    for _ in range(3):
        assert sel.fold(store, session_id, agent_id="main") == first, (
            "the frontier for one boundary must be reused, not re-minted per render")

    sel.ingest(store, session_id,
               [user_request("orientation"), *complete_pair(), *complete_pair()],
               agent_id="main")
    second = sel.fold(store, session_id, agent_id="main", boundary=2)
    assert second != first

    rows = sql(store, "SELECT id FROM message WHERE synthesized = 1 ORDER BY id")
    assert [r[0] for r in rows] == [first, second], (
        f"exactly two frontier rows for two boundaries; got {rows}")


def test_folds_are_restart_shaped_with_an_empty_tail(tmp_path):
    """After a fold the rendered history is the orientation row plus the frontier and
    nothing else — no verbatim tail of turns since the previous fold survives on the path.

    This is Scope's named behaviour change to PIN rather than plumbing: `_compact_messages`
    kept a live verbatim tail (`messages[marker+1:]`), and the store version absorbs
    everything up to the fold point into the frontier. U1 (is the frontier a sufficient
    carrier?) admits no hermetic probe, so this demand pins the SHAPE only."""
    sel = selection_mod()
    ss = store_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")
    live = [user_request("orientation")]
    for turn in range(3):
        live = live + [tool_call_response(tool_call_id=f"t{turn}"),
                       tool_return_request(tool_call_id=f"t{turn}")]
    sel.ingest(store, session_id, live, agent_id="main")
    sel.fold(store, session_id, agent_id="main")

    rendered = sel.render(store, session_id, live, agent_id="main", fold=True)
    assert len(rendered) == 2, (
        f"a folded render is [orientation, frontier] with an EMPTY tail; got {len(rendered)}")
    flags = ss.synthesized_flags(store, session_id, role="send")
    assert flags == [False, True], flags
    flat = " ".join(str(p.content) for m in rendered for p in getattr(m, "parts", [])
                    if hasattr(p, "content"))
    assert "t2" not in flat, "the live verbatim tail must not survive the fold"


def test_request_row_carries_run_step_duration_ms_and_wire_sha(tmp_path):
    """Every request row the renderer writes carries a `run_step`, a `duration_ms` and a
    `wire_sha`, and response rows carry none of the three — the three fields are a
    property of the request the renderer stamped, not of the response the log records."""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    sel.render(store, session_id, [], agent_id="main", fold=False,
               run_step=1, duration_ms=12.5)
    sel.ingest(store, session_id, [user_request("root"), text_response("a")],
               agent_id="main")
    sel.render(store, session_id, [], agent_id="main", fold=False,
               run_step=2, duration_ms=34.0)

    rows = sql(store, "SELECT kind, run_step, duration_ms, wire_sha FROM message ORDER BY id")
    requests = [r for r in rows if r[0] == "request"]
    responses = [r for r in rows if r[0] == "response"]
    assert requests, "no request row was written"
    for _kind, run_step, duration_ms, wire_sha in requests:
        assert run_step is not None, (run_step, duration_ms, wire_sha)
        assert duration_ms is not None, (run_step, duration_ms, wire_sha)
        assert wire_sha, (run_step, duration_ms, wire_sha)
    for row in responses:
        assert row[1:] == (None, None, None), f"a response row carries the three: {row}"


def test_compaction_on_a_restored_history_survives_against_selection(tmp_path):
    """Compaction over a restored history still folds correctly when the fold boundary is
    a store query rather than a sentinel scan through message text — including over a
    history whose message CONTENT contains the old sentinel string, which the scan it
    replaces would have mistaken for a boundary.

    `_frontier_index` has ZERO test coverage at this base (F14), so its behaviour is
    unpinned at the moment it is replaced; this is the issue's own "keep the test" hedge
    made executable against the replacement."""
    sel = selection_mod()
    store = make_store(tmp_path)
    session_id = store.new_session(agent_id="main")

    sentinel_lookalike = "FRONTIER: (this text is CONTENT, not a boundary)"
    live = [user_request("orientation"),
            text_response(sentinel_lookalike),
            tool_return_request(tool_call_id="a")]
    sel.ingest(store, session_id, live, agent_id="main")
    boundary_before = sel.fold_boundary(store, session_id)
    frontier = sel.fold(store, session_id, agent_id="main")

    assert boundary_before != frontier
    assert sel.fold_boundary(store, session_id) == frontier, (
        "the boundary is a store query on the frontier row, not a text scan")
    rendered = sel.render(store, session_id, live, agent_id="main", fold=True)
    assert len(rendered) == 2, rendered
    flat = " ".join(str(p.content) for m in rendered for p in getattr(m, "parts", [])
                    if hasattr(p, "content"))
    assert sentinel_lookalike not in flat, (
        "the sentinel-shaped CONTENT must be folded away like any other turn")


def test_the_human_coordinate_carries_a_session_component(tmp_path):
    """A projected coordinate names the session as well as the agent and the ordinal —
    `{session_id}/{agent_id}#{seq}` — so a source `main#0` and a fork `main#0` no longer
    print identically.

    C26 read the shipped form (`f"{agent_id}#{seq}"`) off `observe.py:65`; R14 re-mints the
    coordinate and records the value change as an ACCEPTED, TESTED difference rather than
    a silent one. This is the one exception in the whole four-reader equivalence set."""
    ss = store_mod()
    store = make_store(tmp_path)
    main = store.new_session(agent_id="main")
    r1 = store.append(main, [user_request("root")], agent_id="main", seq=0)[0]
    fork = store.fork(main, at_message_id=r1)
    store.append(fork, [text_response("fork's first")], agent_id="main", seq=0, parent_id=r1)

    main_rows = ss.hydrate(store, main, role="actor")
    fork_rows = ss.hydrate(store, fork, role="actor")
    assert main_rows[0]["coord"] == f"{main}/main#0"
    assert fork_rows[-1]["coord"] == f"{fork}/main#0"
    assert main_rows[0]["coord"] != fork_rows[-1]["coord"], (
        "C26's collision — a source main#0 and a fork main#0 printing identically — must "
        "not survive into the fork era")
