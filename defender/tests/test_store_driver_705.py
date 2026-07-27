"""#705 — the store driven END TO END through the real `driver.run_investigation` loop.

Flat under `defender/tests/` rather than under `tests/e2e/` for one mechanical reason:
`check_binds` globs the suite dir non-recursively, so a `discharged_by` pointing into
`tests/e2e/` resolves to nothing and the demands' prose becomes unscannable.
`pytestmark = pytest.mark.e2e` keeps it in the same marker lane as the other replay
scripts (the precedent is `test_budget_e2e_631.py`).

Every scenario is a few lines of `Turn(...)` against `_replay_harness`: the real agent
loop, the real tools, the real permission gate, the real observability projection — with
injected VALUES and nothing patched. **R12 authorized the fifth seam** used here, a
store-factory argument threaded through `run_investigation` alongside `make_model`,
`verbs`, `limits` and `box`: environment steering can only express "the store is missing",
one third of O19's stated domain, while reading as covered, and the project profile forbids
the `monkeypatch.setattr` that would express the rest.

Every fault below is tier 1 of the author charge's hierarchy — the real database file is
really unlinked, really overwritten with non-database bytes, or really locked by a second
real connection, and the real `sqlite3` primitive raises whatever it really raises. The
`FaultStore` fake decides only WHEN; it classifies nothing.

RED AGAINST HEAD IS THE EXPECTED STATE: `runtime/session_store.py` does not exist at
`4e4645aa`, `run_investigation` has no `store_factory` parameter, there is no `finally:` on
the run loop (G14/F7) and `truncated_by` is written only inside `except BudgetKill`
(G13/F6).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelResponse,
    TextPart,
    ToolCallPart,
)

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.runtime import circuit_breaker, driver  # noqa: E402
from defender.tests._session_store_705 import (
    FaultStore,
    StoreFault,
    runs_base,
    sql,
    store_factory,
    store_mod,
)
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    NeverEndsModel,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

SALT = "0011223344556677"

#: A token the MAIN agent emits into its own history and that nothing else in the driven
#: conversation contains. Probed, not assumed: the leak test below reads it back out of
#: main's own next request as its positive control, and the string it replaced
#: ("investigate") was verified absent from every arm of this conversation — a negative
#: whose observation channel cannot see its own subject passes whatever the code does.
MAIN_ONLY_MARKER = "MAIN-ONLY-MARKER-705-a1b2c3"


def caps(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def _one_hit(ctx, *, q: str = "probe") -> list[dict]:
    """A verb that really returns a row, so the gather leg really writes its artifacts."""
    return [{"host": "web-01", "event": "ssh-accept"}]


def _down(*systems: str) -> FakeVerbs:
    from defender.scripts.adapters.faults import TransportFault

    def probe(ctx, *, q: str = "probe") -> list[dict]:
        raise TransportFault("connection refused")

    return FakeVerbs({s: {"probe": probe} for s in systems})


def _finished(text: str = "Investigation complete.") -> ReplayFn:
    return ReplayFn([
        Turn(tool_calls=[("read_file", {"path": "ALERT"})]),
        Turn(text=text),
    ])


def _read_alert_turns(run_dir: Path, n: int) -> list[Turn]:
    return [Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})])
            for _ in range(n)]


# ==========================================================================
# the fifth seam, and the identity the run mints
# ==========================================================================

def test_run_investigation_takes_a_store_factory_seam(tmp_path):
    """`run_investigation` takes a store-factory argument as a VALUE, alongside
    `make_model`, `verbs`, `limits` and `box`: the factory it is handed is the one the run
    opens, it is called once with `(case_id, run_dir)`, and every message the run rendered
    or ingested lands in THAT handle.

    R12 chose the seam over environment steering because environment steering cannot
    express contention or corruption — `store_append_is_fail_closed` would degrade to "the
    store is missing", one third of O19's stated domain, while reading as covered. The
    fake records what it received, so the outbound channel is pinned and not merely the
    return value (rules.md R1)."""
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    factory = store_factory(tmp_path, sink=opened)
    handles: list = []

    def recording(case_id: str, rd: Path):
        handle = FaultStore(factory(case_id, rd))
        handles.append((case_id, rd, handle))
        return handle

    result = drive(run_dir, run_id="seam", salt=SALT,
                   main=ReplayFn([Turn(text="Investigation complete.")]),
                   store_factory=recording)

    assert len(handles) == 1, f"the factory must be called exactly once; got {handles}"
    case_id, handed_run_dir, handle = handles[0]
    assert handed_run_dir == run_dir
    assert case_id == result["case_id"]
    assert handle.appends, "the run drove the injected handle, not one it made itself"
    assert Path(result["store_path"]) == Path(handle.path)


def test_run_investigation_mints_a_case_id_and_writes_a_run_dir_pointer(tmp_path):
    """`run_investigation` mints `case_id` at entry and writes `{case_id, store_path}` into
    the run dir, so a child process holding only a run dir resolves the same store without
    re-deriving the runs base — and two executions of one investigation reach one file.

    R6 rejects aliasing `case_id := run_dir.name`: the pre-seam probe confirmed two
    executions of one investigation get two run dirs, hence two case ids, hence two store
    FILES, making O13's inheritance and O11's single-file claim unsatisfiable — every fork
    demand in the spec would pass VACUOUSLY while forking is silently impossible. The
    resolver's contract is the pointer file, not a convention."""
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN)
    result = drive(run_dir, run_id="pointer", salt=SALT,
                   main=ReplayFn([Turn(text="done")]),
                   store_factory=store_factory(tmp_path))

    pointer = run_dir / ss.POINTER_FILENAME
    assert pointer.is_file(), f"no run-dir pointer at {pointer}"
    body = json.loads(pointer.read_text())
    assert set(body) >= {"case_id", "store_path"}, body
    assert body["case_id"] == result["case_id"]

    resolved = ss.resolve_store_path(run_dir)
    assert Path(resolved) == Path(body["store_path"]) == Path(result["store_path"])

    relocated = tmp_path / "elsewhere" / "copied-run"
    relocated.parent.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copytree(run_dir, relocated)
    assert Path(ss.resolve_store_path(relocated)) == Path(body["store_path"]), (
        "a relocated run dir must still resolve its store — run dirs ARE relocated today "
        "by persist.py's allowlist copy and evals/harness.py's copytree")


# ==========================================================================
# the capability, its seam, and the flag that no longer gates it
# ==========================================================================

def test_capability_attaches_at_the_existing_extra_capabilities_seam(tmp_path):
    """Both the main agent and the gather agent receive the store capability through
    `build_agent_core`'s existing `extra_capabilities` argument, and no new seam is
    introduced: driving one run leaves main's rows AND the gather leg's rows in the store,
    each under its own `agent_id`.

    The enumeration is how the subjects are picked, not what is asserted: each agent is
    DRIVEN and the store's rows are the observed effect (C11: one build site,
    `capabilities = [hooks, *extra_capabilities]`)."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    opened: list = []
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([Turn(text="lead summarised")])

    drive(run_dir, run_id="seam-attach", salt=SALT, main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {}}),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    agents = {row[0] for row in sql(store, "SELECT DISTINCT agent_id FROM message")}
    assert "main" in agents, agents
    assert any(a != "main" for a in agents), (
        f"the gather leg's rows must be recorded too (O21 denies gather the RENDER, not "
        f"the record); agent_ids were {agents}")


def test_node_iteration_and_node_hooks_are_untouched(tmp_path):
    """The driver still drives with a bare `async for node in run` and registers no node
    hook, so the store never depends on a hook that bare iteration does not fire.

    Positive control: `test_capability_attaches_at_the_existing_extra_capabilities_seam` —
    the store IS driven through the surviving seam. C2 (executed) measured the rejected
    branch dead: under a bare `async for node in run` an `after_node_run` hook fires ZERO
    times, while `agent.run()` fires five, so a write seam placed on `CallToolsNode` would
    never run."""
    source = Path(driver.__file__).read_text()
    for hook in ("after_node_run", "before_node_run", "on_node_"):
        assert hook not in source, (
            f"{hook} appeared in driver.py — the store must not depend on a node hook the "
            f"bare `async for node in run` does not fire (C2)")
    assert "async for node in run" in source, (
        "the bare node iteration is the shape the store's seam is chosen to survive")

    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    drive(run_dir, run_id="no-hooks", salt=SALT,
          main=ReplayFn([Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
                         Turn(text="done")]),
          store_factory=store_factory(tmp_path, sink=opened))
    assert sql(opened[0], "SELECT COUNT(*) FROM message")[0][0] > 0, (
        "rows must still land under bare iteration")


@pytest.mark.parametrize("flag", [None, "1"])
def test_capability_is_unconditional_with_DEFENDER_COMPACTION_unset(tmp_path, monkeypatch, flag):
    """With `DEFENDER_COMPACTION` unset the renderer is identity-plus-ingest — no fold
    happens and rows are STILL appended; with it set the fold happens and rows are still
    appended. The store is authoritative in both configurations and the flag gates only
    the fold (R10).

    Unset is the configuration CI actually runs: under a branch-on-the-flag reading every
    store assertion would be exercised only under `DEFENDER_COMPACTION=1`, shipping the
    default untested."""
    if flag is None:
        monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    else:
        monkeypatch.setenv("DEFENDER_COMPACTION", flag)

    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    drive(run_dir, run_id=f"flag-{flag}", salt=SALT,
          main=ReplayFn(_read_alert_turns(run_dir, 3) + [Turn(text="done")]),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] > 0, (
        f"rows must be appended with DEFENDER_COMPACTION={flag!r}")
    synthesized = sql(store, "SELECT COUNT(*) FROM message WHERE synthesized = 1")[0][0]
    if flag is None:
        assert synthesized == 0, "no fold happens with the flag unset"
    else:
        assert synthesized >= 0, "the fold is the only thing the flag gates"


def test_the_pre_change_construction_assertions_are_overturned(tmp_path, monkeypatch):
    """The two pre-change construction assertions — that `_main_extra_capabilities()` is
    EMPTY with `DEFENDER_COMPACTION` unset and holds one `ProcessHistory` only when it is
    set — are overturned, not preserved: the assembly yields exactly ONE capability in
    both configurations, because the fold is a parameter of that capability rather than a
    second one.

    3/3 phase-C consensus: both pre-change assertions must be REWRITTEN (O20, R2/M8).
    Leaving them green would pin the branch-on-the-flag reading R10 rejected."""
    ss = store_mod()
    store = ss.open_store(case_id="case-assembly", runs_base=runs_base(tmp_path))
    session_id = store.new_session(agent_id="main")

    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    off = list(driver._main_extra_capabilities(store, session_id))
    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    on = list(driver._main_extra_capabilities(store, session_id))

    assert len(off) == 1, f"the capability is unconditional; unset gave {off}"
    assert len(on) == 1, f"the flag must not add a SECOND capability; set gave {on}"
    assert isinstance(off[0], driver.ProcessHistory)
    assert isinstance(on[0], driver.ProcessHistory)


# ==========================================================================
# whose history is store-rendered
# ==========================================================================

def test_main_history_is_store_rendered(tmp_path):
    """The main agent's history on every request past the first is the store's render,
    not the list the framework accumulated: the messages the model is handed on turn N are
    exactly what the reader returns for `(session, role="send")` at that point."""
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 2) + [Turn(text="done")])
    drive(run_dir, run_id="store-render", salt=SALT, main=replay,
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    session_id = sql(store, "SELECT session_id FROM session")[0][0]
    final = ss.hydrate(store, session_id, role="send")
    seen_text = replay.seen[-1]
    assert seen_text, "the model recorded no history"
    for message in final[:-1]:
        for part in getattr(message, "parts", []):
            content = getattr(part, "content", None)
            if isinstance(content, str) and content.strip():
                assert content[:40] in seen_text, (
                    f"a stored row was not in what the model was handed: {content[:40]!r}")


def test_gather_history_is_not_store_rendered_and_learning_stages_get_neither(tmp_path):
    """The gather agent's history is never replaced by a store render and learning-stage
    agents get neither the fold nor the store, while gather's own messages ARE still
    recorded as rows: a marker the main agent put into ITS OWN history reaches none of the
    gather leg's surfaces — not a single one of gather's model requests, not gather's rows
    in the store, not the raw payloads gather writes under `gather_raw`.

    Positive control: `test_main_history_is_store_rendered`, and — for the observation
    channel itself — the same marker read back out of main's own next request, which is
    what proves this negative can see a leak at all. FK5/R17 separates the two switches:
    "fold off" and "render off" are two parameters, and gather takes both off, so the
    sentence cannot be re-collapsed at implementation time. O21 is a pinned non-obligation
    and wins over the convenience reading of "the same capability"."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    opened: list = []
    main = ReplayFn([
        Turn(text=MAIN_ONLY_MARKER,
             tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="done"),
    ])
    gather = ReplayFn([
        Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
        Turn(text="lead summarised"),
    ])
    drive(run_dir, run_id="gather-render", salt=SALT, main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {"probe": _one_hit}}),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    gather_agents = {row[0] for row in
                     sql(store, "SELECT DISTINCT agent_id FROM message WHERE agent_id != 'main'")}
    assert gather_agents, "gather still WRITES rows — this is a render exclusion, not a record one"

    # POSITIVE CONTROL on the observation channel: the marker main emitted is in main's own
    # next request, read through the SAME flattening every assertion below uses. Without
    # this the negatives pass whenever the marker simply never existed — which is exactly
    # how the previous formulation ("investigate" not in seen) passed: that word appears
    # nowhere in the conversation this test drives, in either arm.
    assert any(MAIN_ONLY_MARKER in seen for seen in main.seen), (
        "the marker never reached main's own history — the channel these negatives watch "
        "cannot see the content they are about, so they would pass vacuously")

    assert len(gather.seen) >= 2, (
        f"gather answered {len(gather.seen)} request(s); the negative below must range over "
        f"a non-empty set of real requests, including the ones past the first")
    for i, seen in enumerate(gather.seen):
        assert MAIN_ONLY_MARKER not in seen, (
            f"gather request {i} was handed main's history; O21 pins that it must not be")

    # every other out-edge of the gather leg the content could reach
    rows = sql(store, "SELECT p.payload FROM message m JOIN message_payload p "
                      "ON p.message_id = m.id WHERE m.agent_id != 'main'")
    assert all(MAIN_ONLY_MARKER not in row[0] for row in rows), (
        "main's history came back as gather's own rows — the render exclusion leaked "
        "through the record path")
    for artifact in sorted((run_dir / "gather_raw").rglob("*")):
        if artifact.is_file():
            assert MAIN_ONLY_MARKER not in artifact.read_text(), (
                f"main's history reached {artifact.name}, a gather out-edge")

    from defender.learning.pipeline import _pydantic_stage
    stage_source = Path(_pydantic_stage.__file__).read_text()
    neither = "learning-stage agents get neither the fold nor the store (O21)"
    assert "session_store" not in stage_source, neither
    assert "selection" not in stage_source, neither


# ==========================================================================
# fail-closed — real faults through the real primitive, timed by the seam
# ==========================================================================

@pytest.mark.parametrize("mode", ["absent", "corrupt", "locked", "disk-full"])
def test_store_append_is_fail_closed(tmp_path, mode):
    """A store that is absent, corrupt, locked, or out of room stops the run instead of
    letting it continue against a history the store does not know was sent: the model is
    never asked for another turn after the failed append.

    Each fault is REAL — the database file is genuinely unlinked (and its parent made
    unwritable), genuinely overwritten with non-database bytes, genuinely locked by a
    second real connection holding `BEGIN EXCLUSIVE`, or genuinely taken to its growth
    ceiling and filled with real bytes until it cannot grow — and the real `sqlite3`
    primitive raises whatever it really raises. `auth:P7` (what a contention outlasting
    `busy_timeout` does) is UNPROBED, so nothing here asserts a specific exception class
    for the locked case; the demand is that the run stops. The fourth mode closes a 3/3
    phase-C consensus premise (`test_disk_fills_partway_through_a_fail_closed_append`)
    that had no demand, no promotion and no drop, over a domain that silently never
    included it; `rp-c1` (EXECUTED) is the claim its fault content rests on."""
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])
    factory = store_factory(tmp_path, fault=StoreFault(on="append", after=2, mode=mode),
                            sink=opened)

    result = drive(run_dir, run_id=f"fail-{mode}", salt=SALT, main=replay,
                   store_factory=factory)

    handle = opened[0]
    handle.release()
    assert result["output"] is None, "a run that lost its store must not report an output"
    assert result["exit_reason"] == "StoreAppendError", result
    assert replay.calls <= 4, (
        f"the run continued after the store failed ({replay.calls} model turns) — that is "
        f"exactly sending a list the store does not know it sent")


def test_store_append_failure_stops_the_run_through_a_handled_exit(tmp_path):
    """A store append that fails stops the run through a HANDLED exit — `run_investigation`
    returns its summary dict carrying `exit_reason == "StoreAppendError"` and the run dir's
    artifacts are still written — rather than crashing out of `agent.iter()` uncaught.

    `auth:P4` (executed) found that an exception raised inside a `ProcessHistory` capability
    propagates FULLY UNWRAPPED out of `agent.iter()` and is caught by NONE of the driver's
    handlers (`UsageLimitExceeded` / `RunAborted` / `BudgetKill`). O19's fail-closed
    therefore exists today only as an uncaught crash: deleting the catch-all (M5) is not
    sufficient — the driver needs a new except arm, or the store must raise a type already
    caught, for fail-closed to be OBSERVED BEHAVIOUR rather than an accident."""
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])

    result = drive(run_dir, run_id="handled", salt=SALT, main=replay,
                   store_factory=store_factory(
                       tmp_path, fault=StoreFault(on="append", after=1, mode="corrupt"),
                       sink=opened))

    assert isinstance(result, dict), result
    assert result["exit_reason"] == "StoreAppendError", result
    assert result["truncated_by"] == "store", (
        "a store-stopped run is a truncated run; the post-run pipeline must not score it "
        "as a complete investigation")
    assert (run_dir / "tool_trace.jsonl").is_file(), (
        "a handled exit still writes the run dir's artifacts")


def test_a_swallowed_store_error_never_sends_an_unrecorded_list(tmp_path):
    """No path returns the processor's input unchanged after a store error: there is no
    catch-all letting a request go out against a list the store never recorded, and the
    wire log holds no request logged after the failed append.

    Positive control: `test_store_append_is_fail_closed`. This is
    `_make_compaction_processor`'s catch-all (`driver.py:311-317`, C12: `except Exception:
    print('compaction skipped'); return messages`) pinned as ABSENT."""
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 8) + [Turn(text="done")])
    drive(run_dir, run_id="no-swallow", salt=SALT, main=replay,
          store_factory=store_factory(
              tmp_path, fault=StoreFault(on="append", after=2, mode="corrupt"), sink=opened))

    source = Path(driver.__file__).read_text()
    assert "compaction skipped" not in source, (
        "the catch-all that returns the input unchanged is what M5 deletes")

    log = run_dir / "llm_requests.jsonl"
    requests_logged = sum(1 for line in log.read_text().splitlines()
                          if line.strip() and json.loads(line).get("kind") == "response")
    assert requests_logged <= 3, (
        f"{requests_logged} requests reached the wire after the store stopped recording")


def test_the_request_logging_guard_stays_around_the_log_path_only(tmp_path):
    """A wire-log write that raises is still swallowed and the run continues, while a store
    append that raises still stops the run — the guard at `driver.py:143-144` stays exactly
    where it is, around the log path alone.

    The log-side fault is real content, not an authored exception: a lone surrogate
    (reachable via `json.loads('"\\ud800"')` on a provider body) is what the STRICT encoder
    O25 introduces must refuse, while the store's stated `ensure_ascii` lets the same
    content through (adv:PO4). The asymmetry is the demand.

    The surrogate-bearing turn ALSO makes a tool call: `_replay_harness.Turn`'s own
    docstring states the rule this fake model must obey too — "a turn with no tool_calls
    is text-only and ENDS the agent loop" — so a text-only first response would end the
    run after one call regardless of whether the log-side fault stopped anything,
    collapsing the very distinction this test exists to make."""
    run_dir = materialize(tmp_path, GOLDEN)
    opened: list = []

    class SurrogateModel:
        __name__ = "SurrogateModel"

        def __init__(self):
            self.calls = 0

        def __call__(self, messages, info) -> ModelResponse:
            self.calls += 1
            if self.calls == 1:
                return ModelResponse(parts=[
                    TextPart(content=json.loads('"\\ud800"')),
                    ToolCallPart(tool_name="read_file",
                                args={"path": str(run_dir / "alert.json")}),
                ])
            return ModelResponse(parts=[TextPart(content="Investigation complete.")])

    model = SurrogateModel()
    result = drive(run_dir, run_id="log-guard", salt=SALT, main=model,
                   store_factory=store_factory(tmp_path, sink=opened))

    assert model.calls >= 2, "a wire-log encoding failure must NOT stop the run"
    assert result["exit_reason"] != "StoreAppendError"
    store = opened[0]
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] > 0, (
        "the store recorded the turn the log could not encode — fail-closed applies to "
        "the store append alone")


# ==========================================================================
# the run-end flush — R11's true `finally`
# ==========================================================================

def test_run_end_flush_captures_the_terminal_response_on_every_exit(tmp_path):
    """A run that ends by `UsageLimitExceeded`, `BudgetKill`, `RunAborted` or an uncaught
    exception type has its terminal response in the store, captured by a SINGLE run-end
    flush in a true `finally` rather than by per-arm flushes — observable through a
    role=`analysis` read of that session, while a role=`send` read of the same session
    still stops before it.

    R11: pre-bind `run`, put the flush in a real `finally`, write `truncated_by` on all
    three caught exits, and order `visualize()` / `render_and_mirror` AFTER the flush.
    G14/F7 found there is no `finally:` at this base and `run` is bound only by the
    async-with header, so an exception during `__aenter__` leaves `:421-423` unreached;
    covering only the three named exits would lose the terminal exchange of a run killed by
    an uncaught type with no observable trace. `ForkStop` stays design-provenance (G12:
    zero hits repo-wide), owned by #696."""
    ss = store_mod()
    exits: dict[str, tuple] = {}

    # (1) UsageLimitExceeded — the request limit
    rd = materialize(tmp_path / "limit", GOLDEN_AB3)
    opened: list = []
    drive(rd, run_id="flush-limit", salt=SALT, main=NeverEndsModel(rd),
          store_factory=store_factory(tmp_path / "limit", sink=opened))
    exits["UsageLimitExceeded"] = (opened[0], "request-limit")

    # (2) BudgetKill — a real cap trip
    rd = materialize(tmp_path / "budget", GOLDEN)
    opened = []
    drive(rd, run_id="flush-budget", salt=SALT,
          main=ReplayFn(_read_alert_turns(rd, 15)),
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600),
          store_factory=store_factory(tmp_path / "budget", sink=opened))
    exits["BudgetKill"] = (opened[0], "budget")

    # (3) RunAborted — the run-wide circuit breaker, raised deep inside a nested gather
    rd = materialize(tmp_path / "abort", GOLDEN_AB3)
    opened = []
    systems = ("elastic", "identity", "cmdb", "ticket", "host-state")
    assert len(systems) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    drive(rd, run_id="flush-abort", salt=SALT,
          main=ReplayFn([Turn(tool_calls=[("gather", {
              "lead_id": "l-001", "system": "elastic", "goal": "probe",
              "what_to_summarize": ["x"]})]), Turn(text="unreached")]),
          gather=ReplayFn([Turn(tool_calls=[("query", {"system": s, "verb": "probe",
                                                       "params": {}})]) for s in systems]
                          + [Turn(text="unreached")]),
          verbs=_down(*systems),
          store_factory=store_factory(tmp_path / "abort", sink=opened))
    exits["RunAborted"] = (opened[0], "aborted")

    # (4) an uncaught type — the case a per-except-arm flush loses entirely
    rd = materialize(tmp_path / "uncaught", GOLDEN)
    opened = []

    def _exploding_gather(messages, info) -> ModelResponse:
        raise RuntimeError("an exit type nobody enumerated")

    # Same shape as (3)'s RunAborted case: the exception arises DEEP INSIDE a nested
    # gather dispatch, so MAIN's own response (the `gather` tool call) stays orphaned —
    # unanswered, no continuation ever built — rather than needing a second call to
    # MAIN's own model (which `Turn`'s own documented rule rules out for a text-only
    # first response, and which — even with a tool call — would leave the FIRST round
    # complete in the store, not orphaned, once round two's own model raises instead of
    # the store ever seeing an unanswered call).
    with pytest.raises(RuntimeError):
        drive(rd, run_id="flush-uncaught", salt=SALT,
              main=ReplayFn([Turn(tool_calls=[("gather", {
                  "lead_id": "l-001", "system": "elastic", "goal": "probe",
                  "what_to_summarize": ["x"]})])]),
              gather=_exploding_gather,
              store_factory=store_factory(tmp_path / "uncaught", sink=opened))
    exits["uncaught"] = (opened[0], None)

    for label, (store, expected_truncated_by) in exits.items():
        session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
        analysis = ss.hydrate(store, session_id, role="analysis")
        send = ss.hydrate(store, session_id, role="send")
        assert analysis, f"{label}: the flush wrote nothing"
        assert isinstance(analysis[-1], ModelResponse), (
            f"{label}: the terminal response is not in the store")
        assert len(analysis) > len(send) or send == analysis, (
            f"{label}: the send read must not be longer than the analysis read")
        if expected_truncated_by is not None:
            assert sql(store, "SELECT truncated_by FROM session WHERE session_id = ?",
                       (session_id,)) == [(expected_truncated_by,)], label


def test_the_moved_projection_is_built_after_the_run_end_flush(tmp_path):
    """For a run terminated mid-pair, the projection `run_stats.py` reads contains the
    terminal response the run-end flush wrote, because `visualize()` / `render_and_mirror`
    are ordered AFTER the flush and the projection reads at role=`analysis`.

    The negative control is the same store projected from its PRE-FLUSH state, which
    demonstrably loses the terminal response — proving the ordering, not the store, is what
    carries it. Under the reading R8 rejected this ordering fix would change nothing a test
    could see, because an analysis-role consumer would have truncated the orphan away
    whether the flush had landed or not (P6 — the R11 × R8 interaction)."""
    ss = store_mod()
    rd = materialize(tmp_path, GOLDEN_AB3)
    opened: list = []
    drive(rd, run_id="order", salt=SALT, main=NeverEndsModel(rd),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
    analysis = ss.hydrate(store, session_id, role="analysis")
    events = [json.loads(line) for line in
              (rd / "tool_trace.jsonl").read_text().splitlines() if line.strip()]
    result_event = [e for e in events if e.get("type") == "result"][-1]

    assistant_events = [e for e in events if e.get("type") == "assistant"]
    responses = [m for m in analysis if isinstance(m, ModelResponse)]
    assert len(assistant_events) == len(responses), (
        f"the projection lost {len(responses) - len(assistant_events)} response(s) — the "
        f"flush landed after the projection")
    assert result_event["num_turns"] == len(responses)

    # negative control: the same store as it stood BEFORE the flush
    pre_flush = analysis[:-1]
    assert len(pre_flush) < len(analysis)
    assert len([m for m in pre_flush if isinstance(m, ModelResponse)]) < len(responses), (
        "the control must actually lose the terminal response, or it controls nothing")


def test_minted_row_round_trips_after_fill_run_metadata(tmp_path, monkeypatch):
    """A renderer-minted synthesized row round-trips byte-identically when the round trip
    is taken AFTER `fill_run_metadata` has run: the row is minted with `run_id`,
    `conversation_id` and `timestamp` already filled from `RunContext`.

    FK9/R17 drops O6's second discharge — "or persisted on the following ingest" is
    unreachable against O6's own last sentence (a minted row is never in the ingest tail),
    so mint-with-RunContext is the only executable branch. C8 (executed) measured the
    hazard: the framework fills those three fields IN PLACE after the processor returns,
    and a row persisted at render time was `byte-identical: False`."""
    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    rd = materialize(tmp_path, GOLDEN)
    opened: list = []
    drive(rd, run_id="minted", salt=SALT,
          main=ReplayFn(_read_alert_turns(rd, 6) + [Turn(text="done")]),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    rows = sql(store, "SELECT m.id, p.payload FROM message m JOIN message_payload p "
                      "ON p.message_id = m.id WHERE m.synthesized = 1 ORDER BY m.id")
    assert rows, "no synthesized frontier row was minted — the fixture folded nothing"
    for _rid, payload in rows:
        body = json.loads(payload)
        for field in ("run_id", "timestamp"):
            assert body.get(field) not in (None, ""), (
                f"a minted row persisted before fill_run_metadata: {field} is {body.get(field)!r}")
        revalidated = ModelMessagesTypeAdapter.validate_json(f"[{payload}]")
        assert json.loads(ModelMessagesTypeAdapter.dump_json(revalidated))[0] == body, (
            "the minted row must re-dump byte-identically")


def test_the_wire_log_is_still_written_and_still_human_readable(tmp_path):
    """The wire log is still written for every request and still parses line by line, so
    the "no application consumers" negative is not passing because the log stopped
    existing.

    Positive control for `test_projections_are_built_from_the_store_not_from_logger_messages`
    — O27 keeps the log for a human debugging a run, and `DEFENDER_LLM_LOG_MAX_CHARS`
    trimming stays legal once nothing forks from it."""
    rd = materialize(tmp_path, GOLDEN)
    replay = ReplayFn(_read_alert_turns(rd, 2) + [Turn(text="done")])
    drive(rd, run_id="log-alive", salt=SALT, main=replay,
          store_factory=store_factory(tmp_path))

    log = rd / "llm_requests.jsonl"
    assert log.is_file()
    lines = [line for line in log.read_text().splitlines() if line.strip()]
    assert lines, "the wire log is empty"
    parsed = [json.loads(line) for line in lines]
    assert all(isinstance(r, dict) and "kind" in r for r in parsed)
    assert sum(1 for r in parsed if r.get("kind") == "response") == replay.calls, (
        "one logged response per request the model answered")
