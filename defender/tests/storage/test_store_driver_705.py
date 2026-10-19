"""The #705 session store driven end to end through the real `driver.run_investigation` loop with an injected store factory: capability seam, which histories are store-rendered, fail-closed appends, run-end flush, minted-row round trip. Faults are real (unlinked/overwritten/locked db files)."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelMessagesTypeAdapter,
    ModelResponse,
    TextPart,
    ToolCallPart,
)

from defender.hooks.budget_enforcer import DEFAULT_LIMITS  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import challenge_gate, circuit_breaker, driver  # noqa: E402
from defender.tests.support.storage._session_store_705 import (
    CLOSED_LOOP_INVLANG,
    FaultStore,
    StoreFault,
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


def _read_alert_turns(run_dir: Path, n: int) -> list[Turn]:
    return [Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})])
            for _ in range(n)]


# the fifth seam, and the identity the run mints

def test_run_investigation_takes_a_store_factory_seam(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN, run_id='seam')
    opened: list = []
    factory = store_factory(tmp_path, sink=opened)
    handles: list = []

    def recording(case_id: str, rd: Path):
        handle = FaultStore(factory(case_id, rd))
        handles.append((case_id, rd, handle))
        return handle

    result = drive(run_dir, run_id="seam",
                   main=ReplayFn([Turn(text="Investigation complete.")]),
                   store_factory=recording)

    assert len(handles) == 1, f"the factory must be called exactly once; got {handles}"
    case_id, handed_run_dir, handle = handles[0]
    assert handed_run_dir == run_dir
    assert case_id == result["case_id"]
    assert handle.appends, "the run drove the injected handle, not one it made itself"
    assert Path(result["store_path"]) == Path(handle.path)


def test_run_investigation_mints_a_case_id_and_writes_a_run_dir_pointer(
    tmp_path,
):
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN, run_id='pointer')
    result = drive(run_dir, run_id="pointer",
                   main=ReplayFn([Turn(text="done")]),
                   store_factory=store_factory(tmp_path))

    pointer = RunPaths(run_dir).session_pointer()
    assert pointer.parent == run_dir.parent, f"the pointer is not beside the run dir: {pointer}"
    assert pointer.is_file(), f"no case pointer sidecar at {pointer}"
    body = json.loads(pointer.read_text())
    assert set(body) >= {"case_id", "store_path"}, body
    assert body["case_id"] == result["case_id"]
    assert not (run_dir / "session_store_pointer.json").exists(), (
        "the case pointer is still written inside the box-writable run dir")

    resolved = ss.resolve_store_path(_run_handle_1165(run_dir))
    assert Path(resolved) == Path(body["store_path"]) == Path(result["store_path"])


# the capability, its seam, and the flag that no longer gates it

def test_capability_attaches_at_the_existing_extra_capabilities_seam(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='seam-attach')
    opened: list = []
    main = ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic",
                                     "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="Investigation complete."),
    ])
    gather = ReplayFn([Turn(text="lead summarised")])

    drive(run_dir, run_id="seam-attach", main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {}}),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    agents = {row[0] for row in sql(store, "SELECT DISTINCT agent_id FROM message")}
    assert "main" in agents, agents
    assert any(a != "main" for a in agents), (
        f"the gather leg's rows must be recorded too (O21 denies gather the RENDER, not "
        f"the record); agent_ids were {agents}")


# whose history is store-rendered

def test_main_history_is_store_rendered(tmp_path):
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN, run_id='store-render')
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 2) + [Turn(text="done")])
    drive(run_dir, run_id="store-render", main=replay,
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
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id='gather-render')
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
    drive(run_dir, run_id="gather-render", main=main, gather=gather,
          verbs=FakeVerbs({"elastic": {"probe": _one_hit}}),
          store_factory=store_factory(tmp_path, sink=opened))

    store = opened[0]
    gather_agents = {row[0] for row in
                     sql(store, "SELECT DISTINCT agent_id FROM message WHERE agent_id != 'main'")}
    assert gather_agents, "gather still WRITES rows — this is a render exclusion, not a record one"

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

    from defender.learning import _pydantic_stage
    stage_source = Path(_pydantic_stage.__file__).read_text()
    neither = "learning-stage agents get neither the fold nor the store (O21)"
    assert "session_store" not in stage_source, neither
    assert "selection" not in stage_source, neither


# fail-closed — real faults through the real primitive, timed by the seam

@pytest.mark.parametrize("mode", ["absent", "corrupt", "locked", "disk-full"])
def test_store_append_is_fail_closed(tmp_path, mode):
    run_dir = materialize(tmp_path, GOLDEN, run_id=f"fail-{mode}")
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])
    factory = store_factory(tmp_path, fault=StoreFault(on="append", after=2, mode=mode),
                            sink=opened)

    result = drive(run_dir, run_id=f"fail-{mode}", main=replay,
                   store_factory=factory)

    handle = opened[0]
    handle.release()
    assert result["output"] is None, "a run that lost its store must not report an output"
    assert result["exit_reason"] == "StoreAppendError", result
    assert replay.calls <= 4, (
        f"the run continued after the store failed ({replay.calls} model turns) — that is "
        f"exactly sending a list the store does not know it sent")


def test_store_append_failure_stops_the_run_through_a_handled_exit(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN, run_id='handled')
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])

    result = drive(run_dir, run_id="handled", main=replay,
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
    run_dir = materialize(tmp_path, GOLDEN, run_id='no-swallow')
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 8) + [Turn(text="done")])
    drive(run_dir, run_id="no-swallow", main=replay,
          store_factory=store_factory(
              tmp_path, fault=StoreFault(on="append", after=2, mode="corrupt"), sink=opened))

    source = Path(driver.__file__).read_text()
    assert "compaction skipped" not in source, (
        "the catch-all that returns the input unchanged is what M5 deletes")

    log = RunPaths(run_dir).wire_log
    requests_logged = sum(1 for line in log.read_text().splitlines()
                          if line.strip() and json.loads(line).get("kind") == "response")
    assert requests_logged <= 3, (
        f"{requests_logged} requests reached the wire after the store stopped recording")


def test_the_request_logging_guard_stays_around_the_log_path_only(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN, run_id='log-guard')
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
                                args={"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)}),
                ])
            return ModelResponse(parts=[TextPart(content="Investigation complete.")])

    model = SurrogateModel()
    result = drive(run_dir, run_id="log-guard", main=model,
                   store_factory=store_factory(tmp_path, sink=opened))

    assert model.calls >= 2, "a wire-log encoding failure must NOT stop the run"
    assert result["exit_reason"] != "StoreAppendError"
    store = opened[0]
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] > 0, (
        "the store recorded the turn the log could not encode — fail-closed applies to "
        "the store append alone")


#: The request-limit run's base ceiling: a few rounds, far under the shipped
#: `DEFAULT_REQUEST_LIMIT`, so the run that ends by `UsageLimitExceeded` gets there quickly.
_SHORT_BASE_REQUEST_LIMIT = 4


@pytest.fixture(scope="module")
def request_limit_run(tmp_path_factory):
    """ONE run that ends by `UsageLimitExceeded` (a `NeverEndsModel` over `GOLDEN_AB3`), shared
    by the two tests that read its store read-only: the run-end flush's (1) exit and the
    projection-order test. Driven once instead of twice; neither test writes to it."""
    base = tmp_path_factory.mktemp("request-limit")
    rd = materialize(base, GOLDEN_AB3, run_id='flush-limit')
    opened: list = []
    bounds = challenge_gate.Bounds(base_request_limit=_SHORT_BASE_REQUEST_LIMIT)
    model = NeverEndsModel(rd)
    drive(rd, run_id="flush-limit", main=model, bounds=bounds,
          store_factory=store_factory(base, sink=opened))
    assert model.calls == challenge_gate.raised_request_limit(bounds), model.calls
    return rd, opened[0]


# the run-end flush — R11's true `finally`

def test_run_end_flush_captures_the_terminal_response_on_every_exit(
        tmp_path, monkeypatch, request_limit_run):
    ss = store_mod()
    exits: dict[str, tuple] = {}

    # (1) UsageLimitExceeded — the request limit
    exits["UsageLimitExceeded"] = (request_limit_run[1], "request-limit")

    # (2) BudgetKill — a real cap trip
    rd = materialize(tmp_path / "budget", GOLDEN, run_id="flush-budget")
    opened = []
    monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "1")
    drive(rd, run_id="flush-budget",
          main=ReplayFn(_read_alert_turns(rd, 15)),
          limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600),
          store_factory=store_factory(tmp_path / "budget", sink=opened))
    exits["BudgetKill"] = (opened[0], "budget")

    # (3) RunAborted — the run-wide circuit breaker, raised deep inside a nested gather
    rd = materialize(tmp_path / "abort", GOLDEN_AB3, run_id="flush-abort")
    opened = []
    systems = ("elastic", "identity", "cmdb", "ticket", "host-state")
    assert len(systems) == circuit_breaker.RUN_FAIL_KILL_LIMIT
    drive(rd, run_id="flush-abort",
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
    rd = materialize(tmp_path / "uncaught", GOLDEN, run_id="flush-uncaught")
    opened = []

    def _exploding_gather(messages, info) -> ModelResponse:
        raise RuntimeError("an exit type nobody enumerated")

    with pytest.raises(RuntimeError):
        drive(rd, run_id="flush-uncaught",
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


def test_the_moved_projection_is_built_after_the_run_end_flush(request_limit_run):
    ss = store_mod()
    rd, store = request_limit_run
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
    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    rd = materialize(tmp_path, GOLDEN, run_id='minted')
    (rd / "investigation.md").write_text(CLOSED_LOOP_INVLANG, encoding="utf-8")
    opened: list = []
    drive(rd, run_id="minted",
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
