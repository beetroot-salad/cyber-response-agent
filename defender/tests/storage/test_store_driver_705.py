"""The #705 session store driven end to end through the real `driver.run_investigation` loop with an injected store factory: capability seam, which histories are store-rendered, fail-closed appends, run-end flush, minted-row round trip. Faults are real (unlinked/overwritten/locked db files)."""
from __future__ import annotations

from defender.tests.support.shared.contracts._spec1077 import fixture_run as _run_handle_1165

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

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
from defender.records import RunPaths  # noqa: E402
from defender.investigation import challenge_gate, driver  # noqa: E402
from defender.systems import circuit_breaker  # noqa: E402
from defender.tests.support.storage._session_store_705 import (
    CLOSED_LOOP_INVLANG,
    FaultStore,
    StoreFault,
    is_open,
    sql,
    store_factory,
    store_mod,
)
from defender.tests.e2e._replay_harness import (
    GOLDEN,
    GOLDEN_AB3,
    FakeVerbs,
    NeverEndsModel,
    Priced,
    ReplayFn,
    Turn,
    drive,
    materialize,
    named_models,
    priced_billed,
    priced_cost,
    priced_gather,
)
from defender.tests.support.storage._store_owner import reread
import contextlib

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.jobs._jobs1342 import REFUSED, RESPONSE, UNSEEN

pytestmark = pytest.mark.e2e

SALT = "0011223344556677"

MAIN_ONLY_MARKER = "MAIN-ONLY-MARKER-705-a1b2c3"


def caps(**over) -> dict:
    return {**DEFAULT_LIMITS, **over}


def _one_hit(ctx, *, q: str = "probe") -> list[dict]:
    """A verb that really returns a row, so the gather leg really writes its artifacts."""
    return [{"host": "web-01", "event": "ssh-accept"}]


def _down(*systems: str) -> FakeVerbs:
    from defender.kit.faults import TransportFault

    def probe(ctx, *, q: str = "probe") -> list[dict]:
        raise TransportFault("connection refused")

    return FakeVerbs({s: {"probe": probe} for s in systems})


def _read_alert_turns(run_dir: Path, n: int) -> list[Turn]:
    return [Turn(tool_calls=[("read_file", {"path": model_path(RunPaths(run_dir).alert, run_dir=run_dir)})])
            for _ in range(n)]


# the store-factory seam, and the identity the run mints

def test_run_investigation_takes_a_store_factory_seam(tmp_path):
    run_dir = materialize(tmp_path, GOLDEN, run_id='seam')
    opened: list = []
    factory = store_factory(tmp_path, sink=opened)
    handles: list = []

    @contextlib.contextmanager
    def recording(case_id: str, rd: Path):
        with factory(case_id, rd) as real:
            handle = FaultStore(real)
            handles.append((case_id, rd, handle))
            yield handle

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


# the capability and its seam

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

    store = reread(opened[0])
    agents = {row[0] for row in sql(store, "SELECT DISTINCT agent_id FROM message")}
    assert "main" in agents, agents
    assert any(a != "main" for a in agents), (
        f"the gather leg's rows were not recorded; agent_ids were {agents}")


# whose history is store-rendered

def test_main_history_is_store_rendered(tmp_path):
    ss = store_mod()
    run_dir = materialize(tmp_path, GOLDEN, run_id='store-render')
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 2) + [Turn(text="done")])
    drive(run_dir, run_id="store-render", main=replay,
          store_factory=store_factory(tmp_path, sink=opened))

    store = reread(opened[0])
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

    store = reread(opened[0])
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
            f"gather request {i} was handed main's history")

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
        "the driver still has the catch-all that returns the input unchanged")

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
    store = reread(opened[0])
    assert sql(store, "SELECT COUNT(*) FROM message")[0][0] > 0, (
        "the store recorded the turn the log could not encode — fail-closed applies to "
        "the store append alone")


def _exploding_gather(messages, info) -> ModelResponse:
    raise RuntimeError("an exit type nobody enumerated")


@pytest.mark.parametrize("ending", ["finished", "budget-kill", "uncaught"])
def test_the_run_closes_the_store_it_opened_on_every_exit(tmp_path, monkeypatch, ending):
    """The driver opened the store through the factory, so the driver closes it — however the
    run ends, including by an exception it does not catch (#1324). A caller that wants the rows
    afterwards reopens the file the summary names."""
    rd = materialize(tmp_path, GOLDEN, run_id=f"close-{ending}")
    opened: list = []
    factory = store_factory(tmp_path, sink=opened)
    if ending == "finished":
        summary = drive(rd, run_id=f"close-{ending}", main=ReplayFn([Turn(text="Nothing to do.")]),
                        store_factory=factory)
        assert summary["truncated_by"] is None, summary
    elif ending == "budget-kill":
        monkeypatch.setenv("DEFENDER_BUDGET_ENFORCE", "1")
        summary = drive(rd, run_id=f"close-{ending}", main=ReplayFn(_read_alert_turns(rd, 15)),
                        limits=caps(max_tool_calls=1, wall_clock_timeout=3600, grace_seconds=600),
                        store_factory=factory)
        assert summary["truncated_by"] == "budget", summary
    else:
        with pytest.raises(RuntimeError):
            drive(rd, run_id=f"close-{ending}", main=ReplayFn([Turn(tool_calls=[("gather", {
                "lead_id": "l-001", "system": "elastic", "goal": "probe",
                "what_to_summarize": ["x"]})])]),
                  gather=_exploding_gather, store_factory=factory)
    assert len(opened) == 1, f"the run opened {len(opened)} stores"
    assert not is_open(opened[0]), f"the run ended ({ending}) with its store still open"


def test_a_refused_branch_point_ends_the_run_through_the_store_exit_and_frees_its_log(tmp_path):
    """A store factory that refuses as `BranchError` — what a resume over an unusable branch
    point raises — is a store-setup failure: the run ends `truncated_by="store"` naming the
    class, and its wire log is released, so the same run dir can be driven again."""
    from defender.investigation import branch, observe

    rd = materialize(tmp_path, GOLDEN, run_id="refused-branch")

    def refusing(case_id: str, run_dir: Path):
        raise branch.BranchError("the branch point names no message")

    summary = drive(rd, run_id="refused-branch", main=ReplayFn([Turn(text="unreached")]),
                    store_factory=refusing)
    assert (summary["truncated_by"], summary["exit_reason"]) == ("store", "BranchError"), summary
    observe.RequestLogger.from_record(_run_handle_1165(rd).observability.wire_log).close()


def test_a_run_whose_opening_message_will_not_build_closes_its_store_and_frees_its_log(tmp_path):
    """A failure after setup and before MAIN's first turn (the orient step that builds the
    opening message raises) escapes the run, and still leaves the store closed and the wire log
    free, so the same run dir can be driven again (#1324)."""
    from defender.investigation import observe

    opened: list = []
    rd = materialize(tmp_path, GOLDEN, run_id="prompt-fails")

    def broken_orient(argv, env):
        raise RuntimeError("the orient step broke")

    with pytest.raises(RuntimeError, match="orient step broke"):
        drive(rd, run_id="prompt-fails", main=ReplayFn([Turn(text="unreached")]),
              store_factory=store_factory(tmp_path, sink=opened), orient_shim=broken_orient)
    assert len(opened) == 1, f"the run opened {len(opened)} stores"
    assert not is_open(opened[0]), "the failed prompt left its store open"
    observe.RequestLogger.from_record(_run_handle_1165(rd).observability.wire_log).close()


def test_a_main_session_that_will_not_open_ends_the_run_and_closes_the_store(tmp_path):
    """Store setup can fail AFTER the store opened (the main session refused): the run ends
    through the `truncated_by="store"` exit and the store it opened is closed (#1324)."""
    ss = store_mod()
    opened: list = []

    class _RefusesSessions:
        def __init__(self, real):
            self._real = real

        def __getattr__(self, name):
            return getattr(self._real, name)

        def new_session(self, agent_id):
            raise ss.StoreError("the main session would not open")

    inner = store_factory(tmp_path, sink=opened)

    @contextlib.contextmanager
    def refusing(case_id: str, run_dir: Path):
        with inner(case_id, run_dir) as real:
            yield _RefusesSessions(real)

    rd = materialize(tmp_path, GOLDEN, run_id="session-refused")
    summary = drive(rd, run_id="session-refused", main=ReplayFn([Turn(text="unreached")]),
                    store_factory=refusing)
    assert (summary["truncated_by"], summary["exit_reason"]) == ("store", "StoreError"), summary
    assert len(opened) == 1, f"the run opened {len(opened)} stores"
    assert not is_open(opened[0]), "the refused setup left its store open"
    assert RunPaths(rd).wire_log.is_file(), "a store-setup failure left no wire log (#1377: the logger exists before the ledger can)"


#: The request-limit run's base ceiling: a few rounds, far under the shipped
#: `DEFAULT_REQUEST_LIMIT`, so the run that ends by `UsageLimitExceeded` gets there quickly.
_SHORT_BASE_REQUEST_LIMIT = 4


@pytest.fixture(scope="module")
def request_limit_run(tmp_path_factory):
    """ONE run that ends by `UsageLimitExceeded` (a `NeverEndsModel` over `GOLDEN_AB3`), shared
    by the two tests that read its store read-only (each through its own `reread`): the run-end flush's (1) exit and the
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


# the run-end flush: a true `finally`

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
    with pytest.raises(RuntimeError):
        drive(rd, run_id="flush-uncaught",
              main=ReplayFn([Turn(tool_calls=[("gather", {
                  "lead_id": "l-001", "system": "elastic", "goal": "probe",
                  "what_to_summarize": ["x"]})])]),
              gather=_exploding_gather,
              store_factory=store_factory(tmp_path / "uncaught", sink=opened))
    exits["uncaught"] = (opened[0], None)

    for label, (closed, expected_truncated_by) in exits.items():
        store = reread(closed)
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
    rd, closed = request_limit_run
    store = reread(closed)
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

    store = reread(opened[0])
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


# #1342 M2 / D-ae: a report is committed once the close tool's `ReviewState.closed` is set, and the job-facts holder
# (`run._JobEndFacts`, whose `review_state` dict the driver takes as `AgentDeps.review_state`) is the only source of the
# fact: the run summary no longer carries a `report_committed` key (D-ae, one owner per fact).


def _job_facts():
    from defender.run import _JobEndFacts

    return _JobEndFacts()

#: Store appends the closing replay makes up to and including the close turn's; the next one faults.
_APPENDS_THROUGH_THE_CLOSE = 3


def _closing_replay(run_dir: Path) -> ReplayFn:
    return ReplayFn([
        Turn(tool_calls=[("append_block", {"text": (GOLDEN / "investigation.md").read_text(encoding="utf-8")})]),
        Turn(tool_calls=[("close_investigation", {"disposition": "inconclusive"})]),
        Turn(text="Investigation complete."),
    ])


def _forced_close_run(tmp_path: Path, run_id: str, *, report_blocked: bool = False) -> tuple[Path, dict, Any]:
    """A run that never closes and hits its request limit, so the host forces the close."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    if report_blocked:
        (run_dir / "report.md").mkdir()
    facts = _job_facts()
    result = drive(run_dir, run_id=run_id, main=NeverEndsModel(run_dir), review_state=facts.review_state,
                   bounds=challenge_gate.Bounds(base_request_limit=_SHORT_BASE_REQUEST_LIMIT))
    return run_dir, result, facts


def test_m2_a_close_the_tool_accepted_is_a_committed_report(tmp_path):
    """The model's close was accepted: the holder's `report_committed` is true; the summary has no such key. (M2, D-ae)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-closed")

    facts = _job_facts()
    result = drive(run_dir, run_id="m2-closed", review_state=facts.review_state, main=_closing_replay(run_dir))

    assert (run_dir / "report.md").is_file(), "premise: the close wrote the report"
    assert result["exit_reason"] is None, result
    assert facts.report_committed is True
    assert "report_committed" not in result, "the run summary still carries a second source of the fact (D-ae)"


def test_m2_a_review_record_write_fault_after_the_report_still_counts(tmp_path):
    """The report was written but the review record could not be: terminality follows the report, so true. (M2)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-record-fault")
    planted = [RunPaths(run_dir).review_record(turn) for turn in (1, 2, 3)]
    for path in planted:
        path.mkdir()

    facts = _job_facts()
    drive(run_dir, run_id="m2-record-fault", review_state=facts.review_state, main=_closing_replay(run_dir))

    assert all(path.is_dir() and not list(path.iterdir()) for path in planted), "premise: no record was written"
    assert (run_dir / "report.md").is_file(), "premise: the report landed past the record fault"
    assert facts.report_committed is True


def test_m2_a_forced_close_that_succeeded_is_a_committed_report(tmp_path):
    """A request-limit end: the host's forced `unresolved` close wrote the report, so true. (M2)"""
    run_dir, result, facts = _forced_close_run(tmp_path, "m2-forced")

    assert result["truncated_by"] == "request-limit", result
    assert (run_dir / "report.md").is_file(), "premise: the forced close wrote the report"
    assert result["exit_reason"] != "ForcedCloseFailed", result
    assert facts.report_committed is True


def test_m2_a_forced_close_that_failed_is_not_a_committed_report(tmp_path):
    """The forced close could not write the report: false, and the exit says so. (M2)"""
    run_dir, result, facts = _forced_close_run(tmp_path, "m2-forced-failed", report_blocked=True)

    assert result["exit_reason"] == "ForcedCloseFailed", result
    assert (run_dir / "report.md").is_dir(), "premise: nothing was written over the blocked report"
    assert facts.report_committed is False


def test_m2_a_run_cut_before_any_close_is_not_a_committed_report(tmp_path):
    """A store end, which the host does not force-close: no report, false. (M2)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-cut")
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])
    factory = store_factory(tmp_path, fault=StoreFault(on="append", after=2, mode="corrupt"), sink=opened)

    facts = _job_facts()
    result = drive(run_dir, run_id="m2-cut", review_state=facts.review_state, main=replay, store_factory=factory)
    opened[0].release()

    assert result["truncated_by"] == "store", result
    assert not (run_dir / "report.md").exists(), "premise: no report was written"
    assert facts.report_committed is False


def test_m2_a_report_file_planted_before_a_cut_is_not_a_committed_report(tmp_path):
    """A `report.md` file the host did not commit (planted, then a store end with no close): false. (M2)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-planted")
    (run_dir / "report.md").write_text("# planted by the box\n\nDisposition: benign\n", encoding="utf-8")
    opened: list = []
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])
    factory = store_factory(tmp_path, fault=StoreFault(on="append", after=2, mode="corrupt"), sink=opened)

    facts = _job_facts()
    result = drive(run_dir, run_id="m2-planted", review_state=facts.review_state, main=replay, store_factory=factory)
    opened[0].release()

    assert result["truncated_by"] == "store", result
    assert (run_dir / "report.md").is_file(), "premise: a report file is there, the host never closed"
    assert facts.report_committed is False


def test_m2_a_report_file_planted_in_a_run_that_ends_normally_is_not_a_committed_report(tmp_path):
    """A `report.md` the host did not commit (planted; the model answers "done", no fault, no close): false. (M2)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-planted-ends")
    (run_dir / "report.md").write_text("# planted by the box\n\nDisposition: benign\n", encoding="utf-8")
    replay = ReplayFn(_read_alert_turns(run_dir, 6) + [Turn(text="done")])

    facts = _job_facts()
    result = drive(run_dir, run_id="m2-planted-ends", review_state=facts.review_state, main=replay)

    assert result["truncated_by"] is None, result
    assert (run_dir / "report.md").is_file(), "premise: a report file is there, the host never closed"
    assert facts.report_committed is False


def test_m2_a_close_before_a_cut_is_a_committed_report(tmp_path):
    """The model closed, then a store fault cut the run: the close still counts, whatever the exit. (M2)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="m2-closed-then-cut")
    opened: list = []
    factory = store_factory(tmp_path, fault=StoreFault(on="append", after=_APPENDS_THROUGH_THE_CLOSE, mode="corrupt"),
                            sink=opened)

    facts = _job_facts()
    result = drive(run_dir, run_id="m2-closed-then-cut", review_state=facts.review_state, main=_closing_replay(run_dir), store_factory=factory)
    opened[0].release()

    assert result["truncated_by"] == "store", result
    assert (run_dir / "report.md").is_file(), "premise: the close wrote the report before the cut"
    assert result["closed_before_cut"] is True, result
    assert facts.report_committed is True


# --- #1377: the spend ledger, driven through the real driver (hand-started: no job lane) -------------

_PRICED_NAMES = {"main": "claude-sonnet-4-6", "gather": "claude-haiku-4-5"}


def _priced(*, main: int, gather: int) -> float:
    """What `main` and `gather` priced stand-in responses cost (the harness's `PRICED_USAGE`, priced by the table)."""
    return priced_cost(_PRICED_NAMES["main"], main) + priced_cost(_PRICED_NAMES["gather"], gather)


def _spend_errors(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR and "spend" in r.getMessage().lower()]


def _run_result(run_dir: Path) -> dict:
    events = [json.loads(line) for line in RunPaths(run_dir).tool_trace.read_text(encoding="utf-8").splitlines()]
    return [e for e in events if e.get("type") == "result"][-1]


def _wire_responses(run_dir: Path) -> int:
    return sum(1 for line in RunPaths(run_dir).wire_log.read_text(encoding="utf-8").splitlines()
               if line.strip() and json.loads(line).get("kind") == "response")


def _refuse_ledger_inserts(store, *, agent_id: str | None = None) -> None:
    """A real sqlite fault on the run's own ledger table, made from a second connection (`agent_id`: only that agent's rows)."""
    from defender.tests.support.jobs._jobs1342 import SPEND_LEDGER

    only = f"WHEN NEW.agent_id = '{agent_id}' " if agent_id else ""
    conn = sqlite3.connect(store.path, timeout=10)
    try:
        conn.execute(f"CREATE TRIGGER refuse_spend BEFORE INSERT ON {SPEND_LEDGER} {only}"  # noqa: S608
                     "BEGIN SELECT RAISE(ABORT, 'the disk is full'); END")
        conn.commit()
    finally:
        conn.close()


@contextlib.contextmanager
def _requested(**by_kind: str):
    """The run's agents BUILT to request `by_kind`'s names ("main", "gather"; r7 S1: a row is priced at the requested model)."""
    with pytest.MonkeyPatch.context() as mp:
        env = {"main": "DEFENDER_MODEL", "gather": "DEFENDER_GATHER_MODEL"}
        for kind, name in by_kind.items():
            mp.setenv(env[kind], name)
        yield


def _priced_run(tmp_path, *, run_id: str, refuse_main_call: int | None = None,
                reported: dict[str, str] | None = None, opened: list | None = None) -> tuple[Path, dict, dict]:
    """MAIN (dispatch, then text; sonnet), lead l-001 (one query, then its final summary) and the correlation lead (haiku), each
    response reporting the harness's `PRICED_USAGE`; `refuse_main_call` makes ledger inserts fail from that MAIN request on.
    CONFLICT-UPDATED (r7 S1): the agents are built to request `_PRICED_NAMES`; `reported` (default the same names) is what
    the stand-ins report. Returns the run folder, the driver's summary and how many calls each model made."""
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    opened = [] if opened is None else opened
    calls = {"main": 0, "gather": 0}

    def count(kind: str):
        def before():
            calls[kind] += 1
            if kind == "main" and calls[kind] == refuse_main_call:
                _refuse_ledger_inserts(opened[0])
        return before

    main = Priced(ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic", "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="done")]), before=count("main"))
    gather = priced_gather(ReplayFn([Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
                                     Turn(text="lead summarised")]), before=count("gather"))
    with _requested(**_PRICED_NAMES):
        summary = drive(run_dir, run_id=run_id, main=main, gather=gather,
                        wrap_model=named_models(**(reported or _PRICED_NAMES)),
                        verbs=FakeVerbs({"elastic": {"probe": _one_hit}}), store_factory=store_factory(tmp_path, sink=opened))
    return run_dir, summary, calls


def test_s1_s5_a_run_files_total_prices_every_response_the_run_received_and_usage_moves_with_it(tmp_path, caplog):
    """The total is every priced response (MAIN, each lead's final one, the correlation lead's), all four billed counts, exact; usage agrees count by count; `num_turns` stays MAIN's. (S1, S5)"""
    run_dir, summary, calls = _priced_run(tmp_path, run_id="ledger-total")

    assert calls == {"main": 2, "gather": 3}, ("premise: the scripted calls", calls)
    assert summary["truncated_by"] is None, summary
    assert _wire_responses(run_dir) == 5, "premise: the request log saw every response"
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(_priced(main=2, gather=3), abs=1e-6), (
        "the lead's final response and the correlation lead are not in the total")
    assert result["total_cost_is_lower_limit"] is False
    assert result["usage"] == priced_billed(5)
    assert result["num_turns"] == 2, "`num_turns` is investigator turns"
    assert _spend_errors(caplog) == [], "a healthy run logged a failed spend write"


def test_s3_a_ledger_write_that_fails_leaves_the_run_unchanged_logs_at_error_and_marks_the_total(tmp_path, caplog):
    """Ledger inserts refused from MAIN's last request on: same exit as the control, the total lacks that response and is marked, ERROR names spend. (S3, S5)"""
    _, control, _ = _priced_run(tmp_path / "control", run_id="ledger-control")
    caplog.clear()
    run_dir, summary, calls = _priced_run(tmp_path / "refused", run_id="ledger-refused", refuse_main_call=2)

    assert calls == {"main": 2, "gather": 3}, ("premise: the run still made every call", calls)
    assert {k: summary.get(k) for k in ("truncated_by", "exit_reason")} == {
        k: control.get(k) for k in ("truncated_by", "exit_reason")} == {"truncated_by": None, "exit_reason": None}
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(_priced(main=1, gather=3), abs=1e-6), "the refused response should be the only one missing"
    assert result["total_cost_is_lower_limit"] is True
    assert result["usage"] == priced_billed(4)
    assert _spend_errors(caplog), "a failed spend write was not logged at ERROR"


def test_s3_the_ledger_is_written_ahead_of_the_request_log_so_a_log_fault_does_not_cost_a_response(tmp_path, caplog):
    """The wire log's file replaced by a directory from MAIN's second request on: every later response still reaches the ledger. (S1, S3)"""
    run_dir = materialize(tmp_path, GOLDEN, run_id="ledger-before-log")
    wire = RunPaths(run_dir).wire_log
    path = model_path(RunPaths(run_dir).alert, run_dir=run_dir)
    calls = {"n": 0}

    def break_the_wire_log():
        calls["n"] += 1
        if calls["n"] == 2:
            wire.unlink()
            wire.mkdir()

    main = Priced(ReplayFn([Turn(tool_calls=[("read_file", {"path": path})]), Turn(tool_calls=[("read_file", {"path": path})]),
                            Turn(text="done")]), before=break_the_wire_log)

    with _requested(main="claude-sonnet-4-6"):  # CONFLICT-UPDATED (r7 S1): MAIN is built for the name it is priced at
        summary = drive(run_dir, run_id="ledger-before-log", main=main, wrap_model=named_models(main="claude-sonnet-4-6"))

    assert summary["truncated_by"] is None, summary
    assert wire.is_dir(), "premise: the wire log is a directory"
    assert any("request logging skipped" in r.getMessage() for r in caplog.records), "premise: the request log's write failed"
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(_priced(main=3, gather=0), abs=1e-6), "a response was lost behind the request-log fault"
    assert result["total_cost_is_lower_limit"] is False
    assert result["num_turns"] == 3
    assert _spend_errors(caplog) == []


def _drop_the_ledger_table(store) -> None:
    """A real session database without its `spend_ledger` table, dropped from a second connection."""
    from defender.tests.support.jobs._jobs1342 import SPEND_LEDGER

    conn = sqlite3.connect(store.path, timeout=10)
    try:
        conn.execute(f"DROP TABLE {SPEND_LEDGER}")
        conn.commit()
    finally:
        conn.close()


def _event_shape(events: list[dict]) -> list[tuple]:
    """Each event's type and the tool names it carries, the result line left out."""
    def tools(e: dict) -> tuple:
        content = (e.get("message") or {}).get("content")
        return tuple(c.get("name") for c in content if isinstance(c, dict) and c.get("type") == "tool_use") if isinstance(content, list) else ()
    return [(e.get("type"), tools(e)) for e in events if e.get("type") != "result"]


def test_a1_a2_a_session_database_without_its_ledger_table_leaves_the_run_file_whole_with_no_total(tmp_path):
    """The ledger table gone from the run's own database: the events and result line stay, `num_turns` is MAIN's, total and usage are null, the mark false. (A1, A2)"""
    control_dir, control_summary, _ = _priced_run(tmp_path / "control", run_id="ledger-present")
    control = _run_result(control_dir)
    assert isinstance(control["total_cost_usd"], float), "positive control: a readable ledger gives a number"
    assert control["total_cost_usd"] > 0, "positive control: a readable ledger gives a number"

    opened: list = []
    run_dir = materialize(tmp_path / "dropped", GOLDEN_AB3, run_id="ledger-dropped")
    calls = {"main": 0}

    def drop_before_the_first_call():
        calls["main"] += 1
        if calls["main"] == 1:
            _drop_the_ledger_table(opened[0])

    main = Priced(ReplayFn([
        Turn(tool_calls=[("gather", {"lead_id": "l-001", "system": "elastic", "goal": "probe", "what_to_summarize": ["x"]})]),
        Turn(text="done")]), before=drop_before_the_first_call)
    gather = priced_gather(ReplayFn([Turn(tool_calls=[("query", {"system": "elastic", "verb": "probe", "params": {}})]),
                                     Turn(text="lead summarised")]))
    summary = drive(run_dir, run_id="ledger-dropped", main=main, gather=gather, wrap_model=named_models(**_PRICED_NAMES),
                    verbs=FakeVerbs({"elastic": {"probe": _one_hit}}), store_factory=store_factory(tmp_path / "dropped", sink=opened))

    conn = sqlite3.connect(summary["store_path"])
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        conn.close()
    assert "spend_ledger" not in tables, "premise: the table is gone"
    assert calls["main"] == 2, "premise: the run made every MAIN call"
    events = [json.loads(line) for line in RunPaths(run_dir).tool_trace.read_text(encoding="utf-8").splitlines()]
    assert any(e.get("type") == "assistant" for e in events), "the run file lost its events"
    control_events = [json.loads(line) for line in RunPaths(control_dir).tool_trace.read_text(encoding="utf-8").splitlines()]
    assert _event_shape(events) == _event_shape(control_events), "the run file's events differ from the control's"
    ending = ("truncated_by", "exit_reason")
    assert {k: summary.get(k) for k in ending} == {k: control_summary.get(k) for k in ending} == {
        "truncated_by": None, "exit_reason": None}, "an unreadable ledger changed how the run ended"
    result = _run_result(run_dir)
    assert result["num_turns"] == control["num_turns"] == 2, "`num_turns` is MAIN's turns"
    assert result["total_cost_usd"] is None
    assert result["usage"] is None
    assert result["total_cost_is_lower_limit"] is False, "the mark is true only beside a number"
    assert _wire_responses(run_dir) == 5, "the request log lost responses"


# --- #1377 r7: the ledger says whether its total is exact --------------------------------------------

def test_s1_r7_a_response_is_priced_at_the_model_its_agent_was_built_to_request_not_the_name_it_reports(tmp_path, caplog):
    """MAIN built for sonnet and the leads for haiku, each stand-in reporting a spelling with no pricing row: the total is
    every response at its requested row, exact. (r7 S1)"""
    from defender.configuration import usage_cost

    reported = {"main": "claude-sonnet-4-6-rerouted", "gather": "glm-5.3-0905"}
    assert all(usage_cost(name, priced_billed()) == 0.0 for name in reported.values()), "premise: the reported names price at 0"
    opened: list = []
    run_dir, summary, calls = _priced_run(tmp_path, run_id=fixture_uuid("ledger-requested"), reported=reported, opened=opened)

    assert calls == {"main": 2, "gather": 3}, ("premise: the scripted calls", calls)
    assert summary["truncated_by"] is None, summary
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(_priced(main=2, gather=3), abs=1e-6), (
        "a response was priced at the name it reported, not the model its agent requested")
    assert result["total_cost_is_lower_limit"] is False
    assert _spend_errors(caplog) == []
    read = _ledger_of(opened, run_dir.name)
    assert read.by_agent == pytest.approx({
        "main": priced_cost(_PRICED_NAMES["main"], 2), "gather:l-001": priced_cost(_PRICED_NAMES["gather"], 2),
        "gather:l-00c": priced_cost(_PRICED_NAMES["gather"], 1)}), "a response is not its requesting agent's, at the requested row"
    assert read.complete is True
    assert _spend_rows(opened, run_dir.name) == sorted([
        *[("main", _PRICED_NAMES["main"], reported["main"], RESPONSE)] * 2,
        *[("gather:l-001", _PRICED_NAMES["gather"], reported["gather"], RESPONSE)] * 2,
        ("gather:l-00c", _PRICED_NAMES["gather"], reported["gather"], RESPONSE)]), (
        "a row does not carry the built name as requested and the stand-in's own name as reported")


def _spend_rows(opened: list, run_id: str) -> list[tuple]:
    """The run's ledger rows as the real hook wrote them, by one SQL read: (agent, requested, reported, outcome), sorted."""
    from defender.tests.support.jobs._jobs1342 import SPEND_COLUMNS, SPEND_LEDGER

    assert SPEND_COLUMNS[:5] == ("run_id", "agent_id", "requested_model", "reported_model", "outcome")
    conn = sqlite3.connect(opened[0].path, timeout=10)
    try:
        found = conn.execute(f"SELECT agent_id, requested_model, reported_model, outcome FROM {SPEND_LEDGER} "  # noqa: S608
                             "WHERE run_id = ?", (run_id,)).fetchall()
    finally:
        conn.close()
    return sorted(found, key=lambda r: tuple("" if v is None else v for v in r))


def _ledger_of(opened: list, run_id: str):
    """The run's ledger through the one read (`session_store.read_ledger`, contract-chosen), on a connection the test owns."""
    from defender.records import session_store as ss

    return ss.read_ledger(reread(opened[0]), run_id)


def _priced_stamped(reported: dict[str, str], *, retries: bool = True):
    """`drive(wrap_model=...)`: each kind's stand-in reports `PRICED_USAGE` under `reported[kind]`, behind the REAL retrier
    (no waiting; `retries=False`: none), so the model-request hook sees each request's outcome as production's does: after the
    retrier, or, without one, an HTTP error as the provider raised it (r7 S2a, E)."""
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.usage import RequestUsage

    from defender.providers import with_retries
    from defender.tests.e2e._replay_harness import PRICED_USAGE
    from defender.tests.runtime.providers import _spec1243 as P

    def wrap(kind: str, model: Any) -> Any:
        inner = model.function

        async def priced(messages, info):
            response = await inner(messages, info)
            response.usage = RequestUsage(**PRICED_USAGE)
            return response

        priced.__name__ = getattr(inner, "__name__", kind)
        stand_in = FunctionModel(priced, model_name=reported[kind])
        return with_retries(stand_in, P.instant_policy()) if retries else stand_in

    return wrap


def _correlation_run(tmp_path, *, label: str, gather: Any, limits: dict | None = None, retries: bool = True,
                     names: dict[str, str] | None = None, refuse_ledger_of: str | None = None) -> tuple[Path, dict, dict, list]:
    """MAIN (one text turn) after the correlation lead `l-00c`, answered by `gather` (a `_spec1222.LeadRouter`); the agents are
    built to request `names` (default `_PRICED_NAMES`) and report the same; `refuse_ledger_of` makes the ledger refuse that
    agent's inserts from the store's opening. Returns the run folder (named by the run id the
    ledger keys on), summary, MAIN's calls and the stores the run opened."""
    names = names or _PRICED_NAMES
    run_id = fixture_uuid(label)
    run_dir = materialize(tmp_path, GOLDEN_AB3, run_id=run_id)
    calls = {"main": 0}
    opened: list = []

    def count():
        calls["main"] += 1

    main = ReplayFn([Turn(text="done")])
    plain = store_factory(tmp_path, sink=opened)

    @contextlib.contextmanager
    def factory(case_id, directory):
        with plain(case_id, directory) as handle:
            if refuse_ledger_of:
                _refuse_ledger_inserts(handle, agent_id=refuse_ledger_of)
            yield handle

    with _requested(**names):
        summary = drive(run_dir, run_id=run_id, main=Priced(main, before=count), gather=gather,
                        wrap_model=_priced_stamped(names, retries=retries), limits=limits,
                        verbs=FakeVerbs({"elastic": {"probe": _one_hit}}), store_factory=factory)
    assert run_dir.name == run_id, "premise: the run folder is the run id"
    return run_dir, summary, calls, opened


def _page_of(run_dir: Path, summary: dict, tmp_path, monkeypatch) -> str:
    """The run page through its real renderer, handed what the post-run step hands it: the in-process summary's own flag."""
    from defender.presentation.visualize_run import render_page

    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "state"))
    return render_page(_run_handle_1165(run_dir), spend_write_failed=summary["spend_write_failed"])


def _unparseable() -> BaseException:
    """What a provider's 200 reply that is JSON but not a completion raises out of the real OpenAI-chat model (probed:
    `httpx.MockTransport` answering `{"bad": 1}`; one attempt, not retried)."""
    from pydantic_ai.exceptions import UnexpectedModelBehavior

    return UnexpectedModelBehavior("Invalid response from openai chat completions endpoint: 4 validation errors for ChatCompletion")


def _outcome_router(outcome: str) -> Any:
    from defender.tests.runtime.providers import _spec1243 as P
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    if outcome == "provider-down":  # every attempt a 503: the retrier gives up with `ProviderDown`
        return P.LeadsFailing(plans={S.L3: P.ALWAYS_503})
    if outcome == "retried-503":  # the first attempt a 503, the retry answers: one request, one response
        return P.LeadsFailing(plans={S.L3: P.first_n(1)})
    faults = {"response": S.CLEAN, "refused-400": S.LeadFault(raise_on=1, exc=S.provider_refusal),
              "cancelled": S.LeadFault(hang=True), "unparseable": S.LeadFault(raise_on=1, exc=_unparseable)}
    return S.LeadRouter(faults={S.L3: faults[outcome]})


#: outcome -> (l-00c's priced responses in the total, the total is "at least", the run's `truncated_by`, MAIN's calls,
#: the outcome word of the lead's one ledger row).
_OUTCOMES = {
    "response": (1, False, None, 1, RESPONSE),
    "retried-503": (1, False, None, 1, RESPONSE),
    "refused-400": (0, False, None, 1, REFUSED),
    "cancelled": (0, True, None, 1, UNSEEN),
    "unparseable": (0, True, None, 1, UNSEEN),
    "provider-down": (0, True, "provider-down", 0, UNSEEN),
}


@pytest.mark.parametrize("outcome", _OUTCOMES, ids=_OUTCOMES)
def test_s2a_r7_the_final_outcome_of_a_request_decides_whether_the_total_is_exact(tmp_path, caplog, monkeypatch, outcome):
    """The correlation lead's one request ends each way the hook sees it: only a response is priced, only a non-retried 400
    keeps the total exact, and the run file, the ledger read and the page agree on sum and mark. (r7 S2a, S5, S6)"""
    from defender.tests.support.presentation import _cost_page_1377 as C
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    lead_responses, at_least, truncated_by, main_calls, lead_row = _OUTCOMES[outcome]
    limits = S.with_deadline(S.SHORT_DEADLINE_S) if outcome == "cancelled" else None
    router = _outcome_router(outcome)
    run_dir, summary, calls, opened = _correlation_run(tmp_path, label=f"ledger-outcome-{outcome}", gather=router, limits=limits)

    if outcome in ("provider-down", "retried-503"):
        assert router.attempts(S.L3) == (4 if outcome == "provider-down" else 2), "premise: the retrier's attempts"
        assert router.requests(S.L3) == (0 if outcome == "provider-down" else 1), "premise: only the answered attempt reached the script"
    else:
        assert router.requests(S.L3) == 1, "premise: the correlation lead made its one request"
    assert calls["main"] == main_calls, ("premise: MAIN's calls", calls)
    assert summary["truncated_by"] == truncated_by, summary
    total = priced_cost(_PRICED_NAMES["main"], main_calls) + priced_cost(_PRICED_NAMES["gather"], lead_responses)
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(total, abs=1e-6)
    assert result["total_cost_is_lower_limit"] is at_least, f"{outcome}: the total's mark"
    assert _spend_errors(caplog) == [], "an outcome the hook saw was logged as a failed spend write"

    read = _ledger_of(opened, run_dir.name)
    assert (read.total, read.complete) == (pytest.approx(total, abs=1e-6), not at_least)
    assert read.by_agent["gather:l-00c"] == pytest.approx(priced_cost(_PRICED_NAMES["gather"], lead_responses), abs=1e-6), (
        "the outcome left no row of the lead's own (a refused request is a $0 row, not no row)")
    assert ("main" in read.by_agent) is (main_calls > 0)
    lead_reported = _PRICED_NAMES["gather"] if lead_row == RESPONSE else None
    assert _spend_rows(opened, run_dir.name) == sorted([
        *[("main", _PRICED_NAMES["main"], _PRICED_NAMES["main"], RESPONSE)] * main_calls,
        ("gather:l-00c", _PRICED_NAMES["gather"], lead_reported, lead_row)], key=lambda r: tuple("" if v is None else v for v in r)), (
        "the hook's one row per request: the built name as requested, the reported name only on a response, the outcome word")

    html = _page_of(run_dir, summary, tmp_path, monkeypatch)
    headline = C.headline(html)
    assert C.at_least(headline) is at_least, f"the page's mark: {headline!r}"
    assert C.dollars(headline) == pytest.approx(total, abs=1e-4), "the page's sum is not the run file's"
    bar = C.segments(html)
    spent = {"main": priced_cost(_PRICED_NAMES["main"], main_calls), "correlation": priced_cost(_PRICED_NAMES["gather"], lead_responses)}
    assert bar == pytest.approx({kind: v for kind, v in spent.items() if v}, abs=1e-4), (
        "the bar holds exactly the kinds that spent: no segment for a kind whose requests were refused, unseen or never made")


@pytest.mark.parametrize("outcome", ["refused-400", "cancelled"])
def test_s2a_r7_s2c_a_request_whose_ledger_write_is_refused_leaves_its_own_ending_and_marks_the_total(tmp_path, caplog, outcome):
    """The correlation lead's refused (400) or deadline-cancelled request, its row's insert refused (MAIN's rows are not): the
    run ends as the control's does (the original exception survives), the total is marked, one spend ERROR. (r7 S2a, S2c)"""
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    _, _, truncated_by, main_calls, _ = _OUTCOMES[outcome]
    limits = S.with_deadline(S.SHORT_DEADLINE_S) if outcome == "cancelled" else None
    _, control, control_calls, _ = _correlation_run(tmp_path / "control", label=f"ledger-refused-control-{outcome}",
                                                    gather=_outcome_router(outcome), limits=limits)
    caplog.clear()
    router = _outcome_router(outcome)
    run_dir, summary, calls, opened = _correlation_run(tmp_path / "refused", label=f"ledger-refused-{outcome}", gather=router,
                                                       limits=limits, refuse_ledger_of="gather:l-00c")

    assert router.requests(S.L3) == 1, "premise: the lead made its one request"
    assert (summary["truncated_by"], summary.get("exit_reason"), calls) == (
        truncated_by, control.get("exit_reason"), control_calls) == (truncated_by, control.get("exit_reason"), {"main": main_calls}), (
        "a failed ledger write changed how the run ended")
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(priced_cost(_PRICED_NAMES["main"], main_calls), abs=1e-6)
    assert result["total_cost_is_lower_limit"] is True, "the total over a lost row reads exact"
    assert len(_spend_errors(caplog)) == 1, _spend_errors(caplog)
    assert [r[0] for r in _spend_rows(opened, run_dir.name)] == ["main"] * main_calls, "premise: only the lead's row was refused"


#: HTTP statuses a provider's error carries as the hook sees them with no retrier in front, and the design's reading of each
#: (r7 S2a: "a 4xx other than 408, 409 or 429" is refused; r7.1 E: a 5xx reaching the hook unwrapped is unseen).
_UNWRAPPED = {**{status: "refused" for status in (400, 401, 403, 404, 413, 422)},
              **{status: "unseen" for status in (408, 409, 429, 500, 502, 503, 529)},
              None: "unseen"}  # a bare `ModelAPIError` (no status: a timeout or dropped connection) is a temporary end


def _http_error(status: int | None) -> BaseException:
    from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

    return ModelAPIError("fake-gather", "x") if status is None else ModelHTTPError(status, "fake-gather", body={"error": "x"})


@pytest.mark.parametrize("status", _UNWRAPPED, ids=[f"{s or 'no-status'}-{v}" for s, v in _UNWRAPPED.items()])
def test_s2a_r7_e_an_http_error_reaching_the_hook_is_refused_exactly_when_the_retrier_would_not_retry_it(tmp_path, status):
    """The lead's one request fails with `status`, no retrier in front: a status the retrier does not retry is a $0 row and an
    exact total; every other is unseen and the total reads "at least". (r7.1 E)"""
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    router = S.LeadRouter(faults={S.L3: S.LeadFault(raise_on=1, exc=lambda: _http_error(status))})
    run_dir, summary, calls, opened = _correlation_run(tmp_path, label=f"ledger-status-{status or 'none'}", gather=router, retries=False)

    assert router.requests(S.L3) == 1, "premise: the lead made its one request"
    result = _run_result(run_dir)
    assert result["total_cost_is_lower_limit"] is (_UNWRAPPED[status] == "unseen"), f"{status}: the total's mark"
    assert result["total_cost_usd"] == pytest.approx(priced_cost(_PRICED_NAMES["main"], calls["main"]), abs=1e-6)
    read = _ledger_of(opened, run_dir.name)
    assert read.by_agent["gather:l-00c"] == 0.0, f"{status}: no row for the failed request"
    assert read.complete is (_UNWRAPPED[status] == "refused")
    assert [r for r in _spend_rows(opened, run_dir.name) if r[0] == "gather:l-00c"] == [
        ("gather:l-00c", _PRICED_NAMES["gather"], None, REFUSED if _UNWRAPPED[status] == "refused" else UNSEEN)]


def test_s2b_r7_a_requested_model_with_no_pricing_row_runs_adds_nothing_and_marks_the_total(tmp_path, caplog):
    """The leads built for a model the pricing table has no row for: the run completes, their responses add $0, and the
    total over MAIN's reads "at least". The priced `response` row of the S2a case is the control. (r7 S2b)"""
    from defender.configuration import usage_cost
    from defender.providers import provider_for
    from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

    unpriced = "claude-opus-9-0"  # routable (a provider builds it), with no pricing row
    assert provider_for(unpriced).id == "anthropic", "premise: the name routes"
    assert usage_cost(unpriced, priced_billed()) == 0.0, "premise: no pricing row prices the name"
    router = S.LeadRouter()
    run_dir, summary, calls, opened = _correlation_run(tmp_path, label="ledger-unpriced", gather=router,
                                                       names={"main": _PRICED_NAMES["main"], "gather": unpriced})

    assert router.requests(S.L3) == 1, "premise: the unpriced lead answered"
    assert (summary["truncated_by"], calls["main"]) == (None, 1), "the unpriced model changed the run"
    result = _run_result(run_dir)
    assert result["total_cost_usd"] == pytest.approx(priced_cost(_PRICED_NAMES["main"], 1), abs=1e-6)
    assert result["total_cost_is_lower_limit"] is True
    assert _spend_errors(caplog) == []
    read = _ledger_of(opened, run_dir.name)
    assert read.by_agent["gather:l-00c"] == 0.0
    assert read.complete is False
