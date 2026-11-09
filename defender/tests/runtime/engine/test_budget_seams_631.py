"""#631 — the seams the enforced posture hangs on: the posture bit, the limits passthrough, the
tier table, the flag and the retry ceiling. Every fake enters through an injection seam
(`build_agent_core`'s `make_model`, the `limits` kwarg, the real environment `env_bool` reads);
nothing is patched onto a module."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from dataclasses import replace as _with_fixture_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

import dataclasses
import inspect
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender.configuration._env import FatalConfigError  # noqa: E402
from defender.hooks.budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    BudgetKill,
    tier,
)
from defender.investigation import driver, observe  # noqa: E402
from defender.investigation.agent_definition import bind, effective_tools_for  # noqa: E402
from defender._agent_role import AgentRole  # noqa: E402
from defender.investigation.driver import MAIN_DEF  # noqa: E402
from defender.providers import BuiltModel  # noqa: E402
from defender.investigation.query_tool import CONTROL_FLOW_EXCEPTIONS  # noqa: E402
from defender.systems.verb_grant import VerbGrant  # noqa: E402
from defender.systems.verbs import VerbRegistry  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.support.tenancy._host1214 import TEST_TENANT

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"
FLAG = "DEFENDER_BUDGET_ENFORCE"


class ScriptedModel:
    """One scripted turn per model request; past the script, text (which ends the loop). A value
    for `build_agent_core`'s `make_model` seam."""

    __name__ = "Scripted"

    def __init__(self, turns):
        self._turns = list(turns)
        self.calls = 0

    def __call__(self, messages, info) -> ModelResponse:
        if self.calls < len(self._turns):
            parts = [ToolCallPart(tool_name=n, args=a) for n, a in self._turns[self.calls]]
            self.calls += 1
            if parts:
                return ModelResponse(parts=parts)
        self.calls += 1
        return ModelResponse(parts=[TextPart(content="stopping")])


def _run_dir(tmp_path: Path, name: str = "run") -> Path:
    """A run folder under `tmp_path`, named by its UUID run id (`name` is a label, or the id itself)."""
    rd = tmp_path / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    (rd / "gather_raw").mkdir(parents=True)
    (rd / "alert.json").write_text(json.dumps({"rule": {"name": "probe"}}))
    return rd


def _state(run_dir: Path, run_id: str = "r"):
    """The run's state as `run_investigation` starts it: the budget a driven agent counts against,
    carried on its deps."""
    from defender.investigation.run_state import RunState

    return RunState(run_dir, run_id)


def _seed_calls(state, n: int) -> None:
    """Spend `n` calls of the state's pool up front, the way the run's earlier calls would."""
    from defender.hooks.budget_enforcer import count_call

    for _ in range(n):
        count_call(state, "bash")


def drive_agent(  # noqa: PLR0913 — one more seam: the model
        defn, run_dir: Path, turns, *, limits, state, enforce: bool | None = None,
                agent_id: str = "main", request_limit: int = 40, model=None, extra_capabilities=(), bind_ledger=None):
    """Build one agent through the real `build_agent_core` (real hooks, tools and gate) and drive it
    with a scripted `FunctionModel`; `state` is the `RunState` its deps carry."""
    scripted = model if model is not None else ScriptedModel(turns)
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    from dataclasses import replace as _replace
    if enforce is not None:
        defn = _replace(defn, budget_enforced=enforce)
    agent: Agent = driver.build_agent_core(
        defn,
        deps_type=defn.deps_cls,
        instructions="probe",
        logger=logger,
        agent_id=agent_id,
        make_model=lambda name, effort: BuiltModel(FunctionModel(scripted), None),
        limits=limits,
        extra_capabilities=extra_capabilities,
    )
    if bind_ledger is not None:
        bind_ledger(logger)
    from defender import box as box_mod
    from defender.tests.e2e._replay_harness import _no_docker_daemon, _unsandboxed_allowed

    with _unsandboxed_allowed():
        box = box_mod.start_box(run_dir, DEFENDER, docker=_no_docker_daemon, tenant_id=TEST_TENANT)
    bindable = _replace(defn, tools=effective_tools_for(defn))
    deps = _replace(bind(bindable, run_dir, defender_dir=DEFENDER, box=box), run_state=state)
    import asyncio

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=request_limit))

    try:
        return asyncio.run(_go()), scripted
    finally:
        logger.close()


def test_budget_kill_is_not_control_flow(tmp_path):
    """`BudgetKill` is not in `CONTROL_FLOW_EXCEPTIONS`, so it passes both of that tuple's except
    sites and `_run_gather`'s handler to reach the driver, never recorded as a query fault."""
    assert BudgetKill not in CONTROL_FLOW_EXCEPTIONS
    assert not any(issubclass(BudgetKill, t) for t in CONTROL_FLOW_EXCEPTIONS)

    from defender.investigation import tools as runtime_tools
    from defender.investigation.tools_gather import GatherRequest

    run_dir = _run_dir(tmp_path)
    state = _state(run_dir, "run-1")

    class KillingVerbs(VerbRegistry):
        def __init__(self):
            super().__init__(VerbGrant(role="gather", entries=(("elastic", "esql", "r"),)))

        def systems(self):
            return ("elastic",)

        def verbs(self, system):
            def esql(ctx, *, index: str) -> dict:
                raise BudgetKill("tail exhausted")
            return {"esql": esql}

    with pytest.raises(BudgetKill):
        _drive_gather_query(run_dir, KillingVerbs(), state)
    assert not (run_dir / "executed_queries.jsonl").exists(), (
        "the kill was filed as a query fault — a row claims a call that never ran"
    )

    class KillingRegistry(VerbRegistry):
        def __init__(self):
            super().__init__(VerbGrant(role="gather", entries=(("elastic", "esql", "r"),)))

        def systems(self):
            raise BudgetKill("tail exhausted")

        def verbs(self, system):
            raise BudgetKill("tail exhausted")

    run2 = _run_dir(tmp_path, "run2")
    run2_state = _state(run2, "run2")
    with pytest.raises(BudgetKill):
        _drive_gather_query(run2, KillingRegistry(), run2_state)

    seen_gather_deps = []

    class _KillingAgent:
        async def run(self, *args, **kwargs):
            seen_gather_deps.append(kwargs["deps"])
            raise BudgetKill("tail exhausted")

    def killing_factory(agent_id, system, request_limit):
        return _KillingAgent()

    import asyncio
    from dataclasses import replace

    deps = replace(_with_fixture_run_1165(bind(MAIN_DEF, run_dir, defender_dir=DEFENDER), run=_fixture_run_1165(run_dir)), run_state=state,
                   tenant=T1106.fixture_run_tenant())
    with pytest.raises(BudgetKill):
        asyncio.run(runtime_tools._run_gather(
            deps, killing_factory, 40,
            GatherRequest("l-001", "elastic", "goal", ("what",)),
            T1106.fixture_grants().gather, catalog=None,
        ))
    assert seen_gather_deps[0].run_state is deps.run_state, \
        "the gather was handed some state other than the parent run's own object"


def _drive_gather_query(run_dir: Path, registry, state):
    """Drive one real `query` call on a real gather agent against an injected verb registry; the
    caller hands in the run state, since this folder never goes through the driver."""
    import asyncio
    from dataclasses import replace

    model = ScriptedModel([[("query", {"system": "elastic", "verb": "esql",
                                       "params": {"index": "logs"},
                                       "query_id": "elastic.probe"})]])
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    gather_def = T1106.fixture_gather_def()
    agent = driver.build_agent_core(
        gather_def, deps_type=gather_def.deps_cls, instructions="probe",
        logger=logger, agent_id="gather:l-001",
        make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
        verbs=registry, limits=DEFAULT_LIMITS,
    )
    deps = replace(_with_fixture_run_1165(bind(gather_def, run_dir,
                        defender_dir=DEFENDER), run=_fixture_run_1165(run_dir)), lead_id="l-001",
                   tenant=T1106.fixture_run_tenant(), run_state=state)

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=4))
    try:
        return asyncio.run(_go())
    finally:
        logger.close()


def test_make_hooks_requires_the_posture_bit_and_every_caller_supplies_it(tmp_path):
    """`_make_hooks` takes the posture bit as a required keyword: a caller that states nothing fails loudly instead of running
    unenforced. It takes no requested model any more (r7.3 T3)."""
    sig = inspect.signature(driver._make_hooks)
    posture = sig.parameters["enforce"]
    assert posture.kind is inspect.Parameter.KEYWORD_ONLY
    assert posture.default is inspect.Parameter.empty, (
        "the posture bit has a default — a caller that states nothing runs unenforced"
    )
    logger = observe.RequestLogger(_run_dir(tmp_path) / "llm_requests.jsonl")
    with pytest.raises(TypeError):
        driver._make_hooks(logger, "main")
    # CONFLICT-UPDATED (#1377 r7.3 T3; was r7.1 D: `requested_model` a required keyword): spend is recorded by a model wrapper
    # built where the agent is, with the name it was asked for, so the hook takes no model name.
    assert "requested_model" not in sig.parameters, "the hook still takes the requested model (r7.3 T3: the model wrapper owns it)"
    with pytest.raises(TypeError):
        driver._make_hooks(logger, "main", requested_model="claude-sonnet-4-6", enforce=False)
    logger.close()

    core_sig = inspect.signature(driver.build_agent_core)
    assert "limits" in core_sig.parameters


def test_t1_r7_3_no_run_exit_or_reader_is_handed_the_failed_write_fact(tmp_path):
    """The failed-write fact is held by the request logger alone, and read through the ledger's seal: no run file writer, run
    summary, post-run step, page function, job fact or job-end record takes or carries it. CONFLICT-UPDATED (r7.3 T1; was
    r7.2 P2: the argument required of the run file writer and the run summary)."""
    from defender import run as run_py
    from defender import run_common
    from defender.presentation import visualize_run
    from defender.records import job_lane

    taking = {"observe.write_trace": (observe.write_trace, "spend_write_failed"),
              "driver._run_summary": (driver._run_summary, "spend_write_failed"),
              "driver.run_investigation": (driver.run_investigation, "on_spend_failure"),
              "RequestLogger.bind_ledger": (observe.RequestLogger.bind_ledger, "on_failure"),
              "visualize_run.render_page": (visualize_run.render_page, "spend_write_failed"),
              "visualize_run.publish_page": (visualize_run.publish_page, "spend_write_failed"),
              "run_common.visualize": (run_common.visualize, "spend_write_failed")}
    still = [name for name, (function, parameter) in taking.items() if parameter in inspect.signature(function).parameters]
    assert not still, f"still taking the failed-write fact: {still}"
    assert "spend_write_failed" not in {f.name for f in dataclasses.fields(job_lane.JobEnd)}, "the job-end record still carries it"
    facts = run_py._JobEndFacts
    assert not hasattr(facts, "note_spend_write_failed"), "the job facts still take the callback"
    assert "spend_write_failed" not in {f.name for f in dataclasses.fields(facts)}, "the job facts still hold the fact"


class _HookTestFailure(BaseException):  # noqa: N818 — a test-defined ending that is neither an Exception nor a cancellation
    pass


def _every_ending():
    """The class of endings the model-request hook can see: a response, and every way a request fails. Each is (label, a
    zero-argument factory of the response or of the exception the handler raises)."""
    import asyncio

    from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError, UnexpectedModelBehavior

    from defender.providers import ProviderDown

    yield "response", lambda: ModelResponse(parts=[TextPart(content="ok")])
    yield "test-defined BaseException", lambda: _HookTestFailure("boom")
    yield "CancelledError", asyncio.CancelledError
    yield "RuntimeError", lambda: RuntimeError("anything")
    yield "unparseable reply", lambda: UnexpectedModelBehavior("Invalid response from openai chat completions endpoint")
    yield "no-status ModelAPIError", lambda: ModelAPIError("m", "dropped")
    for status in range(100, 600):
        yield f"ModelHTTPError {status}", lambda status=status: ModelHTTPError(status, "m", body={"error": "x"})
    for status in (408, 409, 429, *range(500, 600), None):
        yield f"ProviderDown {status}", lambda status=status: ProviderDown(model="m", status=status, attempts=4)


async def _what_the_agent_got(agent, deps, label: str, ending) -> str | None:
    """Run `agent` once on a model whose request ends as `ending`; None when the agent got that very response or exception."""
    try:
        with override_allow_model_requests(False):
            got = await agent.run("go", deps=deps, usage_limits=UsageLimits(request_limit=4))
    except BaseException as raised:  # noqa: BLE001 — the point: whatever else came out is a finding
        if raised is not ending:
            return f"{label}: raised {type(raised).__name__}({raised}) instead of {type(ending).__name__}"
        return None
    if isinstance(ending, BaseException):
        return f"{label}: swallowed {type(ending).__name__}"
    if got.response is not ending and got.response.parts != ending.parts:
        return f"{label}: the agent got {got.response!r}, not the model's own response"
    return None


@pytest.mark.parametrize("agent_id", ["main", "gather:l-001", "gather:l-00c", "review:support", "review:ablation", "review:composer"])
def test_f1_r7_2_a_request_s_ending_reaches_the_agent_unchanged_whatever_the_ledger_does_with_it(tmp_path, agent_id):
    """CONFLICT-UPDATED (r7.3 T3; was: the hook built by `_make_hooks` called directly): an agent built by `build_agent_core`
    for each agent kind, with no ledger bound (so every ending is a failed spend write), on a model whose request ends each way
    in turn (a response; a test-defined BaseException, a cancellation, an unparseable reply, a status-less API error; a provider
    error at every HTTP status 100 to 599; `ProviderDown` at every temporary last status and none): the agent gets the very
    response or the very exception, and nothing else propagates. Bookkeeping never changes how a request ends. (r3 decision 2;
    r7 S2c; triage F1)"""
    import asyncio
    from dataclasses import replace

    from defender import box as box_mod
    from defender.tests.e2e._replay_harness import _no_docker_daemon, _unsandboxed_allowed

    run_dir = _run_dir(tmp_path, f"ending-{agent_id.replace(':', '-')}")
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    current: list = []

    async def model(messages, info):
        ending = current[0]
        if isinstance(ending, BaseException):
            raise ending
        return ending

    agent = driver.build_agent_core(MAIN_DEF, deps_type=MAIN_DEF.deps_cls, instructions="probe", logger=logger, agent_id=agent_id,
                                    make_model=lambda name, effort: BuiltModel(FunctionModel(model), None), limits=DEFAULT_LIMITS)
    with _unsandboxed_allowed():
        box = box_mod.start_box(run_dir, DEFENDER, docker=_no_docker_daemon, tenant_id=TEST_TENANT)
    bindable = replace(MAIN_DEF, tools=effective_tools_for(MAIN_DEF))
    deps = replace(bind(bindable, run_dir, defender_dir=DEFENDER, box=box), run_state=_state(run_dir))
    changed: list[str] = []

    async def through(label: str, made):
        current[:] = [made()]
        found = await _what_the_agent_got(agent, deps, label, current[0])
        if found is not None:
            changed.append(found)

    async def run_all():
        for label, made in _every_ending():
            await through(label, made)

    try:
        asyncio.run(run_all())
    finally:
        logger.close()

    assert not changed, f"{len(changed)} endings reached the agent changed, e.g. {changed[:5]}"


def _ledger_rows_of(tmp_path, label: str, capabilities=()):
    """One agent (MAIN) driven through `build_agent_core` on a scripted model, its request logger bound to the ledger of a real
    session store, as the driver binds it; returns the model, the ledger's rows (agent, outcome) and the capabilities' notes."""
    from defender.records import SessionPaths
    from defender.records import session_store as ss
    from defender.tests.support.shared._locations_1210 import fixture_runs_base

    run_dir = _run_dir(tmp_path, label)
    with ss.open_store(case_id=f"t3-{label}", sessions=SessionPaths(fixture_runs_base(tmp_path / "runs"))) as store:
        _, model = drive_agent(MAIN_DEF, run_dir, [], limits=DEFAULT_LIMITS, state=_state(run_dir), enforce=False,
                               extra_capabilities=list(capabilities),
                               bind_ledger=lambda logger: logger.bind_ledger(observe.SpendLedger(store, run_dir.name)))
        return model, [(r.agent_id, r.outcome) for r in ss.run_spend(store, run_dir.name)]


def _capability(behaviour: str):
    """A capability that, on the agent's first model request, `skip-wrap`s it (answers without calling the model), `skip-before`
    it (the same, one hook earlier) or `retry-after` the model has answered (calls it, then raises `ModelRetry` as an output
    check does); later requests pass through."""
    from pydantic_ai.capabilities import AbstractCapability
    from pydantic_ai.exceptions import ModelRetry, SkipModelRequest

    class Once(AbstractCapability):
        def __init__(self) -> None:
            self.fired = 0

        def _first(self) -> bool:
            self.fired += 1
            return self.fired == 1

        async def before_model_request(self, ctx, request_context):
            if behaviour == "skip-before" and self._first():
                raise SkipModelRequest(ModelResponse(parts=[TextPart(content="answered without the model")]))
            return request_context

        async def wrap_model_request(self, ctx, *, request_context, handler):
            if behaviour == "skip-wrap" and self._first():
                raise SkipModelRequest(ModelResponse(parts=[TextPart(content="answered without the model")]))
            response = await handler(request_context)
            if behaviour == "retry-after" and self._first():
                raise ModelRetry("the answer failed its output check")
            return response

    return Once()


@pytest.mark.parametrize("behaviour", ["skip-wrap", "skip-before"])
def test_t3_r7_3_a_capability_that_skips_a_model_request_writes_no_ledger_row(tmp_path, caplog, behaviour):
    """Another capability answers the agent's request without calling the model: the ledger holds no row for it (spend is
    recorded at the model, not around the request step) and no failed write is logged; the same agent with no such capability
    is the control, one row. (r7.3 T3)"""
    control_model, control_rows = _ledger_rows_of(tmp_path, f"control-{behaviour}")
    assert (control_model.calls, control_rows) == (1, [("main", "response")]), "control: the model's one answer is one row"
    caplog.clear()

    model, rows = _ledger_rows_of(tmp_path, behaviour, [_capability(behaviour)])

    assert model.calls == 0, "premise: the model was never asked"
    assert rows == [], f"a request the model never saw left ledger rows: {rows}"
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR and "spend" in r.getMessage().lower()]


def test_t3_r7_3_an_error_raised_after_the_model_answered_leaves_the_response_row_in_place(tmp_path):
    """The model answers and a capability then rejects the answer (a retry asked for, as output validation does): the answer
    keeps its `response` row, and the retry's answer has its own. (r7.3 T3: "an output-validation retry after a response keeps
    the response row")"""
    model, rows = _ledger_rows_of(tmp_path, "retry-after", [_capability("retry-after")])

    assert model.calls == 2, "premise: the model was asked twice, the first answer rejected"
    assert rows == [("main", "response"), ("main", "response")], rows


def test_s3_a_run_side_hook_with_no_ledger_bound_counts_each_response_as_a_failed_spend_write(tmp_path, caplog):
    """A response recorded while no ledger is bound is logged at ERROR naming spend, never dropped silently; the agent runs on. (S3, r4 carrier)"""
    import logging

    run_dir = _run_dir(tmp_path, "unbound")
    result, model = drive_agent(MAIN_DEF, run_dir, [[("bash", {"command": "echo hi"})]], limits=DEFAULT_LIMITS,
                                state=_state(run_dir), enforce=False)

    assert model.calls == 2, "the agent should have run to its end"
    assert "stopping" in str(result.output)
    failures = [r for r in caplog.records if r.levelno >= logging.ERROR and "spend" in r.getMessage().lower()]
    assert len(failures) == 2, f"one failed write per response, got {[r.getMessage() for r in failures]}"


class _FailingModel(ScriptedModel):
    """A model whose first request raises `exc`."""

    def __init__(self, exc: BaseException):
        super().__init__([])
        self._exc = exc

    def __call__(self, messages, info):
        raise self._exc


def _http_error(status: int):
    from pydantic_ai.exceptions import ModelHTTPError

    return ModelHTTPError(status, "fake", body={"error": "x"})


@pytest.mark.parametrize("exc", [_http_error(400), _http_error(503), RuntimeError("unparseable reply")],
                         ids=["refused", "unwrapped-5xx", "other"])
def test_s3_r7_h_a_request_that_ends_without_a_response_while_no_ledger_is_bound_is_a_failed_spend_write_too(tmp_path, caplog, exc):
    """The hook with no ledger bound, its one request ending refused or unseen: logged at ERROR naming spend once, and the
    error still reaches the caller. (r7.1 H, S2c)"""
    import logging

    run_dir = _run_dir(tmp_path, "unbound-failing")
    with pytest.raises(type(exc)):
        drive_agent(MAIN_DEF, run_dir, [], limits=DEFAULT_LIMITS, state=_state(run_dir), enforce=False, model=_FailingModel(exc))

    failures = [r for r in caplog.records if r.levelno >= logging.ERROR and "spend" in r.getMessage().lower()]
    assert len(failures) == 1, f"one failed write for the one request, got {[r.getMessage() for r in failures]}"


def test_limits_threaded_from_boundary(tmp_path):
    """Limits are threaded inward from the boundary: an injected cap of 3, not `DEFAULT_LIMITS`, is
    what refuses."""
    for fn, param in ((driver.run_investigation, "limits"),
                      (driver.build_agent_core, "limits"),
                      (driver._make_hooks, "limits")):
        assert param in inspect.signature(fn).parameters

    from defender.tests.e2e import _replay_harness
    assert "limits" in inspect.signature(_replay_harness.drive).parameters

    run_dir = _run_dir(tmp_path, "seam")
    state = _state(run_dir)
    injected = {**DEFAULT_LIMITS, "max_tool_calls": 3, "wall_clock_timeout": 3600,
                "grace_seconds": 600}
    script = [[("bash", {"command": f"echo {i}"})] for i in range(12)]
    result, _ = drive_agent(MAIN_DEF, run_dir, script, limits=injected, enforce=True,
                            state=state)
    assert "BUDGET" in str(result.all_messages()).upper(), (
        "no refusal at 12 calls against an injected cap of 3 — DEFAULT_LIMITS (200) was "
        "read inside the hook instead of the threaded value"
    )
    assert state.budget_snapshot()["tool_calls"] == 3, \
        "the injected cap did not bound the executed calls"


def test_the_hook_counts_on_the_state_the_deps_carry_and_on_nothing_else(tmp_path):
    """The budget hook counts on the `RunState` the deps carry, nothing keyed by the folder: two runs
    on one folder each count only their own call, and a call on a state at its cap is refused."""
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}
    run_dir = _run_dir(tmp_path, "one-folder")
    script = [[("bash", {"command": "echo counted"})]]

    first = _state(run_dir)
    drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=first)
    second = _state(run_dir)
    result, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True,
                            state=second)
    assert "BUDGET" not in str(result.all_messages()).upper(), \
        "the second run's call was refused on the first run's count"
    assert second.budget_snapshot()["tool_calls"] == 1, "the second run's state did not count"
    assert first.budget_snapshot()["tool_calls"] == 1, \
        "the second run's call landed in the first run's state"

    again, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True, state=first)
    assert "BUDGET" in str(again.all_messages()).upper(), \
        "the control: a call on a state at its cap was not refused"
    assert first.budget_snapshot()["tool_calls"] == 1, "a refused call moved the count"


def test_caps_are_not_operator_configurable(tmp_path, monkeypatch):
    """No environment variable or config file changes a cap. The sweep runs in a child process:
    reloading `budget_enforcer` here would rebind `BudgetKill`/`DEFAULT_LIMITS`, which sibling
    tests hold by identity."""
    before = dict(DEFAULT_LIMITS)

    probe = (
        "import os, json, sys;"
        f"sys.path.insert(0, {str(REPO_ROOT)!r});"
        "from defender.hooks.budget_enforcer import DEFAULT_LIMITS;"
        "print(json.dumps(DEFAULT_LIMITS))"
    )
    (tmp_path / "budget_limits.json").write_text(json.dumps({"max_tool_calls": 1}))
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT)}
    for name in ("DEFENDER_MAX_TOOL_CALLS", "DEFENDER_BUDGET_MAX_TOOL_CALLS",
                 "DEFENDER_WALL_CLOCK_TIMEOUT", "DEFENDER_MAX_SUBAGENT_SPAWNS",
                 "DEFENDER_BUDGET_LIMITS", "DEFENDER_GRACE_SECONDS"):
        env[name] = "1"
    child = subprocess.run([sys.executable, "-c", probe], cwd=tmp_path, env=env,
                           capture_output=True, text=True)
    assert child.returncode == 0, child.stderr
    assert json.loads(child.stdout) == before, "an env var or config file changed a cap"


def test_unknown_tool_tiers_as_core(tmp_path):
    """A tool missing from the tail table tiers as core (the restrictive arm), so a newly registered
    tool inherits the tight cap and raises no `KeyError`."""
    assert tier("a_tool_that_does_not_exist", AgentRole.MAIN) == "core"
    assert tier("", AgentRole.GATHER) == "core"
    assert tier("read_file", AgentRole.GATHER) == "core"
    for name in ("", "gather", "read_file", "\x00", "write_file", "totally-made-up"):
        assert tier(name, AgentRole.MAIN) in {"core", "tail"}


def test_tier_table_over_the_real_census(tmp_path):
    """Over the registered census, MAIN's tail tier is exactly `read_file`, `append_block` and
    `fix_row`, and every gather tool (and `gather` itself) is core; on a tripped pool MAIN's bash is
    refused while `append_block` still lands, so MAIN can always record what it knows."""
    main_names = _registered_names(MAIN_DEF)
    gather_names = _registered_names(T1106.fixture_gather_def())
    assert {"read_file", "append_block", "fix_row", "bash", "gather"} <= main_names
    assert not {"write_file", "edit_file"} & main_names, "the general write lane left MAIN"
    assert {"read_file", "bash", "template_search", "query"} <= gather_names

    assert {n for n in main_names if tier(n, AgentRole.MAIN) == "tail"} == \
        {"read_file", "append_block", "fix_row"}
    assert all(tier(n, AgentRole.GATHER) == "core" for n in gather_names)
    assert tier("gather", AgentRole.MAIN) == "core"

    run_dir = _run_dir(tmp_path, "census")
    state = _state(run_dir)
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    _seed_calls(state, 1)
    inv = run_dir / "investigation.md"
    script = [[("bash", {"command": "echo hi"})],
              [("append_block", {"text": "+ tail-tier append\n"})]]
    result, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True,
                            state=state)
    text = str(result.all_messages())
    assert "BUDGET" in text.upper(), "the core-tier bash was not refused on a tripped pool"
    assert inv.is_file(), "the tail-tier append_block was refused inside the tail band"


def test_same_tool_name_on_two_agents(tmp_path):
    """`read_file` is tail on MAIN and core on gather at once: tiers are keyed on (tool, agent)."""
    assert tier("read_file", AgentRole.MAIN) == "tail"
    assert tier("read_file", AgentRole.GATHER) == "core"

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}

    main_dir = _run_dir(tmp_path, "pair-main")
    main_state = _state(main_dir)
    _seed_calls(main_state, 1)
    main_result, _ = drive_agent(
        MAIN_DEF, main_dir, [[("read_file", {"path": model_path(main_dir / "alert.json", run_dir=main_dir)})]],
        limits=limits, enforce=True, state=main_state)

    gather_dir = _run_dir(tmp_path, "pair-gather")
    gather_state = _state(gather_dir)
    _seed_calls(gather_state, 1)
    gather_result, _ = drive_agent(
        T1106.fixture_gather_def(), gather_dir, [[("read_file", {"path": model_path(gather_dir / "alert.json", run_dir=gather_dir)})]],
        limits=limits, enforce=True, agent_id="gather:l-001", state=gather_state)

    assert "BUDGET" not in str(main_result.all_messages()).upper(), (
        "read_file (tail on MAIN) was refused on a tripped pool"
    )
    assert "BUDGET" in str(gather_result.all_messages()).upper(), (
        "read_file (core on GATHER) survived a tripped pool"
    )


def _registered_names(defn) -> set[str]:
    """The registered tool-name census, read off a real Agent: what the framework dispatches, not a
    hand-kept list."""
    logger = observe.RequestLogger(Path(os.devnull))
    agent = driver.build_agent_core(
        defn, deps_type=defn.deps_cls, instructions="probe", logger=logger,
        agent_id="probe", make_model=lambda n, e: BuiltModel(FunctionModel(
            ScriptedModel([])), None), limits=DEFAULT_LIMITS,
    )
    if defn is MAIN_DEF:
        from defender.investigation.tools import register_gather_tool
        register_gather_tool(
            agent, lambda agent_id, system, request_limit: agent, driver.GATHER_REQUEST_LIMIT,
            T1106.fixture_grants().gather, catalog=None,
        )
    return set(agent._function_toolset.tools)


def test_gather_keeps_its_request_limit(tmp_path):
    """`GATHER_REQUEST_LIMIT` stays 40 and is still what stops a subagent that never ends."""
    assert driver.GATHER_REQUEST_LIMIT == 40

    from pydantic_ai.exceptions import UsageLimitExceeded

    run_dir = _run_dir(tmp_path, "grl")
    never_stops = [[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]] * 200
    with pytest.raises(UsageLimitExceeded):
        drive_agent(T1106.fixture_gather_def(), run_dir, never_stops, limits=DEFAULT_LIMITS,
                    enforce=False, agent_id="gather:l-001",
                    request_limit=driver.GATHER_REQUEST_LIMIT, state=_state(run_dir))


def test_enforce_flag_defaults_off(monkeypatch):
    """`DEFENDER_BUDGET_ENFORCE` defaults off when unset, and the empty string reads as off too."""
    monkeypatch.delenv(FLAG, raising=False)
    assert driver.enforcement_enabled() is False
    monkeypatch.setenv(FLAG, "")
    assert driver.enforcement_enabled() is False
    monkeypatch.setenv(FLAG, "false")
    assert driver.enforcement_enabled() is False
    for on in ("1", "on", "true", "yes", " TRUE "):
        monkeypatch.setenv(FLAG, on)
        assert driver.enforcement_enabled() is True


def test_enforce_flag_unrecognized_token(monkeypatch):
    """An unrecognized `DEFENDER_BUDGET_ENFORCE` token raises `FatalConfigError` instead of reading
    as off."""
    monkeypatch.setenv(FLAG, "maybe")
    with pytest.raises(FatalConfigError):
        driver.enforcement_enabled()


def test_retired_learning_state_override_cannot_redirect_tenant_state(
    tmp_path, monkeypatch, d9_tenant, data_root,
):
    """The retired `DEFENDER_LEARNING_STATE_DIR` cannot redirect a tenant's runs or learning state."""
    from defender.tenancy import _tenant
    from defender.learning.core.config import LoopPaths
    from defender.learning.core.state import FINDINGS, LearningState

    tenant = T1106.accept(data_root, d9_tenant)
    location_path(tenant.learning).mkdir(exist_ok=True)
    expected = {"finding_id": "tenant/0", "run_id": "tenant"}
    with LearningState.open(LoopPaths.for_tenant(tenant)) as state:
        assert state.append(FINDINGS, [expected]) == (1, 0)
    alias = tmp_path / "alias"
    alias.symlink_to(data_root)
    decoy = tmp_path / "ambient-learning"
    queue = decoy / FINDINGS.queue
    queue.parent.mkdir(parents=True)
    decoy_bytes = b'{"finding_id":"ambient/0","run_id":"ambient"}\n'
    queue.write_bytes(decoy_bytes)
    for ambient in (location_path(tenant.runs), alias, decoy):
        monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(ambient))
        accepted = T1106.accept(_tenant.resolve_data_root(), d9_tenant)
        assert location_path(accepted.runs) == data_root.resolve() / d9_tenant / "runs"
        paths = LoopPaths.for_tenant(accepted)
        assert location_path(paths.state_root) == location_path(tenant.learning)
        with LearningState.open(paths) as state:
            assert state.rows(FINDINGS) == [expected]
    assert queue.read_bytes() == decoy_bytes
    assert not (location_path(tenant.runs) / FINDINGS.queue).exists()


def test_every_agent_construction_pins_retries_explicitly(tmp_path):
    """Two consecutive denied tool calls do not abort the run: the retry ceiling is pinned. (That every
    `Agent(...)` passes `retries=` is `tooling/lint/lint_agent_retries.py`.)"""
    assert driver.DEFAULT_TOOL_RETRIES == 10

    run_dir = _run_dir(tmp_path, "retries")
    missing = model_path(run_dir / "nope" / "absent.json", run_dir=run_dir)
    script = [[("read_file", {"path": missing})],
              [("read_file", {"path": missing})],
              []]
    result, model = drive_agent(MAIN_DEF, run_dir, script, limits=DEFAULT_LIMITS,
                                enforce=False, state=_state(run_dir))
    assert model.calls >= 3, "the loop did not reach its stopping turn — a denial aborted it"
    assert result.output is not None, "two consecutive denials aborted — retries was not pinned"
