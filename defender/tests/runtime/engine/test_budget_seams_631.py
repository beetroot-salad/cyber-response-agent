"""#631 — the seams the enforced posture hangs on: the posture bit, the limits passthrough, the tier table, the flag, the retry ceiling, the two pool roots, and the CI wiring."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from dataclasses import replace as _with_fixture_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165
from defender.tests.support.shared._fixture_uuid import fixture_uuid, is_fixture_uuid_shape

import inspect
import json
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

REPO_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = REPO_ROOT / "defender"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FLAG = "DEFENDER_BUDGET_ENFORCE"


class ScriptedModel:
    """Emits one scripted turn per model request; past the script, text (which ends the loop). The same shape..."""

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
    """A run folder under `tmp_path`, `name` its label (or its id, when already a UUID)."""
    # #1187 (declared change 1): a run id is a canonical UUID — the folder is fixture_uuid(<label>)
    rd = tmp_path / (name if is_fixture_uuid_shape(name) else fixture_uuid(name))
    (rd / "gather_raw").mkdir(parents=True)
    (rd / "alert.json").write_text(json.dumps({"rule": {"name": "probe"}}))
    return rd


def _state(run_dir: Path, run_id: str = "r"):
    """The run's state, as `run_investigation` starts it (#1235 round 2): the budget a driven agent counts..."""
    from defender.investigation.run_state import RunState

    return RunState(run_dir, run_id)


def _seed_calls(state, n: int) -> None:
    """Spend `n` calls of the state's pool up front, the way the run's earlier calls would."""
    from defender.hooks.budget_enforcer import count_call

    for _ in range(n):
        count_call(state, "bash")


def drive_agent(defn, run_dir: Path, turns, *, limits, state, enforce: bool | None = None,
                agent_id: str = "main", request_limit: int = 40):
    """Build ONE agent through the real `build_agent_core` and drive it — the real hooks, the real tools, the..."""
    model = ScriptedModel(turns)
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
        make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
        limits=limits,
    )
    from defender import box as box_mod
    from defender.tests.e2e._replay_harness import _no_docker_daemon, _unsandboxed_allowed

    with _unsandboxed_allowed():
        box = box_mod.start_box(run_dir, DEFENDER, docker=_no_docker_daemon)
    bindable = _replace(defn, tools=effective_tools_for(defn))
    deps = _replace(bind(bindable, run_dir, defender_dir=DEFENDER, box=box), run_state=state)
    import asyncio

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=request_limit))

    try:
        return asyncio.run(_go()), model
    finally:
        logger.close()


def test_budget_kill_is_not_control_flow(tmp_path):
    """The budget kill type is absent from query_tool.CONTROL_FLOW_EXCEPTIONS and passes through BOTH of that..."""
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
    """Drive ONE real `query` call on a real GATHER agent against an injected verb registry — the seam..."""
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
    """_make_hooks takes the budget-posture bit as a REQUIRED keyword parameter — constructing it without one..."""
    sig = inspect.signature(driver._make_hooks)
    posture = sig.parameters["enforce"]
    assert posture.kind is inspect.Parameter.KEYWORD_ONLY
    assert posture.default is inspect.Parameter.empty, (
        "the posture bit has a default — a caller that states nothing runs unenforced"
    )
    logger = observe.RequestLogger(_run_dir(tmp_path) / "llm_requests.jsonl")
    with pytest.raises(TypeError):
        driver._make_hooks(logger, "main")
    logger.close()

    core_sig = inspect.signature(driver.build_agent_core)
    assert "limits" in core_sig.parameters


def test_limits_threaded_from_boundary(tmp_path):
    """The driver resolves DEFAULT_LIMITS ONCE at the boundary and threads it inward through check_budgets'..."""
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
    """#1235 round 2: the budget hook counts each executed call on the `RunState` the deps carry and on nothing..."""
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
    """No environment variable and no config file changes any cap, and no per-signature default layers one —..."""
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
    """A tool absent from the tail table tiers as core — the restrictive arm — so adding a tool to either ToolSet..."""
    assert tier("a_tool_that_does_not_exist", AgentRole.MAIN) == "core"
    assert tier("", AgentRole.GATHER) == "core"
    assert tier("read_file", AgentRole.GATHER) == "core"
    for name in ("", "gather", "read_file", "\x00", "write_file", "totally-made-up"):
        assert tier(name, AgentRole.MAIN) in {"core", "tail"}


def test_tier_table_over_the_real_census(tmp_path):
    """The tail tier is exactly MAIN's read_file and append_block; every GATHER tool is core including read_file,..."""
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
    """A tool name that is tail on MAIN is core on GATHER, simultaneously and in the same run: `read_file` is..."""
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
    """The REGISTERED tool-name census, read off a real Agent — the same route SC5 used, so the tier table is..."""
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
    """GATHER_REQUEST_LIMIT stays 40, the bound a multi-dimension lead needs, and it is still the ceiling a..."""
    assert driver.GATHER_REQUEST_LIMIT == 40

    from pydantic_ai.exceptions import UsageLimitExceeded

    run_dir = _run_dir(tmp_path, "grl")
    never_stops = [[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})]] * 200
    with pytest.raises(UsageLimitExceeded):
        drive_agent(T1106.fixture_gather_def(), run_dir, never_stops, limits=DEFAULT_LIMITS,
                    enforce=False, agent_id="gather:l-001",
                    request_limit=driver.GATHER_REQUEST_LIMIT, state=_state(run_dir))


def test_enforce_flag_defaults_off(monkeypatch):
    """DEFENDER_BUDGET_ENFORCE is read through env_bool and defaults to False when UNSET, so interactive..."""
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
    """An unrecognized token for DEFENDER_BUDGET_ENFORCE raises FatalConfigError at startup rather than being..."""
    monkeypatch.setenv(FLAG, "maybe")
    with pytest.raises(FatalConfigError):
        driver.enforcement_enabled()


def test_retired_learning_state_override_cannot_redirect_tenant_state(
    tmp_path, monkeypatch, d9_tenant, data_root,
):
    """O1: a retired ambient root cannot change accepted runs or actual tenant state reads."""
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


def _markers(root: Path) -> set[str]:
    return {str(p) for p in root.rglob("*") if p.is_file() and "queue" in str(p)}
