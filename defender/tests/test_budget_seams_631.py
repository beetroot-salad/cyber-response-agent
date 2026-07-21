"""#631 — the seams the enforced posture hangs on: the posture bit, the limits
passthrough, the tier table, the flag, the retry ceiling, the two pool roots, and the
CI wiring.

Every fake here enters through an INJECTION SEAM — `make_model` on
`build_agent_core`, the `limits` kwarg, `monkeypatch.setenv` on the real environment
the real `env_bool` reads. Nothing is monkeypatched onto a module.

RED AGAINST HEAD IS THE EXPECTED STATE. At `483b5809` `_make_hooks(logger, agent_id)`
takes no posture bit (SC13), `run_investigation` exposes no limits seam (SC12),
`AgentDefinition` carries no budget bit (SC8 records the three that DO exist as the
precedent), `DEFENDER_BUDGET_ENFORCE` does not exist, and CI's unit-test step has no
`env:` block at all (SC26).
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

import yaml  # noqa: E402
from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402

from defender._env import FatalConfigError  # noqa: E402
from defender.agents import AGENTS  # noqa: E402
from defender.hooks.budget_enforcer import (  # noqa: E402
    DEFAULT_LIMITS,
    BudgetKill,
    open_budget,
    tier,
    update_budget_locked,
)
from defender.runtime import driver, observe  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.query_tool import CONTROL_FLOW_EXCEPTIONS  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FLAG = "DEFENDER_BUDGET_ENFORCE"


# --- a real agent, built through the real construction site ------------------

class ScriptedModel:
    """Emits one scripted turn per model request; past the script, text (which ends
    the loop). The same shape `tests/e2e/_replay_harness.ReplayFn` uses — a VALUE
    handed to `build_agent_core`'s `make_model` seam, never a patched symbol."""

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
    rd = tmp_path / name
    (rd / "gather_raw").mkdir(parents=True)
    (rd / "alert.json").write_text(json.dumps({"rule": {"name": "probe"}}))
    return rd


def drive_agent(defn, run_dir: Path, turns, *, limits, enforce: bool | None = None,
                agent_id: str = "main", request_limit: int = 40):
    """Build ONE agent through the real `build_agent_core` and drive it — the real
    hooks, the real tools, the real gate — against an injected `FunctionModel`."""
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
    deps = bind(defn, run_dir, salt="0011223344556677", defender_dir=DEFENDER)
    import asyncio

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=request_limit))

    try:
        return asyncio.run(_go()), model
    finally:
        logger.close()


# --- the kill's type and where it must NOT be absorbed ----------------------

def test_budget_kill_is_not_control_flow(tmp_path):
    """The budget kill type is absent from query_tool.CONTROL_FLOW_EXCEPTIONS and
    passes through BOTH of that tuple's except sites, and is not absorbed by
    _run_gather's widened handler, so it propagates to the driver instead of being
    recorded as a query fault or converted into a measurement string.

    X10 (read, re-verified) is why both sites are bound rather than one: there are TWO
    `except CONTROL_FLOW_EXCEPTIONS:` consumers, query_tool.py:242 (the reject path)
    and :319 (the execute path). Membership is what both read, so a demand binding one
    would leave the other unmodelled. RF4: RunAborted is NOT reusable — its
    __init__(total_failures, systems) builds a connectivity-flavoured message — and
    adding the budget's own type to this tuple by reflex would convert the kill into a
    recorded query fault.

    The positive control is test_budget_kill_writes_partial_trace (e2e): the kill DOES
    propagate to run_investigation's catch, which writes the partial trace — so this
    negative cannot pass by the exception never being raised."""
    assert BudgetKill not in CONTROL_FLOW_EXCEPTIONS
    assert not any(issubclass(BudgetKill, t) for t in CONTROL_FLOW_EXCEPTIONS)

    from defender.runtime import tools as runtime_tools
    from defender.runtime.tools_gather import GatherRequest

    run_dir = _run_dir(tmp_path)
    open_budget(run_dir, "run-1")

    # THE EXECUTE PATH (query_tool.py:319): a verb that raises the kill. The catch-all
    # around `await handler(args)` writes a row for an unmapped fault; the kill must
    # escape it instead, and leave NO row claiming the query ran.
    class KillingVerbs:
        def systems(self):
            return ("elastic",)

        def verbs(self, system):
            def esql(ctx, *, index: str) -> dict:
                raise BudgetKill("tail exhausted")
            return {"esql": esql}

    with pytest.raises(BudgetKill):
        _drive_gather_query(run_dir, KillingVerbs())
    assert not (run_dir / "executed_queries.jsonl").exists(), (
        "the kill was filed as a query fault — a row claims a call that never ran"
    )

    # THE REJECT PATH (query_tool.py:242): the registry itself raises the kill while
    # the capture is resolving the system, inside `_reject_guarded`'s BaseException
    # catch-all — which would otherwise file it as "adapter failed to load".
    class KillingRegistry:
        def systems(self):
            raise BudgetKill("tail exhausted")

        def verbs(self, system):
            raise BudgetKill("tail exhausted")

    with pytest.raises(BudgetKill):
        _drive_gather_query(_run_dir(tmp_path, "run2"), KillingRegistry())

    # _run_gather's handler: the kill must NOT become the measurement-shaped string.
    async def killing_factory(agent_id):
        raise BudgetKill("tail exhausted")

    import asyncio
    deps = bind(MAIN_DEF, run_dir, salt="0011223344556677", defender_dir=DEFENDER)
    with pytest.raises(BudgetKill):
        asyncio.run(runtime_tools._run_gather(
            deps, killing_factory, 40,
            GatherRequest("l-001", "elastic", "goal", ("what",)),
        ))


def _drive_gather_query(run_dir: Path, registry):
    """Drive ONE real `query` call on a real GATHER agent against an injected verb
    registry — the seam `run_investigation(verbs=…)` already exposes (#611)."""
    import asyncio
    from dataclasses import replace

    model = ScriptedModel([[("query", {"system": "elastic", "verb": "esql",
                                       "params": {"index": "logs"},
                                       "query_id": "elastic.probe"})]])
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent = driver.build_agent_core(
        GATHER_DEF, deps_type=GATHER_DEF.deps_cls, instructions="probe",
        logger=logger, agent_id="gather:l-001",
        make_model=lambda name, effort: BuiltModel(FunctionModel(model), None),
        verbs=registry, limits=DEFAULT_LIMITS,
    )
    deps = replace(bind(GATHER_DEF, run_dir, salt="0011223344556677",
                        defender_dir=DEFENDER), lead_id="l-001")

    async def _go():
        with override_allow_model_requests(False):
            return await agent.run("go", deps=deps,
                                   usage_limits=UsageLimits(request_limit=4))
    try:
        return asyncio.run(_go())
    finally:
        logger.close()


# --- posture is data, not role ----------------------------------------------

def test_enforcement_keys_on_declared_bit(tmp_path):
    """The refusal and the kill read a declared budget-posture bit on the agent
    DEFINITION, carried through deps.policy to the hook closure; role is never
    branched on, so a new agent must state its posture rather than inheriting one.

    SC8: `requires_confine`, `requires_explicit_tree` and `bindable` are already
    per-role safe-by-construction DATA bits checked generically in `bind` with no role
    branch — this bit has direct precedent. The observation is the WIRING, not the
    field: two definitions of the SAME role, differing only in the bit, produce
    different observable outcomes over the identical script."""
    assert "budget_enforced" in {f.name for f in
                                 __import__("dataclasses").fields(MAIN_DEF)}
    assert MAIN_DEF.budget_enforced is True
    assert AGENTS[AgentRole.JUDGE].budget_enforced is False

    # The bit reaches the hook closure through deps.policy, not through the role.
    deps = bind(MAIN_DEF, _run_dir(tmp_path, "p"), salt="0" * 16, defender_dir=DEFENDER)
    assert deps.policy.budget_enforced is True

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    on_dir = _run_dir(tmp_path, "enf-on")
    open_budget(on_dir, "r")
    on_script = [[("read_file", {"path": str(on_dir / "alert.json")})]] * 3
    result_on, _ = drive_agent(MAIN_DEF, on_dir, on_script, limits=limits, enforce=True)

    off_dir = _run_dir(tmp_path, "enf-off")
    open_budget(off_dir, "r")
    off_script = [[("read_file", {"path": str(off_dir / "alert.json")})]] * 3
    result_off, _ = drive_agent(MAIN_DEF, off_dir, off_script, limits=limits,
                                enforce=False)

    on_text = str(result_on.all_messages())
    off_text = str(result_off.all_messages())
    assert "BUDGET" in on_text.upper(), "the declared-True agent was never refused"
    assert "BUDGET" not in off_text.upper(), (
        "the declared-False agent of the SAME role was refused — enforcement keyed "
        "on the role, not on the declared bit"
    )


def test_make_hooks_requires_the_posture_bit_and_every_caller_supplies_it(tmp_path):
    """_make_hooks takes the budget-posture bit as a REQUIRED keyword parameter —
    constructing it without one raises rather than defaulting — and every call site
    supplies it, including experiments/gather-verifiable-code-289/run_arms.py, which
    builds its Agent by hand with no AgentDefinition.

    SC3 (executed): `_make_hooks` has THREE call sites, and the third is invisible
    three ways — the resolver's searchPath excludes experiments/, CI collects only
    tests/ and learning/, and no import edge reaches it from defender/. SC26 confirms
    CI never collects it. So this test EXERCISES that site's argument list against the
    real signature rather than relying on collection: a required argument fails loudly
    at the one site that would otherwise run unenforced, while an optional one
    reproduces the fail-open M2 exists to prevent."""
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

    # Exercise the experiments/ call site's ACTUAL argument list against the real
    # signature — the site CI never collects, fixed in this diff.
    src = (REPO_ROOT / "experiments" / "gather-verifiable-code-289" / "run_arms.py")
    tree = ast.parse(src.read_text())
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "_make_hooks"]
    assert calls, "run_arms.py no longer calls driver._make_hooks — re-scope this demand"
    for call in calls:
        # A `**kwargs` splat has kw.arg is None (blind reader R18); guard it so the
        # census fails cleanly rather than erroring, and a splat cannot mask a missing
        # required keyword.
        assert all(kw.arg is not None for kw in call.keywords), (
            "run_arms.py splats **kwargs into _make_hooks — the required posture bit is "
            "no longer statically visible at the call site"
        )
        kwargs = {kw.arg for kw in call.keywords}
        sig.bind(*(object() for _ in call.args), **{k: object() for k in kwargs})

    # And the boundary every OTHER caller reaches it through carries the bit too.
    core_sig = inspect.signature(driver.build_agent_core)
    assert "limits" in core_sig.parameters


def test_learning_stages_are_accounting_only(tmp_path):
    """The learning-loop agents built through _pydantic_stage — actor, judge, oracle,
    lead author, both curators — observe no refusal and no kill however far over the
    caps a run runs; their accounting is unchanged and their counters still advance.

    Q1 (executed) established the pools never overlap under any shipped configuration
    — a SHARED FACTORY OVER DISJOINT KEYS IS NOT A SHARED POOL — and
    test_the_learning_state_root_and_the_runs_base_cannot_be_the_same_dir asserts the
    disjointness rather than assuming it. The positive control is
    test_budget_trip_returns_summary_and_writes_trace (e2e): an ENFORCED agent under
    the identical injected caps IS stopped, so this negative cannot pass by
    enforcement being dead everywhere."""
    for role, defn in AGENTS.items():
        if role in (AgentRole.MAIN, AgentRole.GATHER):
            continue
        assert defn.budget_enforced is False, f"{role} declares itself enforced"

    run_dir = _run_dir(tmp_path, "learn")
    open_budget(run_dir, "stage-1")
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    judge = AGENTS[AgentRole.JUDGE]
    script = [[("read_file", {"path": str(run_dir / "alert.json")})]] * 4
    result, _ = drive_agent(judge, run_dir, script, limits=limits)

    assert "BUDGET" not in str(result.all_messages()).upper()
    state = json.loads((run_dir / "budget.json").read_text())
    assert state["tool_calls"] >= 4, "the unenforced stage stopped being accounted for"


# --- the limits seam and the absence of operator config ---------------------

def test_limits_threaded_from_boundary(tmp_path):
    """The driver resolves DEFAULT_LIMITS ONCE at the boundary and threads it inward
    through check_budgets' existing `limits` parameter, so a test can inject low
    limits without any operator-facing configuration existing — and the injected cap,
    not the module default, is what fires."""
    for fn, param in ((driver.run_investigation, "limits"),
                      (driver.build_agent_core, "limits"),
                      (driver._make_hooks, "limits")):
        assert param in inspect.signature(fn).parameters

    from defender.tests.e2e import _replay_harness
    assert "limits" in inspect.signature(_replay_harness.drive).parameters

    # The wired half must be able to FAIL (blind reader R6): the old bound
    # `tool_calls <= 3 + 10` was true whether limits was honoured, ignored, or dropped,
    # because five turns can never exceed five. Drive a CORE-tier script well past the
    # injected cap of 3 and assert a refusal was OBSERVED — which happens only if the
    # INJECTED cap (not the module default of 200) is what the hook read.
    run_dir = _run_dir(tmp_path, "seam")
    open_budget(run_dir, "r")
    injected = {**DEFAULT_LIMITS, "max_tool_calls": 3, "wall_clock_timeout": 3600,
                "grace_seconds": 600}
    script = [[("bash", {"command": f"echo {i}"})] for i in range(12)]
    result, _ = drive_agent(MAIN_DEF, run_dir, script, limits=injected, enforce=True)
    assert "BUDGET" in str(result.all_messages()).upper(), (
        "no refusal at 12 calls against an injected cap of 3 — DEFAULT_LIMITS (200) was "
        "read inside the hook instead of the threaded value"
    )
    state = json.loads((run_dir / "budget.json").read_text())
    assert state["tool_calls"] == 3, "the injected cap did not bound the executed calls"


def test_caps_are_not_operator_configurable(tmp_path, monkeypatch):
    """No environment variable and no config file changes any cap, and no
    per-signature default layers one — DEFAULT_LIMITS stays inline and single-default,
    because the flag governs POSTURE rather than tuning.

    PB5 (executed) confirmed both declared vias dead by execution rather than by
    reading: the dict is unchanged after an env sweep and a module reload, and the
    module contains none of the four read primitives. The positive control is
    test_limits_threaded_from_boundary — the `api` via IS reachable and an injected
    cap demonstrably fires — so this negative cannot pass by the caps being unreadable
    from everywhere.

    The env/config sweep runs in a CHILD PROCESS (blind reader R19): reloading
    budget_enforcer in-process rebinds BudgetKill / DEFAULT_LIMITS to new objects, which
    the sibling tests hold by identity (`BudgetKill not in CONTROL_FLOW_EXCEPTIONS`,
    `pytest.raises(BudgetKill)`) — a latent cross-test failure under any reordering."""
    before = dict(DEFAULT_LIMITS)

    # A child process imports budget_enforcer with every plausible cap env var set and a
    # config file planted in its cwd; its DEFAULT_LIMITS must match this process's.
    probe = (
        "import os, json, sys;"
        "sys.path.insert(0, %r);"
        "from defender.hooks.budget_enforcer import DEFAULT_LIMITS;"
        "print(json.dumps(DEFAULT_LIMITS))"
    ) % str(REPO_ROOT)
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

    # And the module reads none of the four config-load primitives at all.
    src = (DEFENDER / "hooks" / "budget_enforcer.py").read_text()
    for primitive in ("os.environ", "environ.get", "env_int(", "open(", "json.load("):
        assert primitive not in src, f"budget_enforcer reads {primitive}"


# --- the tier table ----------------------------------------------------------

def test_unknown_tool_tiers_as_core(tmp_path):
    """A tool absent from the tail table tiers as core — the restrictive arm — so
    adding a tool to either ToolSet raises no KeyError anywhere on the enforcement
    path and inherits the tight cap by default.

    SCOPE NOTE, and no doc or demand may cite this one as covering the other: P7
    (executed) showed totality protects a REGISTERED tool the tail table forgot. It
    does NOT cover an undeclared/undispatched ToolSet bit —
    `ExtendedToolSet(read=True, undispatched=True)` registers exactly ['read_file'],
    so the bit produces no tool name and never reaches the tier function at all. The
    safety there is INERTNESS, not the fail-closed default."""
    # The tier function is TOTAL over arbitrary names — the default arm is `core`, the
    # restrictive one — so a tool the tail table forgot inherits the tight cap rather
    # than raising a KeyError on the enforcement path. Driving an UNREGISTERED name
    # proves nothing (blind reader R25/A22: pydantic-ai rejects it upstream, so it never
    # reaches the tier function), so this is asserted directly over the function, which
    # is what the enforcement seam calls with `call.tool_name`.
    assert tier("a_tool_that_does_not_exist", AgentRole.MAIN) == "core"
    assert tier("", AgentRole.GATHER) == "core"
    assert tier("read_file", AgentRole.GATHER) == "core"  # a real tool the tail table omits on GATHER
    # Totality is a property of the LOOKUP, not of any one name: no input yields a
    # KeyError or anything other than {"core", "tail"}.
    for name in ("", "gather", "read_file", "\x00", "write_file", "totally-made-up"):
        assert tier(name, AgentRole.MAIN) in {"core", "tail"}


def test_tier_table_over_the_real_census(tmp_path):
    """The tail tier is exactly MAIN's read_file, write_file and edit_file; every
    GATHER tool is core including read_file, and `gather` itself is core — so parallel
    subagents cannot drain the ten-call window MAIN needs for its report.

    The enumeration picks the subjects; the assertion is WIRED, not structural: with
    the pool tripped, MAIN's write_file (tail) still executes and lands its bytes
    while MAIN's bash (core) is refused in the same run. SAME FACT SEEN TWICE — the
    tail window granted to fund the report is granted over the record that BOUNDS the
    window, which is why test_model_cannot_author_its_own_budget_state exists;
    demoting write_file out of the tail breaks O2 and is the WRONG repair."""
    main_names = _registered_names(MAIN_DEF)
    gather_names = _registered_names(GATHER_DEF)
    assert {"read_file", "write_file", "edit_file", "bash", "gather"} <= main_names
    assert {"read_file", "bash", "template_search", "query"} <= gather_names

    assert {n for n in main_names if tier(n, AgentRole.MAIN) == "tail"} == \
        {"read_file", "write_file", "edit_file"}
    assert all(tier(n, AgentRole.GATHER) == "core" for n in gather_names)
    assert tier("gather", AgentRole.MAIN) == "core"

    run_dir = _run_dir(tmp_path, "census")
    open_budget(run_dir, "r")
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    update_budget_locked(run_dir, "r", "bash", limits=limits)
    report = run_dir / "report.md"
    script = [[("bash", {"command": "echo hi"})],
              [("write_file", {"path": str(report),
                               "content": "---\ncase_id: c\ndisposition: benign\n"
                                          "confidence: low\n---\n\nDone.\n"})]]
    result, _ = drive_agent(MAIN_DEF, run_dir, script, limits=limits, enforce=True)
    text = str(result.all_messages())
    assert "BUDGET" in text.upper(), "the core-tier bash was not refused on a tripped pool"
    assert report.is_file(), "the tail-tier write_file was refused inside the tail band"


def test_same_tool_name_on_two_agents(tmp_path):
    """A tool name that is tail on MAIN is core on GATHER, simultaneously and in the
    same run: `read_file` is tail for MAIN and core for GATHER, so the tier table is
    keyed on the (tool_name, agent) PAIR rather than on the tool name alone."""
    assert tier("read_file", AgentRole.MAIN) == "tail"
    assert tier("read_file", AgentRole.GATHER) == "core"

    # Each agent drives its OWN pre-tripped run dir (blind reader R10): the previous
    # version ran both against ONE shared budget.json with MAIN first, so a pure
    # spend-threshold implementation with no (tool, agent) keying produced the same
    # allowed-then-refused pair from the rising count alone. Two identically-tripped
    # pools remove that confound — the ONLY difference is the agent, so read_file being
    # tail for one and core for the other must be what admits one and refuses the other.
    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1, "wall_clock_timeout": 3600,
              "grace_seconds": 600}

    main_dir = _run_dir(tmp_path, "pair-main")
    open_budget(main_dir, "r")
    update_budget_locked(main_dir, "r", "bash", limits=limits)  # trip it
    main_result, _ = drive_agent(
        MAIN_DEF, main_dir, [[("read_file", {"path": str(main_dir / "alert.json")})]],
        limits=limits, enforce=True)

    gather_dir = _run_dir(tmp_path, "pair-gather")
    open_budget(gather_dir, "r")
    update_budget_locked(gather_dir, "r", "bash", limits=limits)  # identically tripped
    gather_result, _ = drive_agent(
        GATHER_DEF, gather_dir, [[("read_file", {"path": str(gather_dir / "alert.json")})]],
        limits=limits, enforce=True, agent_id="gather:l-001")

    assert "BUDGET" not in str(main_result.all_messages()).upper(), (
        "read_file (tail on MAIN) was refused on a tripped pool"
    )
    assert "BUDGET" in str(gather_result.all_messages()).upper(), (
        "read_file (core on GATHER) survived a tripped pool"
    )


def _registered_names(defn) -> set[str]:
    """The REGISTERED tool-name census, read off a real Agent — the same route SC5
    used, so the tier table is checked against what the framework actually dispatches
    rather than against a hand-kept list."""
    logger = observe.RequestLogger(Path(os.devnull))
    agent = driver.build_agent_core(
        defn, deps_type=defn.deps_cls, instructions="probe", logger=logger,
        agent_id="probe", make_model=lambda n, e: BuiltModel(FunctionModel(
            ScriptedModel([])), None), limits=DEFAULT_LIMITS,
    )
    if defn is MAIN_DEF:
        from defender.runtime.tools import register_gather_tool
        register_gather_tool(agent, lambda agent_id: agent, driver.GATHER_REQUEST_LIMIT)
    return set(agent._function_toolset.tools)


# --- GATHER's own bound is untouched -----------------------------------------

def test_gather_keeps_its_request_limit(tmp_path):
    """GATHER_REQUEST_LIMIT stays 40, the bound a multi-dimension lead needs, and it
    is still the ceiling a dispatch actually runs into: a subagent that never stops
    aborts at its own request limit rather than at anything this design adds."""
    assert driver.GATHER_REQUEST_LIMIT == 40

    from pydantic_ai.exceptions import UsageLimitExceeded

    run_dir = _run_dir(tmp_path, "grl")
    open_budget(run_dir, "r")
    never_stops = [[("read_file", {"path": str(run_dir / "alert.json")})]] * 200
    with pytest.raises(UsageLimitExceeded):
        drive_agent(GATHER_DEF, run_dir, never_stops, limits=DEFAULT_LIMITS,
                    enforce=False, agent_id="gather:l-001",
                    request_limit=driver.GATHER_REQUEST_LIMIT)


# --- the flag's own input surface --------------------------------------------

def test_enforce_flag_defaults_off(monkeypatch):
    """DEFENDER_BUDGET_ENFORCE is read through env_bool and defaults to False when
    UNSET, so interactive development ships unenforced — and the empty string reads
    as an explicit False rather than diverging from unset."""
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
    """An unrecognized token for DEFENDER_BUDGET_ENFORCE raises FatalConfigError at
    startup rather than being silently coerced to False — a typo that silently ships
    an unenforced run is the fail-open this closed token set exists to prevent."""
    monkeypatch.setenv(FLAG, "maybe")
    with pytest.raises(FatalConfigError):
        driver.enforcement_enabled()


def test_enforcement_flag_diverges_across_a_process_boundary(monkeypatch, tmp_path):
    """The enforcement flag set once near the top of a run's process chain is read
    identically by every later hop: it is inherited WHOLESALE across all three known
    process boundaries — run.py's execv re-exec and the two os.environ.copy() hops in
    evals/_pipeline.py — so a later hop that reads the environment on its own does not
    diverge from the hop that set it.

    NAME NOTE (blind reader R16): the function name reads "diverges" but the asserted —
    and correct, per the 3/3 consensus — property is the OPPOSITE, wholesale
    inheritance with NO divergence. The name is the demand's original framing (the
    question "can it diverge?"), and the answer this pins is "no". SC25 (search)
    established the three specific hops (execv, two os.environ.copy()); this arm drives
    a real child to exercise the environment-inheritance mechanism ALL THREE rely on,
    rather than re-reading the source. The bash-lane child is included because FF21
    records the bash child env is dict(os.environ) minus provider keys — the flag is
    VISIBLE there and unwritable by the model."""
    monkeypatch.setenv(FLAG, "true")
    child = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r);"
         "from defender.runtime import driver;"
         "print(driver.enforcement_enabled())" % str(REPO_ROOT)],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert child.returncode == 0, child.stderr
    assert child.stdout.strip() == "True", child.stdout

    monkeypatch.setenv(FLAG, "false")
    child = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.path.insert(0, %r);"
         "from defender.runtime import driver;"
         "print(driver.enforcement_enabled())" % str(REPO_ROOT)],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
    )
    assert child.stdout.strip() == "False"


def test_ci_runs_the_suite_with_enforcement_on():
    """CI runs the collected suite with DEFENDER_BUDGET_ENFORCE on: the unit-test job
    carries the env block, so every test in tests/ and learning/ executes under the
    enforcing posture rather than the default-off one.

    D11 was REVERSED in §7 round 5. Its round-3 waiver rested on C6 — "real runs land
    at 10-26 tool calls against a cap of 200, so the flag alone executes the deny
    branch never" — and C6 IS REFUTED: two full-loop captures committed to THIS tree,
    experiments/actor-basin-276/fixtures/{falco-net-tool-live,sshd-gabe-live}/
    budget.json, sit at 191 and 182 tool_calls (95.5% and 91.0% of the cap) with
    subagent_spawns: 7 each. Real runs range at least 10-191 and the 75% warning line
    fires in production today. The hermetic e2e is KEPT alongside this: it covers the
    deny branch deterministically, CI covers it realistically."""
    wf = yaml.safe_load(CI_WORKFLOW.read_text())
    steps = [s for job in wf["jobs"].values() for s in job.get("steps", [])]
    unit = [s for s in steps if "pytest tests/" in str(s.get("run", ""))]
    assert unit, "the unit-test step moved — re-scope this demand"
    for step in unit:
        value = (step.get("env") or {}).get(FLAG)
        assert value is not None, f"{step.get('name')!r} carries no {FLAG} env block"
        # The token CI sets must be one the real reader accepts as ON.
        os.environ[FLAG] = str(value)
        try:
            assert driver.enforcement_enabled() is True
        finally:
            os.environ.pop(FLAG, None)


# --- the two pool roots ------------------------------------------------------

def test_the_learning_state_root_and_the_runs_base_cannot_be_the_same_dir(
    tmp_path, monkeypatch,
):
    """The learning state root and $DEFENDER_RUNS_BASE cannot resolve to the same
    directory: pairing the two env vars onto one path is REFUSED rather than quietly
    letting unenforced learning agents spend the enforced pool.

    Q1's probe dissolved D3 — learning stages bind under the learning state root,
    MAIN/GATHER bind $DEFENDER_RUNS_BASE, overlap False for all five — but the
    disjointness is EMERGENT FROM TWO ENV-VAR DEFAULTS, and the probe collided them
    deliberately: one operator pairing yields `SAME DIR? True`, at which point
    unenforced learning agents spend the enforced pool. Asserted, not assumed."""
    from defender import run_common

    shared = tmp_path / "both"
    shared.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(shared))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(shared))
    with pytest.raises(FatalConfigError):
        run_common.resolve_runs_base()

    # A symlinked alias to the same dir is the same collision.
    alias = tmp_path / "alias"
    alias.symlink_to(shared)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(alias))
    with pytest.raises(FatalConfigError):
        run_common.resolve_runs_base()

    # The control: the shipped defaults are disjoint and resolve cleanly.
    runs = tmp_path / "runs"
    learn = tmp_path / "learn"
    runs.mkdir()
    learn.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(learn))
    assert run_common.resolve_runs_base().resolve() == runs.resolve()


# --- the retry ceiling -------------------------------------------------------

def test_every_agent_construction_pins_retries_explicitly(tmp_path):
    """Every Agent construction site passes `retries` explicitly: the framework
    default is None, which resolves to an EFFECTIVE CEILING OF 1, so a site that omits
    the kwarg silently lands on the value that aborts the run on the second
    consecutive denial.

    PB4 (executed) killed W1 with this: omitting the kwarg and passing 1 abort at the
    same denial with the same message ("Tool 'work' exceeded max retries count of
    1"), so the unsafe value is reached by OMISSION, not by SELECTION — "nothing
    selects 1" is true and irrelevant.

    WHY retries is LOAD-BEARING on THIS change and not scope creep (VR2): the budget
    refusal returns a ToolReturnPart, so a SCHEMA-VALID re-issue of a stopped tool
    accumulates zero retries (test_repeated_reissue_accumulates_no_retries). But P3
    (executed) showed pydantic-ai validates args BEFORE the execute-family hooks, so a
    model spamming a stopped tool with SCHEMA-INVALID args never reaches the seam and
    climbs the retry ceiling — that is the path where the ceiling saves the run
    (bounding the spam at the request limit, which run_investigation catches). The
    blind reader's "zero retries" observation is true only for the schema-valid path.

    The enumeration picks the subjects; the wired half drives the real construction
    site and observes that two consecutive denials do NOT abort the run, which they
    would at the framework default of None."""
    sites = []
    for src in (DEFENDER / "runtime" / "driver.py",
                REPO_ROOT / "experiments" / "gather-verifiable-code-289" / "run_arms.py"):
        tree = ast.parse(src.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and (
                (isinstance(node.func, ast.Name) and node.func.id == "Agent")
                or (isinstance(node.func, ast.Attribute) and node.func.attr == "Agent")
            ):
                sites.append((src.name, node.lineno, {kw.arg for kw in node.keywords}))
    assert sites, "no Agent(...) construction site found — re-scope this demand"
    for name, lineno, kwargs in sites:
        assert "retries" in kwargs, f"{name}:{lineno} omits retries="

    assert driver.DEFAULT_TOOL_RETRIES == 10

    # Driven: two consecutive denials of the same tool survive AND the run reaches its
    # third (text) turn — at the framework default of None (an effective ceiling of 1)
    # the second denial would raise UnexpectedModelBehavior out of `agent.run`, which
    # drive_agent would propagate. Observing the loop RUN TO COMPLETION is the discriminator.
    run_dir = _run_dir(tmp_path, "retries")
    open_budget(run_dir, "r")
    missing = str(run_dir / "nope" / "absent.json")
    script = [[("read_file", {"path": missing})],
              [("read_file", {"path": missing})],
              []]
    result, model = drive_agent(MAIN_DEF, run_dir, script, limits=DEFAULT_LIMITS,
                                enforce=False)
    assert model.calls >= 3, "the loop did not reach its stopping turn — a denial aborted it"
    assert result.output is not None, "two consecutive denials aborted — retries was not pinned"


# --- D8's boundary: what a truncated run does downstream --------------------

def test_the_runtime_skips_the_learning_enqueue_for_a_truncated_run(tmp_path, monkeypatch):
    """The runtime itself skips the learning enqueue for a run marked
    truncated_by: "budget" — no queue marker is dropped — rather than relying on
    downstream report.md validation to reject it.

    One auditable check the runtime OWNS, versus a validation-layer contract it does
    not: if that gate is ever weakened, the loop trains on truncated investigations.
    The positive control is test_a_completed_run_is_still_enqueued_for_learning."""
    from defender import run_common

    # Point the learning state dir INTO tmp (blind reader R9): otherwise a real enqueue
    # writes under the DEFAULT dir outside tmp_path, so `_markers(tmp_path) == before`
    # holds whether or not a marker was dropped — and a regression would pollute the
    # developer's / CI's real learning state directory.
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    run_dir = _run_dir(tmp_path, "trunc")
    alert = run_dir / "alert.json"
    before = _markers(tmp_path / "learn")
    assert run_common.enqueue_learning(run_dir, alert, truncated_by="budget") is False
    assert _markers(tmp_path / "learn") == before, "a truncated run dropped a learn-queue marker"


def test_a_completed_run_is_still_enqueued_for_learning(tmp_path, monkeypatch):
    """An untruncated run is still enqueued for learning under the same harness — the
    control that keeps the suppression demand from passing by killing the learning
    loop outright.

    `truncated_by` absent is an untruncated run and falsy_valid is true, which is the
    `x or DEFAULT` swallow shape: an implementation that treated "no mark" and "a mark
    I could not read" alike would suppress learning for EVERY run."""
    from defender import run_common

    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    run_dir = _run_dir(tmp_path, "ok")
    alert = run_dir / "alert.json"
    assert run_common.enqueue_learning(run_dir, alert, truncated_by=None) is True
    assert _markers(tmp_path / "learn"), "the completed run dropped no marker"


def _markers(root: Path) -> set[str]:
    return {str(p) for p in root.rglob("*") if p.is_file() and "queue" in str(p)}
