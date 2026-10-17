"""The fix_row verb's grants, the budget roster, and the negatives: main is not re-granted general write verbs and bash cannot reach investigation.md."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from defender.tests._defender_sql import assert_query_error, run_sql_py
from defender.tests._invlang_warn_836 import (
    WARN_DOC,
    main_deps,
    seed_investigation,
)


def _registered_names(defn) -> set[str]:
    """The REGISTERED tool-name census, read off a real Agent — the same route
    `test_budget_seams_631._registered_names` uses, so registration is checked against what
    the framework actually dispatches rather than against a hand-kept list."""
    import os

    from pydantic_ai.models import override_allow_model_requests
    from pydantic_ai.models.function import FunctionModel

    from defender.hooks.budget_enforcer import DEFAULT_LIMITS
    from defender.runtime import driver, observe
    from defender.runtime.providers import BuiltModel
    from defender.runtime.tools import AgentDeps
    from defender.tests.e2e._replay_harness import ReplayFn

    logger = observe.RequestLogger(Path(os.devnull))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=defn.deps_cls or AgentDeps, instructions="probe", logger=logger,
            agent_id="probe",
            make_model=lambda name, effort: BuiltModel(FunctionModel(ReplayFn([])), None),
            limits=DEFAULT_LIMITS,
        )
    return set(agent._function_toolset.tools)


# A5 — which agents are offered the repair verb

def test_exactly_one_agent_definition_is_offered_fix_row():
    """A5: `fix_row` rides `append=True` — no new capability bit, matching N4's posture of not widening the write surface — and exactly ONE definition in the tree grants it."""
    from defender.agents import AGENTS
    from defender.runtime.agent_role import AgentRole

    granting = {role for role, defn in AGENTS.items() if defn.tools.append}
    assert granting == {AgentRole.MAIN}

    main_names = _registered_names(AGENTS[AgentRole.MAIN])
    assert "fix_row" in main_names
    assert "append_block" in main_names

    ungranted = replace(
        AGENTS[AgentRole.MAIN], tools=replace(AGENTS[AgentRole.MAIN].tools, append=False)
    )
    without_append = _registered_names(ungranted)
    assert "fix_row" not in without_append, "fix_row registers without the append grant"
    assert "append_block" not in without_append
    assert "read_file" in without_append, "the whole roster vanished — a vacuous comparison"


# R1 — the budget roster, and what tail tier does and does not buy

def _budgeted(tmp_path, tool_calls: int):
    """MAIN deps whose run's real budget — the run's `RunState`, started and counted through the production `RunState(...)` / `count_call` (#1235 round 2) and carried on the deps as the run's own — holds `tool_calls` executed calls."""
    from defender.hooks.budget_enforcer import count_call
    from defender.runtime.run_state import RunState

    deps, run = main_deps(tmp_path)
    state = RunState(run, run.name)
    for _ in range(tool_calls):
        count_call(state, "bash")
    return replace(deps, run_state=state), run


def _short_circuit(deps, tool_name, limits):
    import os

    from defender.runtime import driver, observe

    logger = observe.RequestLogger(Path(os.devnull))
    return driver._budget_short_circuit(deps, tool_name, limits, logger, "main")


def test_budget_tripped_run_still_completes_repair_cycle(tmp_path):
    """Resolution R1: `fix_row` joins `_MAIN_TAIL_TOOLS`, so a run that trips its TOOL-CALL cap with an outstanding warning can still repair and close."""
    from defender.hooks.budget_enforcer import (
        BUDGET_EXEMPT_TOOLS,
        DEFAULT_LIMITS,
        should_refuse,
        tier,
    )
    from defender.runtime.agent_role import AgentRole

    assert tier("fix_row", AgentRole.MAIN) == "tail"
    assert "fix_row" not in BUDGET_EXEMPT_TOOLS, "R1 deliberately did NOT exempt it"

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 3}
    over_cap = {"tool_calls": 99, "started_monotonic": None}
    assert should_refuse(over_cap, "fix_row", tier("fix_row", AgentRole.MAIN), limits) is False
    assert should_refuse(over_cap, "gather", tier("gather", AgentRole.MAIN), limits) is True

    # ...and the whole cycle survives the cap: the repair lands and the close commits.
    deps, run = _budgeted(tmp_path, tool_calls=limits["max_tool_calls"] + 1)
    seed_investigation(run, WARN_DOC)
    assert _short_circuit(deps, "fix_row", limits) is None
    assert _short_circuit(deps, "close_investigation", limits) is None


def test_repair_verb_under_budget_pressure(tmp_path):
    """R1's accepted trade-off, and the boundary the design's own text does not state."""
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS, TAIL_ALLOWANCE, BudgetKill, tier
    from defender.runtime.agent_role import AgentRole

    assert tier("fix_row", AgentRole.MAIN) == "tail"

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 2}
    deps, run = _budgeted(tmp_path, tool_calls=limits["max_tool_calls"] + TAIL_ALLOWANCE)
    seed_investigation(run, WARN_DOC)

    with pytest.raises(BudgetKill):
        _short_circuit(deps, "fix_row", limits)

    assert _short_circuit(deps, "close_investigation", limits) is None


def test_budget_stop_message_while_flagged(tmp_path):
    """`BUDGET_REFUSAL_MESSAGE` names the survivor set the model still has — and with a repair window open, today's set is the WRONG one."""
    from defender.hooks.budget_enforcer import DEFAULT_LIMITS, refusal_message

    limits = {**DEFAULT_LIMITS, "max_tool_calls": 1}
    text = refusal_message({"tool_calls": 99, "started_monotonic": None}, "gather", limits)

    assert "gather" in text, "the message is not about the refused tool at all"
    assert "append_block" in text
    assert "fix_row" in text, "the model is told the wrong survivor set while a window is open"


# the remaining by-name rosters


# A7 — the four model-facing prose sites


# O3 / SEC1 — the grants the negative universal rests on

def test_main_is_not_regranted_write_file_or_edit_file():
    """N4: the repair window does not re-open the surface #810 closed on measurement."""
    from defender.runtime.agent_definition import ToolSet
    from defender.runtime.driver import MAIN_DEF

    assert MAIN_DEF.tools == ToolSet(read=True, bash=True, append=True, close=True)
    assert MAIN_DEF.tools.write is False

    names = _registered_names(MAIN_DEF)
    assert "write_file" not in names
    assert "edit_file" not in names
    assert {"append_block", "fix_row", "read_file", "bash"} <= names


def test_bash_grant_cannot_construct_a_write_reaching_investigation_md(tmp_path):
    """O3/SEC1 are only as strong as this negative, which the brief stated with no claim behind it."""
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.driver import MAIN_DEF

    deps, run = main_deps(tmp_path)
    inv = seed_investigation(run, WARN_DOC)
    before = inv.read_bytes()
    policy = compile_policy_for(MAIN_DEF, run, defender_dir=deps.defender_dir)

    def decide(cmd):
        return permission.decide_bash(
            cmd, policy=policy, run_dir=run, defender_dir=deps.defender_dir,
            cwd_anchor=deps.cwd_anchor,
        )

    for cmd in (
        f"echo x > {inv}",
        f"cat /etc/hostname >> {inv}",
        f"printf x > {inv}",
        f"sed -i s/a/b/ {inv}",
        f"tee {inv}",
        f"cp /etc/hostname {inv}",
        f"mv /etc/hostname {inv}",
        f"dd of={inv}",
        f"python3 -c open('{inv}','w')",
        f"rm {inv}",
    ):
        assert decide(cmd).allow is False, cmd

    # rt6 — the gate ALLOWS write-shaped SQL; duckdb's locked configuration is the boundary.
    sql = f"COPY (SELECT 1 AS a) TO '{inv}' (FORMAT CSV)"
    assert decide(f"defender-sql \"{sql}\"").allow is True, (
        "the permission gate started parsing SQL — rt6's correction no longer applies and "
        "this test is pinning the wrong boundary"
    )
    # ...and a sanctioned reader on the same lane IS allowed. Asserted before the spawn,
    # which may skip on a checkout without duckdb and would take this gate check with it.
    assert decide(f"cat {inv}").allow is True

    proc = run_sql_py(sql, stdin='[{"a": 1}]')
    assert_query_error(proc, "duckdb did not refuse the write-shaped statement")
    assert inv.read_bytes() == before
