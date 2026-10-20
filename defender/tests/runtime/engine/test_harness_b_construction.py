"""Single-source agent construction: `build_agent_core` threads the AgentDefinition's model/effort/cache key, registers tools from its ToolSet, and the MAIN/GATHER builders delegate to it."""
from __future__ import annotations

from dataclasses import replace as _with_fixture_run_1165
from defender.tests.support.shared.contracts._spec1077 import fixture_run as _fixture_run_1165

from pathlib import Path

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.runtime import challenge_gate, driver, observe  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    ToolSet,
)
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools import AgentDeps  # noqa: E402
from defender.run_repository import SessionPaths

_DEFENDER = Path(__file__).resolve().parents[3]

_CACHE = {
    "anthropic_cache_instructions": "1h",
    "anthropic_cache_tool_definitions": "1h",
    "anthropic_cache": "5m",
}


def _text_fn(text: str = "ok"):
    return lambda messages, info: ModelResponse(parts=[TextPart(content=text)])


def _capture_make_model(settings=None):
    """A `make_model` fake for the (name, effort) seam: records every call and returns a
    hermetic FunctionModel paired with `settings`. Returns (fake, calls) where `calls`
    accrues (model_name, effort) tuples."""
    calls: list[tuple[str, object]] = []

    def fake(model: str, effort):
        calls.append((model, effort))
        return BuiltModel(FunctionModel(_text_fn()), settings)

    return fake, calls


@pytest.fixture
def logger(tmp_path):
    lg = observe.RequestLogger(tmp_path / "llm_requests.jsonl")
    try:
        yield lg
    finally:
        lg.close()


def test_build_agent_core_threads_def_model_and_effort_to_make_model(logger):
    """build_agent_core resolves the model via make_model(defn.model(), defn.effort) — the (name, effort) seam, calling the def's model THUNK — and pairs the returned model + settings onto the Agent (observable via agent.model / agent.model_settings)."""
    sentinel = {"SENTINEL": "s"}
    fake, calls = _capture_make_model(settings=sentinel)
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.3", effort="low")
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert calls == [("glm-5.3", "low")]
    assert isinstance(agent.model, FunctionModel)
    assert agent.model_settings == {**sentinel, "openai_prompt_cache_key": "main"}


def test_build_agent_core_keys_the_cache_on_the_conversation_when_there_is_one(logger):
    """WITH a session the affinity key is that conversation's, so every turn of one growing prefix asks for the replica already holding the previous turn;"""
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.3", effort="low")
    with override_allow_model_requests(False):
        in_session = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=_capture_make_model()[0], session_id="sess-7",
        )
        one_shot = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="ablation", make_model=_capture_make_model()[0],
        )
    assert in_session.model_settings["openai_prompt_cache_key"] == "sess-7:main"
    assert one_shot.model_settings["openai_prompt_cache_key"] == "ablation"


def test_835_an_explicit_cache_key_overrides_both_derived_arms(logger):
    """The third arm (#835)."""
    defn = AgentDefinition(role=AgentRole.GATHER, model=lambda: "glm-5.3", effort="low")
    with override_allow_model_requests(False):
        keyed = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="gather:l-005", make_model=_capture_make_model()[0],
            session_id="sess-7", cache_key="gather:identity",
        )
    assert keyed.model_settings["openai_prompt_cache_key"] == "gather:identity"


def test_835_gather_is_cache_keyed_on_the_system_while_its_agent_id_stays_the_lead(logger, tmp_path):
    """The two names are now distinct, and each is load-bearing for something different:"""
    import asyncio

    from defender.runtime import tools_gather
    from defender.runtime.agent_definition import bind
    from defender.runtime.driver import MAIN_DEF
    from defender.tests.support.tenancy import _tenants1106

    seen: list[tuple[str, str]] = []

    class _Agent:
        async def run(self, *a, **kw):
            raise UsageLimitExceeded("stop here — the factory call is what this pins")

    def _factory(agent_id: str, system: str, request_limit: int):
        seen.append((agent_id, system))
        return _Agent()

    from dataclasses import replace

    from defender.runtime.run_state import RunState

    run_dir = tmp_path / fixture_uuid("run")
    (run_dir / "gather_raw").mkdir(parents=True)
    # MAIN's deps carry the run's one `RunState` (#1235 round 2), as the driver hands them:
    # the dispatch's breaker screen reads it.
    deps = replace(_with_fixture_run_1165(bind(MAIN_DEF, run_dir, defender_dir=_DEFENDER), run=_fixture_run_1165(run_dir)),
                   run_state=RunState(run_dir, "r-harness-b"))
    asyncio.run(tools_gather._run_gather(
        deps, _factory, 40,
        tools_gather.GatherRequest("l-005", "identity", "goal", ("what",)),
        _tenants1106.fixture_grants().gather, catalog=None,
    ))

    assert seen == [("gather:l-005", "identity")]

    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(
            _DEFENDER, logger, "gather:l-005", make_model=fake, verbs=FakeVerbs({}),
            session_id="sess-7", cache_key="gather:identity",
            verb_grant=driver.GATHER_DEF.verb_grant,
        )
    assert agent.model_settings["openai_prompt_cache_key"] == "gather:identity"


def test_build_agent_core_registers_read_only_pair(logger):
    """A read + bash ToolSet → build_agent_core registers ONLY the read-only pair; no file
    writers reach a read-only agent (the security-relevant default)."""
    fake, _ = _capture_make_model()
    defn = AgentDefinition(role=AgentRole.GATHER, model=lambda: "glm-5.3", effort=None,
                           tools=ToolSet(read=True, bash=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=fake,
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_build_agent_core_registers_write_tools(logger):
    """A read + bash + write ToolSet → the full four tools incl. write_file/edit_file (MAIN's
    authoring surface). The writers bit is the one build-time permission the def carries."""
    fake, _ = _capture_make_model()
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.3", effort="low",
                           tools=ToolSet(read=True, bash=True, write=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_build_agent_core_propagates_make_model_error(logger):
    def boom(model, effort):
        raise RuntimeError("no key")
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.3", effort="low")
    with pytest.raises(RuntimeError), override_allow_model_requests(False):
        driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=boom,
        )


def test_build_gather_agent_is_read_only_and_cannot_self_dispatch(monkeypatch, logger):
    """build_gather_agent (re-pointed at build_agent_core via the GATHER spec) yields the read-only surface ONLY — no writers, and NO 'gather' dispatch tool (the gather subagent must not dispatch itself)."""
    monkeypatch.delenv("DEFENDER_GATHER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(
            _DEFENDER, logger, "gather:l-001", make_model=fake, verbs=FakeVerbs({}),
            verb_grant=driver.GATHER_DEF.verb_grant,
        )
    assert list(agent._function_toolset.tools) == [
        "bash", "read_file", "template_search", "query", "list_verbs",
    ]
    assert "gather" not in agent._function_toolset.tools
    assert "write_file" not in agent._function_toolset.tools


def test_build_agent_main_has_gather_dispatch_and_writers(monkeypatch, logger):
    """MAIN routed through build_agent_core still ends up with BOTH the authoring tools (writers=True) AND the layered 'gather' dispatch tool (register_gather_tool is applied after construction, at MAIN's call site only)."""
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_agent(
            _DEFENDER, logger, make_model=fake,
            bounds=challenge_gate.default_bounds(), catalog=None,
            gather_grant=driver.GATHER_DEF.verb_grant,
        )
    tools = set(agent._function_toolset.tools)
    assert {"bash", "read_file", "append_block"} <= tools
    assert not {"write_file", "edit_file"} & tools
    assert "gather" in tools


def test_main_extra_capabilities_is_unconditional(tmp_path, monkeypatch):
    """SEAM CONTRACT, overturned by #705 (O20, R2/M8 — not preserved):"""
    from defender.runtime import session_store

    store = session_store.open_store(case_id="case-harness", sessions=SessionPaths(tmp_path / "runs"))
    session_id = store.new_session(agent_id="main")

    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    off = list(driver._main_extra_capabilities(store, session_id))
    monkeypatch.setenv("DEFENDER_COMPACTION", "on")
    on = list(driver._main_extra_capabilities(store, session_id))

    assert len(off) == 1, f"the capability is unconditional; unset gave {off}"
    assert len(on) == 1, f"the flag must not add a SECOND capability; set gave {on}"
    assert isinstance(off[0], driver.ProcessHistory)
    assert isinstance(on[0], driver.ProcessHistory)
