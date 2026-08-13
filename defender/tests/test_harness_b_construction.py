"""Executable spec for #493/#495 — single-source Harness B agent construction.

The PydanticAI runtime ("Harness B") builds its agents at three near-duplicate
`Agent(...)` sites today (`driver.build_agent` MAIN, `driver._build_subagent`
GATHER, `engine_pydantic.build_judge_agent` JUDGE). #493 collapsed them onto one
`build_agent_core(...)` site + the single `settings_for_effort(effort_for_role(role))`
path; **#538 then folded the per-agent config into an `AgentDefinition`** — so
`build_agent_core` now takes an `AgentDefinition` (its `ToolSet` drives registration),
and the old `AgentSpec` / `spec_for_role` are gone (their shape is now pinned by
`test_agent_definition.py`, and the agent REGISTRY now lives at `defender.agents` — #575 moved it
out of `runtime/`, since a registry ENUMERATES agents and `runtime/` is the library they are built
on). What remains here covers the provider effort/settings seam and the three callers surviving the
collapse.

#575 also split tool PRESENCE from PERMISSION: `ToolSet.bash` is a plain `bool` (does the bash tool
get REGISTERED) and WHAT an agent may then run is its def's `bash_shapes` grants. These construction
tests only ever asserted registration, so they read the bool; the grants are pinned at the gate.

Resolved design forks (see issue #493 comment thread):
  - EFFORT OMIT = **None-canonical**. `effort_for_role` returns `str | None`; None is
    the single omit representation (Anthropic → None always; Fireworks normalizes env
    "default" → None; keeps "low"/"none"/"high"). `settings_for_effort` accepts None
    (→ omit) and still tolerates the "default" string for the judge's config.
  - SETTINGS IDENTITY = **value-equality**. The collapsed path builds fresh settings
    objects; the cross-role `is`-identity guarantee is downgraded to `==` (the existing
    `test_anthropic_settings_are_the_cache_and_role_invariant` is retargeted to `==`).
  - build_judge_agent stays a **thin wrapper** delegating to build_agent_core.

Observability note: pydantic-ai exposes NO public capabilities surface — a
`ProcessHistory` capability does NOT appear in `agent.history_processors` (it lands in
the private `_root_capability`, combined with framework capabilities). So the compaction
toggle is pinned here at the **assembly seam** (`_main_extra_capabilities`), and the
ordering `[hooks, *extra]` + its wiring into the live agent is pinned by the e2e replay
suite (`tests/test_replay_*`), NOT by reaching into Agent internals here.

Hermetic: no network, no API key — a `FunctionModel` is injected through the
`make_model` DI seam under `override_allow_model_requests(False)`. Faults enter through
that parameter seam and env vars (`monkeypatch.setenv`), never `monkeypatch.setattr`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.core.config import StageWiring  # noqa: E402
from defender._env import FatalConfigError  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.runtime import challenge_gate, driver, observe, providers  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    ToolSet,
)
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools import AgentDeps  # noqa: E402

_DEFENDER = Path(__file__).resolve().parents[1]

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





def test_effort_for_role_anthropic_is_none_for_every_role():
    """Anthropic exposes no role→effort policy → effort_for_role returns None for MAIN
    AND GATHER (omit the anthropic_effort knob), preserving today's cache-only settings."""
    assert providers.effort_for_role("claude-sonnet-4-6", AgentRole.MAIN) is None
    assert providers.effort_for_role("claude-sonnet-4-6", AgentRole.GATHER) is None


def test_effort_for_role_fireworks_main_default_is_low(monkeypatch):
    """Fireworks MAIN, no env override → "low" (the production DEFAULT_MODEL=glm-5.2 main
    effort). This is the value the live main loop must keep running under."""
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    assert providers.effort_for_role("glm-5.2", AgentRole.MAIN) == "low"


def test_effort_for_role_fireworks_gather_default_is_none_string_not_None(monkeypatch):
    """Fireworks GATHER default → the explicit string "none" (reasoning DISABLED for the
    mechanical ES|QL loop), which is DISTINCT from None/omit — the knob is set, not absent.
    A regression collapsing "none" into None would silently re-enable gather reasoning."""
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    assert providers.effort_for_role("glm-5.2", AgentRole.GATHER) == "none"


def test_effort_for_role_fireworks_main_env_override(monkeypatch):
    """DEFENDER_MAIN_REASONING_EFFORT overrides the role default → the env value flows
    through effort_for_role verbatim."""
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "high")
    assert providers.effort_for_role("glm-5.2", AgentRole.MAIN) == "high"


def test_effort_for_role_fireworks_env_default_sentinel_normalizes_to_None(monkeypatch):
    """Env DEFENDER_MAIN_REASONING_EFFORT=default → effort_for_role returns None (the
    single omit representation), NOT the string "default". None-canonicalization is the
    resolved fork: one omit spelling reaches the definition's effort.
    # rejected: return "default" — that would keep two omit spellings (None and "default")."""
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "default")
    assert providers.effort_for_role("glm-5.2", AgentRole.MAIN) is None


def test_effort_for_role_fireworks_bad_env_fails_loud(monkeypatch):
    """A typo'd role-effort env is a run-independent config fault → FatalConfigError at
    read (env_str choices), never a silently-forwarded bad reasoning_effort."""
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "hgih")
    with pytest.raises(FatalConfigError):
        providers.effort_for_role("glm-5.2", AgentRole.MAIN)


def test_effort_for_role_unknown_model_fails_loud():
    """An unroutable model name (typo) → ValueError from provider_for, before any role
    dispatch — the same fail-loud provider_for() gives, not a silent default."""
    with pytest.raises(ValueError, match="unknown model"):
        providers.effort_for_role("gpt-4o", AgentRole.MAIN)



def test_anthropic_settings_for_effort_none_is_cache_only():
    """settings_for_effort(None) omits the anthropic_effort override → cache-only,
    equal to today's role settings. This is what settings(role)=settings_for_effort(
    effort_for_role(role)=None) must resolve to for the collapse to preserve value."""
    assert providers.ANTHROPIC.settings_for_effort(None) == _CACHE


def test_fireworks_settings_for_effort_none_disables_the_param():
    """settings_for_effort(None) → None settings for Fireworks (omit reasoning_effort),
    matching the existing "default"-string behavior — both omit spellings agree."""
    assert providers.FIREWORKS.settings_for_effort(None) is None


def test_settings_role_still_equals_pinned_values_after_collapse(monkeypatch):
    """Equivalence guard: the live role→settings path settings_for_effort(effort_for_role(
    role)) — which replaced settings(role) (#493) — yields the EXACT dicts test_glm_fireworks
    pins: Fireworks MAIN {"extra_body":{"reasoning_effort":"low"}}, GATHER "none", Anthropic
    cache-only + role-invariant by VALUE."""
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    fw, an = providers.FIREWORKS, providers.ANTHROPIC
    assert fw.settings_for_effort(fw.effort_for_role(AgentRole.MAIN)) == {"extra_body": {"reasoning_effort": "low"}}
    assert fw.settings_for_effort(fw.effort_for_role(AgentRole.GATHER)) == {"extra_body": {"reasoning_effort": "none"}}
    assert an.settings_for_effort(an.effort_for_role(AgentRole.MAIN)) == _CACHE
    assert (an.settings_for_effort(an.effort_for_role(AgentRole.MAIN))
            == an.settings_for_effort(an.effort_for_role(AgentRole.GATHER)))



def test_build_agent_core_threads_def_model_and_effort_to_make_model(logger):
    """build_agent_core resolves the model via make_model(defn.model(), defn.effort) — the
    (name, effort) seam, calling the def's model THUNK — and pairs the returned model +
    settings onto the Agent (observable via agent.model / agent.model_settings).

    The seam stays TWO positional arguments. The prompt-cache affinity key is applied after
    it returns, so what reaches the Agent is the seam's settings plus that one key — pinned
    by EQUALITY against exactly that, so a third thing appearing between the seam and the
    Agent is a failure here rather than something only the cache-key test below would see."""
    sentinel = {"SENTINEL": "s"}
    fake, calls = _capture_make_model(settings=sentinel)
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low")
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert calls == [("glm-5.2", "low")]
    assert isinstance(agent.model, FunctionModel)
    assert agent.model_settings == {**sentinel, "openai_prompt_cache_key": "main"}


def test_build_agent_core_keys_the_cache_on_the_conversation_when_there_is_one(logger):
    """WITH a session the affinity key is that conversation's, so every turn of one growing
    prefix asks for the replica already holding the previous turn; WITHOUT one it is the bare
    agent id, which is what a single-call role (the review lenses) can reuse ACROSS runs.

    Both arms are pinned here because they are the whole of the policy, and a key that
    collapsed to one of them would be silently wrong in exactly the lane it did not fit: a
    per-run key on a lens defeats the only reuse it has, and a bare agent id on `main` points
    every concurrent run at one replica."""
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low")
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
    """The third arm (#835). Gather HAS a session, so the derived key would be
    `{session}:gather:{lead_id}` — which routes every sibling lead to its own replica and lets
    none of them read the prefix they all share: gather's SKILL.md plus the dispatched system's
    catalog, identical across leads AND across runs. An explicit key is how the caller that
    knows what that prefix is keyed on says so.

    Pinned against the SESSION arm specifically: an override that only beat the session-less arm
    would be dead code on the one role that needs it. The two derived arms themselves stay
    pinned, untouched, by the test above."""
    defn = AgentDefinition(role=AgentRole.GATHER, model=lambda: "glm-5.2", effort="low")
    with override_allow_model_requests(False):
        keyed = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="gather:l-005", make_model=_capture_make_model()[0],
            session_id="sess-7", cache_key="gather:identity",
        )
    assert keyed.model_settings["openai_prompt_cache_key"] == "gather:identity"


def test_835_gather_is_cache_keyed_on_the_system_while_its_agent_id_stays_the_lead(logger, tmp_path):
    """The two names are now distinct, and each is load-bearing for something different: the
    prompt-cache lane is the SYSTEM's (that is what the shared prefix belongs to), while
    `agent_id` remains `gather:{lead_id}` — the wire log's line key, the session store's
    `agent_id` column, and what `_stamp_gather_terminator` looks a session up by.

    Two halves, and NEITHER reaches `driver._build_gather` — it is a closure inside
    `build_agent`, unreachable without the `monkeypatch.setattr` this module's header forbids.
    So: `_run_gather` driven with a recording fake pins the CONTRACT that carries the system
    down (`gather_factory(agent_id, system, request_limit)`), and `build_gather_agent` pins that a `cache_key`
    argument lands on the model settings. The composition root's own
    `cache_key=f"gather:{system}"` is still unpinned — an integration seam worth a test that can
    observe the built gather agent's settings end-to-end."""
    import asyncio

    from defender.runtime import tools_gather
    from defender.runtime.agent_definition import bind
    from defender.runtime.driver import GATHER_DEF, MAIN_DEF

    seen: list[tuple[str, str]] = []

    class _Agent:
        async def run(self, *a, **kw):
            raise UsageLimitExceeded("stop here — the factory call is what this pins")

    def _factory(agent_id: str, system: str, request_limit: int):
        seen.append((agent_id, system))
        return _Agent()

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    deps = bind(MAIN_DEF, run_dir, salt="0011223344556677", defender_dir=_DEFENDER)
    asyncio.run(tools_gather._run_gather(
        deps, _factory, 40,
        tools_gather.GatherRequest("l-005", "identity", "goal", ("what",)),
        GATHER_DEF.verb_grant,
    ))

    assert seen == [("gather:l-005", "identity")]

    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(
            _DEFENDER, logger, "gather:l-005", make_model=fake, verbs=FakeVerbs({}),
            session_id="sess-7", cache_key="gather:identity",
        )
    assert agent.model_settings["openai_prompt_cache_key"] == "gather:identity"


def test_build_agent_core_registers_read_only_pair(logger):
    """A read + bash ToolSet → build_agent_core registers ONLY the read-only pair; no file
    writers reach a read-only agent (the security-relevant default)."""
    fake, _ = _capture_make_model()
    defn = AgentDefinition(role=AgentRole.GATHER, model=lambda: "glm-5.2", effort=None,
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
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low",
                           tools=ToolSet(read=True, bash=True, write=True))
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_build_agent_core_propagates_make_model_error(logger):
    """make_model raising (unroutable name / missing key / bad effort) propagates —
    build_agent_core adds no defensive catch, so a config fault surfaces at the build,
    not as a half-built agent that 401s mid-run."""
    def boom(model, effort):
        raise RuntimeError("no key")
    defn = AgentDefinition(role=AgentRole.MAIN, model=lambda: "glm-5.2", effort="low")
    with pytest.raises(RuntimeError), override_allow_model_requests(False):
        driver.build_agent_core(
            defn, deps_type=AgentDeps, instructions="x", logger=logger,
            agent_id="a", make_model=boom,
        )


def test_build_agent_core_extra_capabilities_default_is_immutable_empty():
    """extra_capabilities defaults to an empty tuple () — an immutable, non-shared default
    (never a mutable []), so two agents built with the default can't alias one list."""
    import inspect
    default = inspect.signature(driver.build_agent_core).parameters["extra_capabilities"].default
    assert default == ()
    assert isinstance(default, tuple)





def test_build_gather_agent_is_read_only_and_cannot_self_dispatch(monkeypatch, logger):
    """build_gather_agent (re-pointed at build_agent_core via the GATHER spec) yields the
    read-only surface ONLY — no writers, and NO 'gather' dispatch tool (the gather subagent
    must not dispatch itself).

    #611 adds `query` (the typed data-source tool) to that surface and #585 added `template_search`:
    gather's query-template discovery is dead on the
    bash lane (`find` was never there, `grep -r` denies since #581, a glob reaches grep as a
    literal filename, and #575 removes `ls`), so the grep comes back as a gated tool with a
    harness-owned root. This is the ONE test that pins gather's REAL registered surface — the
    `["bash", "read_file"]` assertions in test_gather_engine_seam.py and at :224 above feed a
    SYNTHETIC ToolSet and would stay green while GATHER_DEF drifted."""
    monkeypatch.delenv("DEFENDER_GATHER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(
            _DEFENDER, logger, "gather:l-001", make_model=fake, verbs=FakeVerbs({}),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "template_search", "query"]
    assert "gather" not in agent._function_toolset.tools
    assert "write_file" not in agent._function_toolset.tools


def test_build_agent_main_has_gather_dispatch_and_writers(monkeypatch, logger):
    """MAIN routed through build_agent_core still ends up with BOTH the authoring tools
    (writers=True) AND the layered 'gather' dispatch tool (register_gather_tool is applied
    after construction, at MAIN's call site only). Injects the (name, effort) make_model
    seam MAIN must now accept."""
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_agent(
            _DEFENDER, logger, make_model=fake,
            bounds=challenge_gate.default_bounds(),
        )
    tools = set(agent._function_toolset.tools)
    # The authoring tool is `append_block` since #810 — MAIN's write grant is `append=True`,
    # so the general write lane is not registered on it. The point of the assertion is that
    # construction gives MAIN its authoring surface AND the layered gather dispatch, which
    # holds unchanged; only the name of the authoring verb moved.
    assert {"bash", "read_file", "append_block"} <= tools
    assert not {"write_file", "edit_file"} & tools
    assert "gather" in tools


def test_main_extra_capabilities_is_unconditional(tmp_path, monkeypatch):
    """SEAM CONTRACT, overturned by #705 (O20, R2/M8 — not preserved): MAIN's assembled
    extra_capabilities is exactly ONE `ProcessHistory` (the store-backed renderer)
    REGARDLESS of `DEFENDER_COMPACTION` — the flag now gates only whether a fold is
    applied inside that one capability, not whether a second capability exists. See
    `tests/test_store_driver_705.py::test_the_pre_change_construction_assertions_are_overturned`,
    the canonical replacement for the two pre-#705 assertions this test used to make."""
    from defender.runtime import session_store

    store = session_store.open_store(case_id="case-harness", runs_base=tmp_path / "runs")
    session_id = store.new_session(agent_id="main")

    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    off = list(driver._main_extra_capabilities(store, session_id))
    monkeypatch.setenv("DEFENDER_COMPACTION", "on")
    on = list(driver._main_extra_capabilities(store, session_id))

    assert len(off) == 1, f"the capability is unconditional; unset gave {off}"
    assert len(on) == 1, f"the flag must not add a SECOND capability; set gave {on}"
    assert isinstance(off[0], driver.ProcessHistory)
    assert isinstance(on[0], driver.ProcessHistory)


def test_build_judge_agent_thin_wrapper_still_applies_per_leg_effort(monkeypatch, logger):
    """The judge stays a thin wrapper over build_agent_core (Fork 3), building its spec
    from per-DIRECTION-LEG config: two legs at different efforts produce two independent
    agents with distinct anthropic_effort — no shared role env can carry two values.
    Uses the real build_for_effort (a fake key keeps it hermetic; settings make no call)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    prompt = Path(__file__)
    malicious = engine_pydantic.build_judge_agent(
        StageWiring(prompt_path=prompt, model="claude-sonnet-4-6", effort="low",
                    trace_name="judge_trace.jsonl", label="judge-malicious"), logger)
    benign = engine_pydantic.build_judge_agent(
        StageWiring(prompt_path=prompt, model="claude-sonnet-4-6", effort="high",
                    trace_name="judge_benign_trace.jsonl", label="judge-benign"), logger)
    assert malicious.model_settings["anthropic_effort"] == "low"
    assert benign.model_settings["anthropic_effort"] == "high"
    assert list(malicious._function_toolset.tools) == ["bash", "read_file"]
