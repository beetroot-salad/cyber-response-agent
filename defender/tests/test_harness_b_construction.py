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

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._env import FatalConfigError  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.runtime import driver, observe, providers  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    AgentDefinition,
    ToolSet,
)
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools import AgentDeps  # noqa: E402

_DEFENDER = Path(__file__).resolve().parents[1]

# The Anthropic three-part prompt cache — the role-invariant base every claude settings
# object carries. Mirrors the constant in tests/test_glm_fireworks.py (the equivalence
# oracle for the settings values this refactor must preserve).
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


# NOTE: the AgentSpec value-object tests moved to test_agent_definition.py (#538 folded
# AgentSpec into AgentDefinition — shape + frozenness are pinned there).


# ============================================================================
# effort_for_role — the provider seam that collapses settings(role) into
# settings_for_effort. Router shape: providers.effort_for_role(name, role).
# ============================================================================

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


# ============================================================================
# settings_for_effort(None) — the new omit input (Fork 1). The "default" string
# stays tolerated (existing test_glm_fireworks cases keep passing).
# ============================================================================

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


# ============================================================================
# build_agent_core — the single construction site
# ============================================================================

def test_build_agent_core_threads_def_model_and_effort_to_make_model(logger):
    """build_agent_core resolves the model via make_model(defn.model(), defn.effort) — the
    (name, effort) seam, calling the def's model THUNK — and pairs the returned model +
    settings onto the Agent (observable via agent.model / agent.model_settings)."""
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
    assert agent.model_settings == sentinel


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


# NOTE: the old `spec_for_role` producer is gone (#538) — MAIN/GATHER are now
# `driver.MAIN_DEF` / `driver.GATHER_DEF` (shape pinned in test_agent_definition.py), and
# `build_agent` / `build_gather_agent` re-bind the per-invocation model+effort onto them.
# Its intents survive here: gather-ignores-the-main-model is structural (build_gather_agent
# takes no main model), and the effort defaults/omit are pinned by the effort_for_role tests
# above + the construction tests below.


# ============================================================================
# MAIN / GATHER / JUDGE construction — the three callers survive the collapse
# ============================================================================

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
    # The GATHER spec routes through the real env path (gather_model() → provider_for,
    # effort_for_role → env_str); clear the gather env so an ambient DEFENDER_GATHER_MODEL
    # (the A/B benchmark exports it) or DEFENDER_GATHER_REASONING_EFFORT can't error the build.
    monkeypatch.delenv("DEFENDER_GATHER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(
            _DEFENDER, logger, "gather:l-001", make_model=fake, verbs=FakeVerbs({}),
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "template_search", "query"]
    assert "gather" not in agent._function_toolset.tools    # no self-dispatch
    assert "write_file" not in agent._function_toolset.tools


def test_build_agent_main_has_gather_dispatch_and_writers(monkeypatch, logger):
    """MAIN routed through build_agent_core still ends up with BOTH the authoring tools
    (writers=True) AND the layered 'gather' dispatch tool (register_gather_tool is applied
    after construction, at MAIN's call site only). Injects the (name, effort) make_model
    seam MAIN must now accept."""
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
    # MAIN's spec routes through effort_for_role → env_str; clear the effort env so an
    # ambient DEFENDER_MAIN_REASONING_EFFORT can't FatalConfigError the build.
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_agent(_DEFENDER, logger, make_model=fake)
    tools = set(agent._function_toolset.tools)
    assert {"bash", "read_file", "write_file", "edit_file"} <= tools  # writers
    assert "gather" in tools  # the layered dispatch tool, MAIN-only


def test_main_extra_capabilities_empty_when_compaction_off(monkeypatch):
    """SEAM CONTRACT (compaction toggle observable): with DEFENDER_COMPACTION off, MAIN's
    assembled extra_capabilities is EMPTY → build_agent_core gets extra_capabilities=(),
    byte-identical to today's no-compaction MAIN. (The [hooks, *extra] ordering + its
    wiring into the live agent is pinned by the e2e replay suite, not here — pydantic-ai
    exposes no public capabilities surface.)"""
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    assert list(driver._main_extra_capabilities()) == []


def test_main_extra_capabilities_has_one_process_history_when_on(monkeypatch):
    """SEAM CONTRACT: with DEFENDER_COMPACTION on, MAIN assembles exactly one ProcessHistory
    capability (the per-loop compaction), which build_agent passes as extra_capabilities."""
    monkeypatch.setenv("DEFENDER_COMPACTION", "on")
    caps = list(driver._main_extra_capabilities())
    assert len(caps) == 1
    assert isinstance(caps[0], driver.ProcessHistory)


def test_build_judge_agent_thin_wrapper_still_applies_per_leg_effort(monkeypatch, logger):
    """The judge stays a thin wrapper over build_agent_core (Fork 3), building its spec
    from per-DIRECTION-LEG config: two legs at different efforts produce two independent
    agents with distinct anthropic_effort — no shared role env can carry two values.
    Uses the real build_for_effort (a fake key keeps it hermetic; settings make no call)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    prompt = Path(__file__)  # any readable file for instructions
    malicious = engine_pydantic.build_judge_agent(prompt, "claude-sonnet-4-6", "low", logger, "judge-malicious")
    benign = engine_pydantic.build_judge_agent(prompt, "claude-sonnet-4-6", "high", logger, "judge-benign")
    assert malicious.model_settings["anthropic_effort"] == "low"
    assert benign.model_settings["anthropic_effort"] == "high"
    # read-only: the judge grades evidence, never writes
    assert list(malicious._function_toolset.tools) == ["bash", "read_file"]
