"""Executable spec for #493/#495 — single-source Harness B agent construction.

The PydanticAI runtime ("Harness B") builds its agents at three near-duplicate
`Agent(...)` sites today (`driver.build_agent` MAIN, `driver._build_subagent`
GATHER, `engine_pydantic.build_judge_agent` JUDGE). This refactor collapses them
onto one `build_agent_core(spec, ...)` fed by a per-agent `AgentSpec(model, effort?,
writers)`, and collapses the provider's `settings(role)` onto the single
`settings_for_effort(effort_for_role(role))` path.

These tests are the SPEC (written before the code) — they pin observable behavior at
the real entry points. The not-yet-written targets are referenced as attributes
(`driver.AgentSpec`, `driver.build_agent_core`, `driver.spec_for_role`,
`driver._main_extra_capabilities`, `providers.effort_for_role`) so this module still
IMPORTS and COLLECTS; each unimplemented target reds at call time with AttributeError,
the expected pre-implementation state.

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

import dataclasses
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender._env import FatalConfigError  # noqa: E402
from defender.learning.pipeline.judge import engine_pydantic  # noqa: E402
from defender.runtime import driver, observe, providers  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime.tools import RunDeps  # noqa: E402

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


# ============================================================================
# AgentSpec — the per-agent config value object
# ============================================================================

def test_agent_spec_defaults_effort_none_and_writers_false():
    """AgentSpec(model=...) with effort/writers omitted → effort is None (omit the knob)
    and writers is False (read-only is the SAFE default; only MAIN opts into writers)."""
    spec = driver.AgentSpec(model="glm-5.2")
    assert spec.model == "glm-5.2"
    assert spec.effort is None
    assert spec.writers is False


def test_agent_spec_is_frozen():
    """AgentSpec is a frozen dataclass → mutating a field raises FrozenInstanceError, so
    an agent's config can't drift after construction."""
    spec = driver.AgentSpec(model="glm-5.2", effort="low", writers=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        spec.effort = "high"  # type: ignore[misc]


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
    resolved fork: one omit spelling reaches AgentSpec.effort.
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
    dispatch — the same fail-loud provider.build() gives, not a silent default."""
    with pytest.raises(ValueError):
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
    """Equivalence guard: after settings(role) collapses to settings_for_effort(
    effort_for_role(role)), the EXACT dicts test_glm_fireworks pins are unchanged —
    Fireworks MAIN {"extra_body":{"reasoning_effort":"low"}}, GATHER "none", Anthropic
    cache-only + role-invariant by VALUE (identity downgraded per Fork 2)."""
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    assert providers.FIREWORKS.settings(AgentRole.MAIN) == {"extra_body": {"reasoning_effort": "low"}}
    assert providers.FIREWORKS.settings(AgentRole.GATHER) == {"extra_body": {"reasoning_effort": "none"}}
    assert providers.ANTHROPIC.settings(AgentRole.MAIN) == _CACHE
    assert providers.ANTHROPIC.settings(AgentRole.MAIN) == providers.ANTHROPIC.settings(AgentRole.GATHER)


# ============================================================================
# build_agent_core — the single construction site
# ============================================================================

def test_build_agent_core_threads_spec_model_and_effort_to_make_model(logger):
    """build_agent_core resolves the model via make_model(spec.model, spec.effort) — the
    (name, effort) seam — and pairs the returned model + settings onto the Agent
    (observable via agent.model / agent.model_settings)."""
    sentinel = {"SENTINEL": "s"}
    fake, calls = _capture_make_model(settings=sentinel)
    spec = driver.AgentSpec(model="glm-5.2", effort="low")
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            spec, deps_type=RunDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert calls == [("glm-5.2", "low")]
    assert isinstance(agent.model, FunctionModel)
    assert agent.model_settings == sentinel


def test_build_agent_core_writers_false_registers_read_only_pair(logger):
    """spec.writers=False → build_agent_core registers ONLY the read-only pair; no file
    writers reach a read-only agent (the security-relevant default)."""
    fake, _ = _capture_make_model()
    spec = driver.AgentSpec(model="glm-5.2", effort=None, writers=False)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            spec, deps_type=RunDeps, instructions="x", logger=logger,
            agent_id="a", make_model=fake,
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_build_agent_core_writers_true_registers_write_tools(logger):
    """spec.writers=True → the full four tools incl. write_file/edit_file (MAIN's authoring
    surface). The writers bit is the one build-time permission the spec carries."""
    fake, _ = _capture_make_model()
    spec = driver.AgentSpec(model="glm-5.2", effort="low", writers=True)
    with override_allow_model_requests(False):
        agent = driver.build_agent_core(
            spec, deps_type=RunDeps, instructions="x", logger=logger,
            agent_id="main", make_model=fake,
        )
    assert list(agent._function_toolset.tools) == ["bash", "read_file", "write_file", "edit_file"]


def test_build_agent_core_propagates_make_model_error(logger):
    """make_model raising (unroutable name / missing key / bad effort) propagates —
    build_agent_core adds no defensive catch, so a config fault surfaces at the build,
    not as a half-built agent that 401s mid-run."""
    def boom(model, effort):
        raise RuntimeError("no key")
    spec = driver.AgentSpec(model="glm-5.2", effort="low")
    with pytest.raises(RuntimeError), override_allow_model_requests(False):
        driver.build_agent_core(
            spec, deps_type=RunDeps, instructions="x", logger=logger,
            agent_id="a", make_model=boom,
        )


def test_build_agent_core_extra_capabilities_default_is_immutable_empty():
    """extra_capabilities defaults to an empty tuple () — an immutable, non-shared default
    (never a mutable []), so two agents built with the default can't alias one list."""
    import inspect
    default = inspect.signature(driver.build_agent_core).parameters["extra_capabilities"].default
    assert default == ()
    assert isinstance(default, tuple)


# ============================================================================
# spec_for_role — MAIN + GATHER producers (the judge builds its spec from config)
# ============================================================================

def test_spec_for_role_main_glm_is_low_and_writers(monkeypatch):
    """spec_for_role(MAIN, "glm-5.2") → AgentSpec("glm-5.2", effort="low", writers=True):
    the passed main model, its role-default effort, and MAIN's writers opt-in."""
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    spec = driver.spec_for_role(AgentRole.MAIN, "glm-5.2")
    assert spec == driver.AgentSpec(model="glm-5.2", effort="low", writers=True)


def test_spec_for_role_gather_uses_gather_model_and_is_read_only(monkeypatch):
    """spec_for_role(GATHER, main_model) IGNORES the passed main model and uses
    gather_model() (its own cheaper model), effort "none", writers=False. Passing the
    MAIN model must NOT leak into the gather spec.
    # rejected: gather inherits the main model — gather runs its own DEFENDER_GATHER_MODEL."""
    monkeypatch.delenv("DEFENDER_GATHER_MODEL", raising=False)
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    spec = driver.spec_for_role(AgentRole.GATHER, "glm-5.2")
    assert spec.model == driver.gather_model()
    assert spec.effort == "none"
    assert spec.writers is False


def test_spec_for_role_main_on_anthropic_omits_effort(monkeypatch):
    """The production gotcha: spec_for_role(MAIN, "claude-sonnet-4-6") → effort None
    (writers=True). On the --model claude-* override path the main agent must stay
    UNCAPPED (cache-only, no anthropic_effort), exactly as today — a wrong default here
    silently caps or uncaps a live agent."""
    spec = driver.spec_for_role(AgentRole.MAIN, "claude-sonnet-4-6")
    assert spec.effort is None
    assert spec.writers is True


# ============================================================================
# MAIN / GATHER / JUDGE construction — the three callers survive the collapse
# ============================================================================

def test_build_gather_agent_is_read_only_and_cannot_self_dispatch(logger):
    """build_gather_agent (re-pointed at build_agent_core via the GATHER spec) yields the
    read-only pair ONLY — no writers, and NO 'gather' dispatch tool (the gather subagent
    must not dispatch itself)."""
    fake, _ = _capture_make_model()
    with override_allow_model_requests(False):
        agent = driver.build_gather_agent(_DEFENDER, logger, "gather:l-001", make_model=fake)
    assert list(agent._function_toolset.tools) == ["bash", "read_file"]


def test_build_agent_main_has_gather_dispatch_and_writers(monkeypatch, logger):
    """MAIN routed through build_agent_core still ends up with BOTH the authoring tools
    (writers=True) AND the layered 'gather' dispatch tool (register_gather_tool is applied
    after construction, at MAIN's call site only). Injects the (name, effort) make_model
    seam MAIN must now accept."""
    monkeypatch.delenv("DEFENDER_COMPACTION", raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)
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
