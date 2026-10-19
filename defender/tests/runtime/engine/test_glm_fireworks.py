"""LLM provider registry + Fireworks integration (GLM main/gather defaults): provider routing, model/settings construction, effort floors, pricing rows, and run.py's FIREWORKS_API_KEY sourcing. Hermetic: no key, no network."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")
pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("openai") is None, reason="openai SDK not installed"
)

_DEFENDER = Path(__file__).resolve().parents[3]
if str(_DEFENDER) not in sys.path:
    sys.path.insert(0, str(_DEFENDER))

import run  # noqa: E402
from defender import agents  # noqa: E402
from defender.configuration._pricing import UnknownModel  # noqa: E402
from defender.runtime import driver, providers  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.runtime import review_roles  # noqa: E402
from defender.runtime.driver import _prompts  # noqa: E402
from defender.configuration import _pricing as pricing  # noqa: E402

_GLM_ID = "accounts/fireworks/models/glm-5p3"
_KIMI_ID = "accounts/fireworks/models/kimi-k3"
#: Decommissioned serverless on 2026-09-25 and dropped from the alias map; their price rows
#: stay so archived traces still cost out. The tests below hold both halves of that.
_GONE = ("glm-5.2", "glm-5p2", "kimi-k2.6", "kimi-k2p6")
_CACHE = {
    "anthropic_cache_instructions": "1h",
    "anthropic_cache_tool_definitions": "1h",
    "anthropic_cache": "5m",
}


def _role_settings(provider, role, name="kimi-k3"):
    """The live role→settings path after `settings(role)` was retired (#493):"""
    return provider.settings_for_effort(provider.effort_for_role(name, role))


def test_role_model_defaults(monkeypatch):
    for k in ("DEFENDER_MODEL", "DEFENDER_GATHER_MODEL"):
        monkeypatch.delenv(k, raising=False)
    assert driver.resolve_main_model() == "glm-5.3"
    assert driver.gather_model() == "glm-5.3-flash"


@pytest.mark.parametrize(("name", "provider"), [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-haiku-4-5", "anthropic"),
    ("anthropic:claude-sonnet-4-6", "anthropic"),
    ("glm-5.3", "fireworks"),
    ("glm-5p3", "fireworks"),
    ("GLM-5.3", "fireworks"),
    ("glm-5.3-flash", "fireworks"),
    ("kimi-k3", "fireworks"),
    ("deepseek-v4.1-flash", "fireworks"),
    (f"fireworks:{_GLM_ID}", "fireworks"),
])
def test_provider_routes_by_name(name, provider):
    assert providers.provider_id_for(name) == provider


def test_provider_for_unknown_name_fails_loud():
    with pytest.raises(ValueError, match="unknown model"):
        providers.provider_for("gpt-4o")


def test_api_key_vars_covers_both_providers():
    assert providers.api_key_vars() == {"ANTHROPIC_API_KEY", "FIREWORKS_API_KEY"}


def test_build_model_routes_claude_to_anthropic(monkeypatch):
    from pydantic_ai.models.anthropic import AnthropicModel

    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    m = providers.provider_for("claude-sonnet-4-6").build_model("claude-sonnet-4-6")
    assert isinstance(m, AnthropicModel)


@pytest.mark.parametrize("name", ["glm-5.3", "glm-5p3", f"fireworks:{_GLM_ID}"])
def test_build_model_fireworks_from_alias_or_prefix(name, monkeypatch):
    from pydantic_ai.models.openai import OpenAIChatModel

    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    m = providers.FIREWORKS.build_model(name)
    assert isinstance(m, OpenAIChatModel)
    assert m.model_name == _GLM_ID
    assert "api.fireworks.ai" in str(m.client.base_url)
    assert m.client.api_key == "fw-test"


def test_build_model_fireworks_requires_key(monkeypatch):
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FIREWORKS_API_KEY"):
        providers.FIREWORKS.build_model("glm-5.3")


def test_build_pairs_model_with_settings(monkeypatch):
    from pydantic_ai.models.openai import OpenAIChatModel

    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    built = providers.build_for_effort("glm-5.3", providers.effort_for_role("glm-5.3", AgentRole.MAIN))
    assert isinstance(built, BuiltModel)
    # #1243 P1: the shared builder hands every caller its model WRAPPED in the provider retrier
    # (a wrapper model); the provider's own model is the one it wraps.
    assert isinstance(getattr(built.model, "wrapped", None), OpenAIChatModel), (
        f"build_for_effort handed out {built.model!r}, not the retrier over the Fireworks model")
    assert built.settings == {"extra_body": {"reasoning_effort": "low"}}


def test_anthropic_settings_are_the_cache_and_role_invariant():
    s_main = _role_settings(providers.ANTHROPIC, AgentRole.MAIN)
    assert s_main == _CACHE
    assert _role_settings(providers.ANTHROPIC, AgentRole.GATHER) == s_main


def test_fireworks_main_defaults_to_low(monkeypatch):
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    assert _role_settings(providers.FIREWORKS, AgentRole.MAIN) == {"extra_body": {"reasoning_effort": "low"}}


def test_fireworks_gather_defaults_to_none(monkeypatch):
    monkeypatch.delenv("DEFENDER_GATHER_REASONING_EFFORT", raising=False)
    assert _role_settings(providers.FIREWORKS, AgentRole.GATHER) == {"extra_body": {"reasoning_effort": "none"}}


def test_fireworks_main_effort_override(monkeypatch):
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "high")
    assert _role_settings(providers.FIREWORKS, AgentRole.MAIN) == {"extra_body": {"reasoning_effort": "high"}}


def test_fireworks_default_sentinel_disables_the_param(monkeypatch):
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "default")
    assert _role_settings(providers.FIREWORKS, AgentRole.MAIN) is None


def test_anthropic_settings_for_effort_adds_effort_to_cache():
    s = providers.ANTHROPIC.settings_for_effort("low")
    assert s == {**_CACHE, "anthropic_effort": "low"}
    assert _role_settings(providers.ANTHROPIC, AgentRole.MAIN) == _CACHE


@pytest.mark.parametrize("bad", ["", "lo", "none", "off"])
def test_anthropic_settings_for_effort_bad_fails_loud(bad):
    with pytest.raises(ValueError, match="unsupported Anthropic effort"):
        providers.ANTHROPIC.settings_for_effort(bad)


def test_fireworks_settings_for_effort_maps_reasoning_effort():
    assert providers.FIREWORKS.settings_for_effort("medium") == {
        "extra_body": {"reasoning_effort": "medium"}
    }
    assert providers.FIREWORKS.settings_for_effort("default") is None


@pytest.mark.parametrize("bad", ["", "lo", "xhigh"])
def test_fireworks_settings_for_effort_bad_fails_loud(bad):
    with pytest.raises(ValueError, match="unsupported reasoning_effort"):
        providers.FIREWORKS.settings_for_effort(bad)


def test_build_for_effort_pairs_model_with_effort_settings(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    built = providers.build_for_effort("claude-sonnet-4-6", "low")
    assert built.settings == {**_CACHE, "anthropic_effort": "low"}


def test_cache_affinity_sets_the_fireworks_prompt_cache_key():
    """Fireworks caching is automatic; what the key buys is REPLICA affinity, and pydantic-ai
    spells it `openai_prompt_cache_key` (forwarded as `prompt_cache_key`)."""
    assert providers.cache_affinity("kimi-k3", None, "ablation") == {
        "openai_prompt_cache_key": "ablation"
    }


def test_cache_affinity_preserves_the_effort_setting_it_merges_into():
    """The key CREATES settings where there were none and MERGES where there were."""
    merged = providers.cache_affinity(
        "glm-5.3", providers.FIREWORKS.settings_for_effort("low"), "sess-7:main"
    )
    assert merged == {
        "extra_body": {"reasoning_effort": "low"},
        "openai_prompt_cache_key": "sess-7:main",
    }


@pytest.mark.parametrize(("model", "key"), [
    (_GLM_ID, "glm-5.3"),
    ("glm-5p3", "glm-5.3"),
    (_KIMI_ID, "kimi-k3"),
    ("kimi-k3", "kimi-k3"),
    ("accounts/fireworks/models/deepseek-v4p1-flash", "deepseek-v4.1-flash"),
    ("accounts/fireworks/models/glm-5p2", "glm-5.2"),
    ("kimi-k2p6", "kimi-k2.6"),
    ("claude-haiku-4-5", "claude-haiku-4-5"),
    ("claude-sonnet-4-6-20260101", "claude-sonnet-4-6"),
    ("", "claude-sonnet-4-6"),
    ("glm-5.3", "glm-5.3"),
    (f"fireworks:{_GLM_ID}", "glm-5.3"),
    ("glm-5.3-flash", "glm-5.3-flash"),
    ("glm-5p3-flash", "glm-5.3-flash"),
    ("accounts/fireworks/models/glm-5p3-flash", "glm-5.3-flash"),
])
def test_pricing_model_key(model, key):
    assert pricing.model_key(model) == key


def test_pricing_glm_uses_fireworks_rates():
    cost = pricing.usage_cost("glm-5p2", {
        "input_tokens": 1_000_000,
        "output_tokens": 1_000_000,
        "cache_read_input_tokens": 1_000_000,
    })
    assert cost == pytest.approx(1.40 + 4.40 + 0.14)


def test_fireworks_cached_input_is_discounted_against_its_own_input():
    for key in ("glm-5.2", "kimi-k2.6", "kimi-k3", "glm-5.3", "glm-5.3-flash", "deepseek-v4.1-flash"):
        row = pricing.PRICING[key]
        assert row["cache_r"] < row["in"], key
        assert row["cache_w"] == row["in"], key


def test_resolve_key_sources_the_fireworks_var(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ENV_FILE", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("ANTHROPIC_API_KEY=sk-a\nFIREWORKS_API_KEY=fw-xyz\n")
    key, src = run.resolve_first_party_key(
        root=repo, main_repo_root=repo, var="FIREWORKS_API_KEY"
    )
    assert key == "fw-xyz"
    assert src == repo / ".env"


def _registry(main_model: str, gather_model: str) -> dict:
    """A stand-in role registry for the startup preflight."""
    return {
        role: SimpleNamespace(role=role, model=(lambda m=name: m))
        for role, name in (
            (AgentRole.MAIN, main_model), (AgentRole.GATHER, gather_model),
        )
    }


def test_preflight_all_fireworks_needs_no_anthropic(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("FIREWORKS_API_KEY=fw-only\n")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    monkeypatch.setattr(agents, "AGENTS", _registry("glm-5.3", "glm-5.3-flash"))  # lint-monkeypatch: ok — the preflight's role registry is its input, and it imports AGENTS at call time
    assert run.preflight_role_models() == 0
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_preflight_missing_required_key_exits_2(monkeypatch):
    monkeypatch.setattr(run, "resolve_first_party_key", lambda **kw: (None, None))  # lint-monkeypatch: ok — isolate from the real repo .env
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    monkeypatch.setattr(agents, "AGENTS", _registry("glm-5.3", "glm-5.3-flash"))  # lint-monkeypatch: ok — the preflight's role registry is its input, and it imports AGENTS at call time
    assert run.preflight_role_models() == 2


# --- #1023: GLM 5.3 ---------------------------------------------------------

def _own_row_key(model: str) -> str:
    """The row name a model spells for itself: `kimi-k2p6` -> `kimi-k2.6`. Compared against
    `model_key`, this is what separates a row a model OWNS from a neighbour's row it merely
    falls through to."""
    import re
    bare = model.split(":", 1)[-1].rsplit("/", 1)[-1]
    return re.sub(r"(?<=\d)p(?=\d)", ".", bare)


@pytest.mark.parametrize("model", [
    _prompts.DEFAULT_MODEL,
    _prompts.DEFAULT_GATHER_MODEL,
    review_roles.DEFAULT_REVIEW_MODEL,
])
def test_every_shipped_default_model_owns_its_pricing_row(model):
    """A shipped default that falls through to a NEIGHBOUR's row costs every run out at the wrong rate, and the run still looks priced."""
    assert pricing.model_key(model) == _own_row_key(model)
    assert _own_row_key(model) in pricing.PRICING


# --- #1023 ask 3: reasoning effort is a MODEL capability, not a provider preference ------

def test_gather_effort_is_floored_for_a_thinking_only_model():
    """`gather_effort="none"` is the PROVIDER saying "gather wants the cheapest thinking on offer"."""
    assert providers.effort_for_role("glm-5.3", AgentRole.GATHER) == "low"
    assert providers.effort_for_role("glm-5p3", AgentRole.GATHER) == "low"
    assert providers.effort_for_role(f"fireworks:{_GLM_ID}", AgentRole.GATHER) == "low"


def test_a_model_that_accepts_none_still_gets_none():
    assert providers.effort_for_role("kimi-k3", AgentRole.GATHER) == "none"
    assert providers.effort_for_role("deepseek-v4.1-flash", AgentRole.GATHER) == "none"


@pytest.mark.parametrize("name", _GONE)
def test_decommissioned_aliases_are_refused_at_routing(name):
    """A run that still names `glm-5.2` or `kimi-k2.6` fails at `provider_for`, with the alias list in the message, rather than at its first dispatch with the provider's 404."""
    with pytest.raises(ValueError, match="unknown model"):
        providers.provider_for(name)


# --- the key is an EQUALITY, not a containment signal ---------------------------------

@pytest.mark.parametrize("model", [
    "kimi-k2p5",            # never shipped; the old `"kimi" in m` branch billed it as K2.6
    "glm-5p4",              # the next GLM, which `"glm" in m` would have billed as 5.2
    "glm",                  # the bare family name names no model and no price
    "accounts/fireworks/models/nope",
    "fireworks:accounts/fireworks/models/nope",
    "gpt-4o",               # the old catch-all answered Sonnet's rate for this
])
def test_a_model_no_row_claims_is_refused_not_absorbed(model):
    """Every silent fallback this table had cost a real run its real number."""
    with pytest.raises(UnknownModel):
        pricing.model_key(model)


def test_a_longer_name_does_not_absorb_a_shorter_row():
    assert pricing.model_key("glm-5p3-flash") == "glm-5.3-flash"
    assert pricing.model_key("glm-5p3") == "glm-5.3"
    assert pricing.PRICING["glm-5.3-flash"]["in"] != pricing.PRICING["glm-5.3"]["in"]


def test_an_unpriced_model_costs_zero_rather_than_a_neighbours_rate():
    """`usage_cost` runs per-response inside a live run and over every archived trace, so it cannot raise — a finished investigation must not lose its trace over a number nobody is billed on."""
    usage = {"input_tokens": 1_000_000, "output_tokens": 1_000_000}
    assert pricing.usage_cost("fireworks:accounts/fireworks/models/nope", usage) == 0.0
    assert pricing.usage_cost("claude-sonnet-4-6", usage) == pytest.approx(3.00 + 15.00)
