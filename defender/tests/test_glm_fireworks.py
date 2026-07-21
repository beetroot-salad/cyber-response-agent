"""Unit tests for the LLM provider abstraction + the Fireworks integration: GLM 5.2
as the MAIN default, Kimi K2.6 as the GATHER default.

Hermetic — no API key, no network. Model construction only builds the provider
client (no request is made), so these run in the default suite. Covers the provider
registry (`provider_for` routing + fail-loud, `build_for_effort`, `api_key_vars`), each
provider's `build_model`, the role→settings path (`settings_for_effort(effort_for_role(
role))`; Anthropic cache / Fireworks `reasoning_effort` incl. fail-loud on a bad value),
the role model defaults, the price table, and run.py's provider-keyed `FIREWORKS_API_KEY`
sourcing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")
pytest.importorskip("openai")

_DEFENDER = Path(__file__).resolve().parents[1]
if str(_DEFENDER) not in sys.path:
    sys.path.insert(0, str(_DEFENDER))

from pydantic_ai.models.anthropic import AnthropicModel  # noqa: E402
from pydantic_ai.models.openai import OpenAIChatModel  # noqa: E402

import run  # noqa: E402
from defender._env import FatalConfigError  # noqa: E402
from defender.runtime import driver, providers  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402
from defender.scripts import pricing  # noqa: E402

_GLM_ID = "accounts/fireworks/models/glm-5p2"
_KIMI_ID = "accounts/fireworks/models/kimi-k2p6"
_CACHE = {
    "anthropic_cache_instructions": "1h",
    "anthropic_cache_tool_definitions": "1h",
    "anthropic_cache": "5m",
}


def _role_settings(provider, role):
    """The live role→settings path after `settings(role)` was retired (#493): resolve the
    role's default effort, then map it to settings."""
    return provider.settings_for_effort(provider.effort_for_role(role))



def test_role_model_defaults(monkeypatch):
    for k in ("DEFENDER_MODEL", "DEFENDER_GATHER_MODEL"):
        monkeypatch.delenv(k, raising=False)
    assert driver.resolve_main_model() == "glm-5.2"
    assert driver.gather_model() == "kimi-k2.6"



@pytest.mark.parametrize(("name", "provider"), [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-haiku-4-5", "anthropic"),
    ("anthropic:claude-sonnet-4-6", "anthropic"),
    ("glm-5.2", "fireworks"),
    ("glm-5p2", "fireworks"),
    ("GLM-5.2", "fireworks"),
    ("kimi-k2.6", "fireworks"),
    ("kimi-k2p6", "fireworks"),
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
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    m = providers.provider_for("claude-sonnet-4-6").build_model("claude-sonnet-4-6")
    assert isinstance(m, AnthropicModel)


@pytest.mark.parametrize("name", ["glm-5.2", "glm-5p2", f"fireworks:{_GLM_ID}"])
def test_build_model_fireworks_from_alias_or_prefix(name, monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    m = providers.FIREWORKS.build_model(name)
    assert isinstance(m, OpenAIChatModel)
    assert m.model_name == _GLM_ID
    assert "api.fireworks.ai" in str(m.client.base_url)
    assert m.client.api_key == "fw-test"


def test_build_model_fireworks_requires_key(monkeypatch):
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FIREWORKS_API_KEY"):
        providers.FIREWORKS.build_model("glm-5.2")


def test_build_model_kimi_alias(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    m = providers.FIREWORKS.build_model("kimi-k2.6")
    assert isinstance(m, OpenAIChatModel)
    assert m.model_name == _KIMI_ID


def test_build_pairs_model_with_settings(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.delenv("DEFENDER_MAIN_REASONING_EFFORT", raising=False)
    built = providers.build_for_effort("glm-5.2", providers.effort_for_role("glm-5.2", AgentRole.MAIN))
    assert isinstance(built, BuiltModel)
    assert isinstance(built.model, OpenAIChatModel)
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


def test_fireworks_gather_effort_override(monkeypatch):
    monkeypatch.setenv("DEFENDER_GATHER_REASONING_EFFORT", "low")
    assert _role_settings(providers.FIREWORKS, AgentRole.GATHER) == {"extra_body": {"reasoning_effort": "low"}}


def test_fireworks_default_sentinel_disables_the_param(monkeypatch):
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", "default")
    assert _role_settings(providers.FIREWORKS, AgentRole.MAIN) is None


@pytest.mark.parametrize("bad", ["", "lo", "hgih", "off"])
def test_fireworks_bad_effort_fails_loud(monkeypatch, bad):
    monkeypatch.setenv("DEFENDER_MAIN_REASONING_EFFORT", bad)
    with pytest.raises(FatalConfigError):
        _role_settings(providers.FIREWORKS, AgentRole.MAIN)



def test_anthropic_settings_for_effort_adds_effort_to_cache():
    s = providers.ANTHROPIC.settings_for_effort("low")
    assert s == {**_CACHE, "anthropic_effort": "low"}
    assert _role_settings(providers.ANTHROPIC, AgentRole.MAIN) == _CACHE


def test_anthropic_settings_for_effort_default_is_cache_only():
    assert providers.ANTHROPIC.settings_for_effort("default") == _CACHE


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



@pytest.mark.parametrize(("model", "key"), [
    (_GLM_ID, "glm-5.2"),
    ("glm-5p2", "glm-5.2"),
    (_KIMI_ID, "kimi-k2.6"),
    ("kimi-k2p6", "kimi-k2.6"),
    ("kimi-k2p5", "kimi-k2.6"),
    ("claude-haiku-4-5", "claude-haiku-4-5"),
    ("claude-sonnet-4-6-20260101", "claude-sonnet-4-6"),
    ("", "claude-sonnet-4-6"),
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


def test_pricing_kimi_uses_fireworks_rates():
    cost = pricing.usage_cost("kimi-k2p6", {"input_tokens": 1_000_000, "output_tokens": 1_000_000})
    assert cost == pytest.approx(0.60 + 3.00)



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


def test_source_provider_keys_all_fireworks_needs_no_anthropic(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("FIREWORKS_API_KEY=fw-only\n")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    assert run._source_provider_keys("glm-5.2", "kimi-k2.6") == 0
    assert "ANTHROPIC_API_KEY" not in os.environ


def test_source_provider_keys_missing_required_key_exits_2(monkeypatch):
    monkeypatch.setattr(run, "resolve_first_party_key", lambda **kw: (None, None))  # lint-monkeypatch: ok — isolate from the real repo .env
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    assert run._source_provider_keys("glm-5.2", "kimi-k2.6") == 2


def test_source_provider_keys_unknown_model_exits_2(capsys):
    assert run._source_provider_keys("glm-5.3", "kimi-k2.6") == 2
    assert "[run.py] ERROR" in capsys.readouterr().err
