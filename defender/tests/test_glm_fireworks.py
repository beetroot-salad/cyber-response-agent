"""Unit tests for the GLM-5.2-via-Fireworks integration (feat/glm-fireworks).

Hermetic — no API key, no network. Model construction only builds the provider
client (no request is made), so these run in the default suite. Covers the
provider seam (`build_model` / `model_provider` / aliases), the per-provider
model settings + GLM `reasoning_effort` default, the GLM price table, and
run.py's provider-keyed `FIREWORKS_API_KEY` sourcing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")
pytest.importorskip("openai")  # the Fireworks path lives behind the openai extra

_DEFENDER = Path(__file__).resolve().parents[1]
if str(_DEFENDER) not in sys.path:
    sys.path.insert(0, str(_DEFENDER))

from pydantic_ai.models.anthropic import AnthropicModel  # noqa: E402
from pydantic_ai.models.openai import OpenAIChatModel  # noqa: E402

import run  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.scripts import pricing  # noqa: E402

_GLM_ID = "accounts/fireworks/models/glm-5p2"


# --- provider classification ------------------------------------------------

@pytest.mark.parametrize(("name", "provider"), [
    ("claude-sonnet-4-6", "anthropic"),
    ("claude-haiku-4-5", "anthropic"),
    ("glm-5.2", "fireworks"),
    ("glm-5p2", "fireworks"),
    (f"fireworks:{_GLM_ID}", "fireworks"),
])
def test_model_provider_classifies_by_name(name, provider):
    assert driver.model_provider(name) == provider


# --- build_model routing ----------------------------------------------------

def test_build_model_routes_claude_to_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    assert isinstance(driver.build_model("claude-sonnet-4-6"), AnthropicModel)


@pytest.mark.parametrize("name", ["glm-5.2", "glm-5p2", f"fireworks:{_GLM_ID}"])
def test_build_model_fireworks_from_alias_or_prefix(name, monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    m = driver.build_model(name)
    assert isinstance(m, OpenAIChatModel)
    assert m.model_name == _GLM_ID              # alias + prefix both resolve to the id
    assert "api.fireworks.ai" in str(m.client.base_url)


def test_build_model_fireworks_requires_key(monkeypatch):
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FIREWORKS_API_KEY"):
        driver.build_model("glm-5.2")


# --- per-provider model settings + GLM reasoning-effort default -------------

def test_settings_for_anthropic_keeps_cache(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    m = driver.build_model("claude-sonnet-4-6")
    assert driver._settings_for(m, AgentRole.MAIN) is driver._CACHE_SETTINGS


def test_settings_for_glm_main_defaults_to_low(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.delenv("DEFENDER_GLM_REASONING_EFFORT", raising=False)
    m = driver.build_model("glm-5.2")
    assert driver._settings_for(m, AgentRole.MAIN) == {"extra_body": {"reasoning_effort": "low"}}


def test_settings_for_glm_gather_defaults_to_none(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.delenv("DEFENDER_GLM_GATHER_REASONING_EFFORT", raising=False)
    m = driver.build_model("glm-5.2")
    assert driver._settings_for(m, AgentRole.GATHER) == {"extra_body": {"reasoning_effort": "none"}}


def test_settings_for_glm_main_effort_override(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.setenv("DEFENDER_GLM_REASONING_EFFORT", "high")
    m = driver.build_model("glm-5.2")
    assert driver._settings_for(m, AgentRole.MAIN) == {"extra_body": {"reasoning_effort": "high"}}


def test_settings_for_glm_gather_effort_override(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.setenv("DEFENDER_GLM_GATHER_REASONING_EFFORT", "low")
    m = driver.build_model("glm-5.2")
    assert driver._settings_for(m, AgentRole.GATHER) == {"extra_body": {"reasoning_effort": "low"}}


def test_settings_for_glm_default_sentinel_disables_the_param(monkeypatch):
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.setenv("DEFENDER_GLM_REASONING_EFFORT", "default")
    m = driver.build_model("glm-5.2")
    assert driver._settings_for(m, AgentRole.MAIN) is None


# --- pricing ----------------------------------------------------------------

@pytest.mark.parametrize(("model", "key"), [
    (_GLM_ID, "glm-5.2"),                          # Fireworks accounts/.../ path
    ("glm-5p2", "glm-5.2"),
    ("claude-haiku-4-5", "claude-haiku-4-5"),
    ("claude-sonnet-4-6-20260101", "claude-sonnet-4-6"),  # date suffix
    ("", "claude-sonnet-4-6"),
])
def test_pricing_model_key(model, key):
    assert pricing.model_key(model) == key


def test_pricing_glm_uses_fireworks_rates():
    # 1M uncached input + 1M output + 1M cache-read at $1.40 / $4.40 / $0.14.
    cost = pricing.usage_cost("glm-5p2", {
        "input_tokens": 1_000_000,
        "output_tokens": 1_000_000,
        "cache_read_input_tokens": 1_000_000,
    })
    assert cost == pytest.approx(1.40 + 4.40 + 0.14)


# --- run.py: FIREWORKS_API_KEY sourcing -------------------------------------

def test_resolve_key_sources_the_fireworks_var(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENDER_ENV_FILE", raising=False)
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env").write_text("ANTHROPIC_API_KEY=sk-a\nFIREWORKS_API_KEY=fw-xyz\n")
    # Both roots injected so resolution is hermetic (see test_run_key.py).
    key, src = run.resolve_first_party_key(
        root=repo, main_repo_root=repo, var="FIREWORKS_API_KEY"
    )
    assert key == "fw-xyz"
    assert src == repo / ".env"
