"""PydanticAI judge migration — metered-key sourcing + engine flag (hermetic).

No model call. The judge is the first learning-loop stage to run in-process on the
metered first-party API; these pin the billing invariants and the flag that gates it.
"""
from __future__ import annotations

import os

import pytest

from defender import _first_party_key
from defender.learning.core import config


def _write_env(tmp_path, **kv):
    p = tmp_path / ".env"
    p.write_text("".join(f"{k}={v}\n" for k, v in kv.items()))
    return p


# --- source_judge_key: metered-key sourcing + the mixed-billing invariant ----

def test_source_judge_key_sonnet_sources_anthropic_and_overrides(tmp_path, monkeypatch):
    env = _write_env(tmp_path, ANTHROPIC_API_KEY="sk-ant-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    # The ambient value (a Claude Code session's subscription credential) is overridden
    # by the .env key. monkeypatch.setenv records it so teardown restores/cleans it up
    # even though source_judge_key mutates os.environ directly.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ambient-subscription")
    config.source_judge_key("claude-sonnet-4-6")
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-fromdotenv"


def test_source_judge_key_preserves_subscription_for_siblings(tmp_path, monkeypatch):
    # THE mixed-billing invariant: after sourcing the metered key into os.environ,
    # subscription_env() (what every sibling `claude -p` runs under) STILL returns a
    # dict without it, so siblings keep billing the subscription. This is the whole
    # reason mixed billing within one run is safe with zero sibling changes.
    env = _write_env(tmp_path, ANTHROPIC_API_KEY="sk-ant-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-for-cleanup")
    config.source_judge_key("claude-sonnet-4-6")
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-fromdotenv"  # judge sees it
    assert "ANTHROPIC_API_KEY" not in config.subscription_env()    # siblings do not


def test_source_judge_key_glm_sources_fireworks(tmp_path, monkeypatch):
    # The provider is derived from the model name: glm-5.2 → FIREWORKS_API_KEY (Step 2).
    env = _write_env(tmp_path, FIREWORKS_API_KEY="fw-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    config.source_judge_key("glm-5.2")
    assert os.environ["FIREWORKS_API_KEY"] == "fw-fromdotenv"


def test_source_judge_key_missing_fails_loud(monkeypatch):
    # No .env key and no ambient → FatalConfigError (→ the orchestrator's exit 2),
    # rather than a 401 mid-judge. resolve_first_party_key is faked to (None, None) so
    # the real repo .env (which does define the keys) can't satisfy it.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(  # lint-monkeypatch: ok — isolate from the real repo .env
        _first_party_key, "resolve_first_party_key", lambda **kw: (None, None)
    )
    with pytest.raises(config.FatalConfigError):
        config.source_judge_key("claude-sonnet-4-6")


def test_source_judge_key_unroutable_model_fails_loud(monkeypatch):
    # A typo'd JUDGE_MODEL / BENIGN_JUDGE_MODEL is unroutable in provider_for; it must
    # surface as a FatalConfigError (→ the orchestrator's exit 2), matching the
    # missing-key path — NOT a bare ValueError the drain would dead-letter per-run for a
    # run-independent config fault.
    with pytest.raises(config.FatalConfigError):
        config.source_judge_key("not-a-real-model")


# --- judge_engine flag -------------------------------------------------------

def test_judge_engine_default_is_claude_print(monkeypatch):
    monkeypatch.delenv("LEARNING_JUDGE_ENGINE", raising=False)
    assert config.judge_engine() == "claude_print"


def test_judge_engine_pydantic_ai(monkeypatch):
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", "pydantic_ai")
    assert config.judge_engine() == "pydantic_ai"


@pytest.mark.parametrize("bad", ["", "pydantic", "claude", "print"])
def test_judge_engine_bad_fails_loud(monkeypatch, bad):
    monkeypatch.setenv("LEARNING_JUDGE_ENGINE", bad)
    with pytest.raises(config.FatalConfigError):
        config.judge_engine()
