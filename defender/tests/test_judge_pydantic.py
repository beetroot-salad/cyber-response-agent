"""In-process PydanticAI stages — metered-key sourcing + the up-front engine-prep gate.

No model call. The actor and the judge run in-process on the metered first-party API; these
pin the billing invariants (``source_first_party_key``) and the up-front key-sourcing gate
(``_prepare_engines_for``, which sources the union of each direction's actor + judge model).
"""
from __future__ import annotations

import dataclasses
import os
import types

import pytest

from defender import _first_party_key
from defender.learning.core import config
from defender.learning.core.directions import ADVERSARIAL_WIRING


def _write_env(tmp_path, **kv):
    p = tmp_path / ".env"
    p.write_text("".join(f"{k}={v}\n" for k, v in kv.items()))
    return p


# --- source_first_party_key: metered-key sourcing + the mixed-billing invariant ----

def test_source_first_party_key_sonnet_sources_anthropic_and_overrides(tmp_path, monkeypatch):
    env = _write_env(tmp_path, ANTHROPIC_API_KEY="sk-ant-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    # The ambient value (a Claude Code session's subscription credential) is overridden
    # by the .env key. monkeypatch.setenv records it so teardown restores/cleans it up
    # even though source_first_party_key mutates os.environ directly.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ambient-subscription")
    config.source_first_party_key("claude-sonnet-4-6")
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-fromdotenv"


def test_source_first_party_key_does_not_leak_to_tool_env(tmp_path, monkeypatch):
    # After sourcing the metered key into os.environ, the bash-tool subprocess env
    # (run_common.run_env) STILL strips it — a tool subprocess runs data-source shims,
    # never LLM calls, so no billable key belongs in it. This is why sourcing the key
    # in-process is safe.
    env = _write_env(tmp_path, ANTHROPIC_API_KEY="sk-ant-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-for-cleanup")
    config.source_first_party_key("claude-sonnet-4-6")
    assert os.environ["ANTHROPIC_API_KEY"] == "sk-ant-fromdotenv"  # the in-process stage sees it
    from defender.run_common import run_env
    tool_env = run_env(tmp_path / "defender", tmp_path / "run")
    assert "ANTHROPIC_API_KEY" not in tool_env  # the tool subprocess does not


def test_source_first_party_key_glm_sources_fireworks(tmp_path, monkeypatch):
    # The provider is derived from the model name: glm-5.2 → FIREWORKS_API_KEY.
    env = _write_env(tmp_path, FIREWORKS_API_KEY="fw-fromdotenv")
    monkeypatch.setenv("DEFENDER_ENV_FILE", str(env))
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    config.source_first_party_key("glm-5.2", label="actor")
    assert os.environ["FIREWORKS_API_KEY"] == "fw-fromdotenv"


def test_source_first_party_key_missing_fails_loud(monkeypatch):
    # No .env key and no ambient → FatalConfigError (→ the orchestrator's exit 2),
    # rather than a 401 mid-stage. resolve_first_party_key is faked to (None, None) so
    # the real repo .env (which does define the keys) can't satisfy it.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(  # lint-monkeypatch: ok — isolate from the real repo .env
        _first_party_key, "resolve_first_party_key", lambda **kw: (None, None)
    )
    with pytest.raises(config.FatalConfigError):
        config.source_first_party_key("claude-sonnet-4-6")


def test_source_first_party_key_unroutable_model_fails_loud(monkeypatch):
    # A typo'd model (JUDGE_MODEL / ACTOR_MODEL / …) is unroutable in provider_for; it must
    # surface as a FatalConfigError (→ the orchestrator's exit 2), matching the missing-key
    # path — NOT a bare ValueError the drain would dead-letter per-run for a run-independent
    # config fault.
    with pytest.raises(config.FatalConfigError):
        config.source_first_party_key("not-a-real-model")


# --- _prepare_engines_for: the up-front run_one key-sourcing gate ----
#
# The gate reads each direction's judge + actor model off BY_NAME; these inject a fake registry
# with EXPLICIT per-direction models so the assertions pin the gate's behavior independent of
# the import-time model constants (an env override can flip them, and monkeypatch.setenv can't
# re-capture a module constant after import).

def _fake_by_name(**specs):
    """A BY_NAME stand-in: {direction: <spec with .judge_wiring + .actor_model>} carrying the
    given per-direction (judge, actor) models. Pass each direction as
    ``name=(judge_model, actor_model)`` (real JudgeWirings, so .model/.label are present)."""
    return {
        name: types.SimpleNamespace(
            judge_wiring=dataclasses.replace(ADVERSARIAL_WIRING, model=judge, label=name),
            actor_model=actor,
        )
        for name, (judge, actor) in specs.items()
    }


def test_prepare_engines_sources_judge_and_actor_models(monkeypatch):
    # Source the metered key for the UNION of each direction's DISTINCT judge + actor model —
    # distinct so the result pins "reads every wiring's judge AND actor model" (a regression
    # dropping either would change the sourced set), not merely "dedup of identical models".
    from defender.learning.core import orchestrate

    registry = _fake_by_name(
        adversarial=("glm-5.2", "kimi-k2.6"), benign=("deepseek-v4", "gpt-oss-120b")
    )
    monkeypatch.setattr(orchestrate, "BY_NAME", registry)  # lint-monkeypatch: ok — inject a per-direction model registry
    called: list[str] = []
    monkeypatch.setattr(  # lint-monkeypatch: ok — spy the gate decision
        orchestrate, "source_first_party_key", lambda model, **kw: called.append(model)
    )
    orchestrate._prepare_engines_for(["adversarial", "benign"])
    assert sorted(called) == ["deepseek-v4", "glm-5.2", "gpt-oss-120b", "kimi-k2.6"]


def test_prepare_engines_dedups_identical_models(monkeypatch):
    # When both directions share one model across judge + actor (the shipped default: everything
    # on glm-5.2), source it ONCE.
    from defender.learning.core import orchestrate

    registry = _fake_by_name(adversarial=("glm-5.2", "glm-5.2"), benign=("glm-5.2", "glm-5.2"))
    monkeypatch.setattr(orchestrate, "BY_NAME", registry)  # lint-monkeypatch: ok — inject a per-direction model registry
    called: list[str] = []
    monkeypatch.setattr(  # lint-monkeypatch: ok — spy the gate decision
        orchestrate, "source_first_party_key", lambda model, **kw: called.append(model)
    )
    orchestrate._prepare_engines_for(["adversarial", "benign"])
    assert called == ["glm-5.2"]
