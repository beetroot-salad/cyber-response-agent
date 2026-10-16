"""Env-backed knobs in `learning/core/config.py` are read at call time, so a later setenv takes effect."""
from __future__ import annotations

import pytest

from defender.learning.core import config  # type: ignore[import-not-found]


@pytest.mark.parametrize(
    ("accessor", "var", "raw", "expected"),
    [
        ("judge_model", "JUDGE_MODEL", "kimi-k3", "kimi-k3"),
        ("author_model", "LEARNING_AUTHOR_MODEL", "deepseek-v4", "deepseek-v4"),
        ("judge_effort", "JUDGE_EFFORT", "high", "high"),
        ("author_timeout", "LEARNING_AUTHOR_TIMEOUT_SECONDS", "42", 42),
        ("author_max_attempts", "LEARNING_AUTHOR_MAX_ATTEMPTS", "10", 10),
        ("subagent_timeout", "LEARNING_SUBAGENT_TIMEOUT_SECONDS", "99", 99),
        ("repo_lock_wait_seconds", "LEARNING_REPO_LOCK_WAIT_SECONDS", "7", 7),
    ],
)
def test_accessor_sees_an_env_set_after_import(monkeypatch, accessor, var, raw, expected):
    """The behavioral guard, spanning both coercions (str + int) and all four knob
    families (stage models/efforts, timeouts, retry caps, lock waits). `config` was
    imported at collection time; the setenv lands after that and must still be seen."""
    monkeypatch.setenv(var, raw)
    assert getattr(config, accessor)() == expected


def test_accessor_returns_the_default_when_unset(monkeypatch):
    """The other half of the contract: the default is the accessor's, not a stale read of
    whatever the environment held when the module first loaded."""
    monkeypatch.delenv("LEARNING_AUTHOR_MAX_ATTEMPTS", raising=False)
    monkeypatch.delenv("LEARNING_AUTHOR_MODEL", raising=False)
    assert config.author_max_attempts() == 3
    assert config.author_model() == "glm-5.3"
