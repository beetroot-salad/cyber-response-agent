from __future__ import annotations

from types import SimpleNamespace

import pytest


from defender import run as run_entry
from defender.runtime import providers
from defender.runtime.review_roles import (
    COMPOSER_DEF,
    DEFAULT_REVIEW_MODEL,
    REVIEW_MODEL_ENV,
    SUPPORT_DEF,
    resolve_review_model,
)
from defender.tests.support.sandbox._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)


@pytest.fixture(autouse=True)
def _clear_model_env(monkeypatch):
    """Both knobs cleared, so every case below states its own environment."""
    monkeypatch.delenv(REVIEW_MODEL_ENV, raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)


REVIEW_DEFS = (SUPPORT_DEF, COMPOSER_DEF)


def test_the_investigator_s_env_var_does_not_reach_the_review(monkeypatch):
    """`DEFENDER_MODEL` is the investigator's knob."""
    monkeypatch.setenv("DEFENDER_MODEL", "glm-5.3")
    assert resolve_review_model() == DEFAULT_REVIEW_MODEL


def test_the_review_s_own_env_var_moves_it(monkeypatch):
    monkeypatch.setenv(REVIEW_MODEL_ENV, "kimi-k3")
    assert resolve_review_model() == "kimi-k3"


def test_an_explicit_override_wins_over_both(monkeypatch):
    monkeypatch.setenv(REVIEW_MODEL_ENV, "kimi-k3")
    monkeypatch.setenv("DEFENDER_MODEL", "glm-5.3")
    assert resolve_review_model("claude-sonnet-5") == "claude-sonnet-5"


def test_every_review_role_resolves_through_that_one_accessor():
    """The pin is worth nothing if a role reaches its model some other way."""
    for defn in REVIEW_DEFS:
        assert defn.model is resolve_review_model, f"{defn.role.name} owns a private accessor"
        assert defn.model() == DEFAULT_REVIEW_MODEL


def test_every_review_effort_is_legal_for_the_model_it_pins():
    for defn in REVIEW_DEFS:
        providers.provider_for(defn.model()).settings_for_effort(defn.effort)


# The signature rule


def test_the_override_reaches_an_accessor_that_takes_one():
    taker = SimpleNamespace(model=lambda explicit=None: explicit or "ambient")
    assert run_entry._role_model_name(taker, "chosen") == "chosen"


def test_the_override_reaches_a_keyword_only_accessor_by_its_name():
    """Non-empty arity is the strictly weaker property."""
    def model(*, explicit: str | None = None) -> str:
        return explicit or "ambient"

    assert run_entry._role_model_name(SimpleNamespace(model=model), "chosen") == "chosen"


def test_an_accessor_naming_no_single_override_is_left_on_its_own_model():
    def model(*, explicit: str | None = None, effort: str | None = None) -> str:
        return explicit or effort or "ambient"

    assert run_entry._role_model_name(SimpleNamespace(model=model), "chosen") == "ambient"


def test_the_override_skips_an_accessor_that_takes_none():
    fixed = SimpleNamespace(model=lambda: "fixed")
    assert run_entry._role_model_name(fixed, "chosen") == "fixed"


def test_no_override_never_calls_an_accessor_with_one():
    taker = SimpleNamespace(model=lambda explicit=None: explicit or "ambient")
    assert run_entry._role_model_name(taker, None) == "ambient"


def test_the_review_roles_are_overridable_by_that_rule():
    for defn in REVIEW_DEFS:
        assert run_entry._role_model_name(defn, "claude-sonnet-5") == "claude-sonnet-5"
