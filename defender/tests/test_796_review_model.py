"""#796 — the review's own model knob, and the arity rule that decides who gets `--model`.

The review roles run on a model pinned APART from the investigator's, for stability rather
than for per-verdict quality (see `review_roles.DEFAULT_REVIEW_MODEL`). Two ways that pin can
be silently undone, and both are asserted here: the resolver reading the investigator's env
var, and the operator's override never reaching the accessor that can take it.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from defender import run as run_entry
from defender.runtime import providers
from defender.runtime.review_roles import (
    COMPOSER_DEF,
    DEFAULT_REVIEW_MODEL,
    DISCRIMINATION_DEF,
    REVIEW_MODEL_ENV,
    SUPPORT_DEF,
    resolve_review_model,
)
from defender.tests._spec791 import (  # noqa: F401 — session-scoped autouse guard
    worktree_package_guard,
)

REVIEW_DEFS = (DISCRIMINATION_DEF, SUPPORT_DEF, COMPOSER_DEF)


@pytest.fixture(autouse=True)
def _clear_model_env(monkeypatch):
    """Both knobs cleared, so every case below states its own environment."""
    monkeypatch.delenv(REVIEW_MODEL_ENV, raising=False)
    monkeypatch.delenv("DEFENDER_MODEL", raising=False)


def test_the_review_default_is_the_review_s_own_and_not_the_investigator_s():
    assert resolve_review_model() == DEFAULT_REVIEW_MODEL
    assert resolve_review_model(None) == DEFAULT_REVIEW_MODEL


def test_the_investigator_s_env_var_does_not_reach_the_review(monkeypatch):
    """`DEFENDER_MODEL` is the investigator's knob. A review that read it would un-pin its
    default on every run that set one — including every hermetic replay, which sets it
    precisely to keep its two fakes distinguishable, so the un-pinning would be invisible
    exactly where a run is cheapest to get wrong."""
    monkeypatch.setenv("DEFENDER_MODEL", "glm-5.2")
    assert resolve_review_model() == DEFAULT_REVIEW_MODEL


def test_the_review_s_own_env_var_moves_it(monkeypatch):
    monkeypatch.setenv(REVIEW_MODEL_ENV, "kimi-k2.6")
    assert resolve_review_model() == "kimi-k2.6"


def test_an_explicit_override_wins_over_both(monkeypatch):
    monkeypatch.setenv(REVIEW_MODEL_ENV, "kimi-k2.6")
    monkeypatch.setenv("DEFENDER_MODEL", "glm-5.2")
    assert resolve_review_model("claude-sonnet-5") == "claude-sonnet-5"


def test_every_review_role_resolves_through_that_one_accessor():
    """The pin is worth nothing if a role reaches its model some other way."""
    for defn in REVIEW_DEFS:
        assert defn.model is resolve_review_model, f"{defn.role.name} owns a private accessor"
        assert defn.model() == DEFAULT_REVIEW_MODEL


def test_the_effort_split_is_lenses_below_composer():
    """A lens reconstructs what a projection supports; the composer weighs the readings
    against the investigation's own account and decides whether a confident close survives."""
    assert DISCRIMINATION_DEF.effort == SUPPORT_DEF.effort, (
        "the lenses must share an effort — the ablation reading is only interpretable "
        "against a support reading produced at the same one"
    )
    assert COMPOSER_DEF.effort == "high"
    assert DISCRIMINATION_DEF.effort == "medium"


def test_every_review_effort_is_legal_for_the_model_it_pins():
    """`settings_for_effort` validates against the tuple of the provider the MODEL NAME
    resolves to, not the role — so an effort and a default model chosen apart can be
    individually reasonable and jointly raise at build time, on a live run only."""
    for defn in REVIEW_DEFS:
        providers.provider_for(defn.model()).settings_for_effort(defn.effort)


# ---------------------------------------------------------------------------------------
# The arity rule
# ---------------------------------------------------------------------------------------


def test_the_override_reaches_an_accessor_that_takes_one():
    taker = SimpleNamespace(model=lambda explicit=None: explicit or "ambient")
    assert run_entry._role_model_name(taker, "chosen") == "chosen"


def test_the_override_skips_an_accessor_that_takes_none():
    """An already-resolved accessor — the bundle builder's `lambda: name`, `gather_model`,
    the learning stages' own knobs — must not be handed the override: it cannot take it, and
    calling it with one is a TypeError on a credentialed run."""
    fixed = SimpleNamespace(model=lambda: "fixed")
    assert run_entry._role_model_name(fixed, "chosen") == "fixed"


def test_no_override_never_calls_an_accessor_with_one():
    taker = SimpleNamespace(model=lambda explicit=None: explicit or "ambient")
    assert run_entry._role_model_name(taker, None) == "ambient"


def test_the_review_roles_are_overridable_by_that_rule():
    """The property the retired hand-list of accessors was maintained by hand to state. It is
    read off arity now, so a role cannot be overridable and unlisted at the same time."""
    for defn in REVIEW_DEFS:
        assert run_entry._role_model_name(defn, "claude-sonnet-5") == "claude-sonnet-5"
