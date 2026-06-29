"""The shared env-coercion + clock primitives (`defender._env`, `defender._clock`).

These live at the `defender.` namespace root so runtime/, scripts/, and learning/
share one fail-loud coercion surface instead of each hand-rolling a crash-prone
`int(os.environ.get(...))` (issue #448). `FatalConfigError` is the layer-neutral
*condition*; the learning loop's StageAbort/exit-2 enrollment is pinned separately
in test_orchestrate_thresholds.py.
"""
from __future__ import annotations

import re

import pytest

from defender import _clock  # type: ignore[import-not-found]
from defender._env import (  # type: ignore[import-not-found]
    FatalConfigError,
    env_bool,
    env_int,
    env_str,
)

_NAME = "DEFENDER_TEST_KNOB"


# --- FatalConfigError surface ------------------------------------------------

def test_fatal_config_error_is_a_value_error():
    """Loud-by-default for any uncatching caller (e.g. runtime startup): a plain
    `ValueError` subclass, not tied to the learning-only StageAbort taxonomy."""
    assert issubclass(FatalConfigError, ValueError)


# --- env_int -----------------------------------------------------------------

def test_env_int_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv(_NAME, raising=False)
    assert env_int(_NAME, 7) == 7


def test_env_int_parses_override(monkeypatch):
    monkeypatch.setenv(_NAME, "12")
    assert env_int(_NAME, 7) == 12


@pytest.mark.parametrize("bad", ["high", "", "5o", "1.5"])
def test_env_int_raises_named_fatal_on_non_numeric(monkeypatch, bad):
    monkeypatch.setenv(_NAME, bad)
    with pytest.raises(FatalConfigError, match=rf"{_NAME} must be an integer"):
        env_int(_NAME, 7)


# --- env_bool ----------------------------------------------------------------

def test_env_bool_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv(_NAME, raising=False)
    assert env_bool(_NAME, True) is True
    assert env_bool(_NAME, False) is False


@pytest.mark.parametrize("tok", ["1", "on", "true", "yes", "TRUE", " On "])
def test_env_bool_true_tokens(monkeypatch, tok):
    monkeypatch.setenv(_NAME, tok)
    assert env_bool(_NAME, False) is True


@pytest.mark.parametrize("tok", ["", "0", "off", "false", "no", "NO"])
def test_env_bool_false_tokens(monkeypatch, tok):
    """The empty string counts as false, so `NAME=` and an unset NAME behave alike —
    preserving the prior hand-rolled `os.environ.get(NAME, "")` behavior."""
    monkeypatch.setenv(_NAME, tok)
    assert env_bool(_NAME, True) is False


@pytest.mark.parametrize("bad", ["maybe", "2", "disabled"])
def test_env_bool_raises_on_unrecognized_token(monkeypatch, bad):
    """The fail-loud upgrade: an unrecognized value is an operator typo we surface,
    not silently coerce to False (the old behavior)."""
    monkeypatch.setenv(_NAME, bad)
    with pytest.raises(FatalConfigError, match=rf"{_NAME} must be a boolean"):
        env_bool(_NAME, False)


# --- env_str -----------------------------------------------------------------

def test_env_str_returns_default_when_unset(monkeypatch):
    monkeypatch.delenv(_NAME, raising=False)
    assert env_str(_NAME, "human_review") == "human_review"


def test_env_str_returns_override(monkeypatch):
    monkeypatch.setenv(_NAME, "auto_on_green")
    assert env_str(_NAME, "human_review") == "auto_on_green"


def test_env_str_accepts_value_in_choices(monkeypatch):
    monkeypatch.setenv(_NAME, "auto_on_green")
    assert env_str(_NAME, "human_review", choices=("auto_on_green", "human_review")) == "auto_on_green"


def test_env_str_raises_on_value_outside_choices(monkeypatch):
    monkeypatch.setenv(_NAME, "bogus")
    with pytest.raises(FatalConfigError, match=rf"{_NAME} must be one of"):
        env_str(_NAME, "human_review", choices=("auto_on_green", "human_review"))


def test_env_str_validates_the_default_against_choices(monkeypatch):
    """An out-of-set *default* is a programming error and fails the same way — the
    validation guards the value actually returned, override or not."""
    monkeypatch.delenv(_NAME, raising=False)
    with pytest.raises(FatalConfigError, match="must be one of"):
        env_str(_NAME, "typo", choices=("a", "b"))


# --- _clock.now_iso ----------------------------------------------------------

def test_now_iso_is_utc_seconds_precision():
    """The loop's canonical clock string: UTC, seconds precision, no microseconds."""
    ts = _clock.now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", ts), ts
