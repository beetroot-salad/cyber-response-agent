"""The shared env-coercion + clock primitives (`defender._env`, `defender._clock`).

These live at the `defender.` namespace root so runtime/, scripts/, and learning/
share one fail-loud coercion surface instead of each hand-rolling a crash-prone
`int(os.environ.get(...))` (issue #448). `FatalConfigError` is the layer-neutral
*condition*; the learning loop's StageAbort/exit-2 enrollment is pinned separately
in test_orchestrate_thresholds.py.
"""
from __future__ import annotations

import logging
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



def test_fatal_config_error_is_a_value_error():
    """Loud-by-default for any uncatching caller (e.g. runtime startup): a plain
    `ValueError` subclass, not tied to the learning-only StageAbort taxonomy."""
    assert issubclass(FatalConfigError, ValueError)



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


# ---------------------------------------------------------------------------------------
# env_choice — the LENIENT choice (#1110 second review): one rule for every setting whose bad
# value must cost the setting, never the process (`DEFENDER_DEPLOYMENT`, `DEFENDER_LOG_FORMAT`).
# `env_str(choices=)` above is the STRICT twin and is unchanged. Imported inside each test, so
# this file collects against a tree that does not have it yet.
# ---------------------------------------------------------------------------------------

_CHOICES = ("dev", "production")


def _env_choice(default: str = "production") -> tuple[str, str | None]:
    from defender import _env

    return _env.env_choice(_NAME, default, _CHOICES)


def _no_warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("raw", [None, "", "   ", "\n"], ids=["unset", "empty", "spaces", "newline"])
def test_env_choice_unset_or_empty_is_the_default_with_no_notice(monkeypatch, caplog, raw):
    """Unset, empty, or nothing but whitespace (stripped first, then judged): the default, and
    no notice — not setting a variable is not a mistake to report."""
    if raw is None:
        monkeypatch.delenv(_NAME, raising=False)
    else:
        monkeypatch.setenv(_NAME, raw)
    caplog.set_level(logging.DEBUG)
    assert _env_choice() == ("production", None)
    assert _env_choice(default="dev") == ("dev", None), "the default is not the caller's"
    assert _no_warnings(caplog) == []


@pytest.mark.parametrize(("raw", "value"), [
    ("dev", "dev"), ("production", "production"),
    (" DEV ", "dev"), ("Production\n", "production"), ("\tdEv", "dev"),
])
def test_env_choice_a_choice_is_read_stripped_and_lowercased_with_no_notice(
        monkeypatch, caplog, raw, value):
    """A choice, whatever its case and surrounding whitespace, answers the NORMALISED choice
    and no notice — whichever default the caller passed."""
    monkeypatch.setenv(_NAME, raw)
    caplog.set_level(logging.DEBUG)
    assert _env_choice() == (value, None)
    assert _env_choice(default="dev") == (value, None)
    assert _no_warnings(caplog) == []


@pytest.mark.parametrize("raw", ["staging", "development", "prod", " Yaml ", "²", "dev production"])
def test_env_choice_anything_else_is_the_default_with_a_notice_naming_it(monkeypatch, caplog, raw):
    """Anything else answers the DEFAULT — never a raise, never a guess at the nearest choice —
    WITH a notice for the caller to log, naming the variable, the raw value as it was set
    (its repr, so stray whitespace is visible), every choice, and the default it fell back to.
    `env_choice` does not log the notice itself: its callers log it (`_env.deployment` as an
    ERROR, `_log.configure_from_env` straight to its handler), once.

    The default is shown to be named, not merely present among the choices: the same bad
    value under two different defaults gives two different notices."""
    monkeypatch.setenv(_NAME, raw)
    caplog.set_level(logging.DEBUG)

    value, notice = _env_choice(default="production")
    other_value, other_notice = _env_choice(default="dev")

    assert (value, other_value) == ("production", "dev"), "a bad value did not fall back"
    assert notice is not None, f"a bad value {raw!r} gave no notice"
    assert _NAME in notice, f"the notice does not name the variable: {notice!r}"
    assert repr(raw) in notice, f"the notice does not show the raw value {raw!r}: {notice!r}"
    for choice in _CHOICES:
        assert choice in notice.replace(repr(raw), ""), (
            f"the notice does not name the choice {choice!r}: {notice!r}")
    assert other_notice is not None
    assert notice != other_notice, (
        f"the notice does not name the default it fell back to: {notice!r} == {other_notice!r}")
    assert _no_warnings(caplog) == [], "env_choice logged the notice itself"



def test_now_iso_is_utc_seconds_precision():
    """The loop's canonical clock string: UTC, seconds precision, no microseconds."""
    ts = _clock.now_iso()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", ts), ts


def test_parse_iso_utc_accepts_the_trailing_z():
    """`Z` is the form these readers meet on the wire — a store row or a seeded ticket
    written by something that is not `now_iso`. Every caller had been rewriting it by hand
    before calling `fromisoformat`, and that rewrite is the reason the reader existed three
    times over."""
    assert _clock.parse_iso_utc("2026-01-01T12:00:00Z") == _clock.parse_iso_utc(
        "2026-01-01T12:00:00+00:00")


def test_parse_iso_utc_reads_a_naive_value_as_utc_rather_than_rejecting_it():
    """The judge's recency screen rested on this. The retired closed-ticket tool asked
    "is every word of this record provably older than the case?", and the stores mint
    `datetime.now(utc)` — but a hand-written seed file may omit the offset. Treating that as
    unparseable would drop legitimate precedent over a formatting detail.

    A naive value in some other zone IS misread; the error is bounded by that zone's offset,
    which cannot approach the gap between seeded precedent and a live case."""
    naive = _clock.parse_iso_utc("2026-01-01T12:00:00")
    assert naive is not None
    assert naive.tzinfo is not None
    assert naive == _clock.parse_iso_utc("2026-01-01T12:00:00+00:00")


def test_parse_iso_utc_returns_aware_always_so_a_mixed_batch_sorts():
    """Aware-always is not tidiness — comparing a naive datetime with an aware one raises
    `TypeError`, and `visualize_data._tile_phase_boundaries` sorts whatever it parsed. A
    reader that passed naive values through would crash the phase tiling on one
    offset-less row rather than skipping it."""
    raw = ("2026-01-01T12:00:00", "2026-01-01T09:00:00Z", "2026-01-01T15:00:00+02:00")
    batch = [_clock.parse_iso_utc(s) for s in raw]
    assert all(dt is not None for dt in batch)
    # 15:00+02:00 is 13:00Z, so it sorts last — the offset is honoured, not stripped.
    assert [dt.isoformat() for dt in sorted(batch)] == [
        "2026-01-01T09:00:00+00:00",
        "2026-01-01T12:00:00+00:00",
        "2026-01-01T15:00:00+02:00",
    ]


def test_parse_iso_utc_returns_none_for_anything_that_is_not_a_timestamp():
    """Never raises — every caller treats `None` as "no usable instant" and carries on.
    A non-`str` is the case worth naming: `visualize_data`'s copy caught `TypeError` and
    `ValueError` but reached `.replace` on the raw value first, so an integer timestamp
    raised `AttributeError` straight through the guard."""
    for raw in (None, 17, b"2026-01-01T12:00:00Z", "", "not a date", {"t": 1}):
        assert _clock.parse_iso_utc(raw) is None, raw
