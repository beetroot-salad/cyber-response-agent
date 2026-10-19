"""defender._env coercion (fail-loud int/bool/str/choice) and defender._clock ISO helpers."""
from __future__ import annotations

import logging

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


@pytest.mark.parametrize("bad", ["high", "", "5o", "1.5"])
def test_env_int_raises_named_fatal_on_non_numeric(monkeypatch, bad):
    monkeypatch.setenv(_NAME, bad)
    with pytest.raises(FatalConfigError, match=rf"{_NAME} must be an integer"):
        env_int(_NAME, 7)


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


def test_parse_iso_utc_accepts_the_trailing_z():
    """`Z` is the form these readers meet on the wire — a store row or a seeded ticket written by
    something that is not `now_iso`."""
    assert _clock.parse_iso_utc("2026-01-01T12:00:00Z") == _clock.parse_iso_utc(
        "2026-01-01T12:00:00+00:00")


def test_parse_iso_utc_reads_a_naive_value_as_utc_rather_than_rejecting_it():
    """The judge's recency screen rested on this."""
    naive = _clock.parse_iso_utc("2026-01-01T12:00:00")
    assert naive is not None
    assert naive.tzinfo is not None
    assert naive == _clock.parse_iso_utc("2026-01-01T12:00:00+00:00")


def test_parse_iso_utc_returns_aware_always_so_a_mixed_batch_sorts():
    """Aware-always is not tidiness — comparing a naive datetime with an aware one raises
    `TypeError`, and `visualize_data._tile_phase_boundaries` sorts whatever it parsed."""
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
    """Never raises — every caller treats `None` as "no usable instant" and carries on."""
    for raw in (None, 17, b"2026-01-01T12:00:00Z", "", "not a date", {"t": 1}):
        assert _clock.parse_iso_utc(raw) is None, raw
