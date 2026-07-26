"""Pins for the interval arithmetic the calibration report is built on (#711).

These are not "does the formula compute" tests — they are the numbers #711's issue
body and design doc quote as the reason the suite cannot certify anything yet. If
`required_n(0.90)` stops being 35, the sizing argument in
`defender/docs/oracle-calibration.md` is silently wrong and the resolver's
threshold goes back to being a picked number rather than a derived one.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

GOLDEN_DIR = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


STATS = _load("oracle_golden_stats", GOLDEN_DIR / "stats.py")


def _rounded(k: int, n: int) -> tuple[float, float]:
    lo, hi = STATS.wilson_interval(k, n)
    return round(lo, 2), round(hi, 2)


@pytest.mark.parametrize(("k", "n", "expected"), [
    # The four cells the issue body tabulates, at lead level.
    (33, 36, (0.78, 0.97)),   # overall class agreement
    (7, 9, (0.45, 0.94)),     # non-`0` leads only
    (5, 7, (0.36, 0.92)),     # +event recall
    (1, 1, (0.21, 1.00)),     # a class resting on a single lead carries no information
    # The same measurements at UNIT level, which is what the reporter publishes.
    (4, 4, (0.51, 1.00)),
    (3, 4, (0.30, 0.95)),
])
def test_the_intervals_the_issue_quotes_reproduce(k, n, expected):
    assert _rounded(k, n) == expected


def test_a_single_perfect_observation_is_not_a_narrow_interval():
    """The failure Wald would produce here: 1/1 has zero Wald width, so a slice
    could be certified off one lead. Wilson keeps it honest at [0.21, 1.00]."""
    lo, hi = STATS.wilson_interval(1, 1)
    assert lo < 0.25 and hi == 1.0


@pytest.mark.parametrize(("rate", "expected_n"), [
    (1.00, 35),    # a PERFECT observed rate still needs 35 units for a >=0.90 bound
    (0.97, 69),
    (0.95, 127),   # the issue body's number; the design doc's 126 used a rounded z=1.96
])
def test_required_n_derives_the_resolver_threshold(rate, expected_n):
    assert STATS.required_n(0.90, rate) == expected_n


def test_required_n_is_none_when_the_rate_cannot_reach_the_bound():
    """The lower bound converges to the rate from below, so 0.90 at an observed
    0.85 is unsatisfiable at any n. Returning a huge n instead would read as
    "keep recruiting" when the honest answer is "this slice cannot qualify"."""
    assert STATS.required_n(0.90, 0.85) is None


def test_an_unexercised_slice_has_no_interval():
    """`None`, not (0.0, 1.0) — the same distinction score.py keeps with `null`,
    so aggregation cannot read "never measured" as a real but wide measurement."""
    assert STATS.wilson_interval(0, 0) is None
    assert STATS.wilson_lower(0, 0) is None


def test_zero_successes_is_a_measurement_not_an_absence():
    """0/4 is a real result (the oracle got every one wrong) and must produce an
    interval — only n == 0 is the absent case."""
    lo, hi = STATS.wilson_interval(0, 4)
    assert lo == 0.0
    assert 0.0 < hi < 1.0


def test_k_greater_than_n_is_a_bug_not_a_clamp():
    with pytest.raises(ValueError):
        STATS.wilson_interval(5, 4)
