#!/usr/bin/env python3
"""Binomial interval arithmetic for the calibration reporter.

A point estimate is weaker than it looks: 33/36 reads as 0.92, but its 95% Wilson
interval is [0.78, 0.97] — a width of 0.19 on the number that is supposed to
certify a slice. So the reporter never publishes a rate without an interval, and
the trust threshold `N` is *derived* from the interval width the policy needs
rather than picked.

Wilson rather than Wald: at the rates that matter here (0.9–1.0) and the n we
actually have (single digits), the Wald interval runs past 1.0 and its lower
bound is badly optimistic — and a perfect observation, `k == n`, gives Wald a
width of exactly zero, which would certify a slice off four leads.

Closed-form on purpose: the repo has no scipy, and pulling one in for two
formulas would put a compiled dependency in the path of a measurement tool.
"""
from __future__ import annotations

import math

# 95% two-sided. Kept as a module constant rather than inlined so the one place
# the confidence level lives is greppable — a report that silently switched to
# 90% would move every threshold in the suite.
Z_95 = 1.959963984540054


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for `k` successes in `n` trials.

    `None` when `n == 0` — an unexercised slice has no interval, and returning
    (0.0, 1.0) would let "never measured" render as a real, if wide, measurement.
    That is the same distinction `score.py._ratio` keeps with `null`.
    """
    if n <= 0:
        return None
    if k < 0 or k > n:
        raise ValueError(f"k={k} out of range for n={n}")
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # Clamp: the algebra can drift a hair outside [0, 1] at the extremes, and a
    # reported upper bound of 1.0000000000000002 reads as a bug in the report.
    return (max(0.0, center - margin), min(1.0, center + margin))


def wilson_lower(k: int, n: int, z: float = Z_95) -> float | None:
    """Just the lower bound — the only end the trust policy reads."""
    interval = wilson_interval(k, n, z)
    return None if interval is None else interval[0]


def required_n(lower_bound: float, rate: float = 1.0, z: float = Z_95,
               max_n: int = 100_000) -> int | None:
    """Smallest `n` whose Wilson lower bound reaches `lower_bound` at `rate`.

    Turns the trust threshold into a derived number. At a *perfect* observed rate
    a ≥0.90 lower bound needs n≈35; at 0.97 it needs ≈69; at 0.95, ≈126.

    `None` when the rate cannot reach the bound at any n — the lower bound
    converges to `rate`, so asking for 0.90 at an observed 0.85 is unsatisfiable
    and must say so rather than spinning to `max_n`.
    """
    if not 0.0 <= rate <= 1.0:
        raise ValueError(f"rate={rate} is not a proportion")
    if rate < lower_bound:
        return None
    n = 1
    while n <= max_n:
        # k must be an integer count; round rather than floor so a rate of 1.0
        # does not silently become n-1 successes.
        got = wilson_lower(round(rate * n), n, z)
        if got is not None and got >= lower_bound:
            return n
        n += 1
    return None
