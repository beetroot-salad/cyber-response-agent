#!/usr/bin/env python3
"""Binomial interval arithmetic for the calibration reporter.

33/36 reads as 0.92, but its 95% Wilson interval is [0.78, 0.97], so the reporter never
publishes a rate without an interval, and the trust threshold `N` is derived from the
required interval rather than picked.

Wilson rather than Wald: at rates near 0.9–1.0 and single-digit n, Wald runs past 1.0,
its lower bound is badly optimistic, and `k == n` gives it zero width.

Closed-form, to avoid a scipy dependency for two formulas.
"""
from __future__ import annotations

import math

# 95% two-sided; the single place the confidence level is set.
Z_95 = 1.959963984540054


def wilson_interval(k: int, n: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for `k` successes in `n` trials.

    `None` when `n == 0`: returning (0.0, 1.0) would render "never measured" as a real,
    if wide, measurement.
    """
    if n <= 0:
        return None
    if k < 0 or k > n:
        raise ValueError(f"k={k} out of range for n={n}")
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    # Clamp float drift just outside [0, 1] at the extremes.
    return (max(0.0, center - margin), min(1.0, center + margin))


def wilson_lower(k: int, n: int, z: float = Z_95) -> float | None:
    """Just the lower bound — the only end the trust policy reads."""
    interval = wilson_interval(k, n, z)
    return None if interval is None else interval[0]


def required_n(lower_bound: float, rate: float = 1.0, z: float = Z_95,
               max_n: int = 100_000) -> int | None:
    """Smallest `n` whose Wilson lower bound reaches `lower_bound` at `rate`.

    At a perfect observed rate a ≥0.90 lower bound needs n≈35; at 0.97, ≈69; at 0.95, ≈126.

    `None` when unreachable: the lower bound converges to `rate`, so a bound above the
    rate can never be met.
    """
    if not 0.0 <= rate <= 1.0:
        raise ValueError(f"rate={rate} is not a proportion")
    if rate < lower_bound:
        return None
    n = 1
    while n <= max_n:
        # Round, not floor, so a rate of 1.0 does not become n-1 successes.
        got = wilson_lower(round(rate * n), n, z)
        if got is not None and got >= lower_bound:
            return n
        n += 1
    return None
