#!/usr/bin/env python3
"""Data-source health probe — generic baseline-rate check.

Given a callable that returns event counts for a time window, samples a few
random windows from the recent past and compares the rate against the
incident window. Returns a structured verdict the gather subagent uses to
decide whether to proceed (Haiku-cheap) or escalate (Sonnet/Opus).

This module is vendor-agnostic. For a working CLI binding, see the example
at `scripts/tools/data_source_health_wazuh_example.py` — new vendors should
copy that shape, pointing `count_fn` at their own query CLI.

Verdicts:
    normal     — incident rate within k·stdev of baseline mean
    elevated   — incident rate > mean + k·stdev (anomaly: real signal or pipeline issue)
    low        — incident rate < mean - k·stdev (data source may have stalled)
    broken     — no usable signal (baseline all zero AND incident zero, OR no
                 baseline samples succeeded, OR all count_fn calls raised)

Triggers (carried in the output for the escalating model):
    recent_above_baseline    — incident rate exceeds baseline + k·stdev
    recent_below_baseline    — incident rate below baseline - k·stdev
    baseline_all_zero        — every baseline sample succeeded but returned 0; incident also 0
    baseline_no_samples      — no baseline samples succeeded (either sampling pool too small,
                               or every sample raised); incident may still have succeeded
    count_fn_error           — every count_fn call (baseline + incident) raised
    normal                   — incident rate within baseline band
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

CountFn = Callable[[datetime, datetime], int]


@dataclass
class HealthVerdict:
    verdict: str
    trigger: str
    reporting_agent: str
    incident_window: tuple[str, str]
    incident_count: int
    incident_rate_per_hour: float
    baseline_mean_per_hour: float | None
    baseline_stdev_per_hour: float | None
    sampled_windows: list[dict] = field(default_factory=list)
    baseline_samples: list[dict] = field(default_factory=list)
    k: float = 2.0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "trigger": self.trigger,
            "reporting_agent": self.reporting_agent,
            "incident_window": {"start": self.incident_window[0], "end": self.incident_window[1]},
            "incident_count": self.incident_count,
            "incident_rate_per_hour": round(self.incident_rate_per_hour, 3),
            "baseline_mean_per_hour": (
                round(self.baseline_mean_per_hour, 3) if self.baseline_mean_per_hour is not None else None
            ),
            "baseline_stdev_per_hour": (
                round(self.baseline_stdev_per_hour, 3) if self.baseline_stdev_per_hour is not None else None
            ),
            "sampled_windows": self.sampled_windows,
            "baseline_samples": self.baseline_samples,
            "k": self.k,
            "notes": self.notes,
        }


def _hours(delta: timedelta) -> float:
    return delta.total_seconds() / 3600.0


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample_windows(
    *,
    incident_start: datetime,
    samples: int,
    sample_hours: int,
    lookback_days: int,
    exclude_recent_hours: int,
    rng: random.Random,
) -> list[tuple[datetime, datetime]]:
    """Pick up to `samples` non-overlapping windows of `sample_hours` from
    [incident_start - lookback_days, incident_start - exclude_recent_hours].

    The exclusion buffer keeps the incident itself (and any precursor events
    that are part of the same activity) out of the baseline. May return fewer
    than `samples` windows if the pool is too small to fit them non-overlapping;
    callers should check the returned length.
    """
    pool_end = incident_start - timedelta(hours=exclude_recent_hours)
    pool_start = incident_start - timedelta(days=lookback_days)
    pool_hours = _hours(pool_end - pool_start)
    if pool_hours < sample_hours:
        return []

    # Quantize candidate offsets to whole hours so non-overlap is trivial.
    max_offset_hours = int(pool_hours - sample_hours)
    if max_offset_hours <= 0:
        return [(pool_start, pool_start + timedelta(hours=sample_hours))]

    chosen: list[int] = []
    attempts = 0
    while len(chosen) < samples and attempts < samples * 20:
        offset = rng.randint(0, max_offset_hours)
        if all(abs(offset - prev) >= sample_hours for prev in chosen):
            chosen.append(offset)
        attempts += 1

    return [
        (pool_start + timedelta(hours=o), pool_start + timedelta(hours=o + sample_hours))
        for o in sorted(chosen)
    ]


def assess_health(
    count_fn: CountFn,
    incident_window: tuple[datetime, datetime],
    reporting_agent: str,
    *,
    samples: int = 5,
    sample_hours: int = 3,
    lookback_days: int = 10,
    exclude_recent_hours: int = 24,
    k: float = 2.0,
    seed: int | None = None,
) -> HealthVerdict:
    """Probe a data source for health by comparing the incident-window event
    rate to a small baseline drawn from random windows in the recent past.

    `count_fn` must accept (start, end) datetimes and return an int count of
    events from the data source for that window. The caller is responsible
    for any entity scoping (e.g., reporting-agent filter) baked into the
    underlying query.

    Returns a HealthVerdict. Never raises for individual count_fn failures —
    those are recorded in `notes` and a per-sample `error` field. If every
    sample fails, verdict is `broken` with trigger `count_fn_error`.
    """
    incident_start, incident_end = incident_window
    incident_hours = _hours(incident_end - incident_start)
    if incident_hours <= 0:
        raise ValueError(f"incident_window has non-positive duration: {incident_window}")

    rng = random.Random(seed)
    windows = _sample_windows(
        incident_start=incident_start,
        samples=samples,
        sample_hours=sample_hours,
        lookback_days=lookback_days,
        exclude_recent_hours=exclude_recent_hours,
        rng=rng,
    )

    # Record every timestamp we chose — this is what gets audited, independent
    # of whether count_fn later succeeds on it.
    sampled_windows = [{"start": _iso(ws), "end": _iso(we)} for ws, we in windows]

    notes: list[str] = []
    if len(windows) < samples:
        notes.append(
            f"sampling pool produced {len(windows)} window(s); requested {samples}"
        )

    baseline_rows: list[dict] = []
    rates: list[float] = []
    errors = 0
    for ws, we in windows:
        row = {"start": _iso(ws), "end": _iso(we)}
        try:
            count = count_fn(ws, we)
            rate = count / sample_hours
            row.update({"count": count, "rate_per_hour": round(rate, 3)})
            rates.append(rate)
        except Exception as e:  # noqa: BLE001 — count_fn is caller-supplied
            row.update({"count": None, "error": str(e)})
            errors += 1
        baseline_rows.append(row)

    try:
        incident_count = count_fn(incident_start, incident_end)
        incident_rate = incident_count / incident_hours
        incident_failed = False
    except Exception as e:  # noqa: BLE001
        incident_count = 0
        incident_rate = 0.0
        incident_failed = True
        notes.append(f"incident-window count_fn failed: {e}")

    # Every call failed (baseline AND incident): pure tooling failure.
    if windows and errors == len(windows) and incident_failed:
        return HealthVerdict(
            verdict="broken",
            trigger="count_fn_error",
            reporting_agent=reporting_agent,
            incident_window=(_iso(incident_start), _iso(incident_end)),
            incident_count=0,
            incident_rate_per_hour=0.0,
            baseline_mean_per_hour=None,
            baseline_stdev_per_hour=None,
            sampled_windows=sampled_windows,
            baseline_samples=baseline_rows,
            k=k,
            notes=notes + ["all count_fn invocations failed"],
        )

    # No usable baseline (either no windows drawn, or every sample raised).
    # Distinct from baseline_all_zero: here we have zero signal about baseline.
    if not rates:
        return HealthVerdict(
            verdict="broken",
            trigger="baseline_no_samples",
            reporting_agent=reporting_agent,
            incident_window=(_iso(incident_start), _iso(incident_end)),
            incident_count=incident_count,
            incident_rate_per_hour=incident_rate,
            baseline_mean_per_hour=None,
            baseline_stdev_per_hour=None,
            sampled_windows=sampled_windows,
            baseline_samples=baseline_rows,
            k=k,
            notes=notes + ["no baseline samples succeeded"],
        )

    mean = statistics.fmean(rates)
    stdev = statistics.pstdev(rates) if len(rates) > 1 else 0.0

    # Floor stdev at a small fraction of the mean so a degenerate
    # zero-variance baseline doesn't trigger on any deviation at all.
    effective_stdev = max(stdev, 0.1 * mean, 1e-6)
    upper = mean + k * effective_stdev
    lower = max(mean - k * effective_stdev, 0.0)

    baseline_all_zero = all(r == 0 for r in rates)

    if baseline_all_zero and incident_count == 0:
        verdict = "broken"
        trigger = "baseline_all_zero"
        notes.append(
            "baseline returned zero events across all samples and incident window is also empty"
        )
    elif baseline_all_zero and incident_count > 0:
        # Baseline looks dead but incident has events — classify as elevated
        # (the escalating model needs to decide: pipeline recovery, misconfigured
        # baseline query, or real spike) and flag the asymmetry explicitly.
        verdict = "elevated"
        trigger = "recent_above_baseline"
        notes.append(
            "baseline is all-zero but incident window has events — baseline query may be "
            "too narrow, data source may have just started reporting, or this is a real spike"
        )
    elif incident_rate > upper:
        verdict = "elevated"
        trigger = "recent_above_baseline"
    elif incident_rate < lower:
        verdict = "low"
        trigger = "recent_below_baseline"
    else:
        verdict = "normal"
        trigger = "normal"

    return HealthVerdict(
        verdict=verdict,
        trigger=trigger,
        reporting_agent=reporting_agent,
        incident_window=(_iso(incident_start), _iso(incident_end)),
        incident_count=incident_count,
        incident_rate_per_hour=incident_rate,
        baseline_mean_per_hour=mean,
        baseline_stdev_per_hour=stdev,
        sampled_windows=sampled_windows,
        baseline_samples=baseline_rows,
        k=k,
        notes=notes,
    )
