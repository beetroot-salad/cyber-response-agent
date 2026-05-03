#!/usr/bin/env python3
"""Data-source health probe — generic baseline-rate check.

Given a callable that returns event counts for a time window, samples a few
random windows from the recent past and compares the rate against the
incident window. Returns a structured verdict the gather subagent uses to
decide whether to proceed (Haiku-cheap) or escalate (Sonnet/Opus).

This module is vendor-agnostic. For a working CLI binding, see
`scripts/tools/data_source_health_wazuh.py` — new vendors should copy that
shape, pointing `count_fn` at their own query CLI.

Verdicts (drive the gather subagent's escalate-vs-proceed decision):
    normal        — incident rate within k·stdev of baseline mean. Proceed.
    elevated      — incident rate > mean + k·stdev. Real anomaly, escalate.
    low           — incident rate < mean - k·stdev. Real anomaly, escalate.
    inconclusive  — baseline uninformative (sparse / all-zero). NOT a tooling
                    failure — common for cron / batch / on-demand sources.
                    Proceed with the lead and characterize incident events directly.
    broken        — actual tooling failure (no baseline samples succeeded, or every
                    count_fn call raised). Escalate.

Triggers (carried in the output for the consuming agent):
    normal                   (verdict=normal)
    recent_above_baseline    (verdict=elevated)   — incident rate exceeds baseline + k·stdev
    recent_below_baseline    (verdict=low)        — incident rate below baseline - k·stdev
    baseline_all_zero        (verdict=inconclusive) — every baseline sample returned 0
    baseline_too_sparse      (verdict=inconclusive) — fewer than min_nonzero_fraction of samples had events
    baseline_no_samples      (verdict=broken)     — no baseline samples succeeded (pool too small or all raised)
    count_fn_error           (verdict=broken)     — every count_fn call (baseline + incident) raised
"""

from __future__ import annotations

import random
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timedelta, UTC
from collections.abc import Callable

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
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sample_windows(
    *,
    incident_start: datetime,
    samples: int,
    sample_duration: timedelta,
    lookback_days: int,
    exclude_recent_hours: int,
    rng: random.Random,
) -> list[tuple[datetime, datetime]]:
    """Pick up to `samples` non-overlapping windows of `sample_duration` from
    [incident_start - lookback_days, incident_start - exclude_recent_hours].

    The exclusion buffer keeps the incident itself (and any precursor events
    that are part of the same activity) out of the baseline. May return fewer
    than `samples` windows if the pool is too small to fit them non-overlapping;
    callers should check the returned length.

    Offsets are quantized to whole seconds so sub-hour incident windows
    (a 60s 5710 alert window, say) sample correctly.
    """
    pool_end = incident_start - timedelta(hours=exclude_recent_hours)
    pool_start = incident_start - timedelta(days=lookback_days)
    pool_seconds = (pool_end - pool_start).total_seconds()
    sample_seconds = sample_duration.total_seconds()
    if pool_seconds < sample_seconds:
        return []

    max_offset_seconds = int(pool_seconds - sample_seconds)
    if max_offset_seconds <= 0:
        return [(pool_start, pool_start + sample_duration)]

    chosen: list[int] = []
    attempts = 0
    while len(chosen) < samples and attempts < samples * 20:
        offset = rng.randint(0, max_offset_seconds)
        if all(abs(offset - prev) >= sample_seconds for prev in chosen):
            chosen.append(offset)
        attempts += 1

    return [
        (pool_start + timedelta(seconds=o), pool_start + timedelta(seconds=o) + sample_duration)
        for o in sorted(chosen)
    ]


def assess_health(
    count_fn: CountFn,
    incident_window: tuple[datetime, datetime],
    reporting_agent: str,
    *,
    samples: int = 5,
    lookback_days: int = 10,
    exclude_recent_hours: int = 24,
    k: float = 2.0,
    min_nonzero_fraction: float = 0.5,
    seed: int | None = None,
) -> HealthVerdict:
    """Probe a data source for health by comparing the incident-window event
    rate to a small baseline drawn from random windows in the recent past.

    Baseline windows are the **same duration** as the incident window — the
    "shift query" pattern documented in `leads/{lead}/definition.md`. This
    keeps rate normalization apples-to-apples and avoids spurious `elevated`
    verdicts when the incident window is much shorter than the baseline (a
    1-event 60s incident vs. a 3h baseline would otherwise normalize to
    60/hr and look like a spike).

    `count_fn` must accept (start, end) datetimes and return an int count of
    events from the data source for that window. The caller is responsible
    for any entity scoping (e.g., reporting-agent filter) baked into the
    underlying query.

    Returns a HealthVerdict. Never raises for individual count_fn failures —
    those are recorded in `notes` and a per-sample `error` field. If every
    sample fails, verdict is `broken` with trigger `count_fn_error`.
    """
    incident_start, incident_end = incident_window
    incident_duration = incident_end - incident_start
    incident_hours = _hours(incident_duration)
    if incident_hours <= 0:
        raise ValueError(f"incident_window has non-positive duration: {incident_window}")

    rng = random.Random(seed)
    windows = _sample_windows(
        incident_start=incident_start,
        samples=samples,
        sample_duration=incident_duration,
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
            rate = count / incident_hours
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

    if baseline_all_zero:
        # Baseline produced no events. This is uninformative — many real data
        # sources are intermittent (cron probes, batch jobs, on-demand flows)
        # and an all-zero historical baseline doesn't mean the pipeline is
        # broken. Don't escalate; let the caller proceed with the lead and
        # interpret the incident-window events directly.
        verdict = "inconclusive"
        trigger = "baseline_all_zero"
        if incident_count == 0:
            notes.append(
                "baseline returned zero events across all samples and incident window "
                "is also empty — data source may be quiet by design or only fire on demand"
            )
        else:
            notes.append(
                "baseline returned zero events across all samples while incident window "
                "has events — typical for intermittent sources (cron probes, batch jobs); "
                "characterize the incident events directly"
            )
    elif (sum(1 for r in rates if r > 0) / len(rates)) < min_nonzero_fraction:
        # Most baseline samples are empty — the data source fires intermittently
        # enough that we cannot establish a reference rate. Same reasoning as
        # above: not a tooling failure, just sparse history. Proceed with lead.
        nonzero = sum(1 for r in rates if r > 0)
        verdict = "inconclusive"
        trigger = "baseline_too_sparse"
        notes.append(
            f"baseline is too sparse to establish a reference rate "
            f"({nonzero} of {len(rates)} sample windows had events; "
            f"need at least {min_nonzero_fraction:.0%}). Characterize the incident events directly."
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
