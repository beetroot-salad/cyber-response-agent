#!/usr/bin/env python3
"""Data-source health probe — generic baseline-rate check.

Given a callable that returns event counts for a time window, samples a few
random windows from the recent past and compares the rate against the
incident window. Returns a structured verdict the gather subagent uses to
decide whether to proceed (Haiku-cheap) or escalate (Sonnet/Opus).

The probe is vendor-agnostic. The CLI wrapper at the bottom binds it to
Wazuh by closing over wazuh_cli.query_alerts(... limit=0). Other vendors
implement their own thin wrapper, calling assess_health() with their own
count_fn.

Verdicts:
    normal     — incident rate within k·stdev of baseline mean
    elevated   — incident rate > mean + k·stdev (anomaly: real signal or pipeline issue)
    low        — incident rate < mean - k·stdev (data source may have stalled)
    broken     — all baseline samples returned 0 and incident count is 0 (no signal at all)
                 or count_fn raised on every sample

Triggers (carried in the output for the escalating model):
    recent_above_baseline
    recent_below_baseline
    baseline_empty
    count_fn_error
    normal
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
    """Pick `samples` non-overlapping windows of `sample_hours` from
    [incident_start - lookback_days, incident_start - exclude_recent_hours].

    The exclusion buffer keeps the incident itself (and any precursor events
    that are part of the same activity) out of the baseline.
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

    notes: list[str] = []

    try:
        incident_count = count_fn(incident_start, incident_end)
        incident_rate = incident_count / incident_hours
        incident_failed = False
    except Exception as e:  # noqa: BLE001
        incident_count = 0
        incident_rate = 0.0
        incident_failed = True
        notes.append(f"incident-window count_fn failed: {e}")

    if errors == len(windows) and incident_failed:
        return HealthVerdict(
            verdict="broken",
            trigger="count_fn_error",
            reporting_agent=reporting_agent,
            incident_window=(_iso(incident_start), _iso(incident_end)),
            incident_count=0,
            incident_rate_per_hour=0.0,
            baseline_mean_per_hour=None,
            baseline_stdev_per_hour=None,
            baseline_samples=baseline_rows,
            k=k,
            notes=notes + ["all count_fn invocations failed"],
        )

    if not rates:
        return HealthVerdict(
            verdict="broken",
            trigger="baseline_empty",
            reporting_agent=reporting_agent,
            incident_window=(_iso(incident_start), _iso(incident_end)),
            incident_count=incident_count,
            incident_rate_per_hour=incident_rate,
            baseline_mean_per_hour=None,
            baseline_stdev_per_hour=None,
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

    if all(r == 0 for r in rates) and incident_count == 0:
        verdict = "broken"
        trigger = "baseline_empty"
        notes.append("baseline returned zero events across all samples and incident window is also empty")
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
        baseline_samples=baseline_rows,
        k=k,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# CLI — Wazuh binding
# ---------------------------------------------------------------------------

def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _build_wazuh_count_fn(query_string: str):
    # Imported lazily so the library is usable in tests without opensearch-py.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import wazuh_cli  # type: ignore

    config = wazuh_cli.load_config()
    client = wazuh_cli.get_indexer_client(config)

    def count_fn(start: datetime, end: datetime) -> int:
        _, total = wazuh_cli.query_alerts(
            client, config, query_string, _iso(start), _iso(end), limit=0
        )
        return int(total)

    return count_fn


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Data-source health probe (Wazuh binding) — emits JSON verdict.",
    )
    p.add_argument("--query", "-q", required=True, help="Lucene query identifying the data source (entity/agent scoping included).")
    p.add_argument("--reporting-agent", required=True, help="Agent identifier whose data this probe is checking. Recorded in output for traceability.")
    p.add_argument("--incident-start", required=True, help="Incident window start (ISO 8601 UTC).")
    p.add_argument("--incident-end", required=True, help="Incident window end (ISO 8601 UTC).")
    p.add_argument("--samples", type=int, default=5, help="Number of baseline windows to sample (default: 5).")
    p.add_argument("--sample-hours", type=int, default=3, help="Length of each baseline window in hours (default: 3).")
    p.add_argument("--lookback-days", type=int, default=10, help="How far back to draw baseline samples from (default: 10).")
    p.add_argument("--exclude-recent-hours", type=int, default=24, help="Buffer between baseline pool and incident start, to avoid contamination (default: 24).")
    p.add_argument("--k", type=float, default=2.0, help="Stdev multiplier for elevated/low thresholds (default: 2.0).")
    p.add_argument("--seed", type=int, help="Optional RNG seed for reproducible sampling.")
    return p


def main() -> int:
    args = build_parser().parse_args()
    incident_window = (_parse_iso(args.incident_start), _parse_iso(args.incident_end))

    try:
        count_fn = _build_wazuh_count_fn(args.query)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(json.dumps({
            "verdict": "broken",
            "trigger": "count_fn_error",
            "reporting_agent": args.reporting_agent,
            "error": f"could not build Wazuh count_fn: {e}",
            "trace": traceback.format_exc(),
        }, indent=2))
        return 1

    verdict = assess_health(
        count_fn,
        incident_window,
        args.reporting_agent,
        samples=args.samples,
        sample_hours=args.sample_hours,
        lookback_days=args.lookback_days,
        exclude_recent_hours=args.exclude_recent_hours,
        k=args.k,
        seed=args.seed,
    )

    print(json.dumps(verdict.to_dict(), indent=2))
    return 0 if verdict.verdict == "normal" else 1


if __name__ == "__main__":
    sys.exit(main())
