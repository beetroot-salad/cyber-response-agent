"""Tests for scripts/tools/data_source_health.py — verdict logic + sampling."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "scripts" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import data_source_health as dsh  # noqa: E402


def _window(end: datetime, hours: int) -> tuple[datetime, datetime]:
    return end - timedelta(hours=hours), end


def test_normal_when_incident_rate_matches_baseline():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    # Baseline: ~10/hr; incident: 10 events in 1h → 10/hr.
    def count_fn(start, end):
        hours = (end - start).total_seconds() / 3600
        return int(round(10 * hours))

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "normal"
    assert v.trigger == "normal"
    assert v.reporting_agent == "agent-001"
    assert v.incident_count == 10
    assert v.baseline_mean_per_hour == 10.0


def test_elevated_when_incident_far_above_baseline():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 500  # incident: huge spike
        return 6  # baseline: 6 events per 3h sample = 2/hr

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "elevated"
    assert v.trigger == "recent_above_baseline"


def test_low_when_incident_far_below_baseline():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 0  # data source stalled during incident
        return 30  # baseline: 30 events per 3h sample = 10/hr

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "low"
    assert v.trigger == "recent_below_baseline"


def test_broken_when_baseline_and_incident_both_empty():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    v = dsh.assess_health(lambda s, e: 0, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "broken"
    assert v.trigger == "baseline_empty"


def test_broken_when_count_fn_always_raises():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    def boom(start, end):
        raise RuntimeError("indexer unreachable")

    v = dsh.assess_health(boom, incident_window, "agent-001", samples=3, seed=1)
    assert v.verdict == "broken"
    assert v.trigger == "count_fn_error"
    assert any("indexer unreachable" in n for n in v.notes) or any(
        "indexer unreachable" in s.get("error", "") for s in v.baseline_samples
    )


def test_partial_baseline_failures_still_produce_verdict():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    incident_window = _window(incident_end, 1)

    calls = {"n": 0}

    def flaky(start, end):
        calls["n"] += 1
        if calls["n"] in (2, 4):
            raise RuntimeError("timeout")
        return 9  # 9 per 3h = 3/hr baseline; or 9/hr incident

    v = dsh.assess_health(flaky, incident_window, "agent-001", samples=5, seed=1)
    # Mix of successes and failures; verdict should still resolve.
    assert v.verdict in {"normal", "elevated"}
    assert v.baseline_mean_per_hour is not None


def test_sample_windows_dont_overlap_incident_buffer():
    incident_start = datetime(2026, 4, 17, 11, 0, tzinfo=timezone.utc)
    rng = __import__("random").Random(0)
    windows = dsh._sample_windows(
        incident_start=incident_start,
        samples=5,
        sample_hours=3,
        lookback_days=10,
        exclude_recent_hours=24,
        rng=rng,
    )
    cutoff = incident_start - timedelta(hours=24)
    for ws, we in windows:
        assert we <= cutoff


def test_to_dict_round_trips_via_json():
    import json as _json
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=timezone.utc)
    v = dsh.assess_health(lambda s, e: 5, _window(incident_end, 1), "agent-001", samples=3, seed=1)
    payload = _json.loads(_json.dumps(v.to_dict()))
    assert payload["reporting_agent"] == "agent-001"
    assert payload["incident_window"]["start"].endswith("Z")
    assert "verdict" in payload and "trigger" in payload
