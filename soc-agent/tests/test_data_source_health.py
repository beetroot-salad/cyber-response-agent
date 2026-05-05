"""Tests for scripts/tools/data_source_health.py — verdict logic + sampling."""

import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent / "scripts" / "tools"
sys.path.insert(0, str(TOOLS_DIR))

import data_source_health as dsh  # noqa: E402


def _window(end: datetime, hours: int) -> tuple[datetime, datetime]:
    return end - timedelta(hours=hours), end


def test_normal_when_incident_rate_matches_baseline():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
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
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 500  # incident: huge spike
        return 6  # baseline: 6 events per 3h sample = 2/hr

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "elevated"
    assert v.trigger == "recent_above_baseline"


def test_low_when_incident_far_below_baseline():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 0  # data source stalled during incident
        return 30  # baseline: 30 events per 3h sample = 10/hr

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "low"
    assert v.trigger == "recent_below_baseline"


def test_inconclusive_when_baseline_and_incident_both_empty():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    v = dsh.assess_health(lambda s, e: 0, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "inconclusive"
    assert v.trigger == "baseline_all_zero"


def test_inconclusive_when_baseline_all_zero_but_incident_has_events():
    """Sparse-source case: baseline historically silent, incident has events.
    This is the expected shape for cron / batch / on-demand sources — don't
    escalate, let the lead characterize the events directly."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 7  # incident has events
        return 0  # baseline dead

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "inconclusive"
    assert v.trigger == "baseline_all_zero"
    assert v.incident_count == 7  # raw count still recorded for the lead
    assert any("intermittent sources" in n for n in v.notes)


def test_broken_when_baseline_samples_all_raise_but_incident_succeeds():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 5  # incident succeeds
        raise RuntimeError("baseline shard down")

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=3, seed=1)
    assert v.verdict == "broken"
    assert v.trigger == "baseline_no_samples"


def test_broken_when_count_fn_always_raises():
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
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
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
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
    incident_start = datetime(2026, 4, 17, 11, 0, tzinfo=UTC)
    rng = __import__("random").Random(0)
    windows = dsh._sample_windows(
        incident_start=incident_start,
        samples=5,
        sample_duration=timedelta(hours=3),
        lookback_days=10,
        exclude_recent_hours=24,
        rng=rng,
    )
    cutoff = incident_start - timedelta(hours=24)
    for ws, we in windows:
        assert we <= cutoff


def test_inconclusive_when_baseline_mostly_zero():
    """If most baseline samples are empty, we can't establish a reference rate
    — return broken/baseline_too_sparse rather than a misleading elevated."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    calls = {"n": 0}

    def count_fn(start, end):
        # incident window: 12 events; baseline: 1 of 5 windows has events.
        if start >= incident_window[0]:
            return 12
        calls["n"] += 1
        return 6 if calls["n"] == 5 else 0

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "inconclusive"
    assert v.trigger == "baseline_too_sparse"
    assert any("too sparse" in n for n in v.notes)


def test_dense_baseline_passes_through_to_elevated_low_normal():
    """When baseline is dense enough (≥50% nonzero), the gate must not block
    the standard elevated/low/normal logic."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    calls = {"n": 0}

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 100  # incident: huge spike
        calls["n"] += 1
        # 3 of 5 baseline windows nonzero (60% — passes the gate)
        return 5 if calls["n"] in (1, 3, 5) else 0

    v = dsh.assess_health(count_fn, incident_window, "agent-001", samples=5, seed=1)
    assert v.verdict == "elevated"
    assert v.trigger == "recent_above_baseline"


def test_min_nonzero_fraction_is_configurable():
    """Caller can tune the gate. A strict 1.0 floor should reject any zero sample."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = _window(incident_end, 1)

    calls = {"n": 0}

    def count_fn(start, end):
        if start >= incident_window[0]:
            return 10
        calls["n"] += 1
        return 0 if calls["n"] == 1 else 5  # 4 of 5 nonzero (80%)

    v_default = dsh.assess_health(count_fn, incident_window, "a", samples=5, seed=1)
    assert v_default.verdict in {"normal", "elevated"}  # passes default 0.5 gate

    calls["n"] = 0
    v_strict = dsh.assess_health(
        count_fn, incident_window, "a", samples=5, seed=1, min_nonzero_fraction=1.0
    )
    assert v_strict.verdict == "inconclusive"
    assert v_strict.trigger == "baseline_too_sparse"


def test_subhour_incident_window_uses_matching_baseline_duration():
    """A 60s incident window must sample 60s baseline windows, not the prior
    hard-coded 3h — otherwise a single event normalizes to a spurious spike."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    incident_window = (incident_end - timedelta(seconds=60), incident_end)

    # count_fn returns 1 for any window of any duration.
    v = dsh.assess_health(lambda s, e: 1, incident_window, "agent-001", samples=5, seed=1)

    # Both incident and baseline have count=1 per their (matching, 60s) windows.
    # Rate per hour is 60 for both → mean equals incident → not elevated.
    assert v.incident_count == 1
    assert v.baseline_mean_per_hour == 60.0
    assert v.verdict == "normal"
    # And every recorded baseline window must be 60s long.
    for w in v.sampled_windows:
        ws = datetime.fromisoformat(w["start"].replace("Z", "+00:00"))
        we = datetime.fromisoformat(w["end"].replace("Z", "+00:00"))
        assert (we - ws) == timedelta(seconds=60)


def test_to_dict_round_trips_via_json():
    import json as _json
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)
    v = dsh.assess_health(lambda s, e: 5, _window(incident_end, 1), "agent-001", samples=3, seed=1)
    payload = _json.loads(_json.dumps(v.to_dict()))
    assert payload["reporting_agent"] == "agent-001"
    assert payload["incident_window"]["start"].endswith("Z")
    assert "verdict" in payload
    assert "trigger" in payload


def test_sampled_windows_present_for_audit():
    """Every timestamp the probe picks must appear in `sampled_windows` — this is
    what the tool-audit log captures for debugging, independent of count_fn outcome."""
    incident_end = datetime(2026, 4, 17, 12, 0, tzinfo=UTC)

    def boom(start, end):
        raise RuntimeError("down")

    v = dsh.assess_health(boom, _window(incident_end, 1), "agent-001", samples=4, seed=1)
    payload = v.to_dict()
    assert "sampled_windows" in payload
    assert len(payload["sampled_windows"]) == 4
    for w in payload["sampled_windows"]:
        assert w["start"].endswith("Z")
        assert w["end"].endswith("Z")
        assert w["start"] < w["end"]
