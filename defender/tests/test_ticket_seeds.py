"""Unit tests for the benign seed sampler (#317 read path).

Pure policy layer — the store read (`_list_closed`) is monkeypatched, so no
subprocess/network. These tests pin the eligibility filter (benign + survived +
window + not-self), the uniform draw, and cold-start behaviour.
"""
from __future__ import annotations

from datetime import datetime, timedelta, UTC

import pytest

from defender.learning import ticket_seeds
from defender.scripts.case_history import case_ticket


NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=UTC)
ALERT = {"rule": {"id": "5710", "description": "sshd brute force"}}


def _ticket(key, *, disposition="benign", outcome="caught",
            event_time=NOW - timedelta(days=10), reason="nightly vuln scan"):
    """A store ticket as `list-tickets --raw` would return it. The window keys on the
    `evt:` label (alert event time), not the server-set `created`."""
    comments = []
    if outcome is not None:
        comments = [{"author": "learning",
                     "body": case_ticket.enrichment_to_comment(outcome)["body"]}]
    iso = event_time.isoformat() if hasattr(event_time, "isoformat") else event_time
    return {"key": key, "resolution": f"{disposition} — {reason}",
            "created": NOW.isoformat(), "labels": ["sig:5710", f"evt:{iso}"],
            "comments": comments}


@pytest.fixture
def stub_store(monkeypatch):
    def _set(tickets):
        monkeypatch.setattr(ticket_seeds, "_list_closed", lambda label: tickets)
    return _set


def _sample(self_id="self", run_id="run-abc"):
    return ticket_seeds.sample_seeds(ALERT, self_id, run_id, now=NOW)


def test_keeps_only_benign_survived_in_window(stub_store):
    stub_store([
        _ticket("ok1"),
        _ticket("ok2", outcome="skip-passthrough"),
        _ticket("self"),                                   # excluded: self
        _ticket("mal", disposition="malicious"),           # excluded: disposition
        _ticket("noflag", outcome=None),                   # excluded: no flag
        _ticket("survived", outcome="survived"),           # excluded: flag=false
        _ticket("recent", event_time=NOW - timedelta(hours=1)),   # excluded: <24h
        _ticket("old", event_time=NOW - timedelta(days=120)),     # excluded: >90d
        _ticket("badts", event_time="not-a-date"),            # dropped: bad timestamp
    ])
    assert sorted(s.case_id for s in _sample()) == ["ok1", "ok2"]


def test_window_boundaries_inclusive(stub_store):
    stub_store([
        _ticket("edge_recent", event_time=NOW - timedelta(hours=24)),  # exactly -24h: in
        _ticket("edge_old", event_time=NOW - timedelta(days=90)),      # exactly -90d: in
        _ticket("just_too_recent", event_time=NOW - timedelta(hours=23, minutes=59)),
        _ticket("just_too_old", event_time=NOW - timedelta(days=90, seconds=1)),
    ])
    assert sorted(s.case_id for s in _sample()) == ["edge_old", "edge_recent"]


def test_bad_timestamp_drops_one_not_pool(stub_store):
    stub_store([_ticket("good"), _ticket("bad", event_time="garbage")])
    assert [s.case_id for s in _sample()] == ["good"]


def test_self_excluded_by_key(stub_store):
    stub_store([_ticket("self"), _ticket("other")])
    assert [s.case_id for s in _sample(self_id="self")] == ["other"]


def test_cold_start_empty_pool(stub_store):
    stub_store([])
    assert _sample() == []


def test_whole_pool_when_below_count(stub_store):
    stub_store([_ticket("a"), _ticket("b")])  # pool of 2, count is 3-5
    assert sorted(s.case_id for s in _sample()) == ["a", "b"]


def test_draw_is_bounded_and_deterministic(stub_store):
    stub_store([_ticket(f"t{i}") for i in range(20)])
    first = [s.case_id for s in _sample(run_id="run-xyz")]
    assert ticket_seeds.SEED_COUNT_MIN <= len(first) <= ticket_seeds.SEED_COUNT_MAX
    # reproducible per run id, varies across run ids
    assert first == [s.case_id for s in _sample(run_id="run-xyz")]
    other = [s.case_id for s in _sample(run_id="run-different")]
    assert (first != other) or (len(first) != len(other))


def test_format_seeds_one_line_each():
    seeds = [ticket_seeds.Seed("c1", "benign", "scan"),
             ticket_seeds.Seed("c2", "benign", "deploy")]
    out = ticket_seeds.format_seeds(seeds)
    assert out.splitlines() == ["- c1: benign — scan", "- c2: benign — deploy"]


def test_reason_not_truncated():
    # The reason is the analyst's actual justification — the actor's grounding — so
    # it is carried in full (only internal whitespace is collapsed, never cut).
    long = "x " * 500
    seed = ticket_seeds._to_seed(_ticket("c", reason=long))
    assert seed.reason == ("x " * 500).strip()
    assert "…" not in seed.reason


def test_multiline_reason_collapsed_to_one_line(stub_store):
    # A multi-line close reason (report.md body wraps) must not forge extra menu
    # lines: _to_seed collapses internal whitespace so format_seeds stays 1:1.
    seed = ticket_seeds._to_seed(_ticket("c", reason="patch window\napproved by ops"))
    assert "\n" not in seed.reason
    assert seed.reason == "patch window approved by ops"
    stub_store([_ticket("c", reason="line one\n\nline two")])
    menu = ticket_seeds.format_seeds(_sample())
    assert len(menu.splitlines()) == 1


def test_draw_is_order_independent(stub_store, monkeypatch):
    # Same run_id must draw the same menu regardless of the store's list order
    # (random.sample is order-sensitive; sample_seeds sorts by key first).
    pool = [_ticket(f"t{i}") for i in range(20)]
    stub_store(pool)
    first = [s.case_id for s in _sample(run_id="run-xyz")]
    monkeypatch.setattr(ticket_seeds, "_list_closed", lambda label: list(reversed(pool)))
    assert [s.case_id for s in _sample(run_id="run-xyz")] == first


def test_window_anchors_on_alert_event_time_not_wallclock(stub_store, monkeypatch):
    # With no `now` override, the window anchors on the CURRENT alert's event time,
    # not wall-clock now: a replayed alert from months ago must still find cases that
    # are in-window relative to *its* date.
    replay_alert = {"rule": {"id": "5710"}, "timestamp": "2026-01-15T00:00:00+00:00"}
    anchor = datetime(2026, 1, 15, tzinfo=UTC)
    stub_store([
        _ticket("in_window", event_time=anchor - timedelta(days=10)),   # 10d before alert
        _ticket("after_alert", event_time=anchor + timedelta(days=5)),  # post-dates alert: out
    ])
    seeds = ticket_seeds.sample_seeds(replay_alert, "self", "run-abc")  # no now=
    assert [s.case_id for s in seeds] == ["in_window"]


def test_non_fatal_when_signature_label_raises(monkeypatch):
    # The module promises "non-fatal by construction": a raising mapping/accessor
    # degrades to an empty pool, never escaping into the benign actor leg.
    def boom(_alert):
        raise case_ticket.CaseTicketError("mapping.yaml missing")

    monkeypatch.setattr(case_ticket, "signature_label", boom)
    assert ticket_seeds.sample_seeds(ALERT, "self", "run-abc", now=NOW) == []
