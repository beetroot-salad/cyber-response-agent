"""Unit tests for the benign seed sampler (#317 read path).

Pure policy layer — the store read (`_list_closed`) is monkeypatched, so no
subprocess/network. These tests pin the eligibility filter (benign + survived +
window + not-self), the uniform draw, and cold-start behaviour.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from defender.learning import ticket_seeds
from defender.scripts.case_history import case_ticket


NOW = datetime(2026, 6, 20, 12, 0, 0, tzinfo=timezone.utc)
ALERT = {"rule": {"id": "5710", "description": "sshd brute force"}}


def _ticket(key, *, disposition="benign", outcome="caught",
            created=NOW - timedelta(days=10), reason="nightly vuln scan"):
    """A store ticket as `list-tickets --raw` would return it."""
    comments = []
    if outcome is not None:
        comments = [{"author": "learning",
                     "body": case_ticket.enrichment_to_comment(outcome)["body"]}]
    iso = created.isoformat() if hasattr(created, "isoformat") else created
    return {"key": key, "resolution": f"{disposition} — {reason}",
            "created": iso, "comments": comments}


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
        _ticket("recent", created=NOW - timedelta(hours=1)),   # excluded: <24h
        _ticket("old", created=NOW - timedelta(days=120)),     # excluded: >90d
        _ticket("badts", created="not-a-date"),            # dropped: bad timestamp
    ])
    assert sorted(s.case_id for s in _sample()) == ["ok1", "ok2"]


def test_window_boundaries_inclusive(stub_store):
    stub_store([
        _ticket("edge_recent", created=NOW - timedelta(hours=24)),  # exactly -24h: in
        _ticket("edge_old", created=NOW - timedelta(days=90)),      # exactly -90d: in
        _ticket("just_too_recent", created=NOW - timedelta(hours=23, minutes=59)),
        _ticket("just_too_old", created=NOW - timedelta(days=90, seconds=1)),
    ])
    assert sorted(s.case_id for s in _sample()) == ["edge_old", "edge_recent"]


def test_bad_timestamp_drops_one_not_pool(stub_store):
    stub_store([_ticket("good"), _ticket("bad", created="garbage")])
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


def test_reason_excerpt_truncated():
    long = "x" * 500
    stub = case_ticket.ticket_reason  # ensure accessor path is what builds the seed
    assert stub is not None
    seed = ticket_seeds._to_seed(_ticket("c", reason=long))
    assert len(seed.reason) <= ticket_seeds._REASON_EXCERPT_MAX
    assert seed.reason.endswith("…")
