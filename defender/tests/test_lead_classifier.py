"""Composite-kind classifier — pin the v1 inference rules."""
from __future__ import annotations

from defender.learning.leads import lead_classifier  # type: ignore[import-not-found]


def _entry(position: int, queries: list[dict]) -> dict:
    return {"position": position, "queries": queries, "lead_description": {"goal": "x"}}


def test_single_query_is_atomic():
    e = _entry(0, [{"id": "wazuh.auth-events", "params": {"host": "h1"}}])
    kind = lead_classifier.infer_composite_kind(e, e["queries"][0], [e])
    assert kind == "atomic"


def test_same_id_repeated_is_sweep():
    e = _entry(0, [
        {"id": "wazuh.auth-events", "params": {"host": "h1"}},
        {"id": "wazuh.auth-events", "params": {"host": "h2"}},
    ])
    kind = lead_classifier.infer_composite_kind(e, e["queries"][0], [e])
    assert kind == "sweep"


def test_cross_system_is_join():
    e = _entry(0, [
        {"id": "wazuh.auth-events", "params": {}},
        {"id": "host-query.process-list", "params": {"pattern": "x"}},
    ])
    kind_a = lead_classifier.infer_composite_kind(e, e["queries"][0], [e])
    kind_b = lead_classifier.infer_composite_kind(e, e["queries"][1], [e])
    assert kind_a == "join"
    assert kind_b == "join"


def test_baseline_shift_across_entries():
    """Same id + same non-window params in two entries with different windows."""
    e0 = _entry(0, [
        {"id": "wazuh.auth-events", "params": {"host": "h1", "window": "1h"}},
    ])
    e1 = _entry(1, [
        {"id": "wazuh.auth-events", "params": {"host": "h1", "window": "30d"}},
    ])
    kind = lead_classifier.infer_composite_kind(e0, e0["queries"][0], [e0, e1])
    assert kind == "baseline_shift"


def test_baseline_shift_requires_different_window():
    """Same id repeated with identical windows is *not* baseline_shift."""
    e0 = _entry(0, [
        {"id": "wazuh.auth-events", "params": {"host": "h1", "window": "1h"}},
    ])
    e1 = _entry(1, [
        {"id": "wazuh.auth-events", "params": {"host": "h1", "window": "1h"}},
    ])
    kind = lead_classifier.infer_composite_kind(e0, e0["queries"][0], [e0, e1])
    assert kind == "atomic"


def _esql(start: str, end: str, user: str = "dev.dana") -> str:
    return (
        'FROM logs-system.auth-* '
        f'| WHERE @timestamp >= "{start}" AND @timestamp < "{end}" '
        f'AND user.name == "{user}" '
        '| STATS accepted = COUNT(*) BY source.ip'
    )


def test_baseline_shift_esql_inlined_timestamps():
    """Under ES|QL the window is inlined in arg0, not a named param. Two runs of
    the same query shape over different windows must still read as baseline_shift
    once the timestamp literals are masked into the window signature."""
    e0 = _entry(0, [{"id": "elastic.sshd-auth-history",
                     "params": {"arg0": _esql("2026-05-25T13:00:00Z", "2026-05-25T14:00:00Z")}}])
    e1 = _entry(1, [{"id": "elastic.sshd-auth-history",
                     "params": {"arg0": _esql("2026-05-18T00:00:00Z", "2026-05-25T00:00:00Z")}}])
    kind = lead_classifier.infer_composite_kind(e0, e0["queries"][0], [e0, e1])
    assert kind == "baseline_shift"


def test_esql_different_entity_is_not_baseline_shift():
    """Same window shape but a different *entity* (user) — that's a different
    measurement target, not a baseline shift. Only timestamps are masked."""
    e0 = _entry(0, [{"id": "elastic.sshd-auth-history",
                     "params": {"arg0": _esql("2026-05-25T13:00:00Z", "2026-05-25T14:00:00Z", "dev.dana")}}])
    e1 = _entry(1, [{"id": "elastic.sshd-auth-history",
                     "params": {"arg0": _esql("2026-05-18T00:00:00Z", "2026-05-25T00:00:00Z", "ops.omar")}}])
    kind = lead_classifier.infer_composite_kind(e0, e0["queries"][0], [e0, e1])
    assert kind == "atomic"


def test_esql_identical_query_is_not_baseline_shift():
    """Identical arg0 (same window) repeated → no window difference → atomic."""
    q = {"id": "elastic.sshd-auth-history",
         "params": {"arg0": _esql("2026-05-25T13:00:00Z", "2026-05-25T14:00:00Z")}}
    e0 = _entry(0, [dict(q)])
    e1 = _entry(1, [dict(q)])
    kind = lead_classifier.infer_composite_kind(e0, e0["queries"][0], [e0, e1])
    assert kind == "atomic"


def test_co_dispatched_excludes_self():
    e = _entry(0, [
        {"id": "wazuh.auth-events", "params": {}},
        {"id": "host-query.process-list", "params": {}},
    ])
    paths = {
        "wazuh.auth-events": "queries/wazuh/auth-events.md",
        "host-query.process-list": "queries/host-query/process-list.md",
    }
    siblings_for_first = lead_classifier.co_dispatched_template_paths(e, 0, paths)
    assert siblings_for_first == ["queries/host-query/process-list.md"]


def test_co_dispatched_drops_unresolved_ids():
    e = _entry(0, [
        {"id": "wazuh.auth-events", "params": {}},
        {"id": "host-query.unknown", "params": {}},
    ])
    paths = {"wazuh.auth-events": "queries/wazuh/auth-events.md"}
    assert lead_classifier.co_dispatched_template_paths(e, 0, paths) == []
