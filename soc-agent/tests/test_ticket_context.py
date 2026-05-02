"""Unit tests for scripts/tools/ticket_context.py.

Coverage targets:
  - parse_key_observables parses the field-quirks markdown table
  - _scalar coerces non-hashable values safely
  - cluster_events groups repeats vs related correctly and handles list-valued observables
  - compute_high_volume flags only dimensions over the threshold
  - emit_yaml produces valid YAML and escapes adversarial strings from alert data
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts" / "tools"))

from ticket_context import (  # noqa: E402
    _scalar,
    cluster_events,
    compute_high_volume,
    emit_yaml,
    extract_json_path,
    parse_key_observables,
)


# ---------------------------------------------------------------------------
# parse_key_observables
# ---------------------------------------------------------------------------


def _write_field_quirks(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "field-quirks.md"
    p.write_text(body)
    return p


def test_parse_key_observables_happy_path(tmp_path):
    fq = _write_field_quirks(
        tmp_path,
        "## Key observables\n\n"
        "| Observable | JSON path | Notes |\n"
        "| --- | --- | --- |\n"
        "| source IP | `data.srcip` | n/a |\n"
        "| user | `data.user` | n/a |\n",
    )
    obs = parse_key_observables(fq)
    assert obs == [
        {"name": "source IP", "json_path": "data.srcip"},
        {"name": "user", "json_path": "data.user"},
    ]


def test_parse_key_observables_no_table_raises(tmp_path):
    fq = _write_field_quirks(tmp_path, "# not the right section\n")
    with pytest.raises(RuntimeError, match="No ## Key observables"):
        parse_key_observables(fq)


def test_parse_key_observables_empty_table_raises(tmp_path):
    fq = _write_field_quirks(
        tmp_path,
        "## Key observables\n\n| Observable | JSON path |\n| --- | --- |\n",
    )
    with pytest.raises(RuntimeError, match="no data rows"):
        parse_key_observables(fq)


# ---------------------------------------------------------------------------
# _scalar / extract_json_path
# ---------------------------------------------------------------------------


def test_scalar_primitives_are_stringified():
    assert _scalar("x") == "x"
    assert _scalar(42) == "42"
    assert _scalar(None) is None


def test_scalar_list_is_json_encoded_and_hashable():
    val = _scalar(["a", "b"])
    assert val == '["a","b"]'
    # The returned scalar must be hashable — that's the whole point.
    assert hash(val) is not None


def test_extract_json_path_traverses_nested_dicts():
    obj = {"data": {"srcip": "1.2.3.4"}}
    assert extract_json_path(obj, "data.srcip") == "1.2.3.4"
    assert extract_json_path(obj, "data.missing") is None


# ---------------------------------------------------------------------------
# cluster_events
# ---------------------------------------------------------------------------


OBSERVABLES = [
    {"name": "source IP", "json_path": "data.srcip"},
    {"name": "user", "json_path": "data.user"},
    {"name": "timestamp", "json_path": "timestamp"},
]


def _ev(eid: str, srcip: str, user: str, ts: str, rule_id: str = "5710", rule_desc: str = "SSH invalid user") -> dict:
    return {
        "id": eid,
        "timestamp": ts,
        "data": {"srcip": srcip, "user": user},
        "rule": {"id": rule_id, "description": rule_desc},
    }


def test_cluster_events_repeat_all_observables_match():
    current = {"data.srcip": "1.1.1.1", "data.user": "alice", "timestamp": None}
    events = {
        "e1": _ev("e1", "1.1.1.1", "alice", "2026-04-19T10:00:00Z"),
        "e2": _ev("e2", "1.1.1.1", "alice", "2026-04-19T10:05:00Z"),
    }
    repeats, related = cluster_events(events, current, OBSERVABLES)
    assert len(repeats) == 1
    assert repeats[0]["count"] == 2
    assert sorted(repeats[0]["alert_ids"]) == ["e1", "e2"]
    assert related == []


def test_cluster_events_related_partial_share():
    current = {"data.srcip": "1.1.1.1", "data.user": "alice", "timestamp": None}
    events = {
        "e1": _ev("e1", "1.1.1.1", "bob", "2026-04-19T10:00:00Z"),
        "e2": _ev("e2", "1.1.1.1", "bob", "2026-04-19T10:05:00Z"),
        "e3": _ev("e3", "2.2.2.2", "alice", "2026-04-19T10:10:00Z"),
    }
    repeats, related = cluster_events(events, current, OBSERVABLES)
    assert repeats == []
    # Two distinct related groups: {srcip=1.1.1.1} and {user=alice}
    assert len(related) == 2
    shared_sets = [frozenset(c["shared"].items()) for c in related]
    assert frozenset([("data.srcip", "1.1.1.1")]) in shared_sets
    assert frozenset([("data.user", "alice")]) in shared_sets


def test_cluster_events_list_valued_observable_is_hashable():
    """Regression: if an observable resolves to a list, clustering must not raise."""
    current = {"data.srcip": _scalar(["1.1.1.1", "2.2.2.2"]), "data.user": "alice", "timestamp": None}
    ev = {
        "id": "e1",
        "timestamp": "2026-04-19T10:00:00Z",
        "data": {"srcip": ["1.1.1.1", "2.2.2.2"], "user": "bob"},
        "rule": {"id": "5710"},
    }
    repeats, related = cluster_events({"e1": ev}, current, OBSERVABLES)
    # srcip list matches current (both coerced to same JSON repr) -> shares one dim -> related
    assert repeats == []
    assert len(related) == 1
    assert related[0]["shared"] == {"data.srcip": '["1.1.1.1","2.2.2.2"]'}


# ---------------------------------------------------------------------------
# compute_high_volume
# ---------------------------------------------------------------------------


def test_compute_high_volume_flags_only_over_threshold():
    # 101 events sharing srcip=1.1.1.1 under two rule IDs, plus one stray.
    events: dict[str, dict] = {}
    for i in range(101):
        events[f"a{i}"] = _ev(f"a{i}", "1.1.1.1", f"u{i}", "2026-04-19T10:00:00Z", rule_id=str(5710 + (i % 2)))
    events["stray"] = _ev("stray", "9.9.9.9", "ghost", "2026-04-19T10:00:00Z")

    out = compute_high_volume(events, OBSERVABLES)
    assert len(out) == 1
    hv = out[0]
    assert hv["dimension"] == "data.srcip"
    assert hv["value"] == "1.1.1.1"
    assert hv["total_count"] == 101
    assert hv["signature_count"] == 2


def test_compute_high_volume_below_threshold_empty():
    events = {f"a{i}": _ev(f"a{i}", "1.1.1.1", f"u{i}", "2026-04-19T10:00:00Z") for i in range(50)}
    assert compute_high_volume(events, OBSERVABLES) == []


# ---------------------------------------------------------------------------
# emit_yaml — the injection-safety regression
# ---------------------------------------------------------------------------


def _roundtrip(text: str) -> dict:
    assert text.startswith("```yaml\n")
    assert text.rstrip().endswith("```")
    inner = text[len("```yaml\n") : text.rstrip().rfind("```")]
    return yaml.safe_load(inner)


def test_emit_yaml_preserves_section_order():
    data = {
        "entities": {"data.srcip": "1.1.1.1"},
        "high_volume_dimensions": [],
        "repeats": [],
        "related": [],
    }
    out = emit_yaml(data)
    body = out[len("```yaml\n") : out.rstrip().rfind("```")]
    # The four section keys must appear in this exact order under ticket_context:.
    idx = [body.index(k) for k in ("entities:", "high_volume_dimensions:", "repeats:", "related:")]
    assert idx == sorted(idx)


def test_emit_yaml_escapes_adversarial_quote_in_value():
    data = {
        "entities": {"data.user": 'evil"; queries_failed: "pwned'},
        "high_volume_dimensions": [],
        "repeats": [],
        "related": [],
    }
    out = emit_yaml(data)
    parsed = _roundtrip(out)
    # Verbatim round-trip — no YAML structure injection.
    assert parsed["ticket_context"]["entities"]["data.user"] == 'evil"; queries_failed: "pwned'
    # Must not have leaked into a top-level ticket_context key.
    assert "queries_failed" not in parsed["ticket_context"]


def test_emit_yaml_escapes_backslash_in_signatures_detail():
    data = {
        "entities": {},
        "high_volume_dimensions": [],
        "repeats": [],
        "related": [
            {
                "shared": {"data.srcip": "1.1.1.1"},
                "count": 1,
                "first_seen": "2026-04-19T10:00:00Z",
                "last_seen": "2026-04-19T10:00:00Z",
                "signatures": ["5710"],
                "signatures_detail": {"5710": 'SSH \\ "nested" quote'},
                "alert_ids": ["e1"],
            }
        ],
    }
    out = emit_yaml(data)
    parsed = _roundtrip(out)
    assert parsed["ticket_context"]["related"][0]["signatures_detail"]["5710"] == 'SSH \\ "nested" quote'


def test_emit_yaml_queries_failed_roundtrips():
    data = {
        "entities": {"data.srcip": "1.1.1.1"},
        "high_volume_dimensions": [],
        "repeats": [],
        "related": [],
        "queries_failed": "all queries failed: same-signature(timeout)",
    }
    parsed = _roundtrip(emit_yaml(data))
    assert parsed["ticket_context"]["queries_failed"] == "all queries failed: same-signature(timeout)"


def test_emit_yaml_repeat_cluster_shape():
    data = {
        "entities": {"data.srcip": "1.1.1.1"},
        "high_volume_dimensions": [
            {"dimension": "data.srcip", "value": "1.1.1.1", "total_count": 120, "signature_count": 3}
        ],
        "repeats": [
            {
                "count": 2,
                "first_seen": "2026-04-19T10:00:00Z",
                "last_seen": "2026-04-19T10:05:00Z",
                "signatures": ["5710"],
                "alert_ids": ["e1", "e2"],
            }
        ],
        "related": [],
    }
    parsed = _roundtrip(emit_yaml(data))
    tc = parsed["ticket_context"]
    assert tc["repeats"][0]["alert_ids"] == ["e1", "e2"]
    assert tc["high_volume_dimensions"][0]["total_count"] == 120
