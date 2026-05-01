"""Round-trip parity tests for the gather + analyze dense emitters.

For each module, build a fixture dict with the canonical handler-built
shape, run it through the emitter, wrap it in a ```invlang fence, parse
it back via `parse_dense_companion`, and assert the projected dict shape
matches expectations.
"""

from __future__ import annotations

import pytest

from scripts.handlers._analyze_dense import (
    AnalyzeDenseEmitError,
    emit_analyze_findings_dense,
)
from scripts.handlers._gather_dense import (
    GatherDenseEmitError,
    emit_gather_findings_dense,
)
from scripts.handlers._dense_parser import parse_dense_companion


def _wrap(body: str) -> str:
    return f"```invlang\n{body}\n```\n"


# ---------------------------------------------------------------------------
# Gather
# ---------------------------------------------------------------------------


def test_gather_round_trip_minimal():
    findings = [{
        "id": "l-001",
        "name": "auth-history",
        "loop": 1,
        "target": "v-001",
        "mode": "lead-pick",
        "status": "active",
        "query_details": {
            "system": "wazuh",
            "template": "tpl-x",
            "query": "user=alice",
            "time_window": "24h",
            "substitutions": {"user": "alice"},
        },
        "outcome": {},
        "resolutions": [],
    }]
    body = emit_gather_findings_dense(findings)
    out = parse_dense_companion(_wrap(body))
    [lead] = out["findings"]
    assert lead["id"] == "l-001"
    assert lead["name"] == "auth-history"
    assert lead["target"] == "v-001"
    assert lead["query_details"]["system"] == "wazuh"
    assert lead["query_details"]["substitutions"] == {"user": "alice"}


def test_gather_rejects_resolutions():
    with pytest.raises(GatherDenseEmitError, match="lead-pick only"):
        emit_gather_findings_dense([{
            "id": "l-1", "name": "x", "query_details": {},
            "resolutions": [{"hypothesis": "h-1"}],
        }])


def test_gather_observations_round_trip():
    findings = [{
        "id": "l-002",
        "name": "src-lookup",
        "loop": 1,
        "target": "v-001",
        "mode": "lead-pick",
        "query_details": {"system": "wazuh", "query": "src=10.0.0.1"},
        "outcome": {
            "observations": {
                "vertices": [{
                    "id": "v-010", "type": "ip",
                    "classification": "internal",
                    "identifier": "10.0.0.1",
                    "attributes": {"asn": 64512},
                }],
                "edges": [{
                    "id": "e-010", "relation": "originated-from",
                    "source_vertex": "v-001", "target_vertex": "v-010",
                    "when": {"timestamp": "2026-04-30T12:00:00Z"},
                    "authority": {"kind": "siem-event", "source": "wazuh"},
                    "attributes": {},
                }],
            },
        },
        "resolutions": [],
    }]
    out = parse_dense_companion(_wrap(emit_gather_findings_dense(findings)))
    [lead] = out["findings"]
    obs = lead["outcome"]["observations"]
    assert obs["vertices"][0]["id"] == "v-010"
    assert obs["edges"][0]["authority"] == {"kind": "siem-event", "source": "wazuh"}


# ---------------------------------------------------------------------------
# Analyze
# ---------------------------------------------------------------------------


def _analyze_finding_with_resolution(**res_overrides):
    res = {
        "hypothesis": "h-001",
        "before_weight": "∅",
        "after": "++",
        "severity": "severe",
        "matched_prediction_ids": ["p1", "p2"],
        "supporting_edges": ["e-010"],
        "reasoning": "lead confirmed",
    }
    res.update(res_overrides)
    return [{
        "id": "l-001",
        "name": "auth-check",
        "loop": 2,
        "target": "v-001",
        "mode": "graded",
        "query_details": {"system": "wazuh", "query": "x"},
        "outcome": {},
        "resolutions": [res],
    }]


def test_analyze_resolution_round_trip():
    out = parse_dense_companion(
        _wrap(emit_analyze_findings_dense(_analyze_finding_with_resolution()))
    )
    [lead] = out["findings"]
    [r] = lead["resolutions"]
    assert r["hypothesis_id"] == "h-001"
    assert r["before"] == "∅"
    assert r["after"] == "++"
    assert r["severity_of_test"] == "severe"
    assert r["supporting_edges"] == ["e-010"]
    assert r["matched_prediction_ids"] == ["p1", "p2"]
    assert r["reasoning"] == "lead confirmed"


def test_analyze_resolution_no_tokens_round_trip():
    findings = _analyze_finding_with_resolution(matched_prediction_ids=[])
    out = parse_dense_companion(_wrap(emit_analyze_findings_dense(findings)))
    [r] = out["findings"][0]["resolutions"]
    assert r["matched_prediction_ids"] == []
    assert r["severity_of_test"] == "severe"


def test_analyze_resolution_no_authority_marker():
    findings = _analyze_finding_with_resolution(
        after="-", severity="moderate",
        supporting_edges=[], supporting_marker="no-authority",
    )
    out = parse_dense_companion(_wrap(emit_analyze_findings_dense(findings)))
    [r] = out["findings"][0]["resolutions"]
    assert r["supporting_marker"] == "no-authority"
    assert r["supporting_edges"] == []


def test_analyze_annotation_with_brackets_and_newlines_survives():
    findings = _analyze_finding_with_resolution(
        reasoning="weird\nprose with ] inside\tand tabs",
    )
    out = parse_dense_companion(_wrap(emit_analyze_findings_dense(findings)))
    [r] = out["findings"][0]["resolutions"]
    # newlines/tabs collapsed to single spaces, `]` preserved.
    assert r["reasoning"] == "weird prose with ] inside and tabs"


def test_analyze_resolution_missing_required_fails_loud():
    with pytest.raises(AnalyzeDenseEmitError, match="before_weight"):
        emit_analyze_findings_dense(_analyze_finding_with_resolution(before_weight=None))
    with pytest.raises(AnalyzeDenseEmitError, match="severity"):
        emit_analyze_findings_dense(_analyze_finding_with_resolution(severity=None))
    with pytest.raises(AnalyzeDenseEmitError, match="invalid `after`"):
        emit_analyze_findings_dense(_analyze_finding_with_resolution(after="?"))


def test_analyze_attr_updates_requires_target():
    findings = [{
        "id": "l-001", "name": "x", "loop": 2, "target": "v-001",
        "mode": "graded", "query_details": {}, "outcome": {
            "attribute_updates": [{"target": "", "updates": {"k": "v"}}],
        },
        "resolutions": [],
    }]
    with pytest.raises(AnalyzeDenseEmitError, match="missing target"):
        emit_analyze_findings_dense(findings)


def test_analyze_consult_multi_asks_fails_loud():
    findings = [{
        "id": "l-001", "name": "x", "loop": 2, "target": "v-001",
        "mode": "graded", "query_details": {}, "outcome": {
            "anchor_consultations": [{
                "asks": ["a-1", "a-2"], "verdict": "confirmed",
                "anchor_kind": "policy", "grounding_kind": "org-authority",
            }],
        },
        "resolutions": [],
    }]
    with pytest.raises(AnalyzeDenseEmitError, match="multiple `asks`"):
        emit_analyze_findings_dense(findings)
