"""Round-trip parity tests for the hypothesize dense emitter.

Build a fixture dict with the canonical handler-built shape, run it through
`emit_hypothesize_dense`, wrap in a ```invlang fence, parse back via
`parse_dense_companion`, and assert the projected dict shape matches
expectations.
"""

from __future__ import annotations

import textwrap

import pytest

from scripts.handlers._dense_parser import parse_dense_companion
from scripts.handlers._hypothesize_dense import (
    HypothesizeDenseEmitError,
    emit_hypothesize_dense,
)
from scripts.handlers._predict_dense import parse_predict_dense


def _wrap(body: str) -> str:
    return f"```invlang\n{body}\n```\n"


def test_round_trip_minimal():
    hyps = [{
        "id": "h-001",
        "name": "?monitoring-probe",
        "attached_to_vertex": "v-001",
        "proposed_edge": {
            "relation": "initiated_by",
            "parent_vertex": {
                "type": "identity",
                "classification": "approved-monitoring-service-account",
            },
        },
        "predictions": [
            {"id": "p1", "subject": "proposed_parent",
             "claim": "triple in approved-monitoring-sources"},
        ],
        "refutation_shape": [
            {"id": "r1", "refutes_predictions": ["p1"], "claim": "triple absent"},
        ],
        "weight": None,
        "status": "active",
    }]
    body = emit_hypothesize_dense(hyps)
    out = parse_dense_companion(_wrap(body))
    parsed = out["hypothesize"]["hypotheses"][0]
    assert parsed["id"] == "h-001"
    assert parsed["predictions"] == [
        {"id": "p1", "subject": "proposed_parent",
         "claim": "triple in approved-monitoring-sources"},
    ]
    assert parsed["refutation_shape"] == [
        {"id": "r1", "claim": "triple absent", "refutes_predictions": ["p1"]},
    ]
    assert parsed["weight"] is None


def test_round_trip_authz_contract():
    hyps = [{
        "id": "h-001",
        "name": "?probe",
        "attached_to_vertex": "v-001",
        "proposed_edge": {
            "relation": "initiated_by",
            "parent_vertex": {"type": "identity", "classification": "sa"},
        },
        "predictions": [
            {"id": "p1", "subject": "proposed_parent", "claim": "triple listed"},
        ],
        "refutation_shape": [
            {"id": "r1", "refutes_predictions": ["p1"], "claim": "absent"},
        ],
        "authorization_contract": [
            {"id": "ac1", "edge_ref": "proposed",
             "anchor_kind": "approved-monitoring-sources",
             "predicate": "triple listed as active",
             "on_unauthorized": "esc", "on_indeterminate": "esc"},
        ],
        "weight": None,
        "status": "active",
    }]
    out = parse_dense_companion(_wrap(emit_hypothesize_dense(hyps)))
    assert out["hypothesize"]["hypotheses"][0]["authorization_contract"] == [{
        "id": "ac1",
        "edge_ref": "proposed",
        "anchor_kind": "approved-monitoring-sources",
        "predicate": "triple listed as active",
        "on_unauthorized": "esc",
        "on_indeterminate": "esc",
    }]


def test_round_trip_claim_with_embedded_quote_and_semicolon():
    """Quote-escape + sub-cell boundary: a claim containing both `"` and `;`
    must survive the pack → split_subcells → unquote round trip intact, and
    must not be mis-split into two sub-cells.
    """
    tricky = 'host says "hello"; world'
    hyps = [{
        "id": "h-001",
        "name": "?quoted",
        "attached_to_vertex": "v-001",
        "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
        "predictions": [
            {"id": "p1", "subject": "proposed_parent", "claim": tricky},
            {"id": "p2", "subject": "proposed_parent", "claim": "second pred"},
        ],
        "refutation_shape": [],
        "weight": None,
        "status": "active",
    }]
    out = parse_dense_companion(_wrap(emit_hypothesize_dense(hyps)))
    preds = out["hypothesize"]["hypotheses"][0]["predictions"]
    assert len(preds) == 2
    assert preds[0]["claim"] == tricky
    assert preds[1]["claim"] == "second pred"


def test_empty_input_returns_empty_string():
    assert emit_hypothesize_dense([]) == ""


def test_non_list_input_raises():
    with pytest.raises(HypothesizeDenseEmitError, match="expected list"):
        emit_hypothesize_dense({"not": "a list"})  # type: ignore[arg-type]


def test_non_list_predictions_raises_loud():
    """Stray scalar in a list-typed slot must not get iterated character-by-
    character — the emitter must reject it explicitly.
    """
    hyps = [{
        "id": "h-001",
        "name": "?x",
        "attached_to_vertex": "v-001",
        "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
        "predictions": "p1:proposed_parent:\"oops\"",  # wrong type
        "weight": None,
        "status": "active",
    }]
    with pytest.raises(HypothesizeDenseEmitError, match="predictions must be a list"):
        emit_hypothesize_dense(hyps)


def test_missing_id_raises():
    hyps = [{
        "id": "",
        "name": "?x",
        "attached_to_vertex": "v-001",
        "proposed_edge": {"relation": "r", "parent_vertex": {"type": "t", "classification": "c"}},
        "weight": None,
        "status": "active",
    }]
    with pytest.raises(HypothesizeDenseEmitError, match="missing id/name"):
        emit_hypothesize_dense(hyps)


def test_comparisons_block_can_precede_refuts_block():
    """Regression for run #54: agent emits :P h-001.comparisons referencing
    `r2` before :P h-001.refuts declares `r2`. The parser must defer
    comparison attachment until all preds/refuts/attr_preds are collected,
    not resolve them inline as it walks blocks in document order.
    """

    class _Err(Exception):
        pass

    stdout = textwrap.dedent(
        """\
        predict loop=1 shape=A

        ### story h-001
        s1. registered triple
        s2. cadence within tolerance

        :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
        h-001|?monitoring-system-is-the-actor|v-001|initiated_by|identity|approved-monitoring-service-account||"none"|null|active

        :P h-001.preds [id|subject|kind|from_story|claim]
        p1|proposed_parent|absolute|s1|"triple in registry"
        p2|proposed_edge|cadence|s2|"foreground cadence matches baseline"

        :P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
        p2|historical-self|"src=X AND user=Y over 24h"|inter-cluster-gap-distribution
        r2|historical-self|"src=X AND user=Y over 24h"|inter-cluster-gap-distribution

        :P h-001.refuts [id|refutes|kind|claim]
        r1|p1|absolute|"triple absent"
        r2|p2|cadence|"foreground deviates from baseline"

        :R routing
        selected_lead         approved-monitoring-sources
        composite_secondary   -
        override_data_source  -
        rationale             "lock authorization"
        """
    )

    pred = parse_predict_dense(stdout, _Err)
    hyp = pred["hypotheses"][0]
    p2 = next(p for p in hyp["predictions"] if p["id"] == "p2")
    r2 = next(r for r in hyp["refutation_shape"] if r["id"] == "r2")
    assert p2["comparison"]["dimension"] == "inter-cluster-gap-distribution"
    assert r2["comparison"]["dimension"] == "inter-cluster-gap-distribution"
