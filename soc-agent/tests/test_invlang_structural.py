"""Unit tests for structural invlang checks (rules 1-9).

Covers: lead required fields, ID formats, ID references, edge authority,
refutation IDs, trust_anchor_result completeness, screen_result scope,
lead.predictions structural shape.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_edge_authority,
    _check_id_formats,
    _check_id_references,
    _check_lead_predictions,
    _check_lead_required_fields,
    _check_refutation_ids,
    _check_screen_result_scope,
    _check_trust_anchor_completeness,
    _merge_blocks,
)

from tests.test_invlang_validate import (
    VALID_PREDICT_YAML,
    VALID_LEAD_YAML,
    VALID_PROLOGUE_YAML,
    _parse_yaml_block,
)


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_required_fields
# ---------------------------------------------------------------------------


class TestCheckLeadRequiredFields:
    def test_valid_lead(self):
        merged = _merge_blocks([_parse_yaml_block(f"```yaml\n{VALID_LEAD_YAML}\n```")])
        assert _check_lead_required_fields(merged) == []

    def test_missing_resolutions(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
            "query_details": {}, "outcome": {},
            # resolutions missing
        }]}
        errors = _check_lead_required_fields(merged)
        assert any("resolutions" in e for e in errors)

    def test_missing_multiple_fields(self):
        merged = {"gather": [{"id": "l-001"}]}
        errors = _check_lead_required_fields(merged)
        assert errors
        assert any("l-001" in e for e in errors)


# ---------------------------------------------------------------------------
# Unit tests: _check_id_formats
# ---------------------------------------------------------------------------


class TestCheckIdFormats:
    def test_valid_ids(self):
        merged = _merge_blocks([_parse_yaml_block(f"```yaml\n{VALID_PROLOGUE_YAML}\n```")])
        assert _check_id_formats(merged) == []

    def test_invalid_vertex_id(self):
        merged = {"prologue": {"vertices": [{"id": "vertex001", "type": "endpoint", "classification": "x", "identifier": "y"}], "edges": []}}
        errors = _check_id_formats(merged)
        assert any("vertex001" in e for e in errors)

    def test_uppercase_id(self):
        merged = {"prologue": {"vertices": [{"id": "V-001", "type": "endpoint", "classification": "x", "identifier": "y"}], "edges": []}}
        errors = _check_id_formats(merged)
        assert errors

    def test_hypothesis_id_valid(self):
        merged = {"hypothesize": {"hypotheses": [{"id": "h-001", "name": "?test"}]}}
        assert _check_id_formats(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_id_references
# ---------------------------------------------------------------------------


class TestCheckIdReferences:
    def test_all_refs_resolve(self):
        import yaml
        prologue = yaml.safe_load(VALID_PROLOGUE_YAML)
        hyp = yaml.safe_load(VALID_PREDICT_YAML)
        lead_raw = yaml.safe_load(VALID_LEAD_YAML)
        merged = _merge_blocks([prologue, hyp, lead_raw])
        errors = _check_id_references(merged)
        assert errors == [], errors

    def test_dangling_target_ref(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "test",
            "target": "v-999",  # doesn't exist
            "query_details": {}, "outcome": {}, "resolutions": [],
        }]}
        errors = _check_id_references(merged)
        assert any("v-999" in e for e in errors)

    def test_dangling_resolution_hypothesis(self):
        merged = {
            "prologue": {"vertices": [{"id": "v-001"}], "edges": [{"id": "e-001", "authority": {"kind": "siem-event"}}]},
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {},
                "resolutions": [{"hypothesis": "h-999", "after": "+", "supporting_edges": ["e-001"]}],
            }],
        }
        errors = _check_id_references(merged)
        assert any("h-999" in e for e in errors)


# ---------------------------------------------------------------------------
# Unit tests: _check_edge_authority
# ---------------------------------------------------------------------------


class TestCheckEdgeAuthority:
    def _make_merged(self, after: str, authority_kind: str) -> dict:
        return {
            "prologue": {
                "vertices": [],
                "edges": [{"id": "e-001", "relation": "attempted_auth",
                            "source_vertex": "v-001", "target_vertex": "v-002",
                            "authority": {"kind": authority_kind, "source": "wazuh"}}]
            },
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
                "resolutions": [{
                    "hypothesis": "h-001", "before": None, "after": after,
                    "severity_of_test": "severe",
                    "matched_prediction_ids": ["p1"],
                    "matched_refutation_ids": [],
                    "reasoning": "test",
                    "supporting_edges": ["e-001"],
                }],
            }],
        }

    def test_pp_with_siem_event_passes(self):
        assert _check_edge_authority(self._make_merged("++", "siem-event")) == []

    def test_mm_with_runtime_audit_passes(self):
        assert _check_edge_authority(self._make_merged("--", "runtime-audit")) == []

    def test_pp_with_client_asserted_fails(self):
        errors = _check_edge_authority(self._make_merged("++", "client-asserted"))
        assert errors

    def test_pp_empty_supporting_edges_fails(self):
        merged = {
            "prologue": {"vertices": [], "edges": []},
            "gather": [{
                "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
                "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
                "resolutions": [{"hypothesis": "h-001", "after": "++", "supporting_edges": []}],
            }],
        }
        errors = _check_edge_authority(merged)
        assert errors

    def test_plus_does_not_require_strong_authority(self):
        assert _check_edge_authority(self._make_merged("+", "client-asserted")) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_refutation_ids
# ---------------------------------------------------------------------------


class TestCheckRefutationIds:
    def test_mm_with_ids_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": ["r1"], "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged) == []

    def test_mm_empty_ids_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": [], "supporting_edges": []}],
        }]}
        errors = _check_refutation_ids(merged)
        assert errors
        assert "l-001" in errors[0]

    def test_mm_missing_key_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--", "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged)


# ---------------------------------------------------------------------------
# Unit tests: _check_trust_anchor_completeness
# ---------------------------------------------------------------------------


class TestCheckTrustAnchorCompleteness:
    def test_complete_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-monitoring-sources",
                    "kind": "org-authority",
                    "result": "confirmed",
                    "as_of": "2026-04-17T09:00:00Z",
                    "authority_for_question": "full",
                },
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [],
        }]}
        assert _check_trust_anchor_completeness(merged) == []

    def test_missing_two_fields_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-monitoring-sources",
                    "kind": "org-authority",
                    # missing: result, as_of, authority_for_question
                },
            },
            "resolutions": [],
        }]}
        errors = _check_trust_anchor_completeness(merged)
        assert errors
        assert "l-001" in errors[0]

    def test_kind_from_edge_authority_taxonomy_rejected(self):
        """The agent commonly writes `authoritative-source` (an edge-authority
        term) into trust_anchor_result.kind — it must be caught at invlang
        layer so the error points at the right schema slot."""
        merged = {"gather": [{
            "id": "l-004", "loop": 0, "name": "approved-monitoring-sources",
            "target": "e-001", "mode": "screen",
            "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-monitoring-sources",
                    "kind": "authoritative-source",
                    "result": "confirmed",
                    "as_of": "2026-04-18T20:32:05Z",
                    "authority_for_question": "full",
                },
            },
            "resolutions": [],
        }]}
        errors = _check_trust_anchor_completeness(merged)
        assert any("trust_anchor_result.kind must be one of" in e for e in errors)
        assert any("l-004" in e for e in errors)
        assert any("authoritative-source" in e for e in errors)

    def test_kind_telemetry_baseline_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 0, "name": "image-baseline",
            "target": "e-001", "query_details": {}, "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "image-baseline",
                    "kind": "telemetry-baseline",
                    "result": "confirmed",
                    "as_of": "2026-04-18T20:32:05Z",
                    "authority_for_question": "full",
                },
            },
            "resolutions": [],
        }]}
        assert _check_trust_anchor_completeness(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_screen_result_scope
# ---------------------------------------------------------------------------


class TestCheckScreenResultScope:
    def test_screen_result_on_screen_lead_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 0, "name": "t", "target": "v-001",
            "mode": "screen",
            "query_details": {}, "outcome": {"screen_result": "no_match"},
            "resolutions": [],
        }]}
        assert _check_screen_result_scope(merged) == []

    def test_screen_result_on_non_screen_lead_fails(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            # mode: screen absent
            "query_details": {}, "outcome": {"screen_result": "no_match"},
            "resolutions": [],
        }]}
        errors = _check_screen_result_scope(merged)
        assert errors
        assert "l-001" in errors[0]


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_predictions
# ---------------------------------------------------------------------------


def _lead_with_predictions(predictions):
    return {"gather": [{
        "id": "l-001", "loop": 1, "name": "volume-profile", "target": "v-001",
        "query_details": {}, "outcome": {},
        "predictions": predictions,
        "resolutions": [],
    }]}


class TestCheckLeadPredictions:
    def test_absent_predictions_passes(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {}, "resolutions": [],
        }]}
        assert _check_lead_predictions(merged) == []

    def test_well_formed_predictions_pass(self):
        merged = _lead_with_predictions([
            {"id": "lp1", "if": "volume within 1σ", "read_as": "authorized",
             "advance_to": "change-management-lookup"},
            {"id": "lp2", "if": "volume >3σ", "read_as": "anomalous",
             "advance_to": "PREDICT"},
        ])
        assert _check_lead_predictions(merged) == []

    def test_missing_required_field(self):
        merged = _lead_with_predictions([
            {"id": "lp1", "if": "x", "read_as": "y"},  # missing advance_to
        ])
        errors = _check_lead_predictions(merged)
        assert errors
        assert "advance_to" in errors[0]

    def test_bad_id_pattern(self):
        merged = _lead_with_predictions([
            {"id": "p1", "if": "x", "read_as": "y", "advance_to": "next"},
        ])
        errors = _check_lead_predictions(merged)
        assert any("does not match pattern" in e for e in errors)

    def test_duplicate_ids(self):
        merged = _lead_with_predictions([
            {"id": "lp1", "if": "x", "read_as": "y", "advance_to": "a"},
            {"id": "lp1", "if": "z", "read_as": "w", "advance_to": "b"},
        ])
        errors = _check_lead_predictions(merged)
        assert any("duplicate id" in e for e in errors)

    def test_empty_advance_to(self):
        merged = _lead_with_predictions([
            {"id": "lp1", "if": "x", "read_as": "y", "advance_to": ""},
        ])
        errors = _check_lead_predictions(merged)
        assert any("non-empty string" in e for e in errors)

    def test_predictions_not_a_list(self):
        merged = {"gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "predictions": "not a list",
            "resolutions": [],
        }]}
        errors = _check_lead_predictions(merged)
        assert any("must be a list" in e for e in errors)
