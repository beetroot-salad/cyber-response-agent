"""Unit tests for structural invlang checks.

Covers: lead required fields, ID formats, ID references, edge authority,
refutation IDs, screen_result scope, lead.predictions structural shape,
plus rule #11 provenance checks (authorization_resolutions,
anchor_consultations).
"""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_anchor_consultation_provenance,
    _check_authorization_resolution_provenance,
    _check_edge_authority,
    _check_id_formats,
    _check_id_references,
    _check_lead_predictions,
    _check_lead_required_fields,
    _check_refutation_ids,
    _check_screen_result_scope,
    _merge_blocks,
)

from tests.test_invlang_validate import (
    VALID_PREDICT_YAML,
    VALID_LEAD_YAML,
    VALID_PROLOGUE_YAML,
    _companion_with_contract,
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
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "test", "target": "v-001",
            "query_details": {}, "outcome": {},
            # resolutions missing
        }]}
        errors = _check_lead_required_fields(merged)
        assert any("resolutions" in e for e in errors)

    def test_missing_multiple_fields(self):
        merged = {"findings": [{"id": "l-001"}]}
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
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "test",
            "target": "v-999",
            "query_details": {}, "outcome": {}, "resolutions": [],
        }]}
        errors = _check_id_references(merged)
        assert any("v-999" in e for e in errors)

    def test_dangling_resolution_hypothesis(self):
        merged = {
            "prologue": {"vertices": [{"id": "v-001"}], "edges": [{"id": "e-001", "authority": {"kind": "siem-event"}}]},
            "findings": [{
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
            "findings": [{
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
            "findings": [{
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
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": ["r1"], "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged) == []

    def test_mm_empty_ids_fails(self):
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--",
                              "matched_refutation_ids": [], "supporting_edges": []}],
        }]}
        errors = _check_refutation_ids(merged)
        assert errors
        assert "l-001" in errors[0]

    def test_mm_missing_key_fails(self):
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{"hypothesis": "h-001", "after": "--", "supporting_edges": []}],
        }]}
        assert _check_refutation_ids(merged)


# ---------------------------------------------------------------------------
# Unit tests: _check_screen_result_scope
# ---------------------------------------------------------------------------


class TestCheckScreenResultScope:
    def test_screen_result_on_screen_lead_passes(self):
        merged = {"findings": [{
            "id": "l-001", "loop": 0, "name": "t", "target": "v-001",
            "mode": "screen",
            "query_details": {}, "outcome": {"screen_result": "no_match"},
            "resolutions": [],
        }]}
        assert _check_screen_result_scope(merged) == []

    def test_screen_result_on_non_screen_lead_fails(self):
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
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
    return {"findings": [{
        "id": "l-001", "loop": 1, "name": "volume-profile", "target": "v-001",
        "query_details": {}, "outcome": {},
        "predictions": predictions,
        "resolutions": [],
    }]}


class TestCheckLeadPredictions:
    def test_absent_predictions_passes(self):
        merged = {"findings": [{
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
        merged = {"findings": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {},
            "predictions": "not a list",
            "resolutions": [],
        }]}
        errors = _check_lead_predictions(merged)
        assert any("must be a list" in e for e in errors)


# ---------------------------------------------------------------------------
# Unit tests: rule #11 — authorization_resolutions[] provenance
# ---------------------------------------------------------------------------


class TestCheckAuthorizationResolutionProvenance:
    """Rule #11 for authz entries — required fields + grounding enum."""

    def test_full_entry_passes(self):
        merged = _companion_with_contract()
        assert _check_authorization_resolution_provenance(merged) == []

    def test_missing_required_fields_reported(self):
        merged = _companion_with_contract()
        edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        # Strip several required fields to verify they all get reported.
        for field in ("anchor_kind", "anchor_id", "as_of"):
            edge["authorization_resolutions"][0].pop(field, None)
        errors = _check_authorization_resolution_provenance(merged)
        assert any("missing required field" in e for e in errors)
        joined = " ".join(errors)
        assert "anchor_kind" in joined
        assert "anchor_id" in joined
        assert "as_of" in joined

    def test_telemetry_baseline_grounding_rejected(self):
        merged = _companion_with_contract()
        edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        edge["authorization_resolutions"][0]["grounding_kind"] = "telemetry-baseline"
        errors = _check_authorization_resolution_provenance(merged)
        assert any("telemetry-baseline" in e for e in errors)

    def test_past_case_requires_cites_past_case(self):
        merged = _companion_with_contract()
        edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        edge["authorization_resolutions"][0]["grounding_kind"] = "past-case"
        # No cites_past_case field
        errors = _check_authorization_resolution_provenance(merged)
        assert any("cites_past_case" in e for e in errors)

    def test_past_case_with_valid_cites_passes(self):
        merged = _companion_with_contract()
        edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        edge["authorization_resolutions"][0]["grounding_kind"] = "past-case"
        edge["authorization_resolutions"][0]["cites_past_case"] = {
            "run_id": "run-2025-01", "contract_ref": "h-001.ac1",
        }
        assert _check_authorization_resolution_provenance(merged) == []

    def test_past_case_missing_run_id_fails(self):
        merged = _companion_with_contract()
        edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        edge["authorization_resolutions"][0]["grounding_kind"] = "past-case"
        edge["authorization_resolutions"][0]["cites_past_case"] = {"contract_ref": "h-001.ac1"}
        errors = _check_authorization_resolution_provenance(merged)
        assert any("run_id" in e for e in errors)


# ---------------------------------------------------------------------------
# Unit tests: rule #11 — anchor_consultations[] provenance
# ---------------------------------------------------------------------------


class TestCheckAnchorConsultationProvenance:
    """Rule #11 for consultations — required fields + grounding enum."""

    def test_full_entry_passes(self):
        merged = _companion_with_contract()
        assert _check_anchor_consultation_provenance(merged) == []

    def test_missing_required_fields_reported(self):
        merged = _companion_with_contract()
        cons = merged["findings"][0]["outcome"]["anchor_consultations"][0]
        cons.pop("result")
        cons.pop("anchor_id")
        errors = _check_anchor_consultation_provenance(merged)
        assert any("missing required field" in e for e in errors)
        joined = " ".join(errors)
        assert "result" in joined
        assert "anchor_id" in joined

    def test_past_case_grounding_rejected(self):
        merged = _companion_with_contract(
            anchor_consultations=[{
                "anchor_id": "x", "anchor_kind": "x",
                "grounding_kind": "past-case",  # forbidden on consultations
                "result": "confirmed", "as_of": "2026-04-18",
                "authority_for_question": "full",
            }],
        )
        errors = _check_anchor_consultation_provenance(merged)
        assert any("past-case" in e for e in errors)

    def test_telemetry_baseline_passes(self):
        merged = _companion_with_contract(
            anchor_consultations=[{
                "anchor_id": "image-baseline", "anchor_kind": "image-baseline",
                "grounding_kind": "telemetry-baseline",
                "result": "confirmed", "as_of": "2026-04-18",
                "authority_for_question": "full",
            }],
        )
        assert _check_anchor_consultation_provenance(merged) == []
