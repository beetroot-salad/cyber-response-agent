"""Tests for the invlang PreToolUse validation hook.

Tests invlang_validate.py: unit tests for check functions, and subprocess
integration tests simulating PreToolUse events on stdin.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    validate_companion,
    _check_lead_required_fields,
    _check_id_formats,
    _check_id_references,
    _check_edge_authority,
    _check_refutation_ids,
    _check_trust_anchor_completeness,
    _check_screen_result_scope,
    _check_lead_predictions,
    _check_route_compliance,
    _check_append_only,
    _check_prediction_coverage,
    _check_partial_authority_cap,
    _check_prediction_lifecycle,
    _check_rollup_parent_weight,
    _check_lead_dedup_warnings,
    _check_silent_empty_result_warnings,
    _check_tool_audit_cross_ref_warnings,
    _check_legitimacy_contract_edge_ref,
    _check_legitimacy_resolution_backrefs,
    _check_legitimacy_gated_disposition,
    _check_attribute_updates_target_shape,
    _check_asks_verdict_shape,
    _check_kind_asks_coherence,
    _check_legitimacy_resolution_target_shape,
    _check_legitimacy_supersede_chain,
    _check_resolution_requires_authorization_asks,
    _merge_blocks,
    collect_warnings,
    YAML_BLOCK_RE,
)

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "invlang_validate.py"

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

VALID_PROLOGUE_YAML = """\
prologue:
  vertices:
    - id: v-001
      type: endpoint
      classification: external-unknown
      identifier: "203.0.113.47"
    - id: v-002
      type: endpoint
      classification: internal-server
      identifier: "web-server-01"
  edges:
    - id: e-001
      relation: attempted_auth
      source_vertex: v-001
      target_vertex: v-002
      authority:
        kind: siem-event
        source: wazuh-indexer
"""

VALID_HYPOTHESIZE_YAML = """\
hypothesize:
  hypotheses:
    - id: h-001
      name: "?opportunistic-scanner"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: identity
          classification: automated-scanner
      predictions:
        - id: p1
          claim: "source IP appears in threat-intel scanner list"
      weight: null
"""

VALID_LEAD_YAML = """\
gather:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-001
    query_details:
      system: wazuh-indexer
      template: source-ip-lookup
      query: "src_ip:203.0.113.47"
      time_window: "30d"
      substitutions: {}
    outcome:
      attribute_updates:
        - target: v-001
          updates:
            classification: external-unknown
      observations:
        vertices: []
        edges:
          - id: e-002
            relation: classified_as
            source_vertex: v-001
            target_vertex: v-002
            authority:
              kind: siem-event
              source: wazuh-indexer
    resolutions:
      - hypothesis: h-001
        before: null
        after: "+"
        severity_of_test: weak
        matched_prediction_ids: []
        matched_refutation_ids: []
        reasoning: "No prior authenticated sessions — consistent with scanner"
        supporting_edges: [e-001]
"""

VALID_CONCLUDE_YAML = """\
conclude:
  termination:
    category: adversarial-refuted
    rationale: "All adversarial hypotheses refuted with -- evidence"
  disposition: benign
  confidence: high
  matched_archetype: external-bruteforce
  summary: "SSH brute force from external scanner; no successful auth"
"""

FULL_COMPANION_MD = f"""## CONTEXTUALIZE

**Alert:** TEST-001

```yaml
{VALID_PROLOGUE_YAML}
```

## HYPOTHESIZE (loop 1)

**Active hypotheses:** ?opportunistic-scanner

```yaml
{VALID_HYPOTHESIZE_YAML}
```

## GATHER (loop 1)

**Raw observation:** source IP not in threat-intel lists

## ANALYZE (loop 1)

**Assessment:** h-001 moves to +

```yaml
{VALID_LEAD_YAML}
```

## CONCLUDE

**Verdict:** resolved

```yaml
{VALID_CONCLUDE_YAML}
```
"""


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_required_fields
# ---------------------------------------------------------------------------


class TestCheckLeadRequiredFields:
    def test_valid_lead(self):
        merged = _merge_blocks([_parse_yaml_block(f"```yaml\n{VALID_LEAD_YAML}\n```")])
        assert _check_lead_required_fields(merged) == []

    def test_missing_resolutions(self):
        lead_no_resolutions = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
"""
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


def _parse_yaml_block(text: str) -> dict:
    import yaml
    for match in YAML_BLOCK_RE.finditer(text):
        doc = yaml.safe_load(match.group(1))
        if isinstance(doc, dict):
            return doc
    return {}


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
        hyp = yaml.safe_load(VALID_HYPOTHESIZE_YAML)
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
             "advance_to": "HYPOTHESIZE"},
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


# ---------------------------------------------------------------------------
# Unit tests: _check_route_compliance (warning channel)
# ---------------------------------------------------------------------------


def _merged_with_leads(leads):
    return {"gather": leads}


def _lead(name, predictions=None):
    return {
        "id": f"l-{name}", "loop": 1, "name": name, "target": "v-001",
        "query_details": {}, "outcome": {},
        "predictions": predictions,
        "resolutions": [],
    }


class TestCheckRouteCompliance:
    def test_no_predictions_is_silent(self):
        merged = _merged_with_leads([_lead("a"), _lead("b")])
        assert _check_route_compliance(merged) == []

    def test_next_lead_matches_advance_to(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "next-step"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("next-step")])
        assert _check_route_compliance(merged) == []

    def test_next_lead_mismatch_emits_warning(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "expected"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("actual-other")])
        warnings = _check_route_compliance(merged)
        assert warnings
        assert "actual-other" in warnings[0]
        assert "expected" in warnings[0]

    def test_terminal_lead_with_conclude_is_silent(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "CONCLUDE"}]
        merged = _merged_with_leads([_lead("first", preds)])
        assert _check_route_compliance(merged) == []

    def test_terminal_lead_without_conclude_warns(self):
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "next-step"}]
        merged = _merged_with_leads([_lead("first", preds)])
        warnings = _check_route_compliance(merged)
        assert warnings
        assert "terminal" in warnings[0].lower()

    def test_hypothesize_advance_does_not_require_next_lead(self):
        # advance_to HYPOTHESIZE is valid even on a terminal lead — the
        # companion may continue in a follow-up HYPOTHESIZE block elsewhere.
        # Here we check the non-terminal case: if next lead isn't HYPOTHESIZE-
        # flavored (which it won't be — phases aren't leads), that's still a
        # mismatch, and the warning is correct.
        preds = [{"id": "lp1", "if": "x", "read_as": "y", "advance_to": "HYPOTHESIZE"}]
        merged = _merged_with_leads([_lead("first", preds), _lead("some-other")])
        warnings = _check_route_compliance(merged)
        assert warnings


class TestCollectWarnings:
    def test_companion_with_route_warning(self):
        text = (
            "```yaml\n"
            "gather:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: first\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    predictions:\n"
            "      - id: lp1\n"
            "        if: x\n"
            "        read_as: y\n"
            "        advance_to: expected-next\n"
            "    resolutions: []\n"
            "  - id: l-002\n"
            "    loop: 1\n"
            "    name: actual-next\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome: {}\n"
            "    resolutions: []\n"
            "```\n"
        )
        warnings = collect_warnings(text)
        assert warnings
        assert "actual-next" in warnings[0]


# ---------------------------------------------------------------------------
# Unit tests: _check_append_only
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Unit tests: _check_prediction_coverage (rule 3 / spec-rule 6)
# ---------------------------------------------------------------------------


def _coverage_fixture(
    predictions: list[str],
    resolutions: list[tuple[str, list[str]]],
) -> dict:
    """Build a merged companion with one hypothesis and N resolutions.

    resolutions is a list of (after_weight, matched_prediction_ids).
    """
    return {
        "hypothesize": {
            "hypotheses": [{
                "id": "h-001",
                "name": "?test",
                "predictions": [{"id": p, "claim": f"claim {p}"} for p in predictions],
            }],
        },
        "gather": [{
            "id": f"l-00{i+1}", "loop": 1, "name": f"lead-{i+1}", "target": "v-001",
            "query_details": {}, "outcome": {},
            "resolutions": [{
                "hypothesis": "h-001", "after": after,
                "matched_prediction_ids": ids, "supporting_edges": [],
            }],
        } for i, (after, ids) in enumerate(resolutions)],
    }


class TestCheckPredictionCoverage:
    def test_pp_full_coverage_passes(self):
        merged = _coverage_fixture(["p1", "p2"], [("++", ["p1", "p2"])])
        assert _check_prediction_coverage(merged) == []

    def test_pp_partial_coverage_fails(self):
        merged = _coverage_fixture(["p1", "p2"], [("++", ["p1"])])
        errors = _check_prediction_coverage(merged)
        assert errors
        assert "p2" in errors[0]
        assert "++" in errors[0]

    def test_pp_across_multiple_resolutions_unions(self):
        merged = _coverage_fixture(
            ["p1", "p2"],
            [("+", ["p1"]), ("++", ["p2"])],
        )
        # Union across both resolutions covers {p1, p2} — the ++ is valid.
        assert _check_prediction_coverage(merged) == []

    def test_plus_does_not_require_coverage(self):
        merged = _coverage_fixture(["p1", "p2"], [("+", ["p1"])])
        assert _check_prediction_coverage(merged) == []

    def test_hypothesis_with_no_predictions_is_skipped(self):
        merged = _coverage_fixture([], [("++", [])])
        assert _check_prediction_coverage(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_partial_authority_cap (rule 6)
# ---------------------------------------------------------------------------


def _partial_authority_fixture(after: str, supporting_edges: list[str]) -> dict:
    return {
        "gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {},
            "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "approved-sources",
                    "kind": "org-authority",
                    "result": "confirmed",
                    "as_of": "2026-04-17T00:00:00Z",
                    "authority_for_question": "partial",
                },
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [{
                "hypothesis": "h-001", "after": after,
                "matched_prediction_ids": [], "matched_refutation_ids": [],
                "supporting_edges": supporting_edges,
            }],
        }],
    }


class TestCheckPartialAuthorityCap:
    def test_plus_with_partial_anchor_passes(self):
        merged = _partial_authority_fixture("+", [])
        assert _check_partial_authority_cap(merged) == []

    def test_pp_with_partial_anchor_only_fails(self):
        merged = _partial_authority_fixture("++", [])
        errors = _check_partial_authority_cap(merged)
        assert errors
        assert "partial" in errors[0]
        assert "++" in errors[0]

    def test_mm_with_partial_anchor_only_fails(self):
        merged = _partial_authority_fixture("--", [])
        errors = _check_partial_authority_cap(merged)
        assert errors

    def test_pp_with_partial_anchor_and_supporting_edge_passes(self):
        merged = _partial_authority_fixture("++", ["e-001"])
        assert _check_partial_authority_cap(merged) == []

    def test_full_authority_anchor_is_not_capped(self):
        merged = _partial_authority_fixture("++", [])
        merged["gather"][0]["outcome"]["trust_anchor_result"]["authority_for_question"] = "full"
        assert _check_partial_authority_cap(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_prediction_lifecycle (append-only on prediction IDs)
# ---------------------------------------------------------------------------


class TestCheckPredictionLifecycle:
    def _merged_with_predictions(self, prediction_ids: list[str], refutation_ids: list[str] | None = None) -> dict:
        h: dict = {
            "id": "h-001",
            "name": "?test",
            "predictions": [{"id": p, "claim": f"c{p}"} for p in prediction_ids],
        }
        if refutation_ids:
            h["refutation_shape"] = [{"id": r, "claim": f"r{r}"} for r in refutation_ids]
        return {"hypothesize": {"hypotheses": [h]}}

    def test_no_current_text_is_silent(self):
        proposed = self._merged_with_predictions(["p1", "p2"])
        assert _check_prediction_lifecycle(proposed, None) == []

    def test_no_change_passes(self):
        m = self._merged_with_predictions(["p1", "p2"])
        assert _check_prediction_lifecycle(m, m) == []

    def test_deleted_prediction_fails(self):
        current = self._merged_with_predictions(["p1", "p2", "p3"])
        proposed = self._merged_with_predictions(["p1", "p2"])  # p3 removed
        errors = _check_prediction_lifecycle(proposed, current)
        assert errors
        assert "p3" in errors[0]
        assert "h-001" in errors[0]

    def test_added_prediction_passes(self):
        current = self._merged_with_predictions(["p1"])
        proposed = self._merged_with_predictions(["p1", "p2"])  # p2 added
        assert _check_prediction_lifecycle(proposed, current) == []

    def test_deleted_refutation_fails(self):
        current = self._merged_with_predictions(["p1"], refutation_ids=["r1"])
        proposed = self._merged_with_predictions(["p1"], refutation_ids=[])
        errors = _check_prediction_lifecycle(proposed, current)
        assert errors
        assert "r1" in errors[0]
        assert "refutation" in errors[0].lower()

    def test_hypothesis_fully_removed_is_silent(self):
        # Block-level append-only handles this; we skip to avoid dup errors.
        current = self._merged_with_predictions(["p1", "p2"])
        proposed = {"hypothesize": {"hypotheses": []}}
        assert _check_prediction_lifecycle(proposed, current) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_rollup_parent_weight
# ---------------------------------------------------------------------------


def _hierarchy_fixture(parent_weight: str | None, child_weights: dict[str, str | None]) -> dict:
    hypotheses = [{"id": "h-001", "name": "?parent"}]
    for cid in child_weights:
        hypotheses.append({"id": cid, "name": f"?{cid}"})
    resolutions: list[dict] = []
    # One lead with resolutions for parent and each child (last one wins).
    if parent_weight is not None:
        resolutions.append({
            "hypothesis": "h-001", "after": parent_weight,
            "supporting_edges": ["e-001"], "matched_prediction_ids": [], "matched_refutation_ids": [],
        })
    for cid, w in child_weights.items():
        if w is None:
            continue
        resolutions.append({
            "hypothesis": cid, "after": w,
            "supporting_edges": ["e-001"], "matched_prediction_ids": [], "matched_refutation_ids": [],
        })
    return {
        "hypothesize": {"hypotheses": hypotheses},
        "gather": [{
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "query_details": {}, "outcome": {"observations": {"vertices": [], "edges": []}},
            "resolutions": resolutions,
        }],
    }


class TestCheckRollupParentWeight:
    def test_no_hierarchy_passes(self):
        merged = {"hypothesize": {"hypotheses": [{"id": "h-001"}]}, "gather": []}
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_le_child_passes(self):
        merged = _hierarchy_fixture("+", {"h-001-001": "++", "h-001-002": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_gt_all_children_fails(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "+", "h-001-002": "+"})
        errors = _check_rollup_parent_weight(merged)
        assert errors
        assert "h-001" in errors[0]
        assert "rollup" in errors[0].lower()

    def test_parent_unresolved_is_skipped(self):
        merged = _hierarchy_fixture(None, {"h-001-001": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_equal_to_max_child_passes(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "++", "h-001-002": "+"})
        assert _check_rollup_parent_weight(merged) == []

    def test_parent_pp_with_all_children_refuted_fails(self):
        merged = _hierarchy_fixture("++", {"h-001-001": "--", "h-001-002": "--"})
        errors = _check_rollup_parent_weight(merged)
        assert errors


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_dedup_warnings
# ---------------------------------------------------------------------------


def _dedup_lead(lead_id: str, template: str, query: str, subs: dict | None = None) -> dict:
    return {
        "id": lead_id, "loop": 1, "name": lead_id, "target": "v-001",
        "query_details": {
            "system": "wazuh",
            "template": template,
            "query": query,
            "time_window": "1h",
            "substitutions": subs or {},
        },
        "outcome": {},
        "resolutions": [],
    }


class TestCheckLeadDedup:
    def test_distinct_queries_silent(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:1.2.3.4"),
            _dedup_lead("l-002", "t1", "src_ip:5.6.7.8"),
        ]}
        assert _check_lead_dedup_warnings(merged) == []

    def test_duplicate_query_warns(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:1.2.3.4", {"ip": "1.2.3.4"}),
            _dedup_lead("l-002", "t1", "src_ip:1.2.3.4", {"ip": "1.2.3.4"}),
        ]}
        warnings = _check_lead_dedup_warnings(merged)
        assert warnings
        assert "l-002" in warnings[0]
        assert "l-001" in warnings[0]

    def test_same_query_different_subs_silent(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:${ip}", {"ip": "1.2.3.4"}),
            _dedup_lead("l-002", "t1", "src_ip:${ip}", {"ip": "5.6.7.8"}),
        ]}
        # Same query string but different substitutions = different effective
        # queries, not a dedup case.
        assert _check_lead_dedup_warnings(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_silent_empty_result_warnings
# ---------------------------------------------------------------------------


class TestCheckSilentEmpty:
    def _lead(self, tests, outcome):
        return {
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "tests": tests,
            "query_details": {}, "outcome": outcome,
            "resolutions": [],
        }

    def test_no_tests_silent(self):
        merged = {"gather": [self._lead([], {"observations": {"vertices": [], "edges": []}})]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_observations_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [{"id": "v-002"}], "edges": []}},
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_empty_outcome_warns(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [], "edges": []}},
        )]}
        warnings = _check_silent_empty_result_warnings(merged)
        assert warnings
        assert "l-001" in warnings[0]

    def test_tests_with_failure_reason_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [], "edges": []}, "failure_reason": "timeout"},
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_trust_anchor_result_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {
                "observations": {"vertices": [], "edges": []},
                "trust_anchor_result": {
                    "anchor_id": "x", "kind": "k", "result": "unavailable",
                    "as_of": "2026-04-17", "authority_for_question": "full",
                },
            },
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_attribute_updates_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {
                "observations": {"vertices": [], "edges": []},
                "attribute_updates": [{"target": "v-001", "updates": {"classification": "x"}}],
            },
        )]}
        assert _check_silent_empty_result_warnings(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_tool_audit_cross_ref_warnings
# ---------------------------------------------------------------------------


class TestCheckToolAuditCrossRef:
    def _make_run_with_audit(self, tmp_path: Path, entries: list[dict]) -> tuple[Path, Path]:
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "test-run"
        run_dir.mkdir(parents=True)
        audit_path = runs_dir / "tool_audit.jsonl"
        with open(audit_path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        return run_dir, audit_path

    def _lead_with_query(self, query: str) -> dict:
        return {
            "gather": [{
                "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
                "query_details": {
                    "system": "wazuh", "template": "t", "query": query,
                    "time_window": "1h", "substitutions": {},
                },
                "outcome": {}, "resolutions": [],
            }],
        }

    def test_missing_audit_file_silent(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "test-run"
        run_dir.mkdir(parents=True)
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_query_match_found_silent(self, tmp_path):
        entry = {
            "timestamp": "2026-04-17T00:00:00Z",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": 'wazuh-query "src_ip:203.0.113.47 AND agent.ip:10.0.0.50"'},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_no_query_match_warns(self, tmp_path):
        entry = {
            "timestamp": "2026-04-17T00:00:00Z",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        warnings = _check_tool_audit_cross_ref_warnings(merged, run_dir)
        assert warnings
        assert "l-001" in warnings[0]

    def test_short_query_skipped(self, tmp_path):
        run_dir, _ = self._make_run_with_audit(tmp_path, [{
            "session_id": "sess-1", "tool_name": "Bash", "tool_input": {"command": "echo"},
        }])
        merged = self._lead_with_query("a")  # too short
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_subagent_session_query_matches_globally(self, tmp_path):
        """Gather subagents log queries under their own session_id.

        The check must match across all sessions; a subagent-dispatched
        query should be found even though its session_id differs from
        the main agent's.
        """
        entry = {
            "session_id": "subagent-sess-xyz",
            "agent_id": "gather-subagent",
            "agent_type": "gather",
            "tool_name": "Bash",
            "tool_input": {"command": 'wazuh-query "src_ip:203.0.113.47 AND agent.ip:10.0.0.50"'},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_append_only
# ---------------------------------------------------------------------------


class TestCheckAppendOnly:
    def test_adding_block_passes(self):
        current = "## CONTEXTUALIZE\n\nsome prose\n"
        proposed = current + "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        assert _check_append_only(proposed, current) == []

    def test_same_count_passes(self):
        block = "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        assert _check_append_only(block, block) == []

    def test_removing_block_fails(self):
        block = "\n```yaml\nprologue:\n  vertices: []\n  edges: []\n```\n"
        current = block + block
        proposed = block  # one block removed
        errors = _check_append_only(proposed, current)
        assert errors
        assert "append-only" in errors[0]


# ---------------------------------------------------------------------------
# Unit tests: validate_companion (end-to-end)
# ---------------------------------------------------------------------------


class TestValidateCompanion:
    def test_no_yaml_blocks_passes(self):
        text = "## CONTEXTUALIZE\n\nsome prose only\n"
        assert validate_companion(text, None) == []

    def test_valid_full_companion_passes(self):
        assert validate_companion(FULL_COMPANION_MD, None) == []

    def test_yaml_parse_error_caught(self):
        text = "## CONTEXTUALIZE\n\n```yaml\n: invalid: yaml: [\n```\n"
        errors = validate_companion(text, None)
        assert any("parse error" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# Integration tests (subprocess)
# ---------------------------------------------------------------------------


def _run_hook(
    content: str,
    tool_name: str = "Write",
    tmp_path: Path | None = None,
    existing_content: str | None = None,
) -> subprocess.CompletedProcess:
    """Simulate a PreToolUse event for investigation.md."""
    # Use a tmp path that looks like a real run dir
    if tmp_path is None:
        import tempfile
        tmp_path = Path(tempfile.mkdtemp())

    runs_dir = tmp_path / "runs"
    run_dir = runs_dir / "test-run"
    run_dir.mkdir(parents=True, exist_ok=True)
    inv_path = run_dir / "investigation.md"

    if existing_content is not None:
        inv_path.write_text(existing_content)

    if tool_name == "Write":
        tool_input: dict = {"file_path": str(inv_path), "content": content}
    else:  # Edit
        old = existing_content or ""
        tool_input = {
            "file_path": str(inv_path),
            "old_string": old,
            "new_string": content,
        }

    event = json.dumps({"tool_name": tool_name, "tool_input": tool_input})
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env={**__import__("os").environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)},
    )


class TestHookIntegration:
    def test_no_yaml_blocks_passes(self, tmp_path):
        result = _run_hook("## CONTEXTUALIZE\n\nsome prose\n", tmp_path=tmp_path)
        assert result.returncode == 0

    def test_valid_prologue_passes(self, tmp_path):
        content = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_valid_full_companion_passes(self, tmp_path):
        result = _run_hook(FULL_COMPANION_MD, tmp_path=tmp_path)
        assert result.returncode == 0, result.stderr

    def test_missing_lead_field_fails(self, tmp_path):
        bad_lead = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    # resolutions missing
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_lead}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "resolutions" in result.stderr

    def test_pp_missing_supporting_edges_fails(self, tmp_path):
        prologue_content = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        lead_no_edges = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    resolutions:
      - hypothesis: h-001
        before: null
        after: "++"
        severity_of_test: severe
        matched_prediction_ids: [p1]
        matched_refutation_ids: []
        reasoning: "strong evidence"
        supporting_edges: []
"""
        content = prologue_content + f"\n```yaml\n{lead_no_edges}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "supporting_edges" in result.stderr

    def test_mm_missing_refutation_ids_fails(self, tmp_path):
        bad_resolution = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges:
          - id: e-003
            relation: attempted_auth
            source_vertex: v-001
            target_vertex: v-002
            authority:
              kind: siem-event
              source: wazuh
    resolutions:
      - hypothesis: h-001
        before: null
        after: "--"
        severity_of_test: severe
        matched_prediction_ids: []
        matched_refutation_ids: []
        reasoning: "contradicts prediction"
        supporting_edges: [e-003]
"""
        prologue = f"```yaml\n{VALID_PROLOGUE_YAML}```\n"
        content = f"## CONTEXTUALIZE\n\n{prologue}\n## ANALYZE\n\n```yaml\n{bad_resolution}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "matched_refutation_ids" in result.stderr

    def test_trust_anchor_incomplete_fails(self, tmp_path):
        incomplete_tar = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      trust_anchor_result:
        anchor_id: approved-sources
        kind: org-authority
        # missing: result, as_of, authority_for_question
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{incomplete_tar}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "trust_anchor_result" in result.stderr

    def test_screen_result_on_non_screen_lead_fails(self, tmp_path):
        bad_screen = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-001
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      screen_result: no_match
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_screen}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "screen_result" in result.stderr

    def test_append_only_removing_block_fails(self, tmp_path):
        existing = f"## CONTEXTUALIZE\n\n```yaml\n{VALID_PROLOGUE_YAML}```\n"
        # Proposed content replaces the prologue block with nothing
        proposed = "## CONTEXTUALIZE\n\nsome prose only\n"
        result = _run_hook(
            content=proposed,
            tool_name="Write",
            tmp_path=tmp_path,
            existing_content=existing,
        )
        assert result.returncode == 2
        assert "append-only" in result.stderr

    def test_yaml_parse_error_fails(self, tmp_path):
        content = "## CONTEXTUALIZE\n\n```yaml\n: invalid: [\n```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "parse error" in result.stderr.lower()

    def test_dangling_id_reference_fails(self, tmp_path):
        # Lead targets v-999 which is not declared
        bad_ref = """\
gather:
  - id: l-001
    loop: 1
    name: test
    target: v-999
    query_details:
      system: wazuh
      template: t
      query: q
      time_window: 1h
      substitutions: {}
    outcome:
      observations:
        vertices: []
        edges: []
    resolutions: []
"""
        content = f"## ANALYZE\n\n```yaml\n{bad_ref}```\n"
        result = _run_hook(content, tmp_path=tmp_path)
        assert result.returncode == 2
        assert "v-999" in result.stderr


# ---------------------------------------------------------------------------
# Legitimacy rules (spec v2.8, rules #19–#22)
# ---------------------------------------------------------------------------


def _companion_with_contract(
    contract_edge_ref: str = "proposed",
    contract_id: str = "lc1",
    resolutions: list[dict] | None = None,
    disposition: str = "benign",
    hypothesis_weight: str = "+",
    extra_edges: list[dict] | None = None,
    trust_anchor_result: dict | None = None,
) -> dict:
    """Build a merged companion carrying one hypothesis with one legitimacy_contract.

    Post-migration shape: `legitimacy_resolutions[]` lives in
    `gather[0].outcome.legitimacy_resolutions[]` as a sibling of
    `attribute_updates`. The lead also carries a `trust_anchor_result`
    with `asks: authorization` and `verdict: authorized` — resolutions
    must be backed by an explicit authority consultation.

    Defaults shape a live-weight benign resolution with one `authorized`
    verdict targeting edge e-002. Override parameters to flip individual
    dimensions for negative cases.
    """
    edges = [
        {
            "id": "e-001",
            "relation": "attempted_auth",
            "source_vertex": "v-001",
            "target_vertex": "v-002",
            "authority": {"kind": "siem-event", "source": "wazuh"},
        }
    ]
    if extra_edges:
        edges.extend(extra_edges)
    observed_edge = {
        "id": "e-002",
        "relation": "classified_as",
        "source_vertex": "v-001",
        "target_vertex": "v-002",
        "authority": {"kind": "authoritative-source", "source": "registry"},
    }
    default_resolutions = [
        {
            "id": "lr1",
            "target": "e-002",
            "fulfills_contract": f"h-001.{contract_id}",
            "verdict": "authorized",
        }
    ]
    default_tar = {
        "anchor_id": "approved-monitoring-sources",
        "anchor_name": "approved-monitoring-sources",
        "kind": "org-authority",
        "asks": "authorization",
        "verdict": "authorized",
        "result": "confirmed",
        "as_of": "2026-04-18T00:00:00Z",
        "authority_for_question": "full",
    }
    return {
        "prologue": {
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "external"},
                {"id": "v-002", "type": "endpoint", "classification": "internal"},
            ],
            "edges": edges,
        },
        "hypothesize": {
            "hypotheses": [
                {
                    "id": "h-001",
                    "name": "?source-authorization-unknown",
                    "attached_to_vertex": "v-001",
                    "proposed_edge": {
                        "relation": "attempted_auth",
                        "parent_vertex": {"type": "identity", "classification": "unknown"},
                    },
                    "predictions": [{"id": "p1", "claim": "source resolves to an approved entry"}],
                    "legitimacy_contract": [
                        {
                            "id": contract_id,
                            "edge_ref": contract_edge_ref,
                            "anchor_kind": "approved-monitoring-sources",
                            "predicate": "authorized iff srcip in approved-monitoring-sources",
                            "on_unauthorized": "escalate",
                            "on_indeterminate": "escalate",
                        }
                    ],
                }
            ]
        },
        "gather": [
            {
                "id": "l-001",
                "loop": 1,
                "name": "trust-anchor-lookup",
                "target": "v-001",
                "query_details": {},
                "outcome": {
                    "observations": {"vertices": [], "edges": [observed_edge]},
                    "trust_anchor_result": (
                        trust_anchor_result
                        if trust_anchor_result is not None
                        else default_tar
                    ),
                    "legitimacy_resolutions": (
                        resolutions if resolutions is not None else default_resolutions
                    ),
                },
                "resolutions": [
                    {
                        "hypothesis": "h-001",
                        "after": hypothesis_weight,
                        "severity_of_test": "severe",
                        "matched_prediction_ids": ["p1"],
                        "matched_refutation_ids": [],
                        "reasoning": "anchor lookup resolved",
                        "supporting_edges": ["e-002"],
                    }
                ],
            }
        ],
        "conclude": {
            "termination": {"category": "trust-root", "rationale": "contract resolved"},
            "disposition": disposition,
            "confidence": "high",
        },
    }


class TestCheckLegitimacyContractEdgeRef:
    def test_valid_proposed(self):
        merged = _companion_with_contract(contract_edge_ref="proposed")
        assert _check_legitimacy_contract_edge_ref(merged) == []

    def test_valid_existing_edge(self):
        merged = _companion_with_contract(contract_edge_ref="e-001")
        assert _check_legitimacy_contract_edge_ref(merged) == []

    def test_unknown_edge_ref(self):
        merged = _companion_with_contract(contract_edge_ref="e-999")
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("e-999" in e and "not a declared edge" in e for e in errors)

    def test_bad_id_pattern(self):
        merged = _companion_with_contract(contract_id="legit1")
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("^lc\\d+$" in e for e in errors)

    def test_missing_edge_ref(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["legitimacy_contract"][0].pop("edge_ref")
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("missing edge_ref" in e for e in errors)

    def test_non_edge_string(self):
        merged = _companion_with_contract(contract_edge_ref="v-001")
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("must be 'proposed' or an e-* id" in e for e in errors)

    def test_missing_id(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["legitimacy_contract"][0].pop("id")
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("missing id" in e for e in errors)

    def test_non_string_id(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["legitimacy_contract"][0]["id"] = 1
        errors = _check_legitimacy_contract_edge_ref(merged)
        assert any("id must be a string" in e for e in errors)


class TestCheckLegitimacyResolutionBackrefs:
    def test_valid_backref(self):
        merged = _companion_with_contract()
        assert _check_legitimacy_resolution_backrefs(merged) == []

    def test_unknown_contract(self):
        merged = _companion_with_contract(
            resolutions=[{
                "verdict": "authorized",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-999.lc1",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("does not resolve" in e for e in errors)

    def test_bad_shape(self):
        merged = _companion_with_contract(
            resolutions=[{
                "verdict": "authorized",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "not-a-reference",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("must be of shape" in e for e in errors)

    def test_missing_backref(self):
        merged = _companion_with_contract(
            resolutions=[{
                "verdict": "authorized",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("missing fulfills_contract" in e for e in errors)

    def test_missing_verdict(self):
        merged = _companion_with_contract(
            resolutions=[{
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("missing verdict" in e for e in errors)

    def test_non_string_verdict(self):
        merged = _companion_with_contract(
            resolutions=[{
                "verdict": 1,
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("verdict must be a string" in e for e in errors)

    def test_bad_verdict(self):
        merged = _companion_with_contract(
            resolutions=[{
                "verdict": "maybe",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }]
        )
        errors = _check_legitimacy_resolution_backrefs(merged)
        assert any("verdict 'maybe'" in e for e in errors)


class TestCheckLegitimacyGatedDisposition:
    def test_benign_with_authorized(self):
        merged = _companion_with_contract(disposition="benign")
        assert _check_legitimacy_gated_disposition(merged) == []

    def test_benign_with_unfulfilled_contract(self):
        merged = _companion_with_contract(disposition="benign", resolutions=[])
        errors = _check_legitimacy_gated_disposition(merged)
        assert any("no fulfilling legitimacy_resolutions" in e for e in errors)

    def test_benign_with_indeterminate_only_fails(self):
        merged = _companion_with_contract(
            disposition="benign",
            resolutions=[{
                "verdict": "indeterminate",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }],
        )
        errors = _check_legitimacy_gated_disposition(merged)
        assert any("'indeterminate'" in e and "Escalate instead" in e for e in errors)

    def test_unauthorized_with_benign_fails(self):
        merged = _companion_with_contract(
            disposition="benign",
            resolutions=[{
                "verdict": "unauthorized",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }],
        )
        errors = _check_legitimacy_gated_disposition(merged)
        assert any("'unauthorized'" in e and "Escalate instead" in e for e in errors)

    def test_unauthorized_with_true_positive_ok(self):
        merged = _companion_with_contract(
            disposition="true_positive",
            resolutions=[{
                "verdict": "unauthorized",
                "anchor_kind": "x",
                "anchor_query": "q",
                "as_of": "2026-04-18",
                "resolved_by_lead": "l-001",
                "fulfills_contract": "h-001.lc1",
            }],
        )
        assert _check_legitimacy_gated_disposition(merged) == []

    def test_indeterminate_with_non_benign_ok(self):
        """Rule intentionally tolerant to 'unclear' vs 'inconclusive' vocabulary.

        The spec names 'unclear' as the escalation disposition, but the report
        frontmatter still uses 'inconclusive' / 'escalated' in the same slot.
        As long as disposition is not 'benign', indeterminate-only contracts
        pass.
        """
        for disp in ("unclear", "inconclusive", "true_positive", "escalated"):
            merged = _companion_with_contract(
                disposition=disp,
                resolutions=[{
                    "verdict": "indeterminate",
                    "anchor_kind": "x",
                    "anchor_query": "q",
                    "as_of": "2026-04-18",
                    "resolved_by_lead": "l-001",
                    "fulfills_contract": "h-001.lc1",
                }],
            )
            assert _check_legitimacy_gated_disposition(merged) == [], disp

    def test_no_conclude_block_passes(self):
        merged = _companion_with_contract()
        merged.pop("conclude", None)
        assert _check_legitimacy_gated_disposition(merged) == []

    def test_hypothesis_refuted_skips_check(self):
        merged = _companion_with_contract(
            disposition="benign",
            hypothesis_weight="--",
            resolutions=[],
        )
        # Matched_refutation_ids must be present for --; the refutation check
        # is covered by other tests, so just wire up a minimal id pair.
        merged["hypothesize"]["hypotheses"][0]["refutation_shape"] = [{"id": "r1", "claim": "x"}]
        merged["gather"][0]["resolutions"][0]["matched_refutation_ids"] = ["r1"]
        assert _check_legitimacy_gated_disposition(merged) == []


class TestCheckAttributeUpdatesTargetShape:
    def _merged_with_update(self, update: dict) -> dict:
        return {
            "prologue": {
                "vertices": [{"id": "v-001", "type": "endpoint"}],
                "edges": [{"id": "e-001", "relation": "attempted_auth"}],
            },
            "gather": [
                {
                    "id": "l-001",
                    "loop": 1,
                    "name": "t",
                    "target": "v-001",
                    "query_details": {},
                    "outcome": {"attribute_updates": [update]},
                    "resolutions": [],
                }
            ],
        }

    def test_valid_vertex_target(self):
        merged = self._merged_with_update({"target": "v-001", "updates": {"classification": "x"}})
        assert _check_attribute_updates_target_shape(merged) == []

    def test_valid_edge_target(self):
        merged = self._merged_with_update({"target": "e-001", "updates": {"note": "y"}})
        assert _check_attribute_updates_target_shape(merged) == []

    def test_legacy_vertex_field_rejected(self):
        merged = self._merged_with_update({"vertex": "v-001", "updates": {"classification": "x"}})
        errors = _check_attribute_updates_target_shape(merged)
        assert any("legacy `vertex:` field" in e for e in errors)

    def test_missing_target(self):
        merged = self._merged_with_update({"updates": {"classification": "x"}})
        errors = _check_attribute_updates_target_shape(merged)
        assert any("missing `target:`" in e for e in errors)

    def test_bad_prefix(self):
        merged = self._merged_with_update({"target": "h-001", "updates": {"classification": "x"}})
        errors = _check_attribute_updates_target_shape(merged)
        assert any("'v-' or 'e-'" in e for e in errors)

    def test_unknown_id(self):
        merged = self._merged_with_update({"target": "v-999", "updates": {"classification": "x"}})
        errors = _check_attribute_updates_target_shape(merged)
        assert any("does not resolve" in e for e in errors)

    def test_missing_updates(self):
        merged = self._merged_with_update({"target": "v-001"})
        errors = _check_attribute_updates_target_shape(merged)
        assert any("missing or non-mapping `updates`" in e for e in errors)


# ---------------------------------------------------------------------------
# Authority-consultation primitive (v2.9): asks / verdict / supersede chain
# ---------------------------------------------------------------------------


class TestCheckAsksVerdictShape:
    """trust_anchor_result.asks discriminator gates the verdict field."""

    def test_authorization_with_verdict_passes(self):
        merged = _companion_with_contract()  # default TAR has asks:authorization + verdict:authorized
        assert _check_asks_verdict_shape(merged) == []

    def test_authorization_without_verdict_fails(self):
        merged = _companion_with_contract()
        merged["gather"][0]["outcome"]["trust_anchor_result"].pop("verdict")
        errors = _check_asks_verdict_shape(merged)
        assert any("authorization" in e and "verdict is missing" in e for e in errors)

    def test_expectation_with_verdict_fails(self):
        merged = _companion_with_contract(
            trust_anchor_result={
                "anchor_id": "image-baseline",
                "kind": "telemetry-baseline",
                "asks": "expectation",
                "verdict": "authorized",  # category error
                "result": "confirmed",
                "as_of": "2026-04-18T00:00:00Z",
                "authority_for_question": "full",
            },
            resolutions=[],  # expectation anchors don't emit resolutions
        )
        errors = _check_asks_verdict_shape(merged)
        assert any("baselines don't authorize" in e for e in errors)

    def test_unknown_asks_value_fails(self):
        merged = _companion_with_contract()
        merged["gather"][0]["outcome"]["trust_anchor_result"]["asks"] = "guess"
        errors = _check_asks_verdict_shape(merged)
        assert any("asks must be one of" in e for e in errors)

    def test_unknown_verdict_value_fails(self):
        merged = _companion_with_contract()
        merged["gather"][0]["outcome"]["trust_anchor_result"]["verdict"] = "maybe"
        errors = _check_asks_verdict_shape(merged)
        assert any("verdict 'maybe' not in" in e for e in errors)

    def test_authorization_unavailable_with_indeterminate_passes(self):
        """asks:authorization + result:unavailable is fine as long as the lead
        commits to verdict:indeterminate — the anchor had no data, but the
        consultation is still honest."""
        merged = _companion_with_contract()
        tar = merged["gather"][0]["outcome"]["trust_anchor_result"]
        tar["result"] = "unavailable"
        tar["verdict"] = "indeterminate"
        tar["authority_for_question"] = "partial"
        # Non-benign disposition since the contract is unresolved-authorized:
        merged["conclude"]["disposition"] = "inconclusive"
        merged["gather"][0]["outcome"]["legitimacy_resolutions"][0]["verdict"] = "indeterminate"
        assert _check_asks_verdict_shape(merged) == []

    def test_legacy_tar_without_asks_passes(self):
        """A TAR that predates v2.9 (no asks field) isn't flagged by this rule
        — it's still legal under the completeness check. Only coherence is
        enforced when asks IS present."""
        merged = _companion_with_contract(
            trust_anchor_result={
                "anchor_id": "approved-monitoring-sources",
                "kind": "org-authority",
                "result": "confirmed",
                "as_of": "2026-04-18T00:00:00Z",
                "authority_for_question": "full",
            },
        )
        assert _check_asks_verdict_shape(merged) == []


class TestCheckKindAsksCoherence:
    """kind: telemetry-baseline ⇒ asks: expectation. Baselines don't authorize."""

    def test_org_authority_with_authorization_passes(self):
        merged = _companion_with_contract()
        assert _check_kind_asks_coherence(merged) == []

    def test_telemetry_baseline_with_expectation_passes(self):
        merged = _companion_with_contract(
            trust_anchor_result={
                "anchor_id": "image-baseline",
                "kind": "telemetry-baseline",
                "asks": "expectation",
                "result": "confirmed",
                "as_of": "2026-04-18T00:00:00Z",
                "authority_for_question": "full",
            },
            resolutions=[],
        )
        assert _check_kind_asks_coherence(merged) == []

    def test_telemetry_baseline_with_authorization_fails(self):
        merged = _companion_with_contract(
            trust_anchor_result={
                "anchor_id": "image-baseline",
                "kind": "telemetry-baseline",
                "asks": "authorization",
                "verdict": "authorized",
                "result": "confirmed",
                "as_of": "2026-04-18T00:00:00Z",
                "authority_for_question": "full",
            },
        )
        errors = _check_kind_asks_coherence(merged)
        assert any("telemetry-baseline" in e and "expectation" in e for e in errors)


class TestCheckResolutionTargetShape:
    """gather[].outcome.legitimacy_resolutions[].target is v-*/e-* and declared."""

    def test_valid_edge_target_passes(self):
        merged = _companion_with_contract()  # default targets e-002
        assert _check_legitimacy_resolution_target_shape(merged) == []

    def test_vertex_target_passes(self):
        """A lead consulting an oncall-roster vertex can resolve an edge-scoped
        contract by writing verdict against either a vertex or an edge — the
        plan's open-q #1 leaned 'both allowed' to mirror attribute_updates."""
        merged = _companion_with_contract(
            resolutions=[{
                "id": "lr1",
                "target": "v-001",
                "fulfills_contract": "h-001.lc1",
                "verdict": "authorized",
            }],
        )
        assert _check_legitimacy_resolution_target_shape(merged) == []

    def test_missing_target_fails(self):
        merged = _companion_with_contract(
            resolutions=[{
                "id": "lr1",
                "fulfills_contract": "h-001.lc1",
                "verdict": "authorized",
            }],
        )
        errors = _check_legitimacy_resolution_target_shape(merged)
        assert any("missing `target:`" in e for e in errors)

    def test_unknown_id_fails(self):
        merged = _companion_with_contract(
            resolutions=[{
                "id": "lr1",
                "target": "e-999",
                "fulfills_contract": "h-001.lc1",
                "verdict": "authorized",
            }],
        )
        errors = _check_legitimacy_resolution_target_shape(merged)
        assert any("e-999" in e and "does not resolve" in e for e in errors)

    def test_bad_prefix_fails(self):
        merged = _companion_with_contract(
            resolutions=[{
                "id": "lr1",
                "target": "h-001",
                "fulfills_contract": "h-001.lc1",
                "verdict": "authorized",
            }],
        )
        errors = _check_legitimacy_resolution_target_shape(merged)
        assert any("must start with 'v-' or 'e-'" in e for e in errors)

    def test_legacy_vertex_field_rejected(self):
        merged = _companion_with_contract(
            resolutions=[{
                "id": "lr1",
                "vertex": "v-001",  # legacy key
                "fulfills_contract": "h-001.lc1",
                "verdict": "authorized",
            }],
        )
        errors = _check_legitimacy_resolution_target_shape(merged)
        assert any("legacy `vertex:`" in e for e in errors)

    def test_lead_target_differs_from_resolution_target(self):
        """A lead with target:v-003 can still emit a resolution targeting e-001
        — the lead's target is 'what I'm asking about', the resolution's
        target is 'which graph element this verdict refines.'"""
        merged = _companion_with_contract()
        merged["gather"][0]["target"] = "v-001"  # lead asks about v-001
        merged["gather"][0]["outcome"]["legitimacy_resolutions"][0]["target"] = "e-001"  # verdict on e-001
        assert _check_legitimacy_resolution_target_shape(merged) == []


class TestLegitimacyCoOccurrence:
    """A lead emitting legitimacy_resolutions[] must have TAR.asks: authorization."""

    def test_resolution_without_tar_fails(self):
        merged = _companion_with_contract()
        merged["gather"][0]["outcome"].pop("trust_anchor_result")
        errors = _check_resolution_requires_authorization_asks(merged)
        assert any("no trust_anchor_result" in e for e in errors)

    def test_tar_without_asks_fails(self):
        merged = _companion_with_contract()
        merged["gather"][0]["outcome"]["trust_anchor_result"].pop("asks")
        errors = _check_resolution_requires_authorization_asks(merged)
        assert any("asks is not set" in e for e in errors)

    def test_asks_expectation_with_resolution_fails(self):
        merged = _companion_with_contract()
        tar = merged["gather"][0]["outcome"]["trust_anchor_result"]
        tar["asks"] = "expectation"
        tar.pop("verdict", None)
        errors = _check_resolution_requires_authorization_asks(merged)
        assert any("asks is 'expectation'" in e for e in errors)


class TestLegitimacySupersedeChain:
    """Supersede chain invariants: id pattern, same contract+target, no cycles."""

    def _with_chain(self, chain: list[dict]) -> dict:
        """Replace default single resolution with a multi-entry chain."""
        return _companion_with_contract(resolutions=chain)

    def test_two_way_supersede_passes(self):
        """Loop-1 indeterminate, loop-2 authorized supersedes it → benign OK."""
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "indeterminate"},
            {"id": "lr2", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized",
             "supersedes": "lr1"},
        ])
        assert _check_legitimacy_supersede_chain(merged) == []
        # And rule #21 should pass (effective verdict is authorized):
        assert _check_legitimacy_gated_disposition(merged) == []

    def test_chain_of_three_picks_latest(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "indeterminate"},
            {"id": "lr2", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "unauthorized",
             "supersedes": "lr1"},
            {"id": "lr3", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized",
             "supersedes": "lr2"},
        ])
        assert _check_legitimacy_supersede_chain(merged) == []
        assert _check_legitimacy_gated_disposition(merged) == []

    def test_dangling_supersede_fails(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized",
             "supersedes": "lr99"},  # no such entry
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("lr99" in e and "does not resolve" in e for e in errors)

    def test_cross_contract_supersede_fails(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized"},
            {"id": "lr2", "target": "e-002",
             "fulfills_contract": "h-001.lc2", "verdict": "authorized",  # different contract
             "supersedes": "lr1"},
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("contract-scoped" in e for e in errors)

    def test_cross_target_supersede_fails(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-001",
             "fulfills_contract": "h-001.lc1", "verdict": "indeterminate"},
            {"id": "lr2", "target": "e-002",  # different target
             "fulfills_contract": "h-001.lc1", "verdict": "authorized",
             "supersedes": "lr1"},
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("target-scoped" in e for e in errors)

    def test_cycle_detected(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized",
             "supersedes": "lr2"},
            {"id": "lr2", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "unauthorized",
             "supersedes": "lr1"},
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("cycle" in e for e in errors)

    def test_duplicate_lr_id_fails(self):
        merged = self._with_chain([
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized"},
            {"id": "lr1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "unauthorized"},
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("already used" in e for e in errors)

    def test_bad_lr_id_pattern_fails(self):
        merged = self._with_chain([
            {"id": "legit-1", "target": "e-002",
             "fulfills_contract": "h-001.lc1", "verdict": "authorized"},
        ])
        errors = _check_legitimacy_supersede_chain(merged)
        assert any("^lr\\d+$" in e for e in errors)


class TestLegitimacyCrossContract:
    """Two contracts on same hypothesis resolving differently — each is gated independently."""

    def test_lc1_authorized_lc2_unauthorized_rejects_benign(self):
        merged = _companion_with_contract()
        # Add a second contract lc2
        merged["hypothesize"]["hypotheses"][0]["legitimacy_contract"].append({
            "id": "lc2",
            "edge_ref": "proposed",
            "anchor_kind": "change-management",
            "predicate": "authorized iff ticket approved",
            "on_unauthorized": "escalate",
            "on_indeterminate": "escalate",
        })
        # Add lr-2 resolving lc2 = unauthorized in a second lead
        merged["gather"].append({
            "id": "l-002", "loop": 1, "name": "cm-ticket-lookup",
            "target": "v-001", "query_details": {},
            "outcome": {
                "trust_anchor_result": {
                    "anchor_id": "change-management",
                    "kind": "org-authority",
                    "asks": "authorization",
                    "verdict": "unauthorized",
                    "result": "confirmed",
                    "as_of": "2026-04-18T01:00:00Z",
                    "authority_for_question": "full",
                },
                "legitimacy_resolutions": [{
                    "id": "lr2", "target": "e-002",
                    "fulfills_contract": "h-001.lc2", "verdict": "unauthorized",
                }],
                "observations": {"vertices": [], "edges": []},
            },
            "resolutions": [],
        })
        errors = _check_legitimacy_gated_disposition(merged)
        assert any("lc2" in e and "unauthorized" in e for e in errors)
