"""Unit tests for authorization-as-edge-attribute invlang checks (rules 19-22).

Covers: contract edge_ref, resolution back-refs, benign-disposition gating,
attribute_updates target shape.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_attribute_updates_target_shape,
    _check_authorization_contract_edge_ref,
    _check_authorization_gated_disposition,
    _check_authorization_resolution_backrefs,
)

from tests.test_invlang_validate import _companion_with_contract


def _base_resolution(**over) -> dict:
    """Build an authorization_resolutions[] entry with all required fields.

    Individual test cases override specific fields to trigger targeted
    failures (e.g. setting `verdict` to an invalid value).
    """
    entry = {
        "verdict": "authorized",
        "anchor_kind": "approved-monitoring-sources",
        "anchor_id": "ams-2026-01",
        "grounding_kind": "org-authority",
        "authority_for_question": "full",
        "anchor_query": "source triple lookup",
        "as_of": "2026-04-18T00:00:00Z",
        "resolved_by_lead": "l-001",
        "fulfills_contract": "h-001.ac1",
    }
    entry.update(over)
    return entry


class TestCheckAuthorizationContractEdgeRef:
    def test_valid_proposed(self):
        merged = _companion_with_contract(contract_edge_ref="proposed")
        assert _check_authorization_contract_edge_ref(merged) == []

    def test_valid_existing_edge(self):
        merged = _companion_with_contract(contract_edge_ref="e-001")
        assert _check_authorization_contract_edge_ref(merged) == []

    def test_unknown_edge_ref(self):
        merged = _companion_with_contract(contract_edge_ref="e-999")
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("e-999" in e and "not a declared edge" in e for e in errors)

    def test_bad_id_pattern(self):
        merged = _companion_with_contract(contract_id="authz1")
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("^ac\\d+$" in e for e in errors)

    def test_missing_edge_ref(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["authorization_contract"][0].pop("edge_ref")
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("missing edge_ref" in e for e in errors)

    def test_non_edge_string(self):
        merged = _companion_with_contract(contract_edge_ref="v-001")
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("must be 'proposed' or an e-* id" in e for e in errors)

    def test_missing_id(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["authorization_contract"][0].pop("id")
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("missing id" in e for e in errors)

    def test_non_string_id(self):
        merged = _companion_with_contract()
        merged["hypothesize"]["hypotheses"][0]["authorization_contract"][0]["id"] = 1
        errors = _check_authorization_contract_edge_ref(merged)
        assert any("id must be a string" in e for e in errors)


class TestCheckAuthorizationResolutionBackrefs:
    def test_valid_backref(self):
        merged = _companion_with_contract()
        assert _check_authorization_resolution_backrefs(merged) == []

    def test_unknown_contract(self):
        merged = _companion_with_contract(
            resolutions=[_base_resolution(fulfills_contract="h-999.ac1")]
        )
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("does not resolve" in e for e in errors)

    def test_bad_shape(self):
        merged = _companion_with_contract(
            resolutions=[_base_resolution(fulfills_contract="not-a-reference")]
        )
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("must be of shape" in e for e in errors)

    def test_missing_backref(self):
        entry = _base_resolution()
        entry.pop("fulfills_contract")
        merged = _companion_with_contract(resolutions=[entry])
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("missing fulfills_contract" in e for e in errors)

    def test_missing_verdict(self):
        entry = _base_resolution()
        entry.pop("verdict")
        merged = _companion_with_contract(resolutions=[entry])
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("missing verdict" in e for e in errors)

    def test_non_string_verdict(self):
        merged = _companion_with_contract(
            resolutions=[_base_resolution(verdict=1)]
        )
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("verdict must be a string" in e for e in errors)

    def test_bad_verdict(self):
        merged = _companion_with_contract(
            resolutions=[_base_resolution(verdict="maybe")]
        )
        errors = _check_authorization_resolution_backrefs(merged)
        assert any("'maybe'" in e for e in errors)


class TestCheckAuthorizationGatedDisposition:
    def test_benign_with_authorized(self):
        merged = _companion_with_contract(disposition="benign")
        assert _check_authorization_gated_disposition(merged) == []

    def test_benign_with_unfulfilled_contract(self):
        merged = _companion_with_contract(disposition="benign", resolutions=[])
        errors = _check_authorization_gated_disposition(merged)
        assert any("no fulfilling authorization_resolutions" in e for e in errors)

    def test_benign_with_indeterminate_only_fails(self):
        merged = _companion_with_contract(
            disposition="benign",
            resolutions=[_base_resolution(verdict="indeterminate")],
        )
        errors = _check_authorization_gated_disposition(merged)
        assert any("'indeterminate'" in e and "Escalate instead" in e for e in errors)

    def test_unauthorized_with_benign_fails(self):
        merged = _companion_with_contract(
            disposition="benign",
            resolutions=[_base_resolution(verdict="unauthorized")],
        )
        errors = _check_authorization_gated_disposition(merged)
        assert any("'unauthorized'" in e and "Escalate instead" in e for e in errors)

    def test_unauthorized_with_true_positive_ok(self):
        merged = _companion_with_contract(
            disposition="true_positive",
            resolutions=[_base_resolution(verdict="unauthorized")],
        )
        assert _check_authorization_gated_disposition(merged) == []

    def test_indeterminate_with_non_benign_ok(self):
        """Non-benign dispositions tolerate indeterminate contracts."""
        for disp in ("unclear", "true_positive"):
            merged = _companion_with_contract(
                disposition=disp,
                resolutions=[_base_resolution(verdict="indeterminate")],
            )
            assert _check_authorization_gated_disposition(merged) == [], disp

    def test_no_conclude_block_passes(self):
        merged = _companion_with_contract()
        merged.pop("conclude", None)
        assert _check_authorization_gated_disposition(merged) == []

    def test_hypothesis_refuted_skips_check(self):
        merged = _companion_with_contract(
            disposition="benign",
            hypothesis_weight="--",
            resolutions=[],
        )
        merged["hypothesize"]["hypotheses"][0]["refutation_shape"] = [{"id": "r1", "claim": "x"}]
        merged["findings"][0]["resolutions"][0]["matched_refutation_ids"] = ["r1"]
        assert _check_authorization_gated_disposition(merged) == []


class TestCheckAttributeUpdatesTargetShape:
    def _merged_with_update(self, update: dict) -> dict:
        return {
            "prologue": {
                "vertices": [{"id": "v-001", "type": "endpoint"}],
                "edges": [{"id": "e-001", "relation": "attempted_auth"}],
            },
            "findings": [
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


class TestAuthorizationCrossContract:
    """Two contracts on one hypothesis resolving differently — each is gated independently."""

    def test_ac1_authorized_ac2_unauthorized_rejects_benign(self):
        merged = _companion_with_contract()
        # Add a second contract ac2 on the same hypothesis.
        merged["hypothesize"]["hypotheses"][0]["authorization_contract"].append({
            "id": "ac2",
            "edge_ref": "proposed",
            "anchor_kind": "change-management",
            "predicate": "authorized iff ticket approved",
            "on_unauthorized": "escalate",
            "on_indeterminate": "escalate",
        })
        # Add a second lead emitting an unauthorized resolution for ac2 on a new edge.
        merged["findings"].append({
            "id": "l-002", "loop": 1, "name": "cm-ticket-lookup",
            "target": "v-001", "query_details": {},
            "outcome": {
                "observations": {
                    "vertices": [],
                    "edges": [{
                        "id": "e-003",
                        "relation": "classified_as",
                        "source_vertex": "v-001",
                        "target_vertex": "v-002",
                        "authority": {"kind": "authoritative-source", "source": "cm"},
                        "authorization_resolutions": [
                            _base_resolution(
                                verdict="unauthorized",
                                anchor_kind="change-management",
                                anchor_id="cm-2026-04",
                                fulfills_contract="h-001.ac2",
                                resolved_by_lead="l-002",
                            ),
                        ],
                    }],
                },
            },
            "resolutions": [],
        })
        errors = _check_authorization_gated_disposition(merged)
        assert any("ac2" in e and "unauthorized" in e for e in errors)


class TestAuthorizationResolutionFromAttributeUpdate:
    """The walker must pick up authz_resolutions attached via attribute_updates.

    This is the v2.11 append-only escape hatch: a contract resolving
    against an already-confirmed edge writes via
    `outcome.attribute_updates[].updates.authorization_resolutions[]`
    rather than mutating the original edge record.
    """

    def test_attribute_update_resolution_counts_for_rule_21(self):
        merged = _companion_with_contract()
        # Drop the edge-inline resolution; emit it via attribute_updates instead.
        obs_edge = merged["findings"][0]["outcome"]["observations"]["edges"][0]
        obs_edge.pop("authorization_resolutions", None)
        merged["findings"][0]["outcome"]["attribute_updates"] = [
            {
                "target": "e-001",
                "updates": {
                    "authorization_resolutions": [
                        _base_resolution(
                            fulfills_contract="h-001.ac1",
                            resolved_by_lead="l-001",
                        ),
                    ],
                },
            }
        ]
        # Benign gate should still pass: the verdict is `authorized` on ac1.
        assert _check_authorization_gated_disposition(merged) == []
        assert _check_authorization_resolution_backrefs(merged) == []
