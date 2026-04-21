"""Unit tests for legitimacy-as-edge-attribute invlang checks (rules 15-22).

Covers: contract edge_ref, resolution back-refs, benign-disposition gating,
attribute_updates / legitimacy_resolutions target shape, asks/verdict
coherence, kind/asks coherence, supersede chain, and the resolution-
requires-authorization co-occurrence.
"""

from __future__ import annotations

import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_asks_verdict_shape,
    _check_attribute_updates_target_shape,
    _check_kind_asks_coherence,
    _check_legitimacy_contract_edge_ref,
    _check_legitimacy_gated_disposition,
    _check_legitimacy_resolution_backrefs,
    _check_legitimacy_resolution_target_shape,
    _check_legitimacy_supersede_chain,
    _check_resolution_requires_authorization_asks,
)

from tests.test_invlang_validate import _companion_with_contract


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
