"""Unit tests for scripts.handlers._output_parser.parse_predict_output.

Pure parser tests — no file I/O, no subagent dispatch. Exercises envelope
extraction, header validation, per-shape presence rules, and routing shape.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._output_parser import (  # noqa: E402
    PredictOutputError,
    parse_predict_output,
)


def _y(body: str) -> str:
    """Wrap a YAML body in a ```yaml fence like subagents emit."""
    return f"```yaml\n{body.strip()}\n```"


# ---------------------------------------------------------------------------
# Shape E — branch plan only, no hypotheses
# ---------------------------------------------------------------------------


SHAPE_E_BODY = textwrap.dedent("""
    predict:
      loop: 1
      shape: E
      branch_plan:
        primary_lead: authentication-history
        predictions:
          - {id: lp1, if: "forward-success within 60s", read_as: "compromise", advance_to: escalate}
          - {id: lp2, if: "periodic cadence", read_as: "sanctioned", advance_to: fork-at-identity-of-use}
      routing:
        selected_lead: authentication-history
        composite_secondary: []
""").strip()


class TestShapeE:
    def test_valid_shape_e_parses(self):
        result = parse_predict_output(_y(SHAPE_E_BODY), expected_loop_n=1)
        assert result.telemetry == {"loop": 1, "shape": "E"}
        assert "hypotheses" not in result.invlang_delta
        assert "branch_plan" in result.invlang_delta
        assert result.invlang_delta["branch_plan"]["primary_lead"] == "authentication-history"
        assert len(result.invlang_delta["branch_plan"]["predictions"]) == 2
        assert result.routing == {
            "selected_lead": "authentication-history",
            "composite_secondary": [],
        }

    def test_shape_e_without_branch_plan_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              routing:
                selected_lead: x
        """))
        with pytest.raises(PredictOutputError, match="shape=E requires a branch_plan"):
            parse_predict_output(body)

    def test_shape_e_with_hypotheses_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              hypotheses:
                - {id: h-001, name: "?x"}
              branch_plan:
                primary_lead: x
                predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]
              routing:
                selected_lead: x
        """))
        with pytest.raises(PredictOutputError, match="shape=E must have empty hypotheses"):
            parse_predict_output(body)

    def test_shape_e_empty_branch_plan_predictions_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              branch_plan:
                primary_lead: x
                predictions: []
              routing: {selected_lead: x}
        """))
        with pytest.raises(PredictOutputError, match="branch_plan.predictions"):
            parse_predict_output(body)


# ---------------------------------------------------------------------------
# Shape A — mechanism pinned, single hypothesis with authorization contract
# ---------------------------------------------------------------------------


SHAPE_A_BODY = textwrap.dedent("""
    predict:
      loop: 1
      shape: A
      hypotheses:
        - id: h-001
          name: "?host-runtime-exec"
          attached_to_vertex: v-001
          proposed_edge:
            relation: spawned
            parent_vertex:
              type: process
              classification: host-side-exec-invoker
          predictions:
            - {id: p1, claim: "container-baseline has prior runc-parent shell"}
          attribute_predictions:
            - {id: ap1, target: proposed_parent, attribute: cmdline, claim: "matches /monitord/"}
          refutation_shape:
            - {id: r1, refutes_predictions: [p1, ap1], claim: "no baseline + cmdline shell-pipe"}
          authorization_contract:
            - {id: ac1, edge_ref: proposed, anchor_kind: ci-cd-job-record, asks: authorization}
          weight: null
      routing:
        selected_lead: container-baseline
        composite_secondary: [correlated-falco-events]
""").strip()


class TestShapeA:
    def test_valid_shape_a_parses(self):
        result = parse_predict_output(_y(SHAPE_A_BODY))
        assert result.telemetry == {"loop": 1, "shape": "A"}
        assert "branch_plan" not in result.invlang_delta
        assert len(result.invlang_delta["hypotheses"]) == 1
        h = result.invlang_delta["hypotheses"][0]
        assert h["id"] == "h-001"
        assert h["attribute_predictions"][0]["id"] == "ap1"
        assert result.routing["selected_lead"] == "container-baseline"
        assert result.routing["composite_secondary"] == ["correlated-falco-events"]

    def test_shape_a_without_hypotheses_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: A
              routing: {selected_lead: x}
        """))
        with pytest.raises(PredictOutputError, match="shape=A requires at least one hypothesis"):
            parse_predict_output(body)

    def test_shape_a_with_branch_plan_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: A
              hypotheses: [{id: h-001, name: "?x"}]
              branch_plan:
                primary_lead: x
                predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]
              routing: {selected_lead: x}
        """))
        with pytest.raises(PredictOutputError, match="shape=A must not emit a branch_plan"):
            parse_predict_output(body)


# ---------------------------------------------------------------------------
# Header + envelope errors
# ---------------------------------------------------------------------------


class TestEnvelope:
    def test_unwrapped_yaml_parses(self):
        """Subagent may emit the YAML without the ```yaml fence — still parses."""
        result = parse_predict_output(SHAPE_E_BODY)
        assert result.telemetry == {"loop": 1, "shape": "E"}

    def test_empty_stdout_fails(self):
        with pytest.raises(PredictOutputError, match="empty"):
            parse_predict_output("")

    def test_missing_predict_key_fails(self):
        with pytest.raises(PredictOutputError, match="top-level key"):
            parse_predict_output("not_predict:\n  shape: E\n")

    def test_non_mapping_top_level_fails(self):
        with pytest.raises(PredictOutputError, match="must be a mapping"):
            parse_predict_output("- item\n- item\n")

    def test_bad_shape_value_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: Z
              routing: {selected_lead: x}
        """))
        with pytest.raises(PredictOutputError, match="shape must be one of"):
            parse_predict_output(body)

    def test_non_integer_loop_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: "one"
              shape: E
              branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
              routing: {selected_lead: x}
        """))
        with pytest.raises(PredictOutputError, match="loop must be an integer"):
            parse_predict_output(body)

    def test_loop_mismatch_with_expected_fails(self):
        with pytest.raises(PredictOutputError, match="does not match orchestrator"):
            parse_predict_output(_y(SHAPE_E_BODY), expected_loop_n=2)

    def test_invalid_yaml_fails(self):
        body = "```yaml\npredict:\n  loop: 1\n  shape: [unclosed\n```"
        with pytest.raises(PredictOutputError, match="not valid YAML"):
            parse_predict_output(body)


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class TestRouting:
    def test_missing_selected_lead_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
              routing: {composite_secondary: []}
        """))
        with pytest.raises(PredictOutputError, match="selected_lead"):
            parse_predict_output(body)

    def test_optional_fields_propagate(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
              routing:
                selected_lead: x
                composite_secondary: [y]
                override_data_source: host_query
                lead_hints:
                  x: "walk ancestry above runc"
                  y: "cross-check session window"
        """))
        result = parse_predict_output(body)
        assert result.routing["override_data_source"] == "host_query"
        assert result.routing["lead_hints"] == {
            "x": "walk ancestry above runc",
            "y": "cross-check session window",
        }

    def test_lead_hints_unknown_lead_rejected(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
              routing:
                selected_lead: x
                composite_secondary: []
                lead_hints:
                  not-prescribed: "stray hint"
        """))
        with pytest.raises(PredictOutputError, match="not-prescribed"):
            parse_predict_output(body)

    def test_bad_composite_secondary_type_fails(self):
        body = _y(textwrap.dedent("""
            predict:
              loop: 1
              shape: E
              branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
              routing:
                selected_lead: x
                composite_secondary: "not-a-list"
        """))
        with pytest.raises(PredictOutputError, match="composite_secondary"):
            parse_predict_output(body)


# ---------------------------------------------------------------------------
# scope_override — optional structured window override on routing
# ---------------------------------------------------------------------------


class TestScopeOverride:
    BASE = textwrap.dedent("""
        predict:
          loop: 1
          shape: E
          branch_plan: {primary_lead: x, predictions: [{id: lp1, if: "a", read_as: "b", advance_to: c}]}
          routing:
            selected_lead: x
            composite_secondary: []
    """).strip()

    def test_absent_scope_override_does_not_appear_in_routing(self):
        result = parse_predict_output(_y(self.BASE))
        assert "scope_override" not in result.routing

    def test_window_hours_only_defaults_anchor_to_alert(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: 24"
        result = parse_predict_output(_y(body))
        assert result.routing["scope_override"] == {
            "window_hours": 24,
            "anchor": "alert",
        }

    def test_window_hours_plus_anchor_now(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: 72\n      anchor: now"
        result = parse_predict_output(_y(body))
        assert result.routing["scope_override"] == {
            "window_hours": 72,
            "anchor": "now",
        }

    def test_non_mapping_fails(self):
        body = self.BASE + "\n    scope_override: \"24h\""
        with pytest.raises(PredictOutputError, match="scope_override must be a mapping"):
            parse_predict_output(_y(body))

    def test_missing_window_hours_fails(self):
        body = self.BASE + "\n    scope_override:\n      anchor: alert"
        with pytest.raises(PredictOutputError, match="window_hours must be a positive integer"):
            parse_predict_output(_y(body))

    def test_zero_window_hours_fails(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: 0"
        with pytest.raises(PredictOutputError, match="window_hours must be > 0"):
            parse_predict_output(_y(body))

    def test_negative_window_hours_fails(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: -4"
        with pytest.raises(PredictOutputError, match="window_hours must be > 0"):
            parse_predict_output(_y(body))

    def test_non_integer_window_hours_fails(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: \"24\""
        with pytest.raises(PredictOutputError, match="window_hours must be a positive integer"):
            parse_predict_output(_y(body))

    def test_boolean_window_hours_fails(self):
        # Python `True` is an int subclass — explicit reject.
        body = self.BASE + "\n    scope_override:\n      window_hours: true"
        with pytest.raises(PredictOutputError, match="window_hours must be a positive integer"):
            parse_predict_output(_y(body))

    def test_bad_anchor_fails(self):
        body = self.BASE + "\n    scope_override:\n      window_hours: 24\n      anchor: yesterday"
        with pytest.raises(PredictOutputError, match="anchor must be one of"):
            parse_predict_output(_y(body))


# ===========================================================================
# Gather envelope tests
# ===========================================================================


from scripts.handlers._output_parser import (  # noqa: E402
    GatherOutputError,
    parse_gather_envelope,
)


GATHER_SINGLE_BODY = textwrap.dedent("""
    gather:
      loop: 1
      leads:
        - id: l-001
          name: source-classification
          status: ok
          query:
            system: wazuh-indexer
            template: source-ip-lookup
            time_window: 1h
          observations:
            vertices:
              - {id: v-002, type: identity, classification: external-source}
            edges:
              - {id: e-002, source: v-002, target: v-001, relation: authenticates_to}
          attribute_updates: []
          consultations: []
          raw:
            siem_response: |
              {"hits": 5, "rows": [{"src_ip": "1.2.3.4"}]}
            consultations: []
""").strip()


class TestGatherSingle:
    def test_valid_single_lead_parses(self):
        result = parse_gather_envelope(_y(GATHER_SINGLE_BODY), expected_loop_n=1, mode="single")
        assert result.telemetry == {"loop": 1, "mode": "single"}
        assert len(result.leads) == 1
        assert result.leads[0]["id"] == "l-001"
        assert result.leads[0]["status"] == "ok"
        # `raw` must be stripped from the lead record (goes to raw_by_lead).
        assert "raw" not in result.leads[0]
        assert "l-001" in result.raw_by_lead
        assert "siem_response" in result.raw_by_lead["l-001"]

    def test_loop_mismatch_fails(self):
        with pytest.raises(GatherOutputError, match="does not match orchestrator"):
            parse_gather_envelope(_y(GATHER_SINGLE_BODY), expected_loop_n=2, mode="single")


GATHER_COMPOSITE_BODY = textwrap.dedent("""
    gather:
      loop: 2
      leads:
        - id: l-010
          name: primary
          status: ok
          query: {system: wazuh-indexer}
          observations: {vertices: [], edges: []}
        - id: l-011
          name: secondary
          status: data_missing
          query: {system: host-query}
          observations: {vertices: [], edges: []}
""").strip()


class TestGatherComposite:
    def test_valid_multi_lead_parses(self):
        result = parse_gather_envelope(_y(GATHER_COMPOSITE_BODY), mode="composite")
        assert len(result.leads) == 2
        assert {lead["id"] for lead in result.leads} == {"l-010", "l-011"}
        statuses = {lead["id"]: lead["status"] for lead in result.leads}
        assert statuses == {"l-010": "ok", "l-011": "data_missing"}
        # No `raw` on these leads — raw_by_lead stays empty.
        assert result.raw_by_lead == {}

    def test_duplicate_lead_id_fails(self):
        body = GATHER_COMPOSITE_BODY.replace("l-011", "l-010")
        with pytest.raises(GatherOutputError, match="duplicates a prior lead"):
            parse_gather_envelope(_y(body))


class TestGatherShape:
    def test_missing_top_level_key_fails(self):
        with pytest.raises(GatherOutputError, match="must have top-level key"):
            parse_gather_envelope(_y("other:\n  loop: 1"))

    def test_empty_leads_fails(self):
        body = "gather:\n  loop: 1\n  leads: []"
        with pytest.raises(GatherOutputError, match="non-empty list"):
            parse_gather_envelope(_y(body))

    def test_bad_status_fails(self):
        body = textwrap.dedent("""
            gather:
              loop: 1
              leads:
                - id: l-001
                  name: foo
                  status: bogus
                  query: {}
                  observations: {vertices: [], edges: []}
        """).strip()
        with pytest.raises(GatherOutputError, match="status must be one of"):
            parse_gather_envelope(_y(body))

    def test_missing_lead_id_fails(self):
        body = textwrap.dedent("""
            gather:
              loop: 1
              leads:
                - name: foo
                  status: ok
                  query: {}
                  observations: {vertices: [], edges: []}
        """).strip()
        with pytest.raises(GatherOutputError, match="id must be a non-empty string"):
            parse_gather_envelope(_y(body))


# ===========================================================================
# Analyze envelope tests
# ===========================================================================


from scripts.handlers._output_parser import (  # noqa: E402
    AnalyzeOutputError,
    parse_analyze_envelope,
)


ANALYZE_HALT_BODY = textwrap.dedent("""
    analyze:
      loop: 2
      resolutions:
        - lead_ref: l-001
          entries:
            - {hypothesis_id: h-001, weight: '++', matched_prediction_ids: [p1]}
            - {hypothesis_id: h-002, weight: '--', matched_prediction_ids: [p2]}
      trust_anchor_result:
        - lead_ref: l-002
          asks: [approved-monitoring-sources]
          verdict: authorized
          reasoning: source on approved list
      anomalies:
        - sparse coverage on endpoint X
      data_wishes:
        - would want 24h cadence baseline
      routing:
        decision: halt
        termination_category: trust-root
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        surviving_hypotheses: ['?monitoring-probe']
""").strip()


class TestAnalyzeHalt:
    def test_valid_halt_parses(self):
        result = parse_analyze_envelope(_y(ANALYZE_HALT_BODY), expected_loop_n=2)
        assert result.telemetry == {"loop": 2}
        assert result.routing["decision"] == "halt"
        assert result.routing["disposition"] == "benign"
        assert result.routing["surviving_hypotheses"] == ["?monitoring-probe"]
        assert "l-001" in result.resolutions_by_lead
        assert len(result.resolutions_by_lead["l-001"]) == 2
        assert "l-002" in result.trust_anchor_by_lead
        assert result.trust_anchor_by_lead["l-002"]["verdict"] == "authorized"
        assert result.anomalies == ["sparse coverage on endpoint X"]
        assert result.data_wishes == ["would want 24h cadence baseline"]
        assert result.legitimacy_by_lead == {}
        assert result.impact_by_lead == {}


ANALYZE_CONTINUE_BODY = textwrap.dedent("""
    analyze:
      loop: 3
      resolutions: []
      routing:
        decision: continue
        unresolved_prescribed_set: [authentication-history]
""").strip()


class TestAnalyzeContinue:
    def test_valid_continue_parses(self):
        result = parse_analyze_envelope(_y(ANALYZE_CONTINUE_BODY), expected_loop_n=3)
        assert result.routing["decision"] == "continue"
        assert result.routing["unresolved_prescribed_set"] == ["authentication-history"]
        assert result.resolutions_by_lead == {}


class TestAnalyzeShape:
    def test_missing_routing_fails(self):
        body = "analyze:\n  loop: 1"
        with pytest.raises(AnalyzeOutputError, match="routing must be a mapping"):
            parse_analyze_envelope(_y(body))

    def test_bad_decision_fails(self):
        body = textwrap.dedent("""
            analyze:
              loop: 1
              routing:
                decision: nope
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="decision must be one of"):
            parse_analyze_envelope(_y(body))

    def test_halt_missing_disposition_fails(self):
        body = textwrap.dedent("""
            analyze:
              loop: 1
              routing:
                decision: halt
                termination_category: trust-root
                confidence: high
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="disposition must be one of"):
            parse_analyze_envelope(_y(body))

    def test_duplicate_lead_ref_in_trust_anchor_fails(self):
        body = textwrap.dedent("""
            analyze:
              loop: 1
              trust_anchor_result:
                - lead_ref: l-001
                  asks: [x]
                  verdict: authorized
                  reasoning: a
                - lead_ref: l-001
                  asks: [y]
                  verdict: unauthorized
                  reasoning: b
              routing:
                decision: continue
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="appears more than once"):
            parse_analyze_envelope(_y(body))

    def test_loop_mismatch_fails(self):
        body = textwrap.dedent("""
            analyze:
              loop: 1
              routing:
                decision: continue
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="does not match orchestrator"):
            parse_analyze_envelope(_y(body), expected_loop_n=2)


# ===========================================================================
# Analyze envelope tests — DENSE block format
# ===========================================================================


from scripts.handlers._output_parser import (  # noqa: E402
    parse_analyze_envelope_dense,
)


_DENSE_HALT = textwrap.dedent("""
:A loop  2

:T resolutions
h-001  ∅ → ++   [l-002 severe ⟂ e-005 :: cadence-check returned 4 prior alerts at 60s intervals ⟺ p3 ∧ ¬r3]

:A routing
decision               halt
termination_category   trust-root
disposition            benign
confidence             high
surviving              h-001
matched_archetype      null
""").strip()


_DENSE_CONTINUE = textwrap.dedent("""
:A loop  1

:T resolutions
h-001  ∅ → +    [l-001 weak ⟂ no-authority :: volume-profile shows monotonic upload ⟺ p1]

:A data_wishes
backup-service job-log query
""").strip()


_DENSE_HALT_FULL = textwrap.dedent("""
:A loop  2

:T resolutions
h-003  + → ++   [l-005 severe ⟂ e-019,e-020 :: dest=s3://prod ∧ CHG-3782.covers(window)=true ⟺ p1 ∧ p2 ∧ ¬r1]

:R authz [lead|edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|reasoning]
l-005|e-019|authorized|change-management|CHG-3782|org-authority|full|2026-04-23T03:42Z|h-003.ac1|backup-window covered

:R impact [lead|pred_ref|dim|observed|verdict|matched_pred|grounding|anchor_id|anchor_kind|authority|as_of|reasoning]
l-005|l-005.ip1|confidentiality|51GB|within|within ±2σ|telemetry-baseline|backup-30d|session-volume-baseline|partial|2026-04-23T03:42Z|observed 51GB; within μ+2σ=54

:A routing
decision               halt
termination_category   trust-root
disposition            benign
confidence             high
surviving              h-003
matched_archetype      null
""").strip()


class TestAnalyzeDenseHalt:
    def test_valid_halt_parses(self):
        env = parse_analyze_envelope_dense(_DENSE_HALT, expected_loop_n=2)
        assert env.telemetry == {"loop": 2}
        assert env.routing["decision"] == "halt"
        assert env.routing["disposition"] == "benign"
        assert env.routing["surviving_hypotheses"] == ["h-001"]
        assert env.routing["matched_archetype"] is None
        assert "l-002" in env.resolutions_by_lead
        entries = env.resolutions_by_lead["l-002"]
        assert len(entries) == 1
        e = entries[0]
        assert e["hypothesis_id"] == "h-001"
        assert e["weight"] == "++"
        assert e["before_weight"] == "∅"
        assert e["severity"] == "severe"
        assert e["matched_prediction_ids"] == ["p3"]
        # r3 appears negated on iff RHS — derived as "tested but failed to materialize".
        assert e["matched_refutation_ids"] == ["r3"]
        assert e["supporting_edges"] == ["e-005"]

    def test_full_halt_with_authz_and_impact(self):
        env = parse_analyze_envelope_dense(_DENSE_HALT_FULL)
        # Resolutions
        e = env.resolutions_by_lead["l-005"][0]
        assert e["weight"] == "++"
        assert sorted(e["matched_prediction_ids"]) == ["p1", "p2"]
        assert e["matched_refutation_ids"] == ["r1"]
        assert e["supporting_edges"] == ["e-019", "e-020"]
        # Authz row
        authz = env.legitimacy_by_lead["l-005"][0]
        assert authz["edge_id"] == "e-019"
        assert authz["contract_id"] == "h-003.ac1"
        assert authz["verdict"] == "authorized"
        assert authz["grounding_kind"] == "org-authority"
        # Impact row
        impact = env.impact_by_lead["l-005"][0]
        assert impact["prediction_ref"] == "l-005.ip1"
        assert impact["dimension"] == "confidentiality"
        assert impact["verdict"] == "within"
        assert impact["grounding_kind"] == "telemetry-baseline"


class TestAnalyzeDenseContinue:
    def test_valid_continue_parses(self):
        env = parse_analyze_envelope_dense(_DENSE_CONTINUE)
        # Continue is encoded as absence of `:A routing`.
        assert env.routing["decision"] == "continue"
        assert "l-001" in env.resolutions_by_lead
        assert env.data_wishes == ["backup-service job-log query"]


class TestAnalyzeDenseRowRules:
    def test_s1_decisive_grade_requires_severe(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 weak ⟂ e-001 :: rep flag=scanner ⟺ p1]
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"severity=severe \(S1\)"):
            parse_analyze_envelope_dense(body)

    def test_s2_double_minus_requires_r_literal(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → --   [l-001 severe ⟂ e-001 :: anchor refutes ⟺ ¬p1]
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"requires at least one r\* literal"):
            parse_analyze_envelope_dense(body)

    def test_s3_iff_rhs_must_have_literal(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 weak ⟂ no-authority :: nothing observable ⟺ true]
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"no `p\*`"):
            parse_analyze_envelope_dense(body)

    def test_ascii_fallback_iff_operators(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 weak ⟂ no-authority :: rate=47/h <=> p1 & ~r1]
        """).strip()
        env = parse_analyze_envelope_dense(body)
        e = env.resolutions_by_lead["l-001"][0]
        assert "p1" in e["matched_prediction_ids"]
        assert "r1" in e["matched_refutation_ids"]

    def test_invalid_severity_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 vague ⟂ no-authority :: obs ⟺ p1]
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="invalid severity"):
            parse_analyze_envelope_dense(body)

    def test_invalid_after_weight_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ?    [l-001 weak ⟂ no-authority :: obs ⟺ p1]
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="invalid <after>"):
            parse_analyze_envelope_dense(body)


class TestAnalyzeDenseCrossBlockInvariants:
    def test_x1_surviving_completeness_omitted(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 severe ⟂ e-001 :: confirms ⟺ p1]
        h-002  ∅ → +    [l-001 weak ⟂ no-authority :: weak match ⟺ p1]

        :A routing
        decision               halt
        termination_category   trust-root
        disposition            benign
        confidence             high
        surviving              h-001
        matched_archetype      null
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"surviving completeness"):
            parse_analyze_envelope_dense(body)

    def test_x1_refuted_in_surviving_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → --   [l-001 severe ⟂ e-001 :: refutes ⟺ ¬p1 ∧ r1]

        :A routing
        decision               halt
        termination_category   adversarial-refuted
        disposition            unclear
        confidence             low
        surviving              h-001
        matched_archetype      null
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"refuted but listed in surviving"):
            parse_analyze_envelope_dense(body)

    def test_x4_benign_with_indeterminate_authz_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 severe ⟂ e-010 :: registry confirms ⟺ p1]

        :R authz [lead|edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|reasoning]
        l-001|e-010|indeterminate|registry|reg-1|org-authority|partial|2026-04-23T12:00Z|h-001.ac1|baseline timed out

        :A routing
        decision               halt
        termination_category   trust-root
        disposition            benign
        confidence             high
        surviving              h-001
        matched_archetype      null
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"benign requires"):
            parse_analyze_envelope_dense(body)

    def test_x6_authz_fulfills_must_be_survivor(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → --   [l-001 severe ⟂ e-001 :: refuted ⟺ ¬p1 ∧ r1]

        :R authz [lead|edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|reasoning]
        l-001|e-001|authorized|registry|reg-1|org-authority|full|2026-04-23T12:00Z|h-001.ac1|registered

        :A routing
        decision               halt
        termination_category   adversarial-refuted
        disposition            unclear
        confidence             low
        surviving
        matched_archetype      null
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"contract owner"):
            parse_analyze_envelope_dense(body)

    def test_x2_adversarial_refuted_with_alive_adversarial_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 severe ⟂ e-001 :: confirms ⟺ p1]
        h-002  ∅ → -    [l-001 weak ⟂ no-authority :: weak match ⟺ p1]

        :A routing
        decision               halt
        termination_category   adversarial-refuted
        disposition            benign
        confidence             high
        surviving              h-001,h-002
        matched_archetype      null
        """).strip()
        names = {"h-001": "?monitoring-probe", "h-002": "?credential-stuffing"}
        with pytest.raises(AnalyzeOutputError, match=r"adversarial hypothesis at --"):
            parse_analyze_envelope_dense(body, declared_hypothesis_names=names)


class TestAnalyzeDenseAuthzGrounding:
    def test_telemetry_baseline_rejected_on_authz(self):
        # Validator rule #11 — :R authz must use org-authority or past-case.
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 severe ⟂ e-001 :: confirms ⟺ p1]

        :R authz [lead|edge|verdict|anchor_kind|anchor_id|grounding|authority|as_of|fulfills|reasoning]
        l-001|e-001|authorized|baseline|baseline-30d|telemetry-baseline|partial|2026-04-23T12:00Z|h-001.ac1|partial baseline

        :A routing
        decision               halt
        termination_category   trust-root
        disposition            benign
        confidence             high
        surviving              h-001
        matched_archetype      null
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"telemetry-baseline is\s+rejected"):
            parse_analyze_envelope_dense(body)


class TestAnalyzeDenseUnknownBlocks:
    def test_unknown_block_tag_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 weak ⟂ no-authority :: obs ⟺ p1]

        :T bogus
        whatever
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="unknown block tag"):
            parse_analyze_envelope_dense(body)

    def test_missing_resolutions_block_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :A anomalies
        sparse coverage
        """).strip()
        with pytest.raises(AnalyzeOutputError, match=r"missing required `:T resolutions`"):
            parse_analyze_envelope_dense(body)

    def test_loop_mismatch_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="does not match orchestrator"):
            parse_analyze_envelope_dense(body, expected_loop_n=2)

    def test_empty_envelope_rejected(self):
        with pytest.raises(AnalyzeOutputError, match="empty"):
            parse_analyze_envelope_dense("")
