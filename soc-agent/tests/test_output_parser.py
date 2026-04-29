"""Unit tests for scripts.handlers._output_parser.parse_predict_output.

Pure parser tests — no file I/O, no subagent dispatch. Exercises the dense-form
envelope (DB grammar): block tokenization, kind/comparison rules, story-prose
sentence-ID consistency, field-presence matrix, routing-block validation.

The YAML envelope was retired in the dense-PREDICT migration (parallel to PR
#153 for ANALYZE). All fixtures here are dense-form.
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


def _d(body: str) -> str:
    """Dense-form fixture — already trimmed; no fence wrapping required.

    The parser tolerates a single outer ``` fence pair, but most fixtures
    don't bother since stdout from the subagent isn't fenced either.
    """
    return body.strip() + "\n"


def _y(body: str) -> str:
    """Wrap a YAML body in a ```yaml fence — used by gather + analyze tests
    further down (those parsers stayed YAML)."""
    return f"```yaml\n{body.strip()}\n```"


# ---------------------------------------------------------------------------
# Shape E — branch plan only, no hypotheses
# ---------------------------------------------------------------------------


SHAPE_E_BODY = textwrap.dedent("""
    predict loop=1 shape=E

    :L lead_preds [id|kind|if|read_as|advance_to]
    lp1|presence|"forward-success within 60s"|compromise|escalate
    lp2|cadence|"foreground within source's 72h cadence baseline"|sanctioned|fork-at-identity-of-use

    :L lead_preds.comparisons [pred_ref|selector_kind|selector|dimension]
    lp2|historical-self|"src=<source_ip> 72h"|inter-event-gap-distribution

    :R routing
    selected_lead         authentication-history
    composite_secondary   -
    override_data_source  -
    rationale             "anchored cadence vs forward-success partitions next-loop questions"
""").strip()


class TestShapeE:
    def test_valid_shape_e_parses(self):
        result = parse_predict_output(_d(SHAPE_E_BODY), expected_loop_n=1)
        assert result.telemetry == {"loop": 1, "shape": "E"}
        assert "hypotheses" not in result.invlang_delta
        assert "branch_plan" in result.invlang_delta
        assert result.invlang_delta["branch_plan"]["primary_lead"] == "authentication-history"
        assert len(result.invlang_delta["branch_plan"]["predictions"]) == 2
        # lp2 (cadence — deviation) carries comparison; lp1 (presence) does not.
        lps = result.invlang_delta["branch_plan"]["predictions"]
        lp1 = next(p for p in lps if p["id"] == "lp1")
        lp2 = next(p for p in lps if p["id"] == "lp2")
        assert "comparison" not in lp1
        assert lp2["comparison"]["dimension"] == "inter-event-gap-distribution"
        assert result.routing["selected_lead"] == "authentication-history"
        assert result.routing["composite_secondary"] == []

    def test_shape_e_without_branch_plan_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=E

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="shape=E requires a branch_plan"):
            parse_predict_output(_d(body))

    def test_shape_e_with_hypotheses_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=E

            ### story h-001
            s1. Some story.

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|host-side-exec-invoker|||null|active

            :L lead_preds [id|kind|if|read_as|advance_to]
            lp1|presence|"a"|b|c

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="shape=E must have empty hypotheses"):
            parse_predict_output(_d(body))


# ---------------------------------------------------------------------------
# Shape A — mechanism pinned, single hypothesis with authorization contract
# ---------------------------------------------------------------------------


SHAPE_A_BODY = textwrap.dedent("""
    predict loop=1 shape=A

    ### story h-001
    s1. The host-side runtime invoker spawned the observed process via syscall, leaving runc as the visible parent in Falco.
    s2. The CI/CD job record is the authoritative source for whether this runtime invocation was scheduled.

    :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
    h-001|?host-runtime-exec|v-001|spawned|process|host-side-exec-invoker|||null|active

    :P h-001.preds [id|subject|kind|from_story|claim]
    p1|proposed_parent|absolute|s1|"container-baseline has prior runc-parent shell"

    :P h-001.attr_preds [id|target|attribute|kind|claim]
    ap1|proposed_parent|cmdline|presence|"matches /monitord/"

    :P h-001.refuts [id|refutes|kind|claim]
    r1|p1,ap1|absolute|"no baseline + cmdline shell-pipe"

    :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
    ac1|proposed|ci-cd-job-record|"job record present in approved registry"|esc|esc

    :R routing
    selected_lead         container-baseline
    composite_secondary   correlated-falco-events
    override_data_source  -
    rationale             "ci-cd job-record anchor settles authorization fastest"
""").strip()


class TestShapeA:
    def test_valid_shape_a_parses(self):
        result = parse_predict_output(_d(SHAPE_A_BODY))
        assert result.telemetry == {"loop": 1, "shape": "A"}
        assert "branch_plan" not in result.invlang_delta
        assert len(result.invlang_delta["hypotheses"]) == 1
        h = result.invlang_delta["hypotheses"][0]
        assert h["id"] == "h-001"
        assert h["attribute_predictions"][0]["id"] == "ap1"
        assert h["authorization_contract"][0]["anchor_kind"] == "ci-cd-job-record"
        assert h["story"].startswith("s1.")
        assert h["predictions"][0]["from_story_link"] == "s1"
        assert h["refutation_shape"][0]["refutes_predictions"] == ["p1", "ap1"]
        assert result.routing["selected_lead"] == "container-baseline"
        assert result.routing["composite_secondary"] == ["correlated-falco-events"]

    def test_shape_a_without_hypotheses_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="shape=A requires at least one hypothesis"):
            parse_predict_output(_d(body))

    def test_shape_a_with_branch_plan_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :L lead_preds [id|kind|if|read_as|advance_to]
            lp1|presence|"a"|b|c

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="shape=A must not emit a branch_plan"):
            parse_predict_output(_d(body))

    def test_shape_a_missing_authz_passes_parser_validator_catches(self):
        # Shape A requires ≥1 authz contract, but _check_shape_consistency
        # checks only presence of hypotheses; the authz requirement is
        # enforced by the invlang validator on the composed companion. We
        # assert the parser passes this case through unchanged.
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        result = parse_predict_output(_d(body))
        assert result.invlang_delta["hypotheses"][0]["authorization_contract"] == []


# ---------------------------------------------------------------------------
# kind / comparison rules — promoted from prose discipline to parse-time check
# ---------------------------------------------------------------------------


class TestKindAndComparison:
    def test_presence_on_refutation_rejected(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.refuts [id|refutes|kind|claim]
            r1|p1|presence|"any signal at all"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="presence is forbidden on refutations"):
            parse_predict_output(_d(body))

    def test_deviation_kind_requires_comparison(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|cadence|s1|"foreground within 72h baseline distribution"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="kind='cadence' requires a comparison"):
            parse_predict_output(_d(body))

    def test_non_deviation_kind_with_comparison_rejected(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
            p1|historical-self|"src=x"|some-dim

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="must not carry a comparison"):
            parse_predict_output(_d(body))

    def test_unknown_kind_rejected(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|hand-wave|s1|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="unknown kind 'hand-wave'"):
            parse_predict_output(_d(body))


# ---------------------------------------------------------------------------
# Story prose / sentence-ID consistency
# ---------------------------------------------------------------------------


class TestStoryProse:
    def test_missing_story_for_declared_hypothesis_rejected(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="missing story prose block"):
            parse_predict_output(_d(body))

    def test_from_story_link_must_name_known_sentence(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. one
            s2. two

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s9|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="from_story_link='s9' not in story sentence IDs"):
            parse_predict_output(_d(body))

    def test_sub_block_for_undeclared_hypothesis_rejected(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-002.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="hypothesis 'h-002' not declared"):
            parse_predict_output(_d(body))


# ---------------------------------------------------------------------------
# Header + envelope errors
# ---------------------------------------------------------------------------


class TestEnvelope:
    def test_fenced_envelope_parses(self):
        """Subagent may wrap stdout in a single ``` fence — still parses."""
        wrapped = "```\n" + SHAPE_E_BODY + "\n```"
        result = parse_predict_output(wrapped)
        assert result.telemetry == {"loop": 1, "shape": "E"}

    def test_empty_stdout_fails(self):
        with pytest.raises(PredictOutputError, match="empty"):
            parse_predict_output("")

    def test_missing_predict_header_fails(self):
        with pytest.raises(PredictOutputError, match="missing header line"):
            parse_predict_output(":H hypotheses [id]\nh-001\n")

    def test_bad_shape_value_fails(self):
        body = "predict loop=1 shape=Z\n\n:R routing\nselected_lead   x\n"
        # Header is recognized; bad shape produces a focused shape error
        # downstream (legacy-shape map applied first, then _VALID_SHAPES check).
        with pytest.raises(PredictOutputError, match="shape must be one of"):
            parse_predict_output(_d(body))

    def test_legacy_shape_d_remapped_to_e(self):
        body = textwrap.dedent("""
            predict loop=1 shape=D

            :L lead_preds [id|kind|if|read_as|advance_to]
            lp1|presence|"a"|b|c

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        result = parse_predict_output(_d(body))
        assert result.telemetry == {"loop": 1, "shape": "E"}

    def test_malformed_predict_header_diagnoses_specifically(self):
        # `predict ` prefix present but the form is broken — not "missing
        # header" but a focused malformation error so the retry prompt
        # tells the subagent what's actually wrong.
        body = "predict loop=one shape=E\n\n:R routing\nselected_lead   x\n"
        with pytest.raises(PredictOutputError, match="header line malformed"):
            parse_predict_output(_d(body))

    def test_loop_mismatch_with_expected_fails(self):
        with pytest.raises(PredictOutputError, match="does not match orchestrator"):
            parse_predict_output(_d(SHAPE_E_BODY), expected_loop_n=2)

    def test_missing_routing_block_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=E

            :L lead_preds [id|kind|if|read_as|advance_to]
            lp1|presence|"a"|b|c
        """)
        with pytest.raises(PredictOutputError, match="selected_lead"):
            parse_predict_output(_d(body))

    def test_missing_hypotheses_block_on_shape_a_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(
            PredictOutputError, match="shape=A requires at least one hypothesis"
        ):
            parse_predict_output(_d(body))

    def test_missing_hypotheses_block_on_shape_m_fails(self):
        body = textwrap.dedent("""
            predict loop=1 shape=M

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="shape=M"):
            parse_predict_output(_d(body))

    def test_story_tolerates_blank_lines_between_sentences(self):
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. first sentence

            s2. second sentence

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s2|"x"

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        # Both s1 and s2 must be retained — s2 is the from_story_link and
        # parsing it would fail the sentence-ID consistency check if blank
        # lines closed the story prematurely.
        result = parse_predict_output(_d(body))
        story = result.invlang_delta["hypotheses"][0]["story"]
        assert "s1." in story and "s2." in story

    def test_attr_pred_in_comparisons_diagnoses_specifically(self):
        # An ap* id in a comparisons row gets a targeted error mentioning
        # that attribute_predictions don't carry comparisons.
        body = textwrap.dedent("""
            predict loop=1 shape=A

            ### story h-001
            s1. story

            :H hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|integrity_waived?|weight|status]
            h-001|?x|v-001|spawned|process|c|||null|active

            :P h-001.preds [id|subject|kind|from_story|claim]
            p1|proposed_parent|absolute|s1|"x"

            :P h-001.attr_preds [id|target|attribute|kind|claim]
            ap1|proposed_parent|cmdline|presence|"x"

            :P h-001.comparisons [pred_ref|selector_kind|selector|dimension]
            ap1|historical-self|"src=x"|some-dim

            :P h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
            ac1|proposed|some-anchor|"x"|esc|esc

            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(
            PredictOutputError, match="attribute_predictions do not carry comparisons"
        ):
            parse_predict_output(_d(body))


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def _shape_e_with_routing(routing_block: str) -> str:
    return textwrap.dedent(f"""
        predict loop=1 shape=E

        :L lead_preds [id|kind|if|read_as|advance_to]
        lp1|presence|"a"|b|c

        {routing_block.strip()}
    """).strip()


class TestRouting:
    def test_missing_selected_lead_fails(self):
        body = _shape_e_with_routing("""
            :R routing
            composite_secondary   -
            override_data_source  -
            rationale             "x"
        """)
        with pytest.raises(PredictOutputError, match="selected_lead"):
            parse_predict_output(_d(body))

    def test_optional_fields_propagate(self):
        body = _shape_e_with_routing("""
            :R routing
            selected_lead         x
            composite_secondary   y
            override_data_source  host_query
            rationale             "test"

            :R routing.lead_hints [lead|hint]
            x|"walk ancestry above runc"
            y|"cross-check session window"
        """)
        result = parse_predict_output(_d(body))
        assert result.routing["override_data_source"] == "host_query"
        assert result.routing["lead_hints"] == {
            "x": "walk ancestry above runc",
            "y": "cross-check session window",
        }

    def test_lead_hints_unknown_lead_rejected(self):
        body = _shape_e_with_routing("""
            :R routing
            selected_lead         x
            composite_secondary   -
            override_data_source  -
            rationale             "x"

            :R routing.lead_hints [lead|hint]
            not-prescribed|"stray hint"
        """)
        with pytest.raises(PredictOutputError, match="not-prescribed"):
            parse_predict_output(_d(body))


# ---------------------------------------------------------------------------
# scope_override — optional structured window override on routing
# ---------------------------------------------------------------------------


class TestScopeOverride:
    BASE = textwrap.dedent("""
        predict loop=1 shape=E

        :L lead_preds [id|kind|if|read_as|advance_to]
        lp1|presence|"a"|b|c

        :R routing
        selected_lead         x
        composite_secondary   -
        override_data_source  -
        rationale             "x"
    """).strip()

    def test_absent_scope_override_does_not_appear_in_routing(self):
        result = parse_predict_output(_d(self.BASE))
        assert "scope_override" not in result.routing

    def test_window_hours_only_defaults_anchor_to_alert(self):
        body = self.BASE + textwrap.dedent("""

            :R routing.scope_override [key|value]
            window_hours|24
        """)
        result = parse_predict_output(_d(body))
        assert result.routing["scope_override"] == {
            "window_hours": 24,
            "anchor": "alert",
        }

    def test_window_hours_plus_anchor_now(self):
        body = self.BASE + textwrap.dedent("""

            :R routing.scope_override [key|value]
            window_hours|72
            anchor|now
        """)
        result = parse_predict_output(_d(body))
        assert result.routing["scope_override"] == {
            "window_hours": 72,
            "anchor": "now",
        }

    def test_zero_window_hours_fails(self):
        body = self.BASE + textwrap.dedent("""

            :R routing.scope_override [key|value]
            window_hours|0
        """)
        with pytest.raises(PredictOutputError, match="window_hours must be > 0"):
            parse_predict_output(_d(body))

    def test_non_integer_window_hours_fails(self):
        body = self.BASE + textwrap.dedent("""

            :R routing.scope_override [key|value]
            window_hours|24h
        """)
        with pytest.raises(PredictOutputError, match="window_hours must be an integer"):
            parse_predict_output(_d(body))

    def test_bad_anchor_fails(self):
        body = self.BASE + textwrap.dedent("""

            :R routing.scope_override [key|value]
            window_hours|24
            anchor|yesterday
        """)
        with pytest.raises(PredictOutputError, match="anchor must be one of"):
            parse_predict_output(_d(body))


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


class TestAnalyzeDenseX5:
    def test_true_positive_without_adversarial_double_plus_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 weak ⟂ no-authority :: weak match ⟺ p1]

        :A routing
        decision               halt
        termination_category   exhaustion-escalation
        disposition            true_positive
        confidence             low
        surviving              h-001
        matched_archetype      null
        """).strip()
        names = {"h-001": "?adversary-controlled-source"}
        with pytest.raises(AnalyzeOutputError, match=r"true_positive requires"):
            parse_analyze_envelope_dense(body, declared_hypothesis_names=names)

    def test_true_positive_with_adversarial_double_plus_accepted(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → ++   [l-001 severe ⟂ e-001 :: anchor confirms attack ⟺ p1 ∧ ¬r1]

        :A routing
        decision               halt
        termination_category   trust-root
        disposition            true_positive
        confidence             high
        surviving              h-001
        matched_archetype      null
        """).strip()
        names = {"h-001": "?adversary-controlled-source"}
        env = parse_analyze_envelope_dense(body, declared_hypothesis_names=names)
        assert env.routing["disposition"] == "true_positive"


class TestAnalyzeDenseTrailingProseRejected:
    def test_trailing_prose_after_routing_rejected(self):
        body = textwrap.dedent("""
        :A loop  1

        :T resolutions
        h-001  ∅ → +    [l-001 weak ⟂ no-authority :: x ⟺ p1]

        :A routing
        decision               halt
        termination_category   trust-root
        disposition            benign
        confidence             high
        surviving              h-001
        matched_archetype      null

        Some trailing prose forgotten by the agent.
        """).strip()
        with pytest.raises(AnalyzeOutputError, match="unknown key"):
            parse_analyze_envelope_dense(body)


class TestAnalyzeDenseDecisiveGradeOrdering:
    def test_double_plus_outranks_plus_for_x1(self):
        # Same hypothesis graded `+` on l-001 (weak) and `++` on l-002
        # (decisive). Effective weight is `++` regardless of row order;
        # X1 must accept h-001 in surviving on both row orderings.
        for ordering in (
            ("h-001  ∅ → +    [l-001 weak ⟂ no-authority :: weak ⟺ p1]",
             "h-001  +  → ++   [l-002 severe ⟂ e-001 :: confirmed ⟺ p1 ∧ ¬r1]"),
            ("h-001  ∅ → ++   [l-002 severe ⟂ e-001 :: confirmed ⟺ p1 ∧ ¬r1]",
             "h-001  ++ → +    [l-001 weak ⟂ no-authority :: weak ⟺ p1]"),
        ):
            body = textwrap.dedent(f"""
            :A loop  1

            :T resolutions
            {ordering[0]}
            {ordering[1]}

            :A routing
            decision               halt
            termination_category   trust-root
            disposition            benign
            confidence             high
            surviving              h-001
            matched_archetype      null
            """).strip()
            env = parse_analyze_envelope_dense(body)
            assert env.routing["surviving_hypotheses"] == ["h-001"]
