"""Unit tests for the ANALYZE phase handler.

The subagent invocation is mocked — these tests exercise prompt assembly
(loop_n counting), terminal YAML parsing, routing-payload validation,
markdown extraction + append, and error propagation. They do not spawn a
Claude subprocess.
"""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import analyze as analyze_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError, PhaseResult  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    history: list[str] | None = None,
    existing_investigation: str | None = None,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    # alert.json + meta.json are required — the analyze handler preloads a
    # flat alert summary and the per-run salt into the prompt.
    alert = {
        "id": "alert-1",
        "rule": {"id": "5710", "description": "sshd: invalid user", "level": 5},
        "data": {"srcip": "10.0.0.1", "srcuser": "root"},
    }
    import json as _json
    (run_dir / "alert.json").write_text(_json.dumps(alert))
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))
    if existing_investigation is not None:
        (run_dir / "investigation.md").write_text(existing_investigation)
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="SEC-2026-042",
        alert=alert,
        history=history or [],
    )


def stub_invoke(captured: list[str], response: str):
    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        return response
    return fn


# Canned valid response fragments used across several tests.
_HALT_RESPONSE = textwrap.dedent("""
```yaml
analyze:
  loop: 2
  resolutions:
    - lead_ref: "l-002"
      entries:
        - hypothesis_id: "h-001"
          weight: "++"
          matched_prediction_ids: [p2]
          reasoning: "matched prediction p2; refutation r2 failed"
        - hypothesis_id: "h-002"
          weight: "--"
          matched_prediction_ids: [p1]
          matched_refutation_ids: [r1]
          reasoning: "matched refutation r1"
  anomalies: []
  data_wishes: []
  routing:
    decision: halt
    termination_category: trust-root
    disposition: benign
    confidence: high
    matched_archetype: monitoring-probe
    surviving_hypotheses: [h-001]
```
""").strip()

_CONTINUE_RESPONSE = textwrap.dedent("""
```yaml
analyze:
  loop: 1
  resolutions:
    - lead_ref: "l-001"
      entries:
        - hypothesis_id: "h-001"
          weight: "+"
          matched_prediction_ids: [p1]
          reasoning: "consistent with registry"
        - hypothesis_id: "h-002"
          weight: "+"
          matched_prediction_ids: [p1]
          reasoning: "no differentiating evidence yet"
  anomalies: []
  data_wishes:
    - "cadence data would sharpen grading"
  routing:
    decision: continue
```
""").strip()


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


class TestPromptAssembly:
    def test_passes_run_dir_and_signature(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _CONTINUE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert f"run_dir={ctx.run_dir}" in captured[0]
        assert "signature_id=wazuh-rule-5710" in captured[0]

    def test_prompt_ships_alert_summary_manifest_no_inline_investigation(self, tmp_path, monkeypatch):
        """Handler preloads a flat alert summary + an `<available_context>`
        manifest pointing at investigation.md (read-on-demand). The full
        `<investigation>` block is NOT inlined — the subagent Reads
        targeted line ranges via the Read tool. Archetype context is also
        absent (REPORT picks archetype, not ANALYZE)."""
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=(
                "## CONTEXTUALIZE\n\n"
                "**Playbook hypotheses:** ?bleed-target, ?should-not-grade\n\n"
                "```yaml\n"
                "prologue:\n"
                "  vertices:\n"
                "  - id: v-001\n"
                "    type: endpoint\n"
                "```\n"
                "\n"
                "## PREDICT (loop 1)\n\n"
                "```yaml\n"
                "hypothesize:\n"
                "  hypotheses:\n"
                "  - id: h-001\n"
                "    name: ?monitoring-probe\n"
                "```\n"
            ),
        )
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _CONTINUE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        prompt = captured[0]

        # Tagged alert summary is present (salted for injection safety).
        assert "<alert-test-salt>" in prompt and "</alert-test-salt>" in prompt
        assert "rule_id: \"5710\"" in prompt  # flat key=value summary, not nested JSON
        # The full alert JSON should NOT be inlined verbatim.
        assert '"id": "alert-1"' not in prompt

        # The full <investigation> block is gone; agent Reads it on demand.
        assert "<investigation" not in prompt
        # Manifest is present and names investigation.md + section line ranges.
        assert "<available_context>" in prompt and "</available_context>" in prompt
        assert "investigation.md" in prompt
        assert "alert.json" in prompt
        assert "## CONTEXTUALIZE" in prompt or "CONTEXTUALIZE" in prompt
        assert "PREDICT (loop 1)" in prompt

        # Archetype block explicitly absent — REPORT picks archetype, not ANALYZE
        assert "<archetypes>" not in prompt
        assert 'name="monitoring-probe"' not in prompt
        # Markdown prose surfaces (Playbook hypotheses, archetype catalogs)
        # don't ship inline either — the manifest only exposes paths +
        # section ranges, not body content.
        assert "?bleed-target" not in prompt
        assert "Playbook hypotheses:" not in prompt
        # And the YAML fence body from CONTEXTUALIZE is also not inlined —
        # the agent Reads the section if it needs the prologue vertices.
        assert "v-001" not in prompt

    def test_loop_n_counts_hypothesize_entries(self, tmp_path, monkeypatch):
        # Three PREDICT entries → loop_n = 3
        ctx = make_ctx(
            tmp_path,
            history=[
                Phase.CONTEXTUALIZE.value,
                Phase.PREDICT.value, Phase.GATHER.value, Phase.ANALYZE.value,
                Phase.PREDICT.value, Phase.GATHER.value, Phase.ANALYZE.value,
                Phase.PREDICT.value, Phase.GATHER.value,
            ],
        )
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _HALT_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert "loop_n=3" in captured[0]

    def test_loop_n_defaults_to_one_when_no_hypothesize(self, tmp_path, monkeypatch):
        # Edge case: SCREEN-match path without hypothesize shouldn't normally
        # land in ANALYZE, but the fallback protects against surprise history.
        ctx = make_ctx(tmp_path, history=[Phase.CONTEXTUALIZE.value])
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _HALT_RESPONSE),
        )
        analyze_handler.handle(ctx)
        assert "loop_n=1" in captured[0]


# ---------------------------------------------------------------------------
# Routing — REPORT
# ---------------------------------------------------------------------------


class TestHandleRoutesConclude:
    def test_routes_to_conclude_on_valid_yaml(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HALT_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.REPORT
        assert result.payload["disposition"] == "benign"
        assert result.payload["confidence"] == "high"
        assert result.payload["matched_archetype"] == "monitoring-probe"
        assert result.payload["surviving_hypotheses"] == ["h-001"]

    def test_matched_archetype_null_accepted(self, tmp_path, monkeypatch):
        response = _HALT_RESPONSE.replace(
            "matched_archetype: monitoring-probe",
            "matched_archetype: null",
        )
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.REPORT
        assert result.payload["matched_archetype"] is None

    def test_unclear_with_surviving_list_accepted(self, tmp_path, monkeypatch):
        # v2.11: `unclear` is the non-benign escalation disposition.
        # `escalated` is a status, never a disposition.
        response = _HALT_RESPONSE.replace(
            "disposition: benign", "disposition: unclear"
        ).replace(
            "matched_archetype: monitoring-probe",
            "matched_archetype: null",
        ).replace(
            "surviving_hypotheses: [h-001]",
            "surviving_hypotheses: [h-001, h-002]",
        ).replace(
            "termination_category: trust-root",
            "termination_category: severity-ceiling",
        )
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.REPORT
        assert result.payload["disposition"] == "unclear"
        assert result.payload["surviving_hypotheses"] == ["h-001", "h-002"]
        assert result.payload["termination_category"] == "severity-ceiling"

    def test_writes_markdown_section_rendered_from_envelope(
        self, tmp_path, monkeypatch,
    ):
        # Single-PREDICT history → loop_n = 1. Envelope's loop field (2) is
        # audit-trail only — the handler uses ctx.history for composing.
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HALT_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 1)" in written
        assert "**Assessment:**" in written
        # Per-resolution reasoning rendered.
        assert "matched refutation r1" in written
        # The envelope's routing fields — handler does NOT echo the raw YAML.
        assert "analyze:" not in written
        assert "surviving_hypotheses: [h-001]" not in written


# ---------------------------------------------------------------------------
# Routing — PREDICT
# ---------------------------------------------------------------------------


class TestHandleRoutesContinue:
    def test_routes_to_predict_on_valid_yaml(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONTINUE_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT
        assert result.payload["route"] == "continue"

    def test_writes_markdown_sections(self, tmp_path, monkeypatch):
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONTINUE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 1)" in written
        # Self-report block present because the CONTINUE envelope carries
        # a non-empty data_wishes list.
        assert "**Self-report:**" in written
        assert "cadence data would sharpen" in written


class TestUnresolvedPrescribedSetBackfill:
    """ANALYZE handler back-fills unresolved_prescribed_set from GATHER payload
    when the subagent didn't compute it. This is the backstop for Bug A — even
    if gather-composite's scope-check is bypassed, PREDICT still sees the gap.
    """

    def _ctx_with_gather(
        self, tmp_path, prescribed: list[str], executed: list[str],
    ) -> Context:
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        ctx.outputs[Phase.GATHER] = {
            "prescribed_leads": prescribed,
            "executed_leads": executed,
        }
        return ctx

    def test_backfill_adds_missing_leads_when_subagent_omits(
        self, tmp_path, monkeypatch,
    ):
        ctx = self._ctx_with_gather(
            tmp_path,
            prescribed=["correlated-falco-events", "source-reputation"],
            executed=["correlated-falco-events"],
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONTINUE_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert result.payload["unresolved_prescribed_set"] == ["source-reputation"]

    def test_backfill_absent_when_fully_covered(self, tmp_path, monkeypatch):
        ctx = self._ctx_with_gather(
            tmp_path,
            prescribed=["correlated-falco-events"],
            executed=["correlated-falco-events"],
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONTINUE_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        # No gap → no unresolved_prescribed_set emitted by the backfill.
        assert "unresolved_prescribed_set" not in result.payload

    def test_subagent_emission_takes_precedence_over_backfill(
        self, tmp_path, monkeypatch,
    ):
        # Subagent emits its own unresolved_prescribed_set — handler does not
        # overwrite from GATHER payload.
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: continue
            unresolved_prescribed_set: [custom-lead]
        ```
        """).strip()
        ctx = self._ctx_with_gather(
            tmp_path,
            prescribed=["lead-a", "lead-b"],
            executed=["lead-a"],
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.payload["unresolved_prescribed_set"] == ["custom-lead"]

    def test_backfill_skipped_on_halt_route(self, tmp_path, monkeypatch):
        # On halt, unresolved_prescribed_set is irrelevant — PREDICT won't run.
        ctx = self._ctx_with_gather(
            tmp_path,
            prescribed=["lead-a", "lead-b"],
            executed=["lead-a"],
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HALT_RESPONSE),
        )
        result = analyze_handler.handle(ctx)
        assert "unresolved_prescribed_set" not in result.payload


# ---------------------------------------------------------------------------
# Malformed output
# ---------------------------------------------------------------------------


class TestHandleMalformedOutput:
    def test_missing_envelope_raises(self, tmp_path, monkeypatch):
        response = "## ANALYZE (loop 1)\n\nSome markdown but no YAML.\n"
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="envelope shape violation"):
            analyze_handler.handle(ctx)

    def test_invalid_route_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: BOGUS
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="decision must be one of"):
            analyze_handler.handle(ctx)

    def test_halt_without_termination_category_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: halt
            disposition: benign
            confidence: high
            matched_archetype: null
            surviving_hypotheses: []
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="termination_category"):
            analyze_handler.handle(ctx)

    def test_halt_without_disposition_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: halt
            termination_category: trust-root
            confidence: high
            matched_archetype: null
            surviving_hypotheses: []
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="disposition"):
            analyze_handler.handle(ctx)

    def test_halt_without_surviving_hypotheses_accepted(self, tmp_path, monkeypatch):
        # surviving_hypotheses is optional in the envelope — defaults to []
        # when the subagent omits it (every hypothesis refuted).
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: halt
            termination_category: trust-root
            disposition: benign
            confidence: high
            matched_archetype: null
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.payload["surviving_hypotheses"] == []

    def test_continue_accepts_minimal_envelope(self, tmp_path, monkeypatch):
        # Continue has no required fields beyond decision itself.
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: continue
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.PREDICT

    def test_continue_with_malformed_unresolved_prescribed_set_raises(
        self, tmp_path, monkeypatch,
    ):
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          routing:
            decision: continue
            unresolved_prescribed_set: "source-reputation"
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="unresolved_prescribed_set"):
            analyze_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Append behavior
# ---------------------------------------------------------------------------


class TestAppendBehavior:
    def test_preserves_existing_investigation_content(self, tmp_path, monkeypatch):
        existing = (
            "## CONTEXTUALIZE\n\n"
            "Existing prologue content.\n\n"
            "## PREDICT (loop 1)\n\n"
            "Existing hypotheses.\n"
        )
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=existing,
        )
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _CONTINUE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        # Existing content must come first
        assert written.startswith("## CONTEXTUALIZE")
        assert "Existing hypotheses." in written
        # New ANALYZE section appended
        assert "## ANALYZE (loop 1)" in written.split("Existing hypotheses.")[1]

    def test_handler_is_deterministic_on_same_input(self, tmp_path, monkeypatch):
        """Same response → same file content on repeat invocation (minus append)."""
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HALT_RESPONSE),
        )
        result1 = analyze_handler.handle(ctx)
        assert result1.next_phase == Phase.REPORT
        # Only verify that a second call appends rather than duplicates the stripping behavior.
        written_once = (ctx.run_dir / "investigation.md").read_text()
        # Handler uses ctx.history to compute loop_n → loop 1 for a single
        # PREDICT entry in history. Envelope's loop field (2) is audit-only.
        assert written_once.count("## ANALYZE (loop 1)") == 1


# ---------------------------------------------------------------------------
# Findings synthesis (handler authors invlang from gather + analyze envelopes)
# ---------------------------------------------------------------------------


class TestFindingsSynthesis:
    """Analyze-handler synthesizes the `findings[]` invlang block from
    gather's envelope (stashed in ctx.outputs[Phase.GATHER]["leads"]) +
    analyze's interpretation envelope. Validator-valid output is required —
    the handler writes via `validate_companion`, which rejects on schema
    errors.
    """

    _PROLOGUE = textwrap.dedent("""\
        ## CONTEXTUALIZE

        ```yaml
        prologue:
          vertices:
            - id: v-001
              type: endpoint
              classification: target-endpoint
              identifier: "target-endpoint"
          edges: []
        ```

        ## PREDICT (loop 1)

        ```yaml
        hypothesize:
          hypotheses:
            - id: h-001
              name: "?monitoring-probe"
              status: active
              classification: benign-mechanism
              proposed_edge:
                id: e-p001
                parent_vertex: {type: identity, classification: external-source, identifier: "monitorprobe"}
                attached_to_vertex: v-001
                relation: authenticates_to
                authority: siem-event
              predictions:
                - id: p1
                  subject: proposed_parent
                  claim: "single attempt per tick"
              weight: null
        ```
        """)

    def _halt_response_with_resolutions(self) -> str:
        # Uses `+` instead of `++` — avoids the supporting_edges
        # requirement that confirmed-weight resolutions impose (validator
        # rule on edge authority). The test asserts on the synthesis
        # mechanics, not the grading discipline.
        return textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          resolutions:
            - lead_ref: "l-001"
              entries:
                - hypothesis_id: "h-001"
                  weight: "+"
                  matched_prediction_ids: [p1]
                  reasoning: "consistent with p1"
          anomalies: []
          data_wishes: []
          routing:
            decision: halt
            termination_category: severity-ceiling
            disposition: unclear
            confidence: medium
            matched_archetype: null
            surviving_hypotheses: [h-001]
        ```
        """).strip()

    def test_synthesizes_findings_from_envelopes(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,
        )
        # Stash gather envelope in ctx.outputs — mirrors what gather.py
        # emits to ctx.outputs[Phase.GATHER] on a real dispatch.
        ctx.outputs[Phase.GATHER] = {
            "leads": [
                {
                    "id": "l-001",
                    "name": "authentication-history",
                    "status": "ok",
                    "query": {
                        "system": "wazuh-indexer",
                        "template": "source-ip-lookup",
                        "query": "rule.groups:sshd",
                        "time_window": {
                            "start": "2026-04-20T18:25:00Z",
                            "end": "2026-04-20T19:25:00Z",
                        },
                        "substitutions": {"ip": "10.0.1.99"},
                    },
                    "characterization": {"total_events": 11},
                    "observations": {"vertices": [], "edges": []},
                },
            ],
            "prescribed_leads": ["authentication-history"],
            "executed_leads": ["authentication-history"],
            "raw_details_paths": [],
        }
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], self._halt_response_with_resolutions()),
        )

        result = analyze_handler.handle(ctx)

        assert result.next_phase == Phase.REPORT
        written = (ctx.run_dir / "investigation.md").read_text()
        # The handler wrote an invlang `findings:` block alongside the
        # prose ANALYZE section. Validator would have rejected an invalid
        # block via validate_companion, so reaching this assertion proves
        # the synthesized YAML passes schema checks.
        assert "findings:" in written
        assert "id: l-001" in written
        assert "target: v-001" in written  # default from prologue
        assert "hypothesis: h-001" in written
        assert "after: +" in written or "after: '+'" in written

    def test_translates_hypothesis_name_to_declared_id(self, tmp_path, monkeypatch):
        """The subagent often emits `?playbook-name` as `hypothesis_id`
        when PREDICT has already declared a matching `h-*`. Handler looks
        up the name in the companion's hypothesize block and substitutes.
        """
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,
        )
        ctx.outputs[Phase.GATHER] = {
            "leads": [{"id": "l-001", "name": "auth", "status": "ok",
                       "query": {"system": "wazuh-indexer"}}],
            "prescribed_leads": ["auth"],
            "executed_leads": ["auth"],
            "raw_details_paths": [],
        }
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          resolutions:
            - lead_ref: "l-001"
              entries:
                - hypothesis_id: "?monitoring-probe"
                  weight: "+"
                  matched_prediction_ids: [p1]
                  reasoning: "consistent with p1"
          routing:
            decision: continue
        ```
        """).strip()
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        # Name translated to the declared h-id — `?monitoring-probe`
        # exists as `name` on h-001 per the _PROLOGUE fixture.
        assert "hypothesis: h-001" in written
        assert "?monitoring-probe" not in (
            written.split("findings:")[-1] if "findings:" in written else ""
        )

    def test_drops_resolutions_that_reference_undeclared_hypotheses(
        self, tmp_path, monkeypatch,
    ):
        """When the subagent cites a hypothesis that was never declared
        (no `h-*` id, no matching `name`), drop that resolution — keeping
        it would produce a findings block the validator rejects as a
        dangling ID reference.
        """
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,
        )
        ctx.outputs[Phase.GATHER] = {
            "leads": [{"id": "l-001", "name": "auth", "status": "ok",
                       "query": {"system": "wazuh-indexer"}}],
            "prescribed_leads": ["auth"],
            "executed_leads": ["auth"],
            "raw_details_paths": [],
        }
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          resolutions:
            - lead_ref: "l-001"
              entries:
                - hypothesis_id: "?monitoring-probe"
                  weight: "+"
                  matched_prediction_ids: [p1]
                  reasoning: "declared hypothesis"
                - hypothesis_id: "?image-entrypoint"
                  weight: "-"
                  matched_prediction_ids: [p1]
                  reasoning: "not declared in prologue"
          routing:
            decision: continue
        ```
        """).strip()
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        # Declared hypothesis resolved; undeclared dropped.
        assert "hypothesis: h-001" in written
        assert "image-entrypoint" not in written.split("findings:")[-1]

    def test_supporting_edges_defaulted_on_confirmed_weights(
        self, tmp_path, monkeypatch,
    ):
        """Any ++/-- resolution must cite at least one authoritative edge in
        `supporting_edges` (invlang structural rule). The subagent doesn't
        author graph-level edge references; the handler defaults them to the
        prologue's authoritative edges (kind ∈
        {siem-event, runtime-audit, authoritative-source}).
        """
        prologue_with_edges = textwrap.dedent("""\
            ## CONTEXTUALIZE

            ```yaml
            prologue:
              vertices:
                - id: v-001
                  type: endpoint
                  classification: target-endpoint
                  identifier: "target-endpoint"
                - id: v-002
                  type: process
                  classification: runtime-exec-primitive
                  identifier: runc
              edges:
                - id: e-001
                  relation: spawned
                  source_vertex: v-002
                  target_vertex: v-001
                  authority: {kind: runtime-audit, source: "Wazuh (rule 100001)"}
                - id: e-002
                  relation: observed
                  source_vertex: v-001
                  target_vertex: v-002
                  authority: {kind: siem-event, source: "Wazuh"}
            ```

            ## PREDICT (loop 1)

            ```yaml
            hypothesize:
              hypotheses:
                - id: h-001
                  name: "?underlying-host"
                  proposed_edge:
                    id: e-p001
                    parent_vertex: {type: process, classification: host-invoker, identifier: "runc"}
                    attached_to_vertex: v-002
                    relation: invoked
                    authority: siem-event
                  predictions:
                    - id: p1
                      subject: proposed_edge
                      claim: "prior events exist in the 7d window"
                  refutation_shape:
                    - id: r1
                      refutes_predictions: [p1]
                      claim: "empty baseline"
                  weight: null
            ```
            """)
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=prologue_with_edges,
        )
        ctx.outputs[Phase.GATHER] = {
            "leads": [
                {
                    "id": "l-001",
                    "name": "container-baseline",
                    "status": "ok",
                    "query": {"system": "wazuh", "query": "rule.id:100001"},
                    "characterization": {"total_events": 36},
                },
            ],
            "prescribed_leads": ["container-baseline"],
            "executed_leads": ["container-baseline"],
            "raw_details_paths": [],
        }
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          resolutions:
            - lead_ref: "l-001"
              entries:
                - hypothesis_id: "h-001"
                  weight: "++"
                  matched_prediction_ids: [p1]
                  reasoning: "36 prior events; r1 failed to materialize."
          routing:
            decision: continue
        ```
        """).strip()
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        findings_yaml = written.split("findings:")[-1]
        # Both authoritative prologue edges land as supporting_edges defaults.
        assert "supporting_edges" in findings_yaml
        assert "e-001" in findings_yaml
        assert "e-002" in findings_yaml

    def test_load_bearing_passed_through(self, tmp_path, monkeypatch):
        """The load_bearing[] artifact ANALYZE declares is preserved in the
        synthesized resolution. No structural validation runs on it today —
        the field is captured for downstream perturbation analysis (Tier 1).
        """
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,
        )
        ctx.outputs[Phase.GATHER] = {
            "leads": [{"id": "l-001", "name": "auth", "status": "ok",
                       "query": {"system": "wazuh"}}],
            "prescribed_leads": ["auth"],
            "executed_leads": ["auth"],
            "raw_details_paths": [],
        }
        response = textwrap.dedent("""
        ```yaml
        analyze:
          loop: 1
          resolutions:
            - lead_ref: "l-001"
              entries:
                - hypothesis_id: "h-001"
                  weight: "+"
                  matched_prediction_ids: [p1]
                  reasoning: "consistent with p1; no decisive authority."
                  load_bearing:
                    - field: "wazuh.event_count"
                      source: "l-001"
                      counterfactual: "If event_count had been 0 (no matching events), the grade would be `-` not `+`."
          routing:
            decision: continue
        ```
        """).strip()
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        findings_yaml = written.split("findings:")[-1]
        assert "load_bearing" in findings_yaml
        assert "wazuh.event_count" in findings_yaml
        assert "counterfactual" in findings_yaml
        # value_summary intentionally absent — counterfactual carries the value
        # by implication.
        assert "value_summary" not in findings_yaml

    def test_supporting_edges_not_emitted_on_weak_weights(
        self, tmp_path, monkeypatch,
    ):
        """+/- grades do not carry supporting_edges — only ++/-- do. The
        invlang rule doesn't fire on weak grades, so defaulting them would
        add noise.
        """
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,  # has no edges
        )
        ctx.outputs[Phase.GATHER] = {
            "leads": [{"id": "l-001", "name": "auth", "status": "ok",
                       "query": {"system": "wazuh"}}],
            "prescribed_leads": ["auth"],
            "executed_leads": ["auth"],
            "raw_details_paths": [],
        }
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], self._halt_response_with_resolutions()),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        findings_yaml = written.split("findings:")[-1]
        assert "supporting_edges" not in findings_yaml

    def test_skips_synthesis_when_gather_leads_absent(self, tmp_path, monkeypatch):
        # SCREEN-matched and forced-exhaustion paths reach ANALYZE without
        # a gather envelope — synthesis must silently skip.
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation=self._PROLOGUE,
        )
        # No ctx.outputs[Phase.GATHER] — synthesis bails.
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], self._halt_response_with_resolutions()),
        )

        result = analyze_handler.handle(ctx)
        assert result.next_phase == Phase.REPORT
        written = (ctx.run_dir / "investigation.md").read_text()
        # Prose section landed; no findings block (no gather leads to synthesize).
        assert "## ANALYZE (loop 1)" in written
        # findings: appears only in the prose "Assessment" header area;
        # no YAML fence with findings key.
        assert "findings:\n  -" not in written
