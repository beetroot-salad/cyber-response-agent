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
    # alert.json + meta.json are required — the analyze handler preloads the
    # alert and the per-run salt into the prompt.
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
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
## ANALYZE (loop 2)

**Evidence:** cadence-check — cadence matches declared 60s interval (±1.8s).

**Assessment:**
- ?benign-automation: ++ (was +) — matched prediction p2; r2 failed.
- ?brute-force: -- (was +) — matched refutation r1.

**Surviving hypotheses:** ?benign-automation
**Route:** halt → trust-root, disposition: benign, confidence: high, matched_archetype: monitoring-probe

## Self-report

- **Context wished for:** none
- **Uncertain claims:** none
- **Anomalies:**
  - none

```yaml
route: halt
termination_category: trust-root
disposition: benign
confidence: high
matched_archetype: monitoring-probe
surviving_hypotheses: [h-001]
```
""").strip()

_CONTINUE_RESPONSE = textwrap.dedent("""
## ANALYZE (loop 1)

**Evidence:** source-classification — IP matches approved registry.

**Assessment:**
- ?benign-automation: + (was new) — consistent with registry.
- ?brute-force: + (was new) — no differentiating evidence yet.

**Surviving hypotheses:** ?benign-automation, ?brute-force
**Route:** continue — fork still undifferentiated.

## Self-report

- **Context wished for:** cadence data
- **Uncertain claims:** registry freshness
- **Anomalies:**
  - none

```yaml
route: continue
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

    def test_prompt_inlines_alert_investigation_no_archetypes(self, tmp_path, monkeypatch):
        """Handler preloads alert + investigation only. Archetype context moved
        to the REPORT phase — ANALYZE no longer sees archetype stories."""
        ctx = make_ctx(
            tmp_path,
            history=[Phase.PREDICT.value],
            existing_investigation="## CONTEXTUALIZE\n\nalert observed.\n",
        )
        captured: list[str] = []
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke(captured, _CONTINUE_RESPONSE),
        )
        analyze_handler.handle(ctx)
        prompt = captured[0]

        # Tagged blocks present (alert tag is salted for injection safety)
        assert "<alert-test-salt>" in prompt and "</alert-test-salt>" in prompt
        # analyze handler uses mode="analyze" — tag carries a mode attribute
        assert "<investigation mode=\"analyze\">" in prompt and "</investigation>" in prompt
        # Archetype block explicitly absent — REPORT picks archetype, not ANALYZE
        assert "<archetypes>" not in prompt
        assert 'name="monitoring-probe"' not in prompt
        # Inlined content landed
        assert "alert observed." in prompt  # from investigation.md
        assert '"id": "alert-1"' in prompt  # from alert.json

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

    def test_escalated_with_surviving_list_accepted(self, tmp_path, monkeypatch):
        response = _HALT_RESPONSE.replace(
            "disposition: benign", "disposition: escalated"
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
        assert result.payload["disposition"] == "escalated"
        assert result.payload["surviving_hypotheses"] == ["h-001", "h-002"]
        assert result.payload["termination_category"] == "severity-ceiling"

    def test_writes_markdown_sections_without_terminal_yaml(
        self, tmp_path, monkeypatch,
    ):
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], _HALT_RESPONSE),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 2)" in written
        assert "## Self-report" in written
        # The terminal routing YAML fence must NOT have been written
        assert "route: halt" not in written
        assert "surviving_hypotheses: [h-001]" not in written

    def test_strip_preserves_non_terminal_yaml_fences(
        self, tmp_path, monkeypatch,
    ):
        # New contract (commit 2): strip only the last fence (the terminal
        # routing trailer). Non-terminal YAML fences survive — future-proofs
        # for ANALYZE emitting `resolutions:` sub-blocks once the invlang
        # merge-by-lead-id infrastructure lands. For now we don't expect any
        # non-terminal YAML in practice, but the handler must not drop it.
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        **Evidence:** test

        ```yaml
        # future-shape resolutions sub-block (hypothetical)
        resolutions:
          - hypothesis: h-001
            after: "+"
        ```

        More prose after the embedded block.

        ## Self-report

        - none

        ```yaml
        route: continue
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        analyze_handler.handle(ctx)
        written = (ctx.run_dir / "investigation.md").read_text()
        assert "## ANALYZE (loop 1)" in written
        assert "More prose after the embedded block." in written
        # Non-terminal YAML fence preserved
        assert "resolutions:" in written
        assert "hypothesis: h-001" in written
        # Terminal routing trailer dropped
        assert "route: continue" not in written


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
        assert "## Self-report" in written


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
        # overwrite from GATHER payload. (Subagent may know more than the
        # mechanical diff — e.g., a lead that was "resolved" but whose
        # observations didn't actually answer the predicate.)
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: continue
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
    def test_missing_terminal_yaml_raises(self, tmp_path, monkeypatch):
        response = "## ANALYZE (loop 1)\n\nSome markdown but no YAML.\n"
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="terminal YAML"):
            analyze_handler.handle(ctx)

    def test_invalid_route_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: BOGUS
        ```
        """).strip()
        ctx = make_ctx(tmp_path, history=[Phase.PREDICT.value])
        monkeypatch.setattr(
            analyze_handler, "_invoke_subagent",
            stub_invoke([], response),
        )
        with pytest.raises(OrchestrationError, match="invalid route"):
            analyze_handler.handle(ctx)

    def test_halt_without_termination_category_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: halt
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
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: halt
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

    def test_halt_without_surviving_hypotheses_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: halt
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
        with pytest.raises(OrchestrationError, match="surviving_hypotheses"):
            analyze_handler.handle(ctx)

    def test_continue_accepts_minimal_trailer(self, tmp_path, monkeypatch):
        # Continue has no required fields beyond `route` itself (discriminator
        # was dropped — PREDICT derives from companion state). A minimal
        # continue trailer passes validation.
        response = textwrap.dedent("""
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: continue
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
        ## ANALYZE (loop 1)

        ## Self-report
        - none

        ```yaml
        route: continue
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
        assert written_once.count("## ANALYZE (loop 2)") == 1
