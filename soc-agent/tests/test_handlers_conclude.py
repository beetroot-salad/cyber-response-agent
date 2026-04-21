"""Unit tests for the CONCLUDE phase handler.

The subagent invocation is mocked — these tests exercise prompt assembly,
routing selection (analyze / screen / forced_exhaustion), terminal YAML
parsing, and error propagation. They do not spawn a Claude subprocess.
"""

import sys
import textwrap
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.state import Phase  # noqa: E402
from scripts.handlers import conclude as conclude_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError, PhaseResult, run  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def make_ctx(
    tmp_path: Path,
    *,
    ticket_id: str = "SEC-2026-042",
    contextualize: dict | None = None,
    analyze: dict | None = None,
    screen: dict | None = None,
    forced_conclude: bool = False,
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    outputs: dict[Phase, dict] = {}
    if contextualize is not None:
        outputs[Phase.CONTEXTUALIZE] = contextualize
    if analyze is not None:
        outputs[Phase.ANALYZE] = analyze
    if screen is not None:
        outputs[Phase.SCREEN] = screen
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id=ticket_id,
        alert={"id": "alert-1"},
        outputs=outputs,
        forced_conclude=forced_conclude,
    )


def stub_invoke(captured: list[str], response: str):
    """Return a replacement for _invoke_subagent that records prompts and
    returns canned output."""
    def fn(prompt, *, timeout=None):
        captured.append(prompt)
        return response
    return fn


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------


class TestPromptAssembly:
    def test_analyze_routing_passes_core_fields(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            contextualize={},
            analyze={"disposition": "benign", "matched_archetype": "monitoring-probe"},
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        monkeypatch.setattr(conclude_handler, "_invoke_subagent", stub_invoke(captured, response))

        conclude_handler.handle(ctx)
        prompt = captured[0]

        assert f"run_dir={ctx.run_dir}" in prompt
        assert "signature_id=wazuh-rule-5710" in prompt
        assert "identifier=SEC-2026-042" in prompt
        assert "routing_source=analyze" in prompt
        assert "forced_exhaustion" not in prompt

    def test_screen_routing_selected_when_only_screen_output_present(
        self, tmp_path, monkeypatch
    ):
        ctx = make_ctx(
            tmp_path,
            contextualize={},
            screen={"screen_result": "match", "matched_archetype": "monitoring-probe"},
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        monkeypatch.setattr(conclude_handler, "_invoke_subagent", stub_invoke(captured, response))

        conclude_handler.handle(ctx)
        assert "routing_source=screen" in captured[0]

    def test_contextualize_dedup_routes_as_screen(self, tmp_path, monkeypatch):
        ctx = make_ctx(
            tmp_path,
            contextualize={"dedup": True},
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: medium
        matched_archetype: null
        status_frontmatter: resolved
        ```
        """).strip()
        monkeypatch.setattr(conclude_handler, "_invoke_subagent", stub_invoke(captured, response))

        conclude_handler.handle(ctx)
        assert "routing_source=screen" in captured[0]

    def test_forced_exhaustion_when_no_upstream_terminal_payload(
        self, tmp_path, monkeypatch
    ):
        ctx = make_ctx(
            tmp_path,
            contextualize={},
            forced_conclude=True,
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: inconclusive
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(conclude_handler, "_invoke_subagent", stub_invoke(captured, response))

        conclude_handler.handle(ctx)
        prompt = captured[0]
        assert "routing_source=forced_exhaustion" in prompt
        assert "forced_exhaustion=true" in prompt

    def test_missing_ticket_id_raises(self, tmp_path):
        ctx = make_ctx(tmp_path, ticket_id="", contextualize={})
        with pytest.raises(OrchestrationError, match="ticket_id"):
            conclude_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Terminal YAML parsing
# ---------------------------------------------------------------------------


class TestOutputParsing:
    def _setup(self, tmp_path, monkeypatch, response: str):
        ctx = make_ctx(
            tmp_path,
            contextualize={},
            analyze={"disposition": "benign"},
        )
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke([], response)
        )
        return ctx

    def test_written_payload_parsed(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        Some preamble the subagent shouldn't emit but we tolerate.

        ```yaml
        status: written
        report_path: /runs/abc/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = conclude_handler.handle(ctx)

        assert result.next_phase == Phase.CONCLUDE
        assert result.payload["status"] == "written"
        assert result.payload["report_path"] == "/runs/abc/report.md"
        assert result.payload["disposition"] == "benign"
        assert result.payload["matched_archetype"] == "monitoring-probe"

    def test_gate_failed_passthrough(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: gate_failed
        failure:
          stage: validate_conclude
          reason: "Judge A flagged: PLUS_PLUS_FALSIFICATION not satisfied"
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = conclude_handler.handle(ctx)

        assert result.payload["status"] == "gate_failed"
        assert result.payload["failure"]["stage"] == "validate_conclude"
        assert "Judge A flagged" in result.payload["failure"]["reason"]

    def test_error_status_propagated(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: error
        reason: "investigation.md not found"
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = conclude_handler.handle(ctx)
        assert result.payload["status"] == "error"
        assert "investigation.md" in result.payload["reason"]

    def test_last_yaml_block_wins(self, tmp_path, monkeypatch):
        """If the subagent emits multiple yaml blocks, the last one is terminal."""
        response = textwrap.dedent("""
        ```yaml
        # intermediate block, should be ignored
        status: written
        report_path: /wrong/path
        disposition: true_positive
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```

        some narration

        ```yaml
        status: written
        report_path: /correct/path
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = conclude_handler.handle(ctx)
        assert result.payload["report_path"] == "/correct/path"
        assert result.payload["disposition"] == "benign"

    def test_missing_yaml_block_raises(self, tmp_path, monkeypatch):
        ctx = self._setup(tmp_path, monkeypatch, "no fenced yaml here at all")
        with pytest.raises(OrchestrationError, match="no terminal YAML"):
            conclude_handler.handle(ctx)

    def test_unknown_status_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: bogus
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)
        with pytest.raises(OrchestrationError, match="unknown status"):
            conclude_handler.handle(ctx)

    def test_non_mapping_yaml_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        - just
        - a
        - list
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)
        with pytest.raises(OrchestrationError, match="not a mapping"):
            conclude_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Orchestrator integration
# ---------------------------------------------------------------------------


class TestOrchestratorIntegration:
    """End-to-end test of the handler wired into run() — verifies the
    orchestrator dispatches the CONCLUDE handler before returning, and
    that the payload lands in the run summary's outputs map."""

    def test_conclude_handler_runs_before_terminal_return(self, tmp_path, monkeypatch):
        run_dir = tmp_path / "run-1"
        run_dir.mkdir()
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="SEC-2026-042",
            alert={"id": "alert-1"},
        )

        def ctx_handler(c):
            return PhaseResult(
                next_phase=Phase.CONCLUDE,
                payload={"dedup": True},
            )

        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /runs/run-1/report.md
        disposition: benign
        confidence: medium
        matched_archetype: null
        status_frontmatter: resolved
        ```
        """).strip()
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke([], response)
        )

        handlers = {
            Phase.CONTEXTUALIZE: ctx_handler,
            Phase.CONCLUDE: conclude_handler.handle,
        }

        result = run(ctx, handlers)

        assert result["status"] == "complete"
        assert result["history"] == ["CONTEXTUALIZE", "CONCLUDE"]
        assert result["outputs"]["CONCLUDE"]["status"] == "written"
        assert result["outputs"]["CONCLUDE"]["report_path"] == "/runs/run-1/report.md"

    def test_conclude_handler_runs_on_forced_conclude(self, tmp_path, monkeypatch):
        """When MAX_LOOPS forces CONCLUDE, the handler still runs and receives
        a ctx with no ANALYZE/SCREEN outputs (forced-exhaustion path)."""
        run_dir = tmp_path / "run-forced"
        run_dir.mkdir()
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="SEC-2026-042",
            alert={"id": "alert-1"},
        )

        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /runs/run-forced/report.md
        disposition: inconclusive
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, response)
        )

        def ctx_handler(_c):
            return PhaseResult(
                next_phase=Phase.HYPOTHESIZE,
                payload={},
            )

        handlers = {
            Phase.CONTEXTUALIZE: ctx_handler,
            Phase.HYPOTHESIZE: lambda _c: PhaseResult(next_phase=Phase.GATHER),
            Phase.GATHER: lambda _c: PhaseResult(next_phase=Phase.ANALYZE),
            # ANALYZE never routes to CONCLUDE — bounces back to HYPOTHESIZE
            # until MAX_LOOPS is hit and orchestrator forces CONCLUDE.
            Phase.ANALYZE: lambda _c: PhaseResult(next_phase=Phase.HYPOTHESIZE),
            Phase.CONCLUDE: conclude_handler.handle,
        }

        result = run(ctx, handlers)

        assert result["status"] == "forced_conclude"
        assert result["history"][-1] == "CONCLUDE"
        # Subagent prompt should reflect forced-exhaustion since ANALYZE
        # never produced a terminal payload.
        prompt = captured[0]
        assert "routing_source=forced_exhaustion" in prompt
        assert "forced_exhaustion=true" in prompt
        assert result["outputs"]["CONCLUDE"]["status_frontmatter"] == "escalated"
