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
    investigation_md: str = "## CONTEXTUALIZE\n\nalert observed.\n",
) -> Context:
    run_dir = tmp_path / "run-test"
    run_dir.mkdir()
    # alert.json + investigation.md + meta.json are now pre-loaded by the
    # handler into the prompt (alert + per-run salt), so all must exist on disk.
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
    import json as _json
    (run_dir / "alert.json").write_text(_json.dumps(alert))
    (run_dir / "investigation.md").write_text(investigation_md)
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))
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
        alert=alert,
        outputs=outputs,
        forced_conclude=forced_conclude,
    )


def _prepare_run_dir(run_dir: Path, *, investigation_md: str = "## CONTEXTUALIZE\n\nalert observed.\n") -> None:
    """Create alert.json + investigation.md + meta.json on disk so the
    handler's preloaded prompt assembly doesn't error. Kept small — tests
    that need specific alert content or investigation shape override per-call."""
    import json as _json
    alert = {"id": "alert-1", "rule": {"id": "5710"}, "data": {}}
    run_dir.mkdir(exist_ok=True)
    (run_dir / "alert.json").write_text(_json.dumps(alert))
    (run_dir / "investigation.md").write_text(investigation_md)
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))


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
    def test_prompt_inlines_alert_investigation_archetypes_with_precedents(self, tmp_path, monkeypatch):
        """Non-forced path preloads alert + investigation + archetype shapes
        with precedents into the prompt so the subagent needs no Read/Glob."""
        ctx = make_ctx(
            tmp_path,
            analyze={"disposition": "benign", "matched_archetype": "monitoring-probe"},
            investigation_md="## CONTEXTUALIZE\n\nsignature analysis.\n\n## ANALYZE (loop 1)\n\nrouting.\n",
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
        # All three tagged blocks present (alert tag is salted)
        assert "<alert-test-salt>" in prompt and "</alert-test-salt>" in prompt
        assert "<investigation>" in prompt and "signature analysis" in prompt
        assert "<archetypes>" in prompt
        # Matched archetype shape inlined
        assert 'name="monitoring-probe"' in prompt
        # Precedents surfaced (5710/monitoring-probe ships SEC-2024-001)
        assert "SEC-2024-001" in prompt

    def test_prompt_omits_archetypes_on_forced_exhaustion(self, tmp_path, monkeypatch):
        """Forced-exhaustion emits matched_archetype=null by contract, so
        loading archetype shapes + precedents is wasted prompt tokens. Block
        must be absent."""
        ctx = make_ctx(tmp_path, forced_conclude=True)
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
        assert "<alert-test-salt>" in prompt
        assert "<investigation>" in prompt
        assert "<archetypes>" not in prompt
        assert "<archetype " not in prompt

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

    def test_contextualize_dedup_falls_through_to_forced_exhaustion(self, tmp_path, monkeypatch):
        """Dedup fast-path is retired (tasks/dedup-fast-path.md). A
        CONTEXTUALIZE payload with `dedup=True` is no longer produced by the
        handler, but even if it were, the CONCLUDE routing source selector
        must not treat it as screen. With no SCREEN or ANALYZE output, this
        case falls through to `forced_exhaustion` (telemetry-only shape that
        an operator can investigate)."""
        ctx = make_ctx(
            tmp_path,
            contextualize={"dedup": True},
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
        assert "routing_source=forced_exhaustion" in captured[0]
        assert "forced_exhaustion=true" in captured[0]

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
        _prepare_run_dir(run_dir)
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="SEC-2026-042",
            alert={"id": "alert-1"},
        )

        def ctx_handler(c):
            # Structural test — confirms the orchestrator dispatches the
            # CONCLUDE handler when an upstream phase routes there.
            # CONTEXTUALIZE→CONCLUDE remains a legal edge in TRANSITIONS
            # even though the live handler no longer routes on dedup.
            return PhaseResult(
                next_phase=Phase.CONCLUDE,
                payload={"dedup": False},
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
        _prepare_run_dir(run_dir)
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


# ---------------------------------------------------------------------------
# Mechanical CONCLUDE composer (SCREEN-match fast-path)
# ---------------------------------------------------------------------------


def _seed_ctx_for_mechanical(tmp_path: Path, *, matched_ticket_id: str | None) -> Context:
    """Build a ctx with a SCREEN payload complete enough to trigger the
    mechanical CONCLUDE composer."""
    run_dir = tmp_path / "run-mech"
    run_dir.mkdir()
    # Seed alert.json + meta.json for the preload path (even though
    # mechanical compose doesn't invoke the subagent, assembling a ctx that
    # validates cleanly means fallback paths still work).
    import json as _json
    (run_dir / "alert.json").write_text(
        _json.dumps({"id": "alert-1", "rule": {"id": "5710"}, "data": {}})
    )
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))
    # Seed investigation.md with a minimal prologue so the mechanical path's
    # investigation.md append produces valid cumulative text.
    (run_dir / "investigation.md").write_text(
        "## CONTEXTUALIZE\n\n"
        "**Alert:** SEC-2026-042 — wazuh-rule-5710\n\n"
        "```yaml\n"
        "prologue:\n"
        "  vertices:\n"
        "  - id: v-001\n"
        "    type: endpoint\n"
        "    classification: internal-monitoring-host\n"
        "    identifier: 172.22.0.10\n"
        "  edges: []\n"
        "```\n"
    )
    screen_payload = {
        "screen_result": "match",
        "matched_pattern": "monitoring-probe fast-path",
        "matched_archetype": "monitoring-probe",
        "matched_ticket_id": matched_ticket_id,
        "disposition": "benign",
        "confidence": "high",
        "evidence_summary": "approved source, single attempt, no successful login follow-up",
        "leads_run": [
            {"lead": "source-classification", "observation": "172.22.0.10 -> internal-monitoring-host"},
            {"lead": "username-classification", "observation": "nagios -> monitoring-pattern"},
            {
                "lead": "approved-monitoring-sources",
                "observation": "(172.22.0.10, nagios, target-endpoint) -> authorized",
            },
            {
                "lead": "authentication-history",
                "observation": "cluster_count=1, no successful logins after",
            },
        ],
        "gather": [
            {
                "id": "l-001", "loop": 0, "name": "source-classification",
                "target": "v-001", "mode": "screen",
                "outcome": {"attribute_updates": [{"target": "v-001", "updates": {"classification": "internal-monitoring-host"}}]},
            },
            {
                "id": "l-003", "loop": 0, "name": "approved-monitoring-sources",
                "target": "e-001", "mode": "screen",
                "outcome": {
                    "trust_anchor_result": {
                        "anchor_id": "approved-monitoring-sources",
                        "kind": "org-authority",
                        "asks": "authorization",
                        "verdict": "authorized",
                        "result": "confirmed",
                        "as_of": "2026-04-20T19:25:01Z",
                        "authority_for_question": "full",
                    },
                },
            },
        ],
    }
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="1776748918.3300232",
        alert={"id": "1776748918.3300232"},
        outputs={Phase.SCREEN: screen_payload},
    )


class TestMechanicalScreenCompose:
    def test_mechanical_path_skips_subagent_and_writes_report(
        self, tmp_path, monkeypatch,
    ):
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-2024-001")
        captured: list[str] = []
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, "UNEXPECTED"),
        )

        result = conclude_handler.handle(ctx)

        # Subagent must not be called on the mechanical fast-path.
        assert captured == []
        assert result.next_phase == Phase.CONCLUDE
        assert result.payload["status"] == "written"
        assert result.payload["compose_mode"] == "screen_mechanical_grounded"
        assert result.payload["matched_archetype"] == "monitoring-probe"
        assert result.payload["status_frontmatter"] == "resolved"

        report_path = ctx.run_dir / "report.md"
        assert report_path.exists()
        report = report_path.read_text()
        # Frontmatter grounds on the precedent.
        assert 'matched_ticket_id: SEC-2024-001' in report
        # Wazuh ids contain a dot; yaml.safe_dump single-quotes them so they
        # aren't parsed as floats when the frontmatter is re-read.
        assert "1776748918.3300232" in report
        assert "ticket_id: '1776748918.3300232'" in report
        assert "status: resolved" in report
        assert "## Summary" in report
        assert "## Investigation Trace" in report
        assert "## Hypothesis Outcomes" in report
        assert "## Key Evidence" in report
        assert "## Verdict" in report
        # No For Analyst section on resolved.
        assert "## For Analyst" not in report

        # investigation.md carries the CONCLUDE markdown + fenced conclude YAML.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "## CONCLUDE" in inv
        assert "conclude:" in inv
        assert "category: trust-root" in inv

    def test_mechanical_path_falls_back_to_anchor_leg_when_precedent_missing(
        self, tmp_path, monkeypatch,
    ):
        """SCREEN claimed a matched_ticket_id that does not exist on disk.
        Handler must drop the precedent cite and ground via the anchor leg."""
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-9999-999")
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )
        result = conclude_handler.handle(ctx)
        assert result.payload["status"] == "written"
        assert result.payload["status_frontmatter"] == "resolved"
        # Report frontmatter has matched_ticket_id: null (anchor leg only).
        report = (ctx.run_dir / "report.md").read_text()
        assert "matched_ticket_id: null" in report

    def test_level_2_partial_grounding_escalates_mechanically(
        self, tmp_path, monkeypatch,
    ):
        """Archetype exists but grounding is incomplete (precedent file
        missing AND anchor not confirmed). Handler composes mechanically at
        Level 2: status=escalated, SCREEN's disposition preserved, confidence
        clamped to medium. No subagent call, no raise."""
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-9999-999")
        # Drop the confirmed trust_anchor_result so the anchor leg also fails.
        screen = ctx.outputs[Phase.SCREEN]
        screen["gather"] = [
            {
                "id": "l-001", "loop": 0, "name": "source-classification",
                "target": "v-001", "mode": "screen",
                "outcome": {"attribute_updates": [{"target": "v-001", "updates": {"classification": "x"}}]},
            },
        ]
        captured: list[str] = []
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, "UNEXPECTED"),
        )

        result = conclude_handler.handle(ctx)
        assert captured == []  # still mechanical, still no subagent
        assert result.payload["compose_mode"] == "screen_mechanical_partial"
        assert result.payload["status_frontmatter"] == "escalated"
        assert result.payload["disposition"] == "benign"  # SCREEN's call preserved
        assert result.payload["confidence"] == "medium"   # clamped from high

        report = (ctx.run_dir / "report.md").read_text()
        assert "status: escalated" in report
        assert "disposition: benign" in report
        assert "confidence: medium" in report
        # For Analyst section appears on escalated.
        assert "## For Analyst" in report
        # Rationale names the missing precedent.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "grounding incomplete" in inv
        assert "SEC-9999-999" in inv

    def test_level_3_fallback_when_archetype_missing(
        self, tmp_path, monkeypatch,
    ):
        """Archetype directory does not exist → mechanical composer raises
        _MechanicalFallback; handler dispatches the conclude subagent with
        the fallback reason noted in the payload."""
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-2024-001")
        # Point at a non-existent archetype.
        ctx.outputs[Phase.SCREEN]["matched_archetype"] = "does-not-exist-arch"

        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: does-not-exist-arch
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, response),
        )

        result = conclude_handler.handle(ctx)
        assert len(captured) == 1  # subagent dispatched
        assert result.payload["compose_mode"] == "subagent"
        assert "archetype dir missing" in result.payload["mechanical_fallback_reason"]

    def test_level_3_fallback_rolls_back_partial_writes(
        self, tmp_path, monkeypatch,
    ):
        """If Tier-1 validation fails on a mechanically-composed report, the
        handler rolls back the investigation.md append and the report.md
        write before falling back to the subagent. The subagent must see the
        run dir in its pre-mechanical state."""
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-2024-001")
        inv_before = (ctx.run_dir / "investigation.md").read_text()

        # Force Tier-1 to always fail, simulating a schema-assumption violation.
        def fail_tier1(_path):
            from scripts.orchestrate import OrchestrationError
            raise OrchestrationError("simulated tier-1 rejection")
        monkeypatch.setattr(conclude_handler, "_run_tier1_validation", fail_tier1)

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
        captured: list[str] = []
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, response),
        )

        result = conclude_handler.handle(ctx)
        assert len(captured) == 1  # subagent was dispatched
        assert result.payload["compose_mode"] == "subagent"
        assert "Tier-1" in result.payload["mechanical_fallback_reason"]

        # Rollback invariants: investigation.md back to pre-mechanical text,
        # report.md deleted (the subagent would create it).
        assert (ctx.run_dir / "investigation.md").read_text() == inv_before
        assert not (ctx.run_dir / "report.md").exists()

    def test_subagent_still_used_when_screen_payload_incomplete(
        self, tmp_path, monkeypatch,
    ):
        """Missing gather block → mechanical composer gated off, handler
        dispatches the conclude subagent as before."""
        run_dir = tmp_path / "run-fallback"
        _prepare_run_dir(run_dir)
        ctx = Context(
            run_dir=run_dir,
            signature_id="wazuh-rule-5710",
            ticket_id="SEC-2026-042",
            alert={"id": "alert-1"},
            outputs={Phase.SCREEN: {
                "screen_result": "match",
                "matched_archetype": "monitoring-probe",
                # no gather key
            }},
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /runs/run-fallback/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        monkeypatch.setattr(
            conclude_handler, "_invoke_subagent", stub_invoke(captured, response),
        )
        result = conclude_handler.handle(ctx)
        assert captured != []  # subagent was called
        assert result.payload["compose_mode"] == "subagent"
