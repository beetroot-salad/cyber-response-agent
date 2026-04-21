"""End-to-end integration tests with live Wazuh SIEM.

Exercises the full investigation system: real SIEM queries via wazuh_cli.py,
real subagent spawns, real hook execution. Tests are mechanical — validating
that all moving parts work together, not that the best lead was chosen.

Requires:
- Playground Wazuh stack running (cd .devcontainer && docker compose up -d)
- Wazuh credentials in environment variables
- config.env populated with real endpoints
- Claude CLI installed and authenticated

Run with: pytest soc-agent/tests/test_e2e_live.py -v -m "llm and live"

These tests are never run in CI — manual execution only.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from conftest import (
    SOC_AGENT_ROOT,
    InvestigationResult,
    make_brute_force_alert,
    make_monitoring_probe_alert,
    make_nagios_probe_alert,
    run_investigation_live,
    seed_prior_investigation,
)

from schemas.state import validate_transition
from hooks.scripts.validate_report import parse_yaml_frontmatter, validate_tier1


pytestmark = [pytest.mark.llm, pytest.mark.live]


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_valid_state_transitions(result: InvestigationResult):
    """Assert state.json exists and all transitions are legal."""
    state = result.state_json
    assert state, f"state.json missing or empty in {result.run_dir}"
    assert "history" in state, "state.json missing 'history' field"

    history = state["history"]
    assert len(history) >= 2, f"Investigation too short: {history}"
    assert history[0] == "CONTEXTUALIZE", f"Must start with CONTEXTUALIZE, got {history}"
    assert history[-1] == "CONCLUDE", f"Must end with CONCLUDE, got {history}"

    current = None
    for phase in history:
        valid, error = validate_transition(current, phase)
        assert valid, f"Illegal transition {current} -> {phase}: {error}"
        current = phase


def assert_valid_report(result: InvestigationResult):
    """Assert report.md exists and passes Tier 1 validation."""
    report_path = result.run_dir / "report.md"
    assert report_path.exists(), f"report.md not created in {result.run_dir}"

    content = report_path.read_text()
    fields = parse_yaml_frontmatter(content)
    assert fields, "report.md has no YAML frontmatter"

    required = ["ticket_id", "signature_id", "status", "disposition",
                 "confidence", "leads_pursued"]
    for field in required:
        assert field in fields, f"Missing field in report: {field}"

    passed, errors, _ = validate_tier1(report_path)
    assert passed, f"Report Tier 1 validation failed: {errors}"


def assert_investigation_md_exists(result: InvestigationResult):
    """Assert investigation.md exists with meaningful content."""
    inv_path = result.run_dir / "investigation.md"
    assert inv_path.exists(), f"investigation.md not created in {result.run_dir}"
    content = inv_path.read_text()
    assert len(content) > 100, "investigation.md is too short — likely incomplete"
    assert "CONTEXTUALIZE" in content, "investigation.md missing CONTEXTUALIZE phase"


def assert_meta_json_valid(result: InvestigationResult):
    """Assert meta.json has required fields."""
    meta = result.meta_json
    assert meta, f"meta.json missing or empty in {result.run_dir}"
    assert "run_id" in meta, "meta.json missing run_id"
    assert "signature_id" in meta, "meta.json missing signature_id"
    assert "salt" in meta, "meta.json missing salt"
    assert len(meta["salt"]) == 16, f"Salt should be 16-char hex, got {meta['salt']!r}"


def assert_budget_tracked(result: InvestigationResult):
    """Assert budget.json was created and has tool call counts.

    budget.json is created by the budget_enforcer PostToolUse hook in plugin.json.
    """
    budget = result.budget_json
    assert budget, (
        f"budget.json missing in {result.run_dir} — plugin hooks may not be firing. "
        f"Run 'claude plugin validate {SOC_AGENT_ROOT}' to check plugin.json."
    )
    assert "tool_calls" in budget, "budget.json missing tool_calls"
    assert budget["tool_calls"] > 0, "budget.json tool_calls should be > 0"
    assert "started_at" in budget, "budget.json missing started_at"


def get_report_fields(result: InvestigationResult) -> dict:
    """Parse and return report frontmatter fields."""
    return parse_yaml_frontmatter(result.report_md)


# ---------------------------------------------------------------------------
# Shared investigation cache — avoid redundant claude invocations
#
# Tests that need the same scenario share a module-scoped fixture.
# This keeps the total to ~6 invocations instead of 8.
# ---------------------------------------------------------------------------

_cache: dict[str, InvestigationResult] = {}


def _cached_investigation(
    key: str,
    alert: dict,
    runs_dir: Path,
    **kwargs,
) -> InvestigationResult:
    """Run investigation once per key, cache the result."""
    if key not in _cache:
        _cache[key] = run_investigation_live(
            alert=alert, runs_dir=runs_dir, **kwargs,
        )
    return _cache[key]


# ---------------------------------------------------------------------------
# Test 1: Screen fast-path → resolved
# ---------------------------------------------------------------------------

class TestScreenResolve:
    """Monitoring probe alert should trigger screen fast-path and resolve."""

    def test_screen_resolve(self, live_alerts_ready, live_runs_dir):
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        # Core assertion: investigation completed
        assert_valid_state_transitions(result)
        assert_valid_report(result)
        assert_investigation_md_exists(result)
        assert_meta_json_valid(result)

        # Screen-specific: history should contain SCREEN
        history = result.state_json["history"]
        assert "SCREEN" in history, (
            f"Screen phase not in history — agent skipped screen: {history}"
        )

        # Report should be resolved as benign
        fields = get_report_fields(result)
        assert fields.get("status") == "resolved", (
            f"Expected resolved, got {fields.get('status')}"
        )
        assert fields.get("disposition") == "benign", (
            f"Expected benign, got {fields.get('disposition')}"
        )

        # Resolved requires matched_archetype
        assert fields.get("matched_archetype"), (
            "Resolved report must have matched_archetype"
        )

    def test_screen_resolve_budget_tracked(self, live_alerts_ready, live_runs_dir):
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)
        assert_budget_tracked(result)


# ---------------------------------------------------------------------------
# Test 2: Full investigation → escalated
# ---------------------------------------------------------------------------

class TestFullInvestigationEscalate:
    """Brute-force alert should trigger full investigation loop and escalate."""

    def test_full_loop_escalate(self, live_alerts_ready, live_runs_dir):
        alert = make_brute_force_alert()
        result = _cached_investigation("full_escalate", alert, live_runs_dir)

        assert_valid_state_transitions(result)
        assert_valid_report(result)
        assert_investigation_md_exists(result)

        # Full loop: must have HYPOTHESIZE → GATHER → ANALYZE
        history = result.state_json["history"]
        assert "HYPOTHESIZE" in history, f"No HYPOTHESIZE phase: {history}"
        assert "GATHER" in history, f"No GATHER phase: {history}"
        assert "ANALYZE" in history, f"No ANALYZE phase: {history}"

        # Report should be escalated
        fields = get_report_fields(result)
        assert fields.get("status") == "escalated", (
            f"Brute-force should be escalated, got {fields.get('status')}"
        )

        # Multiple leads for medium severity
        leads = fields.get("leads_pursued", 0)
        assert leads >= 2, f"Expected >= 2 leads for brute-force, got {leads}"

    def test_escalation_has_hypotheses(self, live_alerts_ready, live_runs_dir):
        alert = make_brute_force_alert()
        result = _cached_investigation("full_escalate", alert, live_runs_dir)

        content = result.investigation_md
        # Must reference hypotheses with ? prefix
        assert re.search(r'\?[\w-]+', content), (
            "No ?hypothesis references found in investigation.md"
        )

    def test_escalation_has_assessment_weights(self, live_alerts_ready, live_runs_dir):
        alert = make_brute_force_alert()
        result = _cached_investigation("full_escalate", alert, live_runs_dir)

        content = result.investigation_md
        has_weights = any(
            marker in content
            for marker in ["++", "--", "strongly supports", "strongly refutes"]
        )
        assert has_weights, "No assessment weights found in ANALYZE phase"

    def test_escalation_siem_queries_executed(self, live_alerts_ready, live_runs_dir):
        """Verify the agent actually queried the SIEM (investigation contains real data)."""
        alert = make_brute_force_alert()
        result = _cached_investigation("full_escalate", alert, live_runs_dir)

        content = result.investigation_md
        # The investigation should contain concrete SIEM data — specific counts,
        # IP addresses, rule IDs, or usernames that could only come from real queries
        siem_evidence = [
            "fail",          # failure counts from authentication-history
            "5710",          # rule ID from alert queries
            "203.0.113.50",  # the source IP being investigated
            "target-endpoint",  # agent name from SIEM
        ]
        found = sum(1 for indicator in siem_evidence if indicator in content)
        assert found >= 2, (
            f"Investigation should contain SIEM-derived data. "
            f"Only {found}/4 indicators found in investigation.md"
        )


# ---------------------------------------------------------------------------
# Test 3: Full investigation → resolved with precedent
# ---------------------------------------------------------------------------

class TestFullInvestigationResolve:
    """Nagios probe alert — internal monitoring pattern, should complete investigation.

    May resolve (if precedent matched) or escalate (if no nagios-specific precedent).
    Either outcome is valid — test validates the investigation completes properly.
    """

    def test_full_loop_resolve(self, live_alerts_ready, live_runs_dir):
        alert = make_nagios_probe_alert()
        result = _cached_investigation("full_resolve", alert, live_runs_dir)

        assert_valid_state_transitions(result)
        assert_valid_report(result)
        assert_investigation_md_exists(result)
        assert_meta_json_valid(result)

        fields = get_report_fields(result)
        status = fields.get("status")
        assert status in ("resolved", "escalated"), (
            f"Expected resolved or escalated, got {status}"
        )

        # If resolved, verify archetype exists (and the optional ticket snapshot,
        # if one was cited).
        if status == "resolved":
            archetype = fields.get("matched_archetype")
            assert archetype, "Resolved report must have matched_archetype"

            archetype_anchors = (
                SOC_AGENT_ROOT / "knowledge" / "signatures" / "wazuh-rule-5710"
                / "archetypes" / archetype / "trust-anchors.md"
            )
            assert archetype_anchors.exists(), (
                f"matched_archetype '{archetype}' trust-anchors.md not found at "
                f"{archetype_anchors}"
            )

            ticket_id = fields.get("matched_ticket_id")
            if ticket_id:
                ticket_filename = (
                    ticket_id if ticket_id.endswith(".json") else f"{ticket_id}.json"
                )
                precedent_path = (
                    SOC_AGENT_ROOT / "knowledge" / "signatures" / "wazuh-rule-5710"
                    / "archetypes" / archetype / ticket_filename
                )
                assert precedent_path.exists(), (
                    f"matched_ticket_id '{ticket_id}' not found at "
                    f"{precedent_path}"
                )
        else:
            # Escalated nagios probe — should have benign disposition
            assert fields.get("disposition") == "benign", (
                f"Internal nagios probe should be benign, got {fields.get('disposition')}"
            )


# ---------------------------------------------------------------------------
# Test 4: Ticket-context fast-resolve with seeded prior investigation
# ---------------------------------------------------------------------------

class TestTicketContextFastResolve:
    """Repeat alert with seeded prior investigation should fast-resolve."""

    def test_fast_resolve_repeat(self, live_alerts_ready, live_runs_dir):
        # Seed a prior investigation so ticket-context finds it
        prior_alert = make_monitoring_probe_alert()
        prior_alert["ticket_id"] = "PRIOR-SEED-001"
        seed_prior_investigation(live_runs_dir, prior_alert)

        # Now run the same scenario — agent should find prior and fast-resolve
        alert = make_monitoring_probe_alert()
        result = run_investigation_live(
            alert=alert,
            runs_dir=live_runs_dir,
            extra_instructions=(
                "Check the runs directory for prior investigations of this signature "
                "and alert pattern. The audit.jsonl file contains prior investigation outcomes."
            ),
        )

        assert_valid_state_transitions(result)
        assert_valid_report(result)

        # Should resolve (either via fast-resolve or normal path)
        fields = get_report_fields(result)
        assert fields.get("status") == "resolved", (
            f"Repeat alert should resolve, got {fields.get('status')}"
        )

    def test_fast_resolve_produces_valid_report(self, live_alerts_ready, live_runs_dir):
        """Fast-resolve should still produce a valid, well-formed report."""
        # The fast-resolve test's run isn't cached — find the most recent
        # non-cached run that has a report
        cached_dirs = {r.run_dir.name for r in _cache.values()}
        fast_runs = [
            d for d in live_runs_dir.iterdir()
            if d.is_dir() and (d / "report.md").exists() and d.name not in cached_dirs
        ]
        if not fast_runs:
            pytest.skip("No fast-resolve run directory found")

        latest = max(fast_runs, key=lambda d: d.stat().st_mtime)
        passed, errors, _ = validate_tier1(latest / "report.md")
        assert passed, f"Fast-resolve report failed Tier 1 validation: {errors}"


# ---------------------------------------------------------------------------
# Test 5: SIEM unreachable → graceful escalation
# ---------------------------------------------------------------------------

class TestSiemUnreachable:
    """When SIEM is unreachable, agent should not crash and should produce artifacts."""

    def test_siem_failure_graceful(self, live_runs_dir):
        """Override SIEM endpoint to unreachable host — agent should not crash."""
        alert = make_monitoring_probe_alert()
        result = _cached_investigation(
            "siem_unreachable", alert, live_runs_dir,
            env_overrides={
                "WAZUH_INDEXER_ENDPOINT": "https://unreachable-host.invalid:9200",
                "WAZUH_INDEXER_USER": "test",
                "WAZUH_INDEXER_PASSWORD": "test",
            },
            timeout=600,
            budget_usd="2.00",
        )

        # Agent should produce at least some artifacts — not silently crash
        has_state = bool(result.state_json)
        has_any_output = bool(result.stdout) or bool(result.stderr)
        assert has_state or has_any_output, (
            "Agent produced no artifacts and no output — silent crash"
        )

        # If it created state, it should have entered CONTEXTUALIZE at minimum
        if has_state:
            history = result.state_json.get("history", [])
            assert len(history) >= 1, "Agent should have entered at least one phase"
            assert history[0] == "CONTEXTUALIZE", f"First phase should be CONTEXTUALIZE, got {history[0]}"

        # If agent completed with a report, validate it
        if not result.timed_out and (result.run_dir / "report.md").exists():
            assert_valid_report(result)


# ---------------------------------------------------------------------------
# Test 6: Malformed alert handling
# ---------------------------------------------------------------------------

class TestMalformedAlert:
    """Agent should handle malformed alert input gracefully."""

    def test_missing_alert_data(self, live_alerts_ready, live_runs_dir):
        """Alert with missing alert_data field should not crash the agent."""
        alert = {
            "ticket_id": f"TEST-MALFORMED-{int(time.time())}",
            "signature_id": "wazuh-rule-5710",
            # No alert_data — agent must handle gracefully
        }

        result = run_investigation_live(
            alert=alert,
            runs_dir=live_runs_dir,
            timeout=600,
            budget_usd="2.00",
            extra_instructions=(
                "The alert may have missing fields. If data is insufficient to investigate, "
                "escalate with an explanation of what's missing."
            ),
        )

        # Agent should not crash
        assert result.returncode == 0 or result.stdout, (
            f"Agent crashed on malformed alert. stderr: {result.stderr[:500]}"
        )

        # Should produce state.json at minimum
        state = result.state_json
        assert state, "state.json should exist even with malformed alert"

        # If report exists, should be escalated
        report_path = result.run_dir / "report.md"
        if report_path.exists():
            fields = get_report_fields(result)
            assert fields.get("status") == "escalated", (
                f"Malformed alert should escalate, got {fields.get('status')}"
            )


# ---------------------------------------------------------------------------
# Test 7: Audit trail completeness (post-hoc, no extra invocation)
# ---------------------------------------------------------------------------

class TestAuditTrailCompleteness:
    """Verify all investigation artifacts and hook-generated outputs."""

    def test_all_core_artifacts_present(self, live_alerts_ready, live_runs_dir):
        """Every completed investigation must have the full artifact set."""
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        run_dir = result.run_dir

        assert (run_dir / "alert.json").exists(), "alert.json missing"
        assert (run_dir / "meta.json").exists(), "meta.json missing"
        assert (run_dir / "state.json").exists(), "state.json missing"
        assert (run_dir / "investigation.md").exists(), "investigation.md missing"
        assert (run_dir / "report.md").exists(), "report.md missing"

    def test_meta_json_structure(self, live_alerts_ready, live_runs_dir):
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)
        assert_meta_json_valid(result)

    def test_state_json_structure(self, live_alerts_ready, live_runs_dir):
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        state = result.state_json
        assert "run_id" in state, "state.json missing run_id"
        assert "ticket_id" in state, "state.json missing ticket_id"
        assert "signature_id" in state, "state.json missing signature_id"
        assert state["signature_id"] == "wazuh-rule-5710"
        assert "updated_at" in state, "state.json missing updated_at"

    def test_validate_report_hook_passes(self, live_alerts_ready, live_runs_dir):
        """Run validate_report.py Tier 1 against the investigation report post-hoc."""
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        report_path = result.run_dir / "report.md"
        assert report_path.exists(), "report.md missing"

        passed, errors, _ = validate_tier1(report_path)
        assert passed, f"Report Tier 1 validation failed: {errors}"

    def test_tool_audit_trail_exists(self, live_alerts_ready, live_runs_dir):
        """audit_tool_calls hook should produce tool_audit.jsonl during investigation."""
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        audit_path = live_runs_dir / "tool_audit.jsonl"
        assert audit_path.exists(), (
            "tool_audit.jsonl missing — audit_tool_calls hook did not fire"
        )
        entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        assert len(entries) > 0, "tool_audit.jsonl is empty"

    def test_investigation_summary_hook_produces_valid_entry(self, live_alerts_ready, live_runs_dir):
        """Stop hook (investigation_summary.py) should produce audit.jsonl entry.

        If the Stop hook fired during the investigation, audit.jsonl will have entries.
        If not, we run the hook post-hoc to validate it WOULD produce correct output.
        """
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)

        audit_path = live_runs_dir / "audit.jsonl"

        # If audit.jsonl doesn't exist, run the Stop hook manually as fallback
        if not audit_path.exists():
            env = os.environ.copy()
            env["SOC_AGENT_RUNS_DIR"] = str(live_runs_dir)
            subprocess.run(
                [sys.executable,
                 str(SOC_AGENT_ROOT / "hooks" / "scripts" / "investigation_summary.py")],
                input="{}",
                capture_output=True, text=True, env=env,
                cwd=str(SOC_AGENT_ROOT),
            )

        assert audit_path.exists(), "investigation_summary hook did not create audit.jsonl"

        entries = [json.loads(line) for line in audit_path.read_text().splitlines() if line.strip()]
        # Filter to entries that match our run
        run_entries = [e for e in entries if e.get("signature_id") == "wazuh-rule-5710"]
        assert run_entries, "No audit.jsonl entries for our signature"

        latest = run_entries[-1]
        assert latest.get("status") in ("resolved", "escalated"), (
            f"Invalid status in audit entry: {latest.get('status')}"
        )


# ---------------------------------------------------------------------------
# Test 8: Budget tracking consistency (post-hoc, no extra invocation)
# ---------------------------------------------------------------------------

class TestBudgetTracking:
    """Verify budget tracking and phase-count comparisons across investigations."""

    def test_screen_resolve_budget_if_available(self, live_alerts_ready, live_runs_dir):
        """If budget.json exists, validate its structure."""
        alert = make_monitoring_probe_alert()
        result = _cached_investigation("screen_resolve", alert, live_runs_dir)
        assert_budget_tracked(result)

    def test_escalation_uses_more_phases(self, live_alerts_ready, live_runs_dir):
        """Full investigation (escalation) should have more state transitions than screen resolve."""
        probe_alert = make_monitoring_probe_alert()
        screen_result = _cached_investigation("screen_resolve", probe_alert, live_runs_dir)

        brute_alert = make_brute_force_alert()
        escalate_result = _cached_investigation("full_escalate", brute_alert, live_runs_dir)

        screen_phases = len(screen_result.state_json.get("history", []))
        escalate_phases = len(escalate_result.state_json.get("history", []))

        assert screen_phases >= 2, "Screen investigation should have >= 2 phases"
        assert escalate_phases >= 4, "Full investigation should have >= 4 phases"
        assert escalate_phases > screen_phases, (
            f"Full investigation ({escalate_phases} phases) should have more phases "
            f"than screen resolve ({screen_phases} phases)"
        )

    def test_fast_resolve_fewer_phases(self, live_alerts_ready, live_runs_dir):
        """Fast-resolve (or screen) should use fewer phases than full investigation."""
        if "full_escalate" not in _cache:
            pytest.skip("Full escalation test hasn't run yet")

        full_phases = len(_cache["full_escalate"].state_json.get("history", []))

        # Screen resolve is the fastest path
        if "screen_resolve" in _cache:
            screen_phases = len(_cache["screen_resolve"].state_json.get("history", []))
            assert full_phases > screen_phases, (
                f"Escalation ({full_phases}) should use more phases than screen ({screen_phases})"
            )
        else:
            pytest.skip("Screen resolve test hasn't run yet")
