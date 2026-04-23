"""Unit tests for warning-channel invlang checks.

Covers: lead dedup, silent empty results, tool-audit cross-ref. Route
compliance lives in `test_invlang_validate.py` alongside the warning
aggregator (`collect_warnings`).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.invlang_validate import (
    _check_lead_dedup_warnings,
    _check_silent_empty_result_warnings,
    _check_tool_audit_cross_ref_warnings,
)


# ---------------------------------------------------------------------------
# Unit tests: _check_lead_dedup_warnings
# ---------------------------------------------------------------------------


def _dedup_lead(lead_id: str, template: str, query: str, subs: dict | None = None) -> dict:
    return {
        "id": lead_id, "loop": 1, "name": lead_id, "target": "v-001",
        "query_details": {
            "system": "wazuh",
            "template": template,
            "query": query,
            "time_window": "1h",
            "substitutions": subs or {},
        },
        "outcome": {},
        "resolutions": [],
    }


class TestCheckLeadDedup:
    def test_distinct_queries_silent(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:1.2.3.4"),
            _dedup_lead("l-002", "t1", "src_ip:5.6.7.8"),
        ]}
        assert _check_lead_dedup_warnings(merged) == []

    def test_duplicate_query_warns(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:1.2.3.4", {"ip": "1.2.3.4"}),
            _dedup_lead("l-002", "t1", "src_ip:1.2.3.4", {"ip": "1.2.3.4"}),
        ]}
        warnings = _check_lead_dedup_warnings(merged)
        assert warnings
        assert "l-002" in warnings[0]
        assert "l-001" in warnings[0]

    def test_same_query_different_subs_silent(self):
        merged = {"gather": [
            _dedup_lead("l-001", "t1", "src_ip:${ip}", {"ip": "1.2.3.4"}),
            _dedup_lead("l-002", "t1", "src_ip:${ip}", {"ip": "5.6.7.8"}),
        ]}
        # Same query string but different substitutions = different effective
        # queries, not a dedup case.
        assert _check_lead_dedup_warnings(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_silent_empty_result_warnings
# ---------------------------------------------------------------------------


class TestCheckSilentEmpty:
    def _lead(self, tests, outcome):
        return {
            "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
            "tests": tests,
            "query_details": {}, "outcome": outcome,
            "resolutions": [],
        }

    def test_no_tests_silent(self):
        merged = {"gather": [self._lead([], {"observations": {"vertices": [], "edges": []}})]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_observations_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [{"id": "v-002"}], "edges": []}},
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_empty_outcome_warns(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [], "edges": []}},
        )]}
        warnings = _check_silent_empty_result_warnings(merged)
        assert warnings
        assert "l-001" in warnings[0]

    def test_tests_with_failure_reason_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {"observations": {"vertices": [], "edges": []}, "failure_reason": "timeout"},
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_anchor_consultation_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {
                "observations": {"vertices": [], "edges": []},
                "anchor_consultations": [{
                    "anchor_id": "x", "anchor_kind": "k",
                    "grounding_kind": "telemetry-baseline",
                    "result": "no-data",
                    "as_of": "2026-04-17", "authority_for_question": "full",
                }],
            },
        )]}
        assert _check_silent_empty_result_warnings(merged) == []

    def test_tests_with_attribute_updates_silent(self):
        merged = {"gather": [self._lead(
            ["h-001"],
            {
                "observations": {"vertices": [], "edges": []},
                "attribute_updates": [{"target": "v-001", "updates": {"classification": "x"}}],
            },
        )]}
        assert _check_silent_empty_result_warnings(merged) == []


# ---------------------------------------------------------------------------
# Unit tests: _check_tool_audit_cross_ref_warnings
# ---------------------------------------------------------------------------


class TestCheckToolAuditCrossRef:
    def _make_run_with_audit(self, tmp_path: Path, entries: list[dict]) -> tuple[Path, Path]:
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "test-run"
        run_dir.mkdir(parents=True)
        audit_path = runs_dir / "tool_audit.jsonl"
        with open(audit_path, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")
        return run_dir, audit_path

    def _lead_with_query(self, query: str) -> dict:
        return {
            "gather": [{
                "id": "l-001", "loop": 1, "name": "t", "target": "v-001",
                "query_details": {
                    "system": "wazuh", "template": "t", "query": query,
                    "time_window": "1h", "substitutions": {},
                },
                "outcome": {}, "resolutions": [],
            }],
        }

    def test_missing_audit_file_silent(self, tmp_path):
        runs_dir = tmp_path / "runs"
        run_dir = runs_dir / "test-run"
        run_dir.mkdir(parents=True)
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_query_match_found_silent(self, tmp_path):
        entry = {
            "timestamp": "2026-04-17T00:00:00Z",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": 'wazuh-query "src_ip:203.0.113.47 AND agent.ip:10.0.0.50"'},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_no_query_match_warns(self, tmp_path):
        entry = {
            "timestamp": "2026-04-17T00:00:00Z",
            "session_id": "sess-1",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        warnings = _check_tool_audit_cross_ref_warnings(merged, run_dir)
        assert warnings
        assert "l-001" in warnings[0]

    def test_short_query_skipped(self, tmp_path):
        run_dir, _ = self._make_run_with_audit(tmp_path, [{
            "session_id": "sess-1", "tool_name": "Bash", "tool_input": {"command": "echo"},
        }])
        merged = self._lead_with_query("a")  # too short
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []

    def test_subagent_session_query_matches_globally(self, tmp_path):
        """Gather subagents log queries under their own session_id.

        The check must match across all sessions; a subagent-dispatched
        query should be found even though its session_id differs from
        the main agent's.
        """
        entry = {
            "session_id": "subagent-sess-xyz",
            "agent_id": "gather-subagent",
            "agent_type": "gather",
            "tool_name": "Bash",
            "tool_input": {"command": 'wazuh-query "src_ip:203.0.113.47 AND agent.ip:10.0.0.50"'},
        }
        run_dir, _ = self._make_run_with_audit(tmp_path, [entry])
        merged = self._lead_with_query("src_ip:203.0.113.47 AND agent.ip:10.0.0.50")
        assert _check_tool_audit_cross_ref_warnings(merged, run_dir) == []
