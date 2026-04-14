"""Tests for the CONCLUDE transition verification hook.

Tests validate_conclude.py: helper functions (lead counting, expected
question parsing) and the hook end-to-end via subprocess, simulating
PostToolUse events piped to stdin.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.validate_conclude import (
    count_leads_from_investigation,
    load_expected_questions,
)

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "validate_conclude.py"


# ---------------------------------------------------------------------------
# Unit tests: count_leads_from_investigation
# ---------------------------------------------------------------------------


class TestCountLeads:
    def test_single_lead_single_block(self):
        text = (
            "## CONTEXTUALIZE\nstuff\n"
            "## HYPOTHESIZE (loop 1)\nstuff\n"
            "## GATHER (loop 1)\n\n**Lead:** authentication-history\nquery stuff\n"
            "## ANALYZE (loop 1)\nstuff\n"
        )
        assert count_leads_from_investigation(text) == 1

    def test_multiple_blocks_distinct_leads(self):
        text = (
            "## GATHER (loop 1)\n**Lead:** authentication-history\n\n"
            "## ANALYZE (loop 1)\n"
            "## GATHER (loop 2)\n**Lead:** source-reputation\n\n"
            "## ANALYZE (loop 2)\n"
        )
        assert count_leads_from_investigation(text) == 2

    def test_composite_dispatch(self):
        text = (
            "## GATHER (loop 1)\n**Leads:** auth-history, data-access, network-flows\n"
            "## ANALYZE (loop 1)\n"
        )
        assert count_leads_from_investigation(text) == 3

    def test_composite_with_parenthetical(self):
        text = (
            "## GATHER (loop 1)\n**Leads:** a, b, c (for composite)\n"
            "## ANALYZE (loop 1)\n"
        )
        assert count_leads_from_investigation(text) == 3

    def test_duplicate_leads_counted_once(self):
        text = (
            "## GATHER (loop 1)\n**Lead:** auth-history\n"
            "## ANALYZE (loop 1)\n"
            "## GATHER (loop 2)\n**Lead:** auth-history\n"
            "## ANALYZE (loop 2)\n"
        )
        assert count_leads_from_investigation(text) == 1

    def test_no_gather_blocks(self):
        text = "## CONTEXTUALIZE\n## SCREEN\n## CONCLUDE\n"
        assert count_leads_from_investigation(text) == 0

    def test_gather_without_lead_marker(self):
        text = "## GATHER (loop 1)\nsome query\n## ANALYZE (loop 1)\n"
        assert count_leads_from_investigation(text) == 0


# ---------------------------------------------------------------------------
# Unit tests: load_expected_questions
# ---------------------------------------------------------------------------


class TestLoadExpectedQuestions:
    def test_returns_both_statuses(self):
        result = load_expected_questions()
        assert "resolved" in result
        assert "escalated" in result

    def test_resolved_has_expected_ids(self):
        result = load_expected_questions()
        resolved = set(result["resolved"])
        # These are the question IDs defined in the prompt file; if the
        # prompt is edited, update this test in lockstep.
        assert "adversarial_refuted" in resolved
        assert "plus_plus_refutation_attempt" in resolved
        assert "authoritative_vs_circumstantial" in resolved
        assert "dangling_evidence" in resolved
        assert "archetype_shape_match" in resolved

    def test_escalated_has_expected_ids(self):
        result = load_expected_questions()
        escalated = set(result["escalated"])
        assert "dangling_evidence" in escalated
        assert "escalation_rationale" in escalated

    def test_escalated_does_not_require_adversarial(self):
        result = load_expected_questions()
        assert "adversarial_refuted" not in result["escalated"]


# ---------------------------------------------------------------------------
# Integration helpers
# ---------------------------------------------------------------------------


VALID_INVESTIGATION = """\
## CONTEXTUALIZE

**Alert:** SEC-001
**Source entity:** 10.0.1.50
**Playbook hypotheses:** ?monitoring-probe, ?brute-force

## HYPOTHESIZE (loop 1)

**Selected lead:** authentication-history

## GATHER (loop 1)

**Lead:** authentication-history
**Raw observation:** 1 authentication attempt from 10.0.1.50

## ANALYZE (loop 1)

hypotheses:
  ?monitoring-probe:
    weight: "++"
    reasoning: matches monitoring cadence
  ?brute-force:
    weight: "--"
    reasoning: single attempt contradicts brute-force prediction of >50

## HYPOTHESIZE (loop 2)

**Selected lead:** source-reputation

## GATHER (loop 2)

**Lead:** source-reputation
**Raw observation:** 10.0.1.50 matches approved-monitoring-sources entry

## ANALYZE (loop 2)

hypotheses:
  ?monitoring-probe:
    weight: "++"
    reasoning: authoritative anchor confirms

## CONCLUDE

**Verdict:** resolved — monitoring probe from approved source
**Confirmed hypothesis:** ?monitoring-probe
"""


def _resolved_checks(investigation_text: str) -> dict:
    """Build a valid conclusion_checks.json dict whose citations all appear
    in the given investigation text."""
    return {
        "status": "resolved",
        "checks": [
            {
                "question_id": "adversarial_refuted",
                "answer": "?brute-force predicted >50 attempts, observed 1.",
                "citations": [
                    "1 authentication attempt from 10.0.1.50",
                    'weight: "--"',
                ],
            },
            {
                "question_id": "plus_plus_refutation_attempt",
                "answer": "Ran source-reputation; a non-matching result would have refuted.",
                "citations": ["source-reputation"],
            },
            {
                "question_id": "authoritative_vs_circumstantial",
                "answer": "Authoritative: approved-monitoring-sources registry match.",
                "citations": ["matches approved-monitoring-sources entry"],
            },
            {
                "question_id": "dangling_evidence",
                "answer": "No unexplained observations.",
                "citations": ["authoritative anchor confirms"],
            },
            {
                "question_id": "archetype_shape_match",
                "answer": "All features fit the monitoring-probe archetype.",
                "citations": ["monitoring probe from approved source"],
            },
        ],
    }


def _setup_run(
    tmp_path: Path,
    investigation_text: str = VALID_INVESTIGATION,
    conclusion_checks: dict | None = None,
    signature_id: str = "wazuh-rule-5710",
    with_ticket_context: bool = True,
) -> tuple[Path, Path]:
    """Create a runs_dir + run_dir with the artifacts a passing run needs."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    run_dir = runs_dir / "run-test"
    run_dir.mkdir()
    (run_dir / "meta.json").write_text(
        json.dumps({"run_id": "run-test", "signature_id": signature_id})
    )
    (run_dir / "investigation.md").write_text(investigation_text)
    if with_ticket_context:
        (run_dir / "ticket_context.yaml").write_text("situation: ok\n")
    if conclusion_checks is not None:
        (run_dir / "conclusion_checks.json").write_text(
            json.dumps(conclusion_checks)
        )
    return runs_dir, run_dir


def _make_hook_event(file_path: str, tool_name: str = "Write") -> str:
    return json.dumps(
        {
            "tool_name": tool_name,
            "tool_input": {"file_path": file_path, "content": ""},
            "tool_use_id": "test-001",
            "session_id": "session-001",
        }
    )


def _make_bash_event(command: str) -> str:
    return json.dumps(
        {
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_use_id": "test-001",
            "session_id": "session-001",
        }
    )


def _run_hook(event: str, runs_dir: Path) -> subprocess.CompletedProcess:
    import os
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env={**os.environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)},
    )


# ---------------------------------------------------------------------------
# Integration tests: hook via subprocess
# ---------------------------------------------------------------------------


class TestHookHappyPath:
    def test_all_gates_pass(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path, conclusion_checks=_resolved_checks(VALID_INVESTIGATION)
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_bash_append_event(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path, conclusion_checks=_resolved_checks(VALID_INVESTIGATION)
        )
        event = _make_bash_event(
            f"cat >> {run_dir / 'investigation.md'} <<EOF\n## CONCLUDE\nEOF"
        )
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_edit_event(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path, conclusion_checks=_resolved_checks(VALID_INVESTIGATION)
        )
        event = _make_hook_event(
            str(run_dir / "investigation.md"), tool_name="Edit"
        )
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestHookNonTriggers:
    def test_no_investigation_md(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        event = _make_hook_event("/tmp/other.md")
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_investigation_without_conclude(self, tmp_path):
        text_no_conclude = VALID_INVESTIGATION.replace("## CONCLUDE", "## ANALYZE (loop 3)")
        runs_dir, run_dir = _setup_run(tmp_path, investigation_text=text_no_conclude)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_unrelated_bash_command(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        event = _make_bash_event("ls /tmp")
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_file_outside_runs_dir(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        (other / "investigation.md").write_text("## CONCLUDE\n")
        event = _make_hook_event(str(other / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0


class TestGate1TicketContext:
    def test_fails_when_ticket_context_missing(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path,
            conclusion_checks=_resolved_checks(VALID_INVESTIGATION),
            with_ticket_context=False,
        )
        # Audit log exists but contains no ticket-context dispatch —
        # without an audit log at all, the check silently passes because
        # the fallback scan has no signal to work with.
        (runs_dir / "tool_audit.jsonl").write_text(
            json.dumps(
                {
                    "tool_name": "Bash",
                    "tool_input": {"command": "ls"},
                }
            )
            + "\n"
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "ticket-context" in result.stderr

    def test_silent_pass_when_no_audit_log(self, tmp_path):
        """Without an audit log and without ticket_context.yaml, the check
        silently passes — there is no signal to work with, and the hook
        deliberately does not fail in that case."""
        runs_dir, run_dir = _setup_run(
            tmp_path,
            conclusion_checks=_resolved_checks(VALID_INVESTIGATION),
            with_ticket_context=False,
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_passes_via_audit_fallback(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path,
            conclusion_checks=_resolved_checks(VALID_INVESTIGATION),
            with_ticket_context=False,
        )
        audit = runs_dir / "tool_audit.jsonl"
        audit.write_text(
            json.dumps(
                {
                    "tool_name": "Task",
                    "tool_input": {
                        "description": "ticket-context for SEC-001",
                        "prompt": "read ticket-context.md",
                    },
                }
            )
            + "\n"
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestGate2LeadsMinimum:
    def test_fails_with_one_lead_medium_severity(self, tmp_path):
        thin_investigation = (
            "## CONTEXTUALIZE\n\n"
            "## HYPOTHESIZE (loop 1)\n\n"
            "## GATHER (loop 1)\n**Lead:** authentication-history\n\n"
            "## ANALYZE (loop 1)\n\n"
            "## CONCLUDE\n**Verdict:** resolved\n"
        )
        checks = {
            "status": "resolved",
            "checks": [
                {
                    "question_id": qid,
                    "answer": "...",
                    "citations": ["authentication-history"],
                }
                for qid in [
                    "adversarial_refuted",
                    "plus_plus_refutation_attempt",
                    "authoritative_vs_circumstantial",
                    "dangling_evidence",
                    "archetype_shape_match",
                ]
            ],
        }
        runs_dir, run_dir = _setup_run(
            tmp_path,
            investigation_text=thin_investigation,
            conclusion_checks=checks,
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "leads pursued" in result.stderr
        assert "medium" in result.stderr

    def test_passes_with_two_leads_medium_severity(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path, conclusion_checks=_resolved_checks(VALID_INVESTIGATION)
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestGate3ConclusionFile:
    def test_fails_when_file_missing(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=None)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "conclusion_checks.json not found" in result.stderr

    def test_fails_on_invalid_json(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=None)
        (run_dir / "conclusion_checks.json").write_text("{ not json")
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "not valid JSON" in result.stderr

    def test_fails_on_invalid_status(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["status"] = "maybe"
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "status" in result.stderr

    def test_fails_on_missing_question(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"] = checks["checks"][:-1]  # drop one required
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "missing required question" in result.stderr

    def test_fails_on_extra_question(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"].append(
            {
                "question_id": "not_a_real_question",
                "answer": "noise",
                "citations": ["CONCLUDE"],
            }
        )
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "unexpected question" in result.stderr

    def test_fails_on_empty_answer(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"][0]["answer"] = "   "
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "empty or missing 'answer'" in result.stderr


class TestGate4Citations:
    def test_fails_on_fabricated_citation(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"][0]["citations"] = ["this string is not in the log"]
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "citation not found" in result.stderr

    def test_fails_on_empty_citations_list(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"][0]["citations"] = []
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "non-empty" in result.stderr

    def test_fails_on_whitespace_citation(self, tmp_path):
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"][0]["citations"] = ["   "]
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "empty or whitespace-only" in result.stderr

    def test_citation_with_comma_ok(self, tmp_path):
        # Commas in citations are a property worth pinning down: JSON
        # handles them cleanly (unlike the stdlib YAML frontmatter parser
        # which was the rationale for choosing JSON for this file).
        checks = _resolved_checks(VALID_INVESTIGATION)
        checks["checks"][0]["citations"] = [
            "?monitoring-probe, ?brute-force"
        ]
        runs_dir, run_dir = _setup_run(tmp_path, conclusion_checks=checks)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"


# ---------------------------------------------------------------------------
# Status branching
# ---------------------------------------------------------------------------


class TestStatusBranching:
    ESCALATED_INVESTIGATION = """\
## CONTEXTUALIZE

**Alert:** SEC-002

## HYPOTHESIZE (loop 1)

## GATHER (loop 1)

**Lead:** authentication-history
**Raw observation:** 47 attempts from unknown source

## ANALYZE (loop 1)

Two live hypotheses, undecidable with current evidence.

## HYPOTHESIZE (loop 2)

## GATHER (loop 2)

**Lead:** source-reputation
**Raw observation:** no registry match

## ANALYZE (loop 2)

Cannot discriminate ?brute-force from ?credential-stuffing.

## CONCLUDE

**Verdict:** escalated — cannot discriminate two live hypotheses
"""

    def test_escalated_passes_with_reduced_question_set(self, tmp_path):
        checks = {
            "status": "escalated",
            "checks": [
                {
                    "question_id": "dangling_evidence",
                    "answer": "No unexplained observations.",
                    "citations": ["no registry match"],
                },
                {
                    "question_id": "escalation_rationale",
                    "answer": "Two live hypotheses undecidable with current leads.",
                    "citations": [
                        "Cannot discriminate ?brute-force from ?credential-stuffing"
                    ],
                },
            ],
        }
        runs_dir, run_dir = _setup_run(
            tmp_path,
            investigation_text=self.ESCALATED_INVESTIGATION,
            conclusion_checks=checks,
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_escalated_with_resolved_questions_rejected(self, tmp_path):
        # Escalated status with resolved-only questions should fail.
        checks = _resolved_checks(self.ESCALATED_INVESTIGATION)
        checks["status"] = "escalated"
        runs_dir, run_dir = _setup_run(
            tmp_path,
            investigation_text=self.ESCALATED_INVESTIGATION,
            conclusion_checks=checks,
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 2
        assert "unexpected question" in result.stderr or "missing required" in result.stderr
