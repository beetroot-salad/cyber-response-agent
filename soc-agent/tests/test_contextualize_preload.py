"""Tests for contextualize_preload.py (UserPromptSubmit hook).

Tests extraction, prompt building, trimming, and error handling — all without
spawning real claude subprocesses.
"""

import json
import sys
from pathlib import Path
import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.contextualize_preload import (
    build_subagent_prompt,
    extract_run_metadata,
    format_additional_context,
    trim_ticket_context,
)


def _has_yaml() -> bool:
    try:
        import yaml  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# extract_run_metadata
# ---------------------------------------------------------------------------


class TestExtractRunMetadata:
    def test_extracts_from_expanded_prompt(self):
        prompt = (
            "some preamble\n"
            "Run directory: /workspace/soc-agent/runs/abc-123\n"
            "Run ID: abc-123\n"
            "Signature: wazuh-rule-5710\n"
            "more content"
        )
        result = extract_run_metadata(prompt)
        assert result == ("/workspace/soc-agent/runs/abc-123", "wazuh-rule-5710")

    def test_returns_none_for_non_investigation(self):
        assert extract_run_metadata("just a normal prompt") is None

    def test_returns_none_missing_signature(self):
        prompt = "Run directory: /some/path\nbut no signature line"
        assert extract_run_metadata(prompt) is None

    def test_returns_none_missing_run_dir(self):
        prompt = "Signature: wazuh-rule-5710\nbut no run dir"
        assert extract_run_metadata(prompt) is None

    def test_strips_whitespace(self):
        prompt = "Run directory:   /path/with/spaces   \nSignature:   sig-123  \n"
        result = extract_run_metadata(prompt)
        assert result == ("/path/with/spaces", "sig-123")


# ---------------------------------------------------------------------------
# build_subagent_prompt
# ---------------------------------------------------------------------------


class TestBuildSubagentPrompt:
    def test_reads_model_from_frontmatter(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nmodel: sonnet\n---\n\nBody text here.")
        body, model = build_subagent_prompt(template, {})
        assert model == "sonnet"
        assert "Body text here." in body

    def test_substitutes_variables(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nmodel: haiku\n---\n\nRun dir: {run_dir}, sig: {signature_id}")
        body, model = build_subagent_prompt(
            template, {"run_dir": "/runs/abc", "signature_id": "wazuh-5710"}
        )
        assert "/runs/abc" in body
        assert "wazuh-5710" in body

    def test_raises_on_missing_model(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("---\nname: test\n---\n\nBody without model.")
        with pytest.raises(ValueError, match="missing required 'model' field"):
            build_subagent_prompt(template, {})

    def test_raises_on_missing_frontmatter(self, tmp_path):
        template = tmp_path / "test.md"
        template.write_text("No frontmatter at all, just body text.")
        with pytest.raises(ValueError, match="missing"):
            build_subagent_prompt(template, {})

    def test_real_ticket_context_prompt(self):
        """Verify the actual ticket-context.md has valid frontmatter."""
        prompt_path = SOC_AGENT_ROOT / "skills" / "investigate" / "ticket-context.md"
        body, model = build_subagent_prompt(
            prompt_path,
            {"run_dir": "/tmp/test", "signature_id": "test-sig", "runs_dir": "/tmp"},
        )
        assert model == "sonnet"
        assert len(body) > 100

    def test_real_archetype_scan_prompt(self):
        """Verify the actual archetype-scan.md has valid frontmatter."""
        prompt_path = SOC_AGENT_ROOT / "skills" / "investigate" / "archetype-scan.md"
        body, model = build_subagent_prompt(
            prompt_path,
            {"run_dir": "/tmp/test", "signature_id": "test-sig", "runs_dir": "/tmp"},
        )
        assert model == "haiku"
        assert len(body) > 100


# ---------------------------------------------------------------------------
# trim_ticket_context
# ---------------------------------------------------------------------------


SAMPLE_TICKET_CONTEXT_YAML = """\
ticket_context:
  situation: |
    Three SSH invalid user alerts on target-endpoint in the last 4 hours.
  definite:
    - alert_ids: ["alert-1", "alert-2", "alert-3"]
      shared: "srcip: 172.22.0.10, agent.name: target-endpoint"
      count: 3
      first_seen: "2026-04-12T10:00:00Z"
      temporal_pattern: "periodic, ~10 min intervals"
      reasoning: "All from same monitoring host on regular cadence"
      prior_investigation:
        exists: true
        run_id: "run-abc"
        disposition: "benign"
        confidence: "high"
        matched_archetype: "monitoring-probe"
        matched_ticket_id: "SEC-2024-001"
        summary: "Resolved as approved monitoring probe"
  maybe:
    - alert_ids: ["alert-4"]
      shared_entities: ["agent.name"]
      signature: "5712 — SSH brute force"
      reasoning: "Same target but different signature, likely composite"
    - alert_ids: ["alert-5"]
      shared_entities: ["data.srcip"]
      signature: "5501 — SSH success"
      reasoning: "Same source, successful login after failures"
    - alert_ids: ["alert-6"]
      shared_entities: ["data.srcuser"]
      signature: "5710 — SSH invalid user"
      reasoning: "Same username, different host"
    - alert_ids: ["alert-7"]
      shared_entities: ["data.srcuser"]
      signature: "5710 — SSH invalid user"
      reasoning: "Fourth maybe entry, should be dropped"
  fast_resolve:
    recommended: true
    reason: "Prior investigation matched monitoring-probe"
    prior_run_id: "run-abc"
    prior_disposition: "benign"
    prior_precedent: "SEC-2024-001"
    risk_note: "none"
"""


class TestTrimTicketContext:
    """Trim tests. PyYAML is optional — without it, trim returns raw (tested below)."""

    def test_returns_raw_without_yaml(self):
        """Without PyYAML, trimming is a no-op — raw output passes through."""
        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        try:
            import yaml  # noqa: F401
        except ImportError:
            # No PyYAML — raw passthrough is correct
            assert result == SAMPLE_TICKET_CONTEXT_YAML
            return
        # PyYAML available — trimming happened, covered by tests below

    def test_returns_raw_on_invalid_yaml(self):
        raw = "not: yaml: at: all: [[[broken"
        result = trim_ticket_context(raw)
        assert result == raw

    def test_returns_raw_on_missing_ticket_context_key(self):
        raw = "some_other_key:\n  data: value\n"
        result = trim_ticket_context(raw)
        # Without PyYAML: returns raw (no parsing attempt)
        # With PyYAML: returns raw (ticket_context key missing)
        assert result == raw

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_trims_alert_ids_to_count(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        definite = data["ticket_context"]["definite"][0]
        assert "alert_ids" not in definite
        assert definite["count"] == 3

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_drops_reasoning_from_definite(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        definite = data["ticket_context"]["definite"][0]
        assert "reasoning" not in definite

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_keeps_situation(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        assert "Three SSH" in data["ticket_context"]["situation"]

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_prior_investigation_trimmed(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        pi = data["ticket_context"]["definite"][0]["prior_investigation"]
        assert pi["disposition"] == "benign"
        assert pi["matched_archetype"] == "monitoring-probe"
        assert pi["matched_ticket_id"] == "SEC-2024-001"
        assert "summary" not in pi
        assert "run_id" not in pi

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_maybe_capped_at_three(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        assert len(data["ticket_context"]["maybe"]) == 3

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_fast_resolve_kept_in_full(self):
        import yaml

        result = trim_ticket_context(SAMPLE_TICKET_CONTEXT_YAML)
        data = yaml.safe_load(result)
        fr = data["ticket_context"]["fast_resolve"]
        assert fr["recommended"] is True
        assert fr["risk_note"] == "none"

    @pytest.mark.skipif(
        not _has_yaml(), reason="PyYAML not installed"
    )
    def test_extracts_from_code_fence(self):
        import yaml

        fenced = "Some text\n```yaml\n" + SAMPLE_TICKET_CONTEXT_YAML + "```\nMore text"
        result = trim_ticket_context(fenced)
        data = yaml.safe_load(result)
        assert "ticket_context" in data


# ---------------------------------------------------------------------------
# format_additional_context
# ---------------------------------------------------------------------------


class TestFormatAdditionalContext:
    def test_both_success(self):
        result = format_additional_context(
            "tc output", None, "as output", None, "/runs/abc"
        )
        assert "## Ticket Context" in result
        assert "tc output" in result
        assert "## Archetype Scan" in result
        assert "as output" in result

    def test_tc_error(self):
        result = format_additional_context(
            None, "timed out", "as output", None, "/runs/abc"
        )
        assert "timed out" in result
        assert "Fall back" in result
        assert "as output" in result

    def test_as_error(self):
        result = format_additional_context(
            "tc output", None, None, "cli not found", "/runs/abc"
        )
        assert "tc output" in result
        assert "cli not found" in result

    def test_both_error(self):
        result = format_additional_context(
            None, "err1", None, "err2", "/runs/abc"
        )
        assert "err1" in result
        assert "err2" in result

    def test_no_output_no_error(self):
        result = format_additional_context(
            None, None, None, None, "/runs/abc"
        )
        assert "Fall back to manual dispatch" in result


# ---------------------------------------------------------------------------
# main() integration — stdin/stdout contract
# ---------------------------------------------------------------------------


class TestMainIntegration:
    def _run_hook(self, stdin_data: str) -> tuple[str, str, int]:
        """Run the hook as a subprocess, return (stdout, stderr, returncode)."""
        import subprocess

        result = subprocess.run(
            [sys.executable, str(SOC_AGENT_ROOT / "hooks" / "scripts" / "contextualize_preload.py")],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout, result.stderr, result.returncode

    def test_non_investigation_prompt_exits_silently(self):
        stdin = json.dumps({"prompt": "just a normal question"})
        stdout, stderr, rc = self._run_hook(stdin)
        assert rc == 0
        assert stdout.strip() == ""

    def test_invalid_json_exits_silently(self):
        stdout, stderr, rc = self._run_hook("not json at all")
        assert rc == 0
        assert stdout.strip() == ""

    def test_empty_stdin_exits_silently(self):
        stdout, stderr, rc = self._run_hook("")
        assert rc == 0
        assert stdout.strip() == ""

    def test_missing_alert_json_exits_silently(self, tmp_path):
        run_dir = tmp_path / "runs" / "test-run"
        run_dir.mkdir(parents=True)
        # No alert.json written
        stdin = json.dumps({
            "prompt": f"Run directory: {run_dir}\nSignature: wazuh-rule-5710\n"
        })
        stdout, stderr, rc = self._run_hook(stdin)
        assert rc == 0
        assert "alert.json not found" in stderr
