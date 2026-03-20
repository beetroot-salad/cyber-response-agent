"""Tests for knowledge base schema validation.

Validates precedent files against the precedent schema and
context.md frontmatter structure.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from config.schemas.precedent import parse_precedent
from hooks.scripts.validate_report import parse_yaml_frontmatter

KNOWLEDGE_DIR = SOC_AGENT_ROOT / "knowledge"
SIGNATURES_DIR = KNOWLEDGE_DIR / "signatures"


# --- Precedent validation ---


class TestPrecedentSchema:
    """All precedent files in knowledge/ must validate against the schema."""

    @staticmethod
    def _get_precedent_files():
        """Find all precedent JSON files, excluding templates."""
        files = []
        for sig_dir in SIGNATURES_DIR.iterdir():
            if sig_dir.name.startswith("_"):
                continue
            precedents_dir = sig_dir / "precedents"
            if precedents_dir.exists():
                files.extend(precedents_dir.glob("*.json"))
        return files

    def test_precedent_files_exist(self):
        """At least one precedent file should exist."""
        files = self._get_precedent_files()
        assert len(files) > 0, "No precedent files found"

    @pytest.mark.parametrize(
        "precedent_file",
        [
            pytest.param(f, id=f.name)
            for f in (SIGNATURES_DIR / "wazuh-rule-5710" / "precedents").glob("*.json")
        ],
    )
    def test_precedent_validates(self, precedent_file):
        """Each precedent file must pass schema validation."""
        data = json.loads(precedent_file.read_text())
        precedent, errors = parse_precedent(data)
        assert errors == [], f"Validation errors in {precedent_file.name}: {errors}"

    def test_monitoring_probe_precedent(self):
        """Specific check: monitoring-probe-001.json has expected structure."""
        path = SIGNATURES_DIR / "wazuh-rule-5710" / "precedents" / "monitoring-probe-001.json"
        data = json.loads(path.read_text())

        assert data["disposition"] == "benign"
        assert data["signature_id"] == "wazuh-rule-5710"
        assert any(h["id"] == "monitoring-probe" and h["status"] == "confirmed" for h in data["hypotheses"])
        assert any(h["id"] == "brute-force" and h["status"] == "refuted" for h in data["hypotheses"])
        assert len(data["flow"]) >= 2
        assert "trace" in data

    def test_brute_force_precedent(self):
        """Specific check: brute-force-001.json has expected structure."""
        path = SIGNATURES_DIR / "wazuh-rule-5710" / "precedents" / "brute-force-001.json"
        data = json.loads(path.read_text())

        assert data["disposition"] == "escalated"
        assert data["signature_id"] == "wazuh-rule-5710"
        assert any(h["id"] == "brute-force" and h["status"] == "confirmed" for h in data["hypotheses"])
        assert len(data["flow"]) >= 3


# --- Context.md frontmatter ---


class TestContextFrontmatter:
    """Context.md files must have valid frontmatter."""

    @staticmethod
    def _get_context_files():
        files = []
        for sig_dir in SIGNATURES_DIR.iterdir():
            if sig_dir.name.startswith("_"):
                continue
            context = sig_dir / "context.md"
            if context.exists():
                files.append(context)
        return files

    def test_context_files_exist(self):
        files = self._get_context_files()
        assert len(files) > 0

    @pytest.mark.parametrize(
        "context_file",
        [
            pytest.param(f, id=f.parent.name)
            for f in [
                d / "context.md"
                for d in SIGNATURES_DIR.iterdir()
                if not d.name.startswith("_") and (d / "context.md").exists()
            ]
        ],
    )
    def test_context_has_required_frontmatter(self, context_file):
        """Context files must have signature_id, name, and severity."""
        content = context_file.read_text()
        fm = parse_yaml_frontmatter(content)
        assert fm, f"No frontmatter in {context_file}"
        assert "signature_id" in fm, f"Missing signature_id in {context_file}"
        assert "name" in fm, f"Missing name in {context_file}"
        assert "severity" in fm, f"Missing severity in {context_file}"

    def test_wazuh_5710_context(self):
        """Specific check: wazuh-rule-5710 context.md."""
        path = SIGNATURES_DIR / "wazuh-rule-5710" / "context.md"
        fm = parse_yaml_frontmatter(path.read_text())
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["severity"] == "medium"


# --- Precedent schema edge cases ---


class TestPrecedentEdgeCases:
    def test_missing_required_field(self):
        """Missing a required field should produce an error."""
        data = {"ticket_id": "SEC-001"}  # Missing everything else
        _, errors = parse_precedent(data)
        assert len(errors) > 0

    def test_invalid_disposition(self):
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "disposition": "unknown",
            "hypotheses": [{"id": "h1", "status": "confirmed", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert any("disposition" in e for e in errors)

    def test_non_escalated_needs_confirmed(self):
        """Non-escalated precedents must have at least one confirmed hypothesis."""
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "disposition": "benign",
            "hypotheses": [{"id": "h1", "status": "refuted", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert any("confirmed hypothesis" in e for e in errors)

    def test_escalated_can_skip_confirmed(self):
        """Escalated precedents don't need a confirmed hypothesis."""
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "disposition": "escalated",
            "hypotheses": [{"id": "h1", "status": "refuted", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert not any("confirmed hypothesis" in e for e in errors)
