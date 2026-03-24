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
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from schemas.precedent import parse_precedent
from hooks.scripts.frontmatter import parse_yaml_frontmatter
from resolve_imports import IMPORT_PATTERN, resolve_import

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

        assert data["status"] == "resolved"
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

        assert data["status"] == "escalated"
        assert data["disposition"] == "true_positive"
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
        """Context files must have signature_id, name, severity, and data_sources."""
        content = context_file.read_text()
        fm = parse_yaml_frontmatter(content)
        assert fm, f"No frontmatter in {context_file}"
        assert "signature_id" in fm, f"Missing signature_id in {context_file}"
        assert "name" in fm, f"Missing name in {context_file}"
        assert "severity" in fm, f"Missing severity in {context_file}"
        assert "data_sources" in fm, f"Missing data_sources in {context_file}"

    def test_wazuh_5710_context(self):
        """Specific check: wazuh-rule-5710 context.md."""
        path = SIGNATURES_DIR / "wazuh-rule-5710" / "context.md"
        fm = parse_yaml_frontmatter(path.read_text())
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["severity"] == "medium"
        assert isinstance(fm["mitre"], dict)
        assert fm["mitre"]["tactics"] == "Initial Access"
        assert fm["mitre"]["techniques"] == "T1110"
        assert isinstance(fm["data_sources"], list)
        assert "sshd" in fm["data_sources"]


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
            "status": "resolved",
            "disposition": "unknown",
            "hypotheses": [{"id": "h1", "status": "confirmed", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert any("disposition" in e for e in errors)

    def test_invalid_status(self):
        """Invalid status value should produce an error."""
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "status": "closed",
            "disposition": "benign",
            "hypotheses": [{"id": "h1", "status": "confirmed", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert any("status" in e for e in errors)

    def test_resolved_needs_confirmed(self):
        """Resolved precedents must have at least one confirmed hypothesis."""
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "status": "resolved",
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
            "status": "escalated",
            "disposition": "inconclusive",
            "hypotheses": [{"id": "h1", "status": "refuted", "reasoning": "r"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert not any("confirmed hypothesis" in e for e in errors)

    def test_active_hypothesis_status(self):
        """Hypothesis with 'active' status should validate."""
        data = {
            "ticket_id": "SEC-001",
            "signature_id": "test",
            "status": "escalated",
            "disposition": "inconclusive",
            "hypotheses": [{"id": "h1", "status": "active", "reasoning": "still investigating"}],
            "flow": [{"lead": "l1", "observation": "o1", "assessment": "a1"}],
            "trace": "t",
            "reasoning": {"conditions": [], "refutes": []},
            "key_indicators": ["k1"],
        }
        _, errors = parse_precedent(data)
        assert not any("hypothesis status" in e for e in errors)


# --- Playbook frontmatter ---


class TestPlaybookFrontmatter:
    """Playbook files must have valid frontmatter."""

    @staticmethod
    def _get_playbook_files():
        files = []
        for sig_dir in SIGNATURES_DIR.iterdir():
            if sig_dir.name.startswith("_"):
                continue
            playbook = sig_dir / "playbook.md"
            if playbook.exists():
                files.append(playbook)
        return files

    def test_playbook_files_exist(self):
        files = self._get_playbook_files()
        assert len(files) > 0, "No playbook files found"

    @pytest.mark.parametrize(
        "playbook_file",
        [
            pytest.param(f, id=f.parent.name)
            for f in [
                d / "playbook.md"
                for d in SIGNATURES_DIR.iterdir()
                if not d.name.startswith("_") and (d / "playbook.md").exists()
            ]
        ],
    )
    def test_playbook_has_required_frontmatter(self, playbook_file):
        """Playbook files must have signature_id and last_updated."""
        content = playbook_file.read_text()
        fm = parse_yaml_frontmatter(content)
        assert fm, f"No frontmatter in {playbook_file}"
        assert "signature_id" in fm, f"Missing signature_id in {playbook_file}"
        assert "last_updated" in fm, f"Missing last_updated in {playbook_file}"


# --- @import: resolution ---


class TestPlaybookImports:
    """All @import:name references in playbooks must resolve to real files."""

    @staticmethod
    def _get_imports_by_playbook():
        """Return list of (playbook_path, import_name) tuples for parametrize."""
        pairs = []
        for sig_dir in SIGNATURES_DIR.iterdir():
            if sig_dir.name.startswith("_"):
                continue
            playbook = sig_dir / "playbook.md"
            if playbook.exists():
                text = playbook.read_text()
                for match in IMPORT_PATTERN.finditer(text):
                    pairs.append((playbook, match.group(1)))
        return pairs

    def test_at_least_one_import_exists(self):
        """At least one signature playbook should have @import: refs."""
        pairs = self._get_imports_by_playbook()
        assert len(pairs) > 0, "No @import: references found in any playbook"

    @pytest.mark.parametrize(
        "playbook_file, import_name",
        [
            pytest.param(pb, name, id=f"{pb.parent.name}/{name}")
            for pb, name in [
                (pb, name)
                for sig_dir in SIGNATURES_DIR.iterdir()
                if not sig_dir.name.startswith("_") and (sig_dir / "playbook.md").exists()
                for pb in [sig_dir / "playbook.md"]
                for name in [m.group(1) for m in IMPORT_PATTERN.finditer(pb.read_text())]
            ]
        ],
    )
    def test_import_resolves(self, playbook_file, import_name):
        """Each @import:name must resolve to a file in lessons/ or utilities/."""
        resolved = resolve_import(import_name)
        assert resolved is not None, (
            f"@import:{import_name} in {playbook_file.parent.name}/playbook.md "
            f"does not resolve to any file in lessons/ or utilities/"
        )
        assert resolved.exists()


# --- Precedent template ---


class TestPrecedentTemplate:
    """The precedent template must exist and have all required fields."""

    def test_precedent_template_exists(self):
        template = SIGNATURES_DIR / "_template" / "precedents" / "_template.json"
        assert template.exists(), "Precedent template missing"
        data = json.loads(template.read_text())
        required = [
            "ticket_id", "signature_id", "status", "disposition",
            "hypotheses", "flow", "trace", "reasoning", "key_indicators",
        ]
        for field in required:
            assert field in data, f"Template missing required field: {field}"
