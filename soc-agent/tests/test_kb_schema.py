"""Tests for knowledge base schema validation.

Validates precedent files against the precedent schema and
context.md / playbook.md frontmatter structure.
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


def _valid_precedent_dict(**overrides):
    """Build a valid minimal precedent dict. Override any field via kwargs."""
    data = {
        "ticket_id": "SEC-2026-001",
        "archetype": "monitoring-probe",
        "captured_at": "2026-04-11",
        "disposition": "benign",
        "narrative": "Internal monitoring host probed SSH with a single attempt.",
        "alert": {"rule": {"id": "5710"}, "data": {"srcip": "10.0.0.1"}},
        "anchors_at_time": [
            {
                "anchor": "approved-monitoring-sources",
                "result": "confirmed",
                "citation": "monitoring cron sanctioned",
            }
        ],
    }
    data.update(overrides)
    return data


class TestPrecedentSchema:
    """Precedent JSON files under archetypes/*/*.json must validate."""

    @staticmethod
    def _get_precedent_files():
        """Find all precedent JSON files, excluding templates."""
        files = []
        for sig_dir in SIGNATURES_DIR.iterdir():
            if sig_dir.name.startswith("_"):
                continue
            archetypes_dir = sig_dir / "archetypes"
            if not archetypes_dir.is_dir():
                continue
            for archetype_dir in archetypes_dir.iterdir():
                if not archetype_dir.is_dir():
                    continue
                files.extend(archetype_dir.glob("*.json"))
        return files

    def test_precedent_files_exist(self):
        """At least one real precedent snapshot must exist."""
        files = self._get_precedent_files()
        assert len(files) > 0, "No precedent files found"

    def test_all_precedents_validate(self):
        """Every precedent file that exists must pass schema validation
        and its `archetype` field must match its parent directory name."""
        for precedent_file in self._get_precedent_files():
            data = json.loads(precedent_file.read_text())
            precedent, errors = parse_precedent(data)
            assert errors == [], (
                f"Validation errors in {precedent_file}: {errors}"
            )
            parent_archetype = precedent_file.parent.name
            assert data["archetype"] == parent_archetype, (
                f"{precedent_file}: archetype field '{data['archetype']}' "
                f"does not match parent directory '{parent_archetype}'"
            )


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
        assert "auth-events" in fm["data_sources"]


# --- Precedent schema edge cases ---


class TestPrecedentEdgeCases:
    def test_minimal_valid_precedent(self):
        """A well-formed precedent dict should validate with no errors."""
        _, errors = parse_precedent(_valid_precedent_dict())
        assert errors == [], f"Valid precedent produced errors: {errors}"

    def test_missing_required_field(self):
        """Missing a required field should produce an error."""
        data = {"ticket_id": "SEC-001"}  # Missing everything else
        _, errors = parse_precedent(data)
        assert len(errors) > 0

    def test_invalid_disposition(self):
        _, errors = parse_precedent(_valid_precedent_dict(disposition="unknown"))
        assert any("disposition" in e for e in errors)

    def test_invalid_captured_at(self):
        _, errors = parse_precedent(
            _valid_precedent_dict(captured_at="not-a-date")
        )
        assert any("captured_at" in e for e in errors)

    def test_empty_alert_rejected(self):
        _, errors = parse_precedent(_valid_precedent_dict(alert={}))
        assert any("alert" in e for e in errors)

    def test_empty_narrative_rejected(self):
        _, errors = parse_precedent(_valid_precedent_dict(narrative=""))
        assert any("narrative" in e for e in errors)

    def test_anchor_result_must_be_valid(self):
        bad = _valid_precedent_dict()
        bad["anchors_at_time"][0]["result"] = "maybe"
        _, errors = parse_precedent(bad)
        assert any("result" in e for e in errors)

    def test_empty_anchors_list_is_ok(self):
        """A precedent with no anchor citations is valid (e.g. escalation
        archetypes where anchor confirmation is not required)."""
        _, errors = parse_precedent(_valid_precedent_dict(anchors_at_time=[]))
        assert errors == []


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

    def test_imports_resolve_if_present(self):
        """If any playbook has @import: refs, each must resolve."""
        pairs = self._get_imports_by_playbook()
        for playbook, name in pairs:
            resolved = resolve_import(name)
            assert resolved is not None, (
                f"@import:{name} in {playbook.parent.name}/playbook.md "
                f"does not resolve to any file in lessons/"
            )
            assert resolved.exists()


# --- Precedent template ---


class TestPrecedentTemplate:
    """The precedent template must exist and validate against the schema."""

    def test_precedent_template_exists(self):
        template = (
            SIGNATURES_DIR / "_template" / "archetypes" / "_template" / "TEMPLATE.json"
        )
        assert template.exists(), "Precedent template missing"
        data = json.loads(template.read_text())
        _, errors = parse_precedent(data)
        assert errors == [], (
            f"Template precedent failed schema validation: {errors}"
        )
