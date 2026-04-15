"""Tests for the YAML frontmatter parser.

Tests are organised by what the parser is actually used for in this project,
plus edge cases that could silently corrupt hook validation if mishandled.
"""

import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter

SIGNATURES_DIR = SOC_AGENT_ROOT / "knowledge" / "signatures"
FIXTURES_DIR = SOC_AGENT_ROOT / "tests" / "fixtures" / "reports"


# ---------------------------------------------------------------------------
# parse_yaml_frontmatter — integration tests against real project frontmatter
# ---------------------------------------------------------------------------


class TestRealFrontmatter:
    """Parse actual frontmatter files from the project. If these break,
    hooks and tests will fail on real investigation data."""

    def test_report_resolved(self):
        """The report format that validate_report.py parses on every Stop hook."""
        text = (FIXTURES_DIR / "valid_resolved.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["ticket_id"] == "SEC-2024-001"
        assert fm["signature_id"] == "wazuh-rule-100001"
        assert fm["status"] == "resolved"
        assert fm["disposition"] == "benign"
        assert fm["confidence"] == "high"
        assert fm["matched_archetype"] == "operator-runtime-debug"
        # Grounding for operator-runtime-debug comes from required_anchors
        # (oncall-schedule + change-windows), so no matched_ticket_id is
        # needed on this fixture.
        assert fm.get("matched_ticket_id") is None
        assert fm["leads_pursued"] == 2
        # Trace contains colons and arrows — must survive parsing
        assert "shell-context" in fm["trace"]
        assert "benign" in fm["trace"]

    def test_report_escalated(self):
        text = (FIXTURES_DIR / "valid_escalate.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["status"] == "escalated"
        # Escalated reports carry no archetype/ticket citation
        assert fm.get("matched_archetype") is None
        assert fm.get("matched_ticket_id") is None
        assert fm["leads_pursued"] == 3

    def test_signature_context(self):
        """The context.md format read by get_signature_severity() and KB tests."""
        text = (SIGNATURES_DIR / "wazuh-rule-5710" / "context.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["severity"] == "medium"
        # Nested dict
        assert isinstance(fm["mitre"], dict)
        assert fm["mitre"]["tactics"] == "Initial Access"
        assert fm["mitre"]["techniques"] == "T1110"
        # Block list
        assert isinstance(fm["data_sources"], list)
        assert "auth-events" in fm["data_sources"]
        assert len(fm["data_sources"]) == 1
        # Nested dict with nulls
        assert isinstance(fm["base_rate"], dict)
        assert fm["base_rate"]["benign_pct"] is None

    def test_signature_playbook(self):
        text = (SIGNATURES_DIR / "wazuh-rule-5710" / "playbook.md").read_text()
        fm = parse_yaml_frontmatter(text)
        assert fm["signature_id"] == "wazuh-rule-5710"
        assert fm["total_investigations"] == 0
        assert fm["resolution_rate"] is None


# ---------------------------------------------------------------------------
# parse_yaml_frontmatter — structural edge cases
# ---------------------------------------------------------------------------


class TestFrontmatterEdgeCases:
    """Edge cases that, if mishandled, would silently corrupt hook validation."""

    def test_no_frontmatter(self):
        assert parse_yaml_frontmatter("# Just a heading") == {}

    def test_empty_string(self):
        assert parse_yaml_frontmatter("") == {}

    def test_only_opening_delimiter(self):
        """Missing closing --- — should still parse what's there."""
        text = "---\nkey: value\n"
        fm = parse_yaml_frontmatter(text)
        assert fm["key"] == "value"

    def test_body_not_included(self):
        """Content after closing --- must not leak into frontmatter."""
        text = """---
real_key: real_value
---
fake_key: fake_value"""
        fm = parse_yaml_frontmatter(text)
        assert "real_key" in fm
        assert "fake_key" not in fm

    def test_value_containing_colon(self):
        """Colons in quoted string values are preserved correctly."""
        text = """---
trace: "auth-history(fail:3) -> escalated"
url: https://example.com
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["trace"] == "auth-history(fail:3) -> escalated"
        assert fm["url"] == "https://example.com"

    def test_blank_lines_in_frontmatter(self):
        """Blank lines between fields should be ignored."""
        text = """---
a: 1

b: 2
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["a"] == 1
        assert fm["b"] == 2

    def test_list_then_scalar(self):
        """A block list followed by a scalar — scalar must not append to the list."""
        text = """---
items:
  - one
  - two
name: test
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["items"] == ["one", "two"]
        assert fm["name"] == "test"

    def test_nested_dict_then_scalar(self):
        """A nested dict followed by a scalar — scalar must be top-level."""
        text = """---
mitre:
  tactics: Persistence
severity: high
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["mitre"] == {"tactics": "Persistence"}
        assert fm["severity"] == "high"

    def test_null_parent_then_list_items(self):
        """Parent key with null value, then indented list items."""
        text = """---
data_sources:
  - sshd
  - auth.log
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["data_sources"] == ["sshd", "auth.log"]

    def test_null_parent_then_nested_keys(self):
        """Parent key with no value, then indented key: value pairs."""
        text = """---
config:
  mode: strict
  timeout: 30
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["config"] == {"mode": "strict", "timeout": 30}

    def test_inline_list_with_spaces(self):
        text = """---
tags: [ Initial Access , Brute Force ]
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["tags"] == ["Initial Access", "Brute Force"]

    def test_empty_inline_list(self):
        text = """---
refs: []
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["refs"] == []

    def test_single_item_block_list(self):
        text = """---
related:
  - wazuh-rule-5712
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["related"] == ["wazuh-rule-5712"]

    def test_whitespace_only_body(self):
        text = "---\nkey: value\n---\n   \n\n"
        fm = parse_yaml_frontmatter(text)
        assert fm["key"] == "value"

    def test_integer_list_items(self):
        text = """---
ports:
  - 22
  - 443
  - 8080
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["ports"] == [22, 443, 8080]

    def test_list_of_dicts_single_item(self):
        """A single dict in a block list — used by trust_anchors_consulted."""
        text = """---
trust_anchors_consulted:
  - anchor: oncall-schedule
    kind: org-authority
    result: confirmed
    citation: "alice on-call"
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["trust_anchors_consulted"] == [
            {
                "anchor": "oncall-schedule",
                "kind": "org-authority",
                "result": "confirmed",
                "citation": "alice on-call",
            }
        ]

    def test_list_of_dicts_multiple_items(self):
        """Multiple dicts in a block list — each ``- key:`` starts a new dict."""
        text = """---
anchors:
  - name: a1
    kind: org-authority
    result: confirmed
  - name: a2
    kind: telemetry-baseline
    result: refuted
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["anchors"] == [
            {"name": "a1", "kind": "org-authority", "result": "confirmed"},
            {"name": "a2", "kind": "telemetry-baseline", "result": "refuted"},
        ]

    def test_list_of_dicts_then_top_level_key(self):
        """A list-of-dicts followed by a top-level key."""
        text = """---
items:
  - k: a
    v: 1
  - k: b
    v: 2
name: test
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["items"] == [{"k": "a", "v": 1}, {"k": "b", "v": 2}]
        assert fm["name"] == "test"

    def test_invalid_yaml_returns_empty(self):
        """Malformed YAML returns an empty dict rather than raising."""
        text = "---\n\t bad: indentation\n---"
        fm = parse_yaml_frontmatter(text)
        assert fm == {}

    def test_deep_nesting(self):
        """pyyaml handles arbitrary nesting depth."""
        text = """---
l1:
  l2:
    l3: deep
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["l1"]["l2"]["l3"] == "deep"

    def test_flow_mapping_value(self):
        """Inline dict values are parsed as dicts by pyyaml."""
        text = """---
config: {mode: strict}
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["config"] == {"mode": "strict"}

    def test_boolean_coercion(self):
        """pyyaml coerces YAML true/false to Python booleans."""
        text = """---
enabled: true
disabled: false
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["enabled"] is True
        assert fm["disabled"] is False

    def test_float_coercion(self):
        """pyyaml coerces decimal values to floats."""
        text = """---
rate: 0.92
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["rate"] == pytest.approx(0.92)
        assert isinstance(fm["rate"], float)

    def test_negative_int_coercion(self):
        """pyyaml coerces negative integers correctly."""
        text = """---
offset: -5
---"""
        fm = parse_yaml_frontmatter(text)
        assert fm["offset"] == -5
        assert isinstance(fm["offset"], int)
