"""Structural tests for the archetype-shape worker validation fixtures.

These tests do NOT invoke an LLM. They verify the fixture matrix for
wazuh-rule-100001 is internally consistent:

- Every alert fixture has a matching SIEM response and anchor response
- Each anchor response references real anchors that exist in
  knowledge/environment/operations/
- Each alert fixture has the field paths the agent will read
  (proc.pname, proc.cmdline, container.image.repository)
- The EXPECTED_OUTCOMES.md catalog covers every fixture
- Every archetype's required_anchors are addressable from the operations
  knowledge layer

If these break, worker validation runs will produce noise — the agent
will hit missing fixture data and the test results will be uninterpretable.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.frontmatter import parse_yaml_frontmatter

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures"
SIGNATURE_ID = "wazuh-rule-100001"
ALERTS_DIR = FIXTURES / "alerts" / SIGNATURE_ID
SIEM_DIR = FIXTURES / "siem_responses"
ANCHOR_DIR = FIXTURES / "anchor_responses" / SIGNATURE_ID
ARCHETYPE_DIR = (
    SOC_AGENT_ROOT / "knowledge" / "signatures" / SIGNATURE_ID / "archetypes"
)
OPERATIONS_DIR = SOC_AGENT_ROOT / "knowledge" / "environment" / "operations"

# (alert basename, siem fixture filename)
EXPECTED_MATRIX = [
    ("operator-debug-confirmed", "wazuh-100001-operator-debug.json"),
    ("post-exploit", "wazuh-100001-post-exploit.json"),
    ("composition-co-firing", "wazuh-100001-composition.json"),
]


# ---------------------------------------------------------------------------
# Per-fixture parametrized checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("alert_name", "siem_name"), EXPECTED_MATRIX)
class TestPerFixture:
    def test_alert_file_exists_and_parses(self, alert_name, siem_name):
        path = ALERTS_DIR / f"{alert_name}.json"
        assert path.exists(), f"Missing alert fixture: {path}"
        data = json.loads(path.read_text())
        assert data["signature_id"] == SIGNATURE_ID
        assert "ticket_id" in data
        assert "alert_data" in data

    def test_alert_has_falco_field_paths(self, alert_name, siem_name):
        """Each alert must contain the fields the agent reads from the playbook."""
        path = ALERTS_DIR / f"{alert_name}.json"
        data = json.loads(path.read_text())
        output_fields = data["alert_data"]["data"]["output_fields"]
        assert "proc" in output_fields
        assert "pname" in output_fields["proc"], "proc.pname is the primary discriminator"
        assert "cmdline" in output_fields["proc"]
        assert "container" in output_fields
        assert "image" in output_fields["container"]
        assert "repository" in output_fields["container"]["image"]

    def test_siem_fixture_exists_and_parses(self, alert_name, siem_name):
        path = SIEM_DIR / siem_name
        assert path.exists(), f"Missing SIEM fixture: {path}"
        data = json.loads(path.read_text())
        assert "queries" in data
        # Both leads from the playbook starter order must have responses
        assert "container_baseline" in data["queries"]
        assert "correlated_falco_events" in data["queries"]

    def test_anchor_fixture_exists_and_parses(self, alert_name, siem_name):
        path = ANCHOR_DIR / f"{alert_name}.json"
        assert path.exists(), f"Missing anchor fixture: {path}"
        data = json.loads(path.read_text())
        assert "anchors" in data, "anchor fixture must have an 'anchors' key"


# ---------------------------------------------------------------------------
# Cross-fixture consistency
# ---------------------------------------------------------------------------


class TestAnchorReferencesResolve:
    """Every anchor named in a fixture must exist as a real operations file."""

    def _operations_anchor_names(self) -> set[str]:
        names = set()
        for path in OPERATIONS_DIR.glob("*.md"):
            if path.name == "SKILL.md":
                continue
            content = path.read_text()
            fm = parse_yaml_frontmatter(content)
            provides = fm.get("provides") or []
            if isinstance(provides, list):
                for name in provides:
                    names.add(name)
        return names

    def test_all_referenced_anchors_have_operation_files(self):
        ops_names = self._operations_anchor_names()
        for fixture_path in ANCHOR_DIR.glob("*.json"):
            data = json.loads(fixture_path.read_text())
            for anchor_name in data.get("anchors", {}).keys():
                assert anchor_name in ops_names, (
                    f"{fixture_path.name} references anchor '{anchor_name}' "
                    f"but no operation file under "
                    f"knowledge/environment/operations/ provides it"
                )

    def test_all_archetype_required_anchors_have_operation_files(self):
        """Every required_anchor in every archetype must have an operation file."""
        ops_names = self._operations_anchor_names()
        for path in ARCHETYPE_DIR.glob("*/trust-anchors.md"):
            content = path.read_text()
            fm = parse_yaml_frontmatter(content)
            required = fm.get("required_anchors") or []
            for anchor_name in required:
                assert anchor_name in ops_names, (
                    f"archetype {path.parent.name} requires anchor "
                    f"'{anchor_name}' but no operation file under "
                    f"knowledge/environment/operations/ provides it"
                )


class TestExpectedOutcomesDocumented:
    """The EXPECTED_OUTCOMES.md catalog must reference every fixture."""

    def test_outcomes_doc_exists(self):
        assert (ANCHOR_DIR / "EXPECTED_OUTCOMES.md").exists()

    def test_every_alert_appears_in_outcomes_doc(self):
        outcomes = (ANCHOR_DIR / "EXPECTED_OUTCOMES.md").read_text()
        for alert_name, _ in EXPECTED_MATRIX:
            assert alert_name in outcomes, (
                f"EXPECTED_OUTCOMES.md does not mention alert '{alert_name}'"
            )


class TestArchetypeFrontmatterParseable:
    """Every archetype trust-anchors.md under wazuh-rule-100001/archetypes/
    must be parseable by the zero-dep frontmatter parser used by the
    validation hook."""

    def test_all_archetypes_parse(self):
        for path in ARCHETYPE_DIR.glob("*/trust-anchors.md"):
            content = path.read_text()
            fm = parse_yaml_frontmatter(content)
            arch_name = path.parent.name
            assert fm.get("archetype"), f"{arch_name} missing archetype name"
            assert fm.get("signature_id") == SIGNATURE_ID
            assert "required_anchors" in fm, (
                f"{arch_name} must declare required_anchors (use [] for none)"
            )


# ---------------------------------------------------------------------------
# Composition rule sanity check
# ---------------------------------------------------------------------------


class TestCompositionFixtureSanity:
    """The composition fixture must have BOTH a confirmed baseline anchor
    AND co-firing of an escalation rule. Without both, the composition rule
    isn't being tested."""

    def test_image_baseline_confirmed(self):
        anchor_data = json.loads(
            (ANCHOR_DIR / "composition-co-firing.json").read_text()
        )
        baseline = anchor_data["anchors"].get("image-baseline")
        assert baseline is not None
        assert baseline["result"] == "confirmed"

    def test_co_firing_event_present(self):
        siem_data = json.loads(
            (SIEM_DIR / "wazuh-100001-composition.json").read_text()
        )
        correlated = siem_data["queries"]["correlated_falco_events"]["response"]
        assert correlated["total"] >= 1, (
            "composition fixture must include at least one co-fired Falco rule"
        )
        # The co-fired rule must be one of the escalation triggers from the playbook
        escalation_rule_ids = {"100002", "100006", "100007", "100008"}
        rule_ids_in_response = {
            hit["rule"]["id"] for hit in correlated.get("hits", [])
        }
        assert rule_ids_in_response & escalation_rule_ids, (
            f"composition fixture must include at least one of {escalation_rule_ids} "
            f"co-fired (the playbook composition rule depends on these)"
        )
