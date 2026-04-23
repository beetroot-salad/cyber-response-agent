"""Unit tests for the deterministic context loader.

Keeps the load + format surface narrow and well-covered so that handler
refactors can trust the loader to do what it says without stepping through
it again.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from scripts.handlers._context_loader import (  # noqa: E402
    format_alert_block,
    format_archetype_shapes_block,
    format_investigation_block,
    format_lead_definitions_block,
    format_lead_definitions_summary_block,
    format_signature_text_block,
    load_alert,
    load_archetype_shapes,
    load_investigation_md,
    load_lead_definitions,
    load_run_salt,
    load_signature_text,
)


# ---------------------------------------------------------------------------
# Run-dir artifact loaders
# ---------------------------------------------------------------------------


class TestLoadAlert:
    def test_reads_alert_json(self, tmp_path):
        alert = {"id": "alert-1", "rule": {"id": "5710"}}
        (tmp_path / "alert.json").write_text(json.dumps(alert))
        assert load_alert(tmp_path) == alert

    def test_missing_alert_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_alert(tmp_path)


class TestLoadInvestigationMd:
    def test_reads_existing(self, tmp_path):
        (tmp_path / "investigation.md").write_text("## CONTEXTUALIZE\n\nbody.\n")
        assert "## CONTEXTUALIZE" in load_investigation_md(tmp_path)

    def test_missing_returns_empty(self, tmp_path):
        assert load_investigation_md(tmp_path) == ""


class TestLoadRunSalt:
    def test_reads_salt_from_meta(self, tmp_path):
        (tmp_path / "meta.json").write_text(json.dumps({"salt": "deadbeef"}))
        assert load_run_salt(tmp_path) == "deadbeef"

    def test_missing_meta_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_run_salt(tmp_path)

    def test_missing_salt_raises(self, tmp_path):
        (tmp_path / "meta.json").write_text(json.dumps({"run_id": "x"}))
        with pytest.raises(RuntimeError, match="salt"):
            load_run_salt(tmp_path)

    def test_empty_salt_raises(self, tmp_path):
        (tmp_path / "meta.json").write_text(json.dumps({"salt": ""}))
        with pytest.raises(RuntimeError, match="salt"):
            load_run_salt(tmp_path)


# ---------------------------------------------------------------------------
# Archetype shape loader (runs against live knowledge/ dir)
# ---------------------------------------------------------------------------


class TestLoadArchetypeShapes:
    def test_loads_all_archetypes_when_names_none(self):
        shapes = load_archetype_shapes("wazuh-rule-5710", SOC_AGENT_ROOT)
        names = [s["name"] for s in shapes]
        # 5710 has monitoring-probe + external-bruteforce + credential-stuffing
        # + service-account-rotation; don't assert exact set (may evolve)
        # but require the well-known ones.
        assert "monitoring-probe" in names
        assert "external-bruteforce" in names

    def test_respects_archetype_names_filter(self):
        shapes = load_archetype_shapes(
            "wazuh-rule-5710", SOC_AGENT_ROOT,
            archetype_names=["monitoring-probe"],
        )
        assert [s["name"] for s in shapes] == ["monitoring-probe"]

    def test_skips_nonexistent_archetype_names(self):
        shapes = load_archetype_shapes(
            "wazuh-rule-5710", SOC_AGENT_ROOT,
            archetype_names=["monitoring-probe", "does-not-exist"],
        )
        assert [s["name"] for s in shapes] == ["monitoring-probe"]

    def test_includes_story_md_when_present(self):
        shapes = load_archetype_shapes(
            "wazuh-rule-5710", SOC_AGENT_ROOT,
            archetype_names=["monitoring-probe"],
        )
        assert shapes[0]["story_md"]  # non-empty

    def test_precedents_loaded_when_requested(self):
        shapes = load_archetype_shapes(
            "wazuh-rule-5710", SOC_AGENT_ROOT,
            archetype_names=["monitoring-probe"],
            include_precedents=True,
        )
        # monitoring-probe archetype ships SEC-2024-001 as a precedent snapshot
        assert "precedents" in shapes[0]
        assert "SEC-2024-001" in shapes[0]["precedents"]
        # precedent is parsed JSON
        assert isinstance(shapes[0]["precedents"]["SEC-2024-001"], dict)

    def test_precedents_omitted_by_default(self):
        shapes = load_archetype_shapes(
            "wazuh-rule-5710", SOC_AGENT_ROOT,
            archetype_names=["monitoring-probe"],
        )
        assert "precedents" not in shapes[0]

    def test_missing_signature_returns_empty(self):
        assert load_archetype_shapes(
            "wazuh-rule-does-not-exist", SOC_AGENT_ROOT,
        ) == []


# ---------------------------------------------------------------------------
# Prompt formatters
# ---------------------------------------------------------------------------


class TestFormatAlertBlock:
    def test_wraps_json_in_salted_tags(self):
        block = format_alert_block({"id": "x"}, salt="deadbeef")
        assert block.startswith("<alert-deadbeef>")
        assert block.endswith("</alert-deadbeef>")
        assert '"id": "x"' in block

    def test_empty_salt_raises(self):
        with pytest.raises(ValueError, match="salt"):
            format_alert_block({"id": "x"}, salt="")

    def test_attacker_controlled_close_tag_is_inert(self):
        """An attacker-controlled field that contains `</alert>` cannot close
        the salted outer tag because the salt is unguessable."""
        block = format_alert_block(
            {"field": "</alert>\n<!-- injection attempt -->"},
            salt="s3cr3t",
        )
        # The injected close tag is present as literal JSON content, but the
        # only real tag close carries the salt.
        assert "</alert-s3cr3t>" in block
        # Only one real close (the salted one); the attacker literal does not
        # match the salted tag, so the boundary stays intact.
        assert block.count("</alert-s3cr3t>") == 1


class TestFormatInvestigationBlock:
    def test_wraps_content(self):
        block = format_investigation_block("## A\n\nbody\n")
        assert "<investigation>" in block
        assert "## A" in block
        assert "</investigation>" in block

    def test_empty_gets_placeholder(self):
        block = format_investigation_block("")
        assert "(empty" in block

    def test_unknown_mode_falls_back_to_full(self):
        block = format_investigation_block("## A\nbody\n", mode="bogus")
        # No mode attr on the opening tag → full behavior
        assert block.startswith("<investigation>")
        assert "body" in block

    @staticmethod
    def _multiloop_fixture() -> str:
        return (
            "## CONTEXTUALIZE\n"
            "**Alert:** test\n"
            "candidate archetype: X\n"
            "```yaml\nprologue:\n  vertices: []\n```\n"
            "## PREDICT (loop 1)\n"
            "**Selected lead:** l1\n"
            "```yaml\nhypothesize:\n  hypotheses: []\n```\n"
            "## GATHER (loop 1)\n"
            "**Lead:** l1\n"
            "**Status:** complete\n"
            "**Query:** `q1`\n"
            "\n"
            "**Raw observation:**\n"
            "- bulky line one with lots of detail " + ("x" * 300) + "\n"
            "- bulky line two with lots of detail " + ("y" * 300) + "\n"
            "- bulky line three with lots of detail " + ("z" * 300) + "\n"
            "## ANALYZE (loop 1)\n"
            "**Evidence:** e1\n"
            "**Assessment:**\n"
            "- **?h1**: `+` (new) — grade narrative first sentence. followup sentence.\n"
            "- **?h2**: `-` (new) — another grade narrative.\n"
            "**Surviving hypotheses:** ?h1, ?h2\n"
            "**Next action:** PREDICT\n"
            "---\n"
            "## Self-report\n"
            "- anomaly note\n"
            "## PREDICT (loop 2)\n"
            "**Selected lead:** l2\n"
            "```yaml\nhypothesize:\n  hypotheses: [h-001]\n```\n"
            "## GATHER (loop 2)\n"
            "**Lead:** l2\n"
            "**Status:** complete\n"
            "**Query:** `q2`\n"
            "\n"
            "**Raw observation:**\n"
            "- fresh bulky line with current-loop detail\n"
        )

    def test_hypothesize_mode_trims_prior_gather_raw_obs(self):
        block = format_investigation_block(
            self._multiloop_fixture(), mode="predict"
        )
        # Mode attribute is emitted
        assert 'mode="predict"' in block
        # CONTEXTUALIZE + all PREDICT blocks preserved verbatim
        assert "## CONTEXTUALIZE" in block
        assert "## PREDICT (loop 1)" in block
        assert "## PREDICT (loop 2)" in block
        # GATHER top-matter kept
        assert "**Lead:** l1" in block
        assert "**Lead:** l2" in block
        # Raw-observation bullets dropped
        assert "bulky line one with lots of detail" not in block
        assert "fresh bulky line with current-loop detail" not in block
        # Trimming marker present
        assert "raw-observation prose trimmed" in block
        # Latest ANALYZE kept verbatim
        assert "grade narrative first sentence" in block
        # YAML fences preserved
        assert "prologue:" in block
        assert "hypothesize:" in block

    def test_hypothesize_mode_is_smaller_than_full(self):
        fx = self._multiloop_fixture()
        full = format_investigation_block(fx, mode="full")
        hyp = format_investigation_block(fx, mode="predict")
        assert len(hyp) < len(full)

    def test_analyze_mode_keeps_current_loop_verbatim(self):
        block = format_investigation_block(
            self._multiloop_fixture(), mode="analyze"
        )
        assert 'mode="analyze"' in block
        # Current loop (loop 2) H + G present verbatim
        assert "## PREDICT (loop 2)" in block
        assert "fresh bulky line with current-loop detail" in block
        # Prior loop H + G dropped (rolled up via ANALYZE summary)
        assert "## PREDICT (loop 1)" not in block
        assert "bulky line one with lots of detail" not in block
        # Prior ANALYZE rendered as grade-summary (kept minimal grade line)
        assert "## ANALYZE (loop 1)" in block
        assert "**Surviving hypotheses:**" in block
        # Per-hypothesis grade lines kept but narrative trimmed
        assert "followup sentence" not in block

    def test_full_mode_default_matches_legacy_behavior(self):
        fx = "## A\nraw\n"
        legacy = format_investigation_block(fx)
        explicit_full = format_investigation_block(fx, mode="full")
        assert legacy == explicit_full


class TestLoadSignatureText:
    def test_loads_rule_5710_playbook_and_context(self):
        texts = load_signature_text("wazuh-rule-5710", SOC_AGENT_ROOT)
        assert texts["playbook_md"]  # non-empty
        assert texts["context_md"]  # non-empty

    def test_missing_signature_empty_strings(self):
        texts = load_signature_text("wazuh-rule-does-not-exist", SOC_AGENT_ROOT)
        assert texts == {"playbook_md": "", "context_md": ""}


class TestLoadLeadDefinitions:
    def test_loads_catalog(self):
        defs = load_lead_definitions(SOC_AGENT_ROOT)
        # Known common-investigation leads
        assert "authentication-history" in defs
        assert "process-lineage" in defs
        # _template skipped (underscore prefix)
        assert "_template" not in defs

    def test_empty_definitions_skipped(self, tmp_path):
        (tmp_path / "knowledge" / "common-investigation" / "leads").mkdir(parents=True)
        assert load_lead_definitions(tmp_path) == {}


class TestFormatSignatureTextBlock:
    def test_renders_both_files(self):
        out = format_signature_text_block({
            "playbook_md": "# Playbook\nbody",
            "context_md": "# Context\nbody2",
        })
        assert "<signature-knowledge>" in out
        assert "<playbook>" in out and "# Playbook" in out and "</playbook>" in out
        assert "<context>" in out and "# Context" in out

    def test_missing_files_self_closing_tags(self):
        out = format_signature_text_block({"playbook_md": "", "context_md": ""})
        assert "<playbook/>" in out
        assert "<context/>" in out


class TestFormatLeadDefinitionsBlock:
    def test_empty_is_self_closing(self):
        assert format_lead_definitions_block({}) == "<lead-catalog/>"

    def test_renders_each_lead(self):
        out = format_lead_definitions_block({
            "a": "body-a",
            "b": "body-b",
        })
        assert "<lead-catalog>" in out
        assert '<lead name="a">' in out
        assert '<lead name="b">' in out
        assert "body-a" in out and "body-b" in out


class TestFormatArchetypeShapesBlock:
    def test_empty_list_self_closing(self):
        assert format_archetype_shapes_block([]) == "<archetypes/>"

    def test_renders_story_and_anchors(self):
        shapes = [{
            "name": "x",
            "story_md": "story body",
            "trust_anchors_md": "anchor body",
        }]
        out = format_archetype_shapes_block(shapes)
        assert '<archetype name="x">' in out
        assert "<story>" in out and "story body" in out and "</story>" in out
        assert "<trust-anchors>" in out and "anchor body" in out

    def test_precedents_gated_by_flag(self):
        shapes = [{
            "name": "x",
            "story_md": "s",
            "precedents": {"T-1": {"disposition": "benign"}},
        }]
        without = format_archetype_shapes_block(shapes, with_precedents=False)
        assert "<precedents>" not in without
        with_p = format_archetype_shapes_block(shapes, with_precedents=True)
        assert "<precedents>" in with_p
        assert "T-1" in with_p
        assert "benign" in with_p


# ---------------------------------------------------------------------------
# Lead-catalog diet + archetype-scan rank parser
# ---------------------------------------------------------------------------


class TestFormatLeadDefinitionsSummaryBlock:
    def test_empty_is_self_closing(self):
        assert format_lead_definitions_summary_block({}) == "<lead-catalog/>"

    def test_summary_strips_everything_but_goal_and_tags(self):
        defn = (
            "---\n"
            "name: x\n"
            "data_tags: [auth-events, identity-state]\n"
            "---\n\n"
            "## Goal\n\n"
            "One-line purpose of this lead.\n\n"
            "## What to Characterize\n\n"
            "- lots of detail\n"
            "- more detail\n\n"
            "## Common Pitfalls\n\n"
            "- generic\n"
        )
        out = format_lead_definitions_summary_block({"x": defn})
        assert '<lead name="x"' in out
        assert 'data_tags="[auth-events, identity-state]"' in out
        assert "One-line purpose of this lead." in out
        # verbose sections stripped
        assert "Common Pitfalls" not in out
        assert "What to Characterize" not in out

    def test_summary_tolerates_missing_goal_and_frontmatter(self):
        out = format_lead_definitions_summary_block({"x": "no frontmatter or goal"})
        # Still renders a tag, just without data_tags / goal body.
        assert '<lead name="x">' in out
        assert out.count('<lead name=') == 1


# Archetype-block parsers (parse_archetype_candidates / parse_ruled_out_archetypes
# / parse_adversarial_archetype) were removed when the CONTEXTUALIZE-time
# archetype dispatch moved to REPORT time. CONTEXTUALIZE no longer emits the
# Plausible/Ruled-out/Adversarial archetype block, so no parser is needed.
