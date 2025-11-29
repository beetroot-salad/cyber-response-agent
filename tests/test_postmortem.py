"""
Tests for the post-mortem hook.
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import after patching to avoid issues
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestPostMortemHook:
    """Tests for post-mortem analysis functions."""

    @pytest.fixture
    def temp_run_dir(self, tmp_path):
        """Create a temporary run directory with test data."""
        run_dir = tmp_path / "test-run"
        run_dir.mkdir()

        # Create alert.json
        alert = {
            "ticket_id": "TEST-001",
            "signature_id": "wazuh-rule-5710",
            "srcip": "10.0.1.50",
            "srcuser": "testuser",
        }
        (run_dir / "alert.json").write_text(json.dumps(alert))

        # Create scratchpad with notes
        scratchpad = run_dir / "scratchpad"
        scratchpad.mkdir()
        (scratchpad / "notes.md").write_text("""
## Investigation Notes

Checked source IP - internal monitoring subnet.
Query used: `rule.id:5710 AND srcip:10.0.1.*`
Result: Single event, no related failures.
""")

        return run_dir

    @pytest.fixture
    def knowledge_dir(self, tmp_path):
        """Create a temporary knowledge directory."""
        knowledge = tmp_path / "knowledge"
        knowledge.mkdir()

        # Create signature lessons file
        sig_dir = knowledge / "signatures" / "wazuh-rule-5710"
        sig_dir.mkdir(parents=True)
        (sig_dir / "lessons.md").write_text("# Lessons Learned\n\nExisting lessons here.\n")

        # Create common lessons
        common_dir = knowledge / "common" / "lessons"
        common_dir.mkdir(parents=True)
        (common_dir / "lessons.md").write_text("# Common Lessons\n\n")

        return knowledge

    def test_read_investigation_report(self, temp_run_dir):
        """Should read and combine investigation artifacts."""
        from app.agent.investigation.hooks.post_mortem import read_investigation_report

        report = read_investigation_report(temp_run_dir)

        assert report is not None
        assert "TEST-001" in report
        assert "wazuh-rule-5710" in report
        assert "Investigation Notes" in report

    def test_read_investigation_report_empty_dir(self, tmp_path):
        """Should return None for empty directory."""
        from app.agent.investigation.hooks.post_mortem import read_investigation_report

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        report = read_investigation_report(empty_dir)
        assert report is None

    def test_apply_lesson_appends_to_file(self, knowledge_dir):
        """Should append lesson to lessons.md."""
        from app.agent.investigation.hooks.post_mortem import apply_lesson

        # Patch KNOWLEDGE_DIR
        with patch("app.agent.investigation.hooks.post_mortem.KNOWLEDGE_DIR", knowledge_dir):
            lesson = {
                "type": "pattern",
                "placement": "signature",
                "content": "10.0.1.x subnet is monitoring infrastructure",
                "evidence": "Confirmed via network team",
            }

            result = apply_lesson(lesson, "wazuh-rule-5710")

            assert result is True

            # Check file was updated
            lessons_file = knowledge_dir / "signatures" / "wazuh-rule-5710" / "lessons.md"
            content = lessons_file.read_text()
            assert "10.0.1.x subnet is monitoring infrastructure" in content
            assert "pattern" in content.lower()

    def test_apply_lesson_rejects_duplicate(self, knowledge_dir):
        """Should not add duplicate lessons."""
        from app.agent.investigation.hooks.post_mortem import apply_lesson

        with patch("app.agent.investigation.hooks.post_mortem.KNOWLEDGE_DIR", knowledge_dir):
            # Add existing content
            lessons_file = knowledge_dir / "signatures" / "wazuh-rule-5710" / "lessons.md"
            lessons_file.write_text("Existing lessons here.\nThis is a known pattern.\n")

            lesson = {
                "type": "tip",
                "placement": "signature",
                "content": "This is a known pattern.",  # Already exists
                "evidence": "Test",
            }

            result = apply_lesson(lesson, "wazuh-rule-5710")
            assert result is False

    def test_apply_utility_creates_file(self, knowledge_dir):
        """Should create utility markdown file."""
        from app.agent.investigation.hooks.post_mortem import apply_utility

        with patch("app.agent.investigation.hooks.post_mortem.KNOWLEDGE_DIR", knowledge_dir):
            utility = {
                "name": "count_failures_by_ip",
                "placement": "signature",
                "description": "Count SSH failures from an IP",
                "content": "rule.id:5710 AND srcip:{{ip}}",
                "rationale": "Useful for distinguishing typos from brute force",
            }

            result = apply_utility(utility, "wazuh-rule-5710")

            assert result is True

            # Check file was created
            util_file = knowledge_dir / "signatures" / "wazuh-rule-5710" / "utilities" / "count_failures_by_ip.md"
            assert util_file.exists()
            content = util_file.read_text()
            assert "Count SSH failures" in content
            assert "rule.id:5710" in content

    def test_apply_utility_rejects_existing(self, knowledge_dir):
        """Should not overwrite existing utility."""
        from app.agent.investigation.hooks.post_mortem import apply_utility

        with patch("app.agent.investigation.hooks.post_mortem.KNOWLEDGE_DIR", knowledge_dir):
            # Create existing utility
            util_dir = knowledge_dir / "signatures" / "wazuh-rule-5710" / "utilities"
            util_dir.mkdir(parents=True)
            (util_dir / "existing_util.md").write_text("Existing content")

            utility = {
                "name": "existing_util",
                "placement": "signature",
                "content": "new content",
            }

            result = apply_utility(utility, "wazuh-rule-5710")
            assert result is False

            # Original content preserved
            assert (util_dir / "existing_util.md").read_text() == "Existing content"


class TestAnalysisOutput:
    """Tests for analysis output parsing."""

    def test_empty_analysis_is_valid(self):
        """Empty arrays should be the common case."""
        analysis = {
            "utilities": [],
            "lessons": [],
            "summary": "No novel insights from this investigation",
        }

        assert len(analysis["utilities"]) == 0
        assert len(analysis["lessons"]) == 0

    def test_valid_utility_structure(self):
        """Utility should have required fields."""
        utility = {
            "name": "test_query",
            "placement": "common",
            "description": "A test query",
            "content": "some query here",
            "rationale": "Because it's useful",
        }

        assert utility["name"]
        assert utility["placement"] in ("common", "signature")
        assert utility["content"]

    def test_valid_lesson_structure(self):
        """Lesson should have required fields."""
        lesson = {
            "type": "pattern",
            "placement": "signature",
            "content": "Specific pattern description",
            "evidence": "What demonstrated this",
        }

        assert lesson["type"] in ("pattern", "pitfall", "tip")
        assert lesson["placement"] in ("common", "signature")
        assert lesson["content"]
