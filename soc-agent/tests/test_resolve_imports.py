"""Tests for the resolve_imports.py script.

Validates that the resolver correctly:
- Outputs context.md, playbook.md, checklist.md for valid signatures
- Extracts and resolves @import:name references from playbook body
- Handles missing imports gracefully (warning, not failure)
- Fails on missing signature directory
"""

import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = SOC_AGENT_ROOT / "scripts" / "resolve_imports.py"


def run_resolver(signature_id: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), signature_id],
        capture_output=True,
        text=True,
        cwd=str(SOC_AGENT_ROOT),
    )


class TestResolverHappyPath:
    """Tests with the real wazuh-rule-5710 signature."""

    def test_exit_code_zero(self):
        result = run_resolver("wazuh-rule-5710")
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_contains_context(self):
        result = run_resolver("wazuh-rule-5710")
        assert "<!-- source: knowledge/signatures/wazuh-rule-5710/context.md -->" in result.stdout
        assert "SSH Invalid User" in result.stdout

    def test_contains_playbook(self):
        result = run_resolver("wazuh-rule-5710")
        assert "<!-- source: knowledge/signatures/wazuh-rule-5710/playbook.md -->" in result.stdout
        assert "Hypothesis Catalog" in result.stdout

    def test_contains_checklist(self):
        result = run_resolver("wazuh-rule-5710")
        assert "<!-- source: knowledge/common/checklist.md -->" in result.stdout
        assert "Investigation Checklist" in result.stdout

    def test_output_order(self):
        """Context before playbook before checklist."""
        result = run_resolver("wazuh-rule-5710")
        out = result.stdout
        ctx_pos = out.index("context.md -->")
        pb_pos = out.index("playbook.md -->")
        cl_pos = out.index("checklist.md -->")
        assert ctx_pos < pb_pos < cl_pos


class TestResolverImports:
    """Tests for @import:name resolution."""

    def test_resolves_imports_from_playbook(self):
        """Once @import: refs are added to wazuh-rule-5710 playbook, they should resolve."""
        result = run_resolver("wazuh-rule-5710")
        # After the playbook is updated with @import:ip-classification and @import:wazuh-queries,
        # both should appear in the output.
        out = result.stdout
        if "@import:ip-classification" in (SOC_AGENT_ROOT / "knowledge" / "signatures" / "wazuh-rule-5710" / "playbook.md").read_text():
            assert "ip-classification.md -->" in out
            assert "IP Classification" in out

    def test_deduplicates_imports(self):
        """Same @import referenced twice should only appear once in output."""
        result = run_resolver("wazuh-rule-5710")
        out = result.stdout
        # Count occurrences of each import source comment
        if "ip-classification.md -->" in out:
            assert out.count("ip-classification.md -->") == 1


class TestResolverErrors:
    """Tests for error handling."""

    def test_missing_signature_fails(self):
        result = run_resolver("nonexistent-sig-99999")
        assert result.returncode == 1
        assert "not found" in result.stderr

    def test_no_args_fails(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "Usage" in result.stderr


class TestExtractImports:
    """Unit tests for the import extraction logic."""

    def test_extract_imports(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import extract_imports

        text = """
### source-reputation
See @import:ip-classification for classification rules.

### authentication-history
Query patterns: @import:wazuh-queries
"""
        imports = extract_imports(text)
        assert imports == ["ip-classification", "wazuh-queries"]

    def test_extract_deduplicates(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import extract_imports

        text = "@import:foo and @import:bar and @import:foo again"
        imports = extract_imports(text)
        assert imports == ["foo", "bar"]

    def test_extract_empty(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import extract_imports

        text = "No imports here."
        imports = extract_imports(text)
        assert imports == []

    def test_resolve_import_lessons(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import resolve_import

        path = resolve_import("ip-classification")
        assert path is not None
        assert path.name == "ip-classification.md"
        assert "lessons" in str(path)

    def test_resolve_import_utilities(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import resolve_import

        path = resolve_import("wazuh-queries")
        assert path is not None
        assert path.name == "wazuh-queries.md"
        assert "utilities" in str(path)

    def test_resolve_import_missing(self):
        sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
        from resolve_imports import resolve_import

        path = resolve_import("nonexistent-atom-xyz")
        assert path is None
