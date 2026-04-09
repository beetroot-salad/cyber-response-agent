"""Tests for the resolve_imports.py script.

Validates that the resolver correctly:
- Outputs context.md, playbook.md, checklist.md for valid signatures
- Extracts and resolves @import:name references from playbook body
- Handles missing imports gracefully (warning, not failure)
- Fails on missing signature directory
- Rejects path traversal attempts
- Produces correct end-to-end concatenated output
"""

import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = SOC_AGENT_ROOT / "scripts" / "resolve_imports.py"

sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))
from resolve_imports import extract_imports, resolve_import


def run_resolver(signature_id: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), signature_id],
        capture_output=True,
        text=True,
        cwd=str(SOC_AGENT_ROOT),
    )


@pytest.fixture(scope="module")
def wazuh_5710_result():
    """Run resolver once for wazuh-rule-5710, share across tests."""
    return run_resolver("wazuh-rule-5710")


@pytest.fixture(scope="module")
def wazuh_100001_result():
    """Run resolver once for wazuh-rule-100001 (signature with archetypes)."""
    return run_resolver("wazuh-rule-100001")


class TestResolverHappyPath:
    """Tests with the real wazuh-rule-5710 signature."""

    def test_exit_code_zero(self, wazuh_5710_result):
        assert wazuh_5710_result.returncode == 0, f"stderr: {wazuh_5710_result.stderr}"

    def test_contains_context(self, wazuh_5710_result):
        assert "<!-- source: knowledge/signatures/wazuh-rule-5710/context.md -->" in wazuh_5710_result.stdout
        assert "SSH Invalid User" in wazuh_5710_result.stdout

    def test_contains_playbook(self, wazuh_5710_result):
        assert "<!-- source: knowledge/signatures/wazuh-rule-5710/playbook.md -->" in wazuh_5710_result.stdout
        # New playbook shape: starter hypotheses replace the old "Hypothesis Catalog" section
        assert "Starter hypotheses" in wazuh_5710_result.stdout

    def test_contains_checklist(self, wazuh_5710_result):
        assert "<!-- source: knowledge/common-investigation/checklist.md -->" in wazuh_5710_result.stdout
        assert "Investigation Checklist" in wazuh_5710_result.stdout

    def test_output_order(self, wazuh_5710_result):
        """Context before playbook before checklist."""
        out = wazuh_5710_result.stdout
        ctx_pos = out.index("context.md -->")
        pb_pos = out.index("playbook.md -->")
        cl_pos = out.index("checklist.md -->")
        assert ctx_pos < pb_pos < cl_pos


class TestResolverImports:
    """Tests for @import:name resolution."""

    def test_no_imports_in_playbook(self, wazuh_5710_result):
        """wazuh-rule-5710 playbook has no @import: refs after migration."""
        out = wazuh_5710_result.stdout
        # No import source markers should appear after checklist
        assert "ip-classification.md -->" not in out
        assert "wazuh-queries.md -->" not in out


class TestResolverArchetypes:
    """Tests for archetype file inclusion (new model — wazuh-rule-100001)."""

    EXPECTED_ARCHETYPES = [
        "app-spawned-shell",
        "ci-pipeline-exec",
        "container-init-script",
        "k8s-exec-probe",
        "operator-runtime-debug",
        "post-exploit-interactive",
    ]

    def test_exit_code_zero(self, wazuh_100001_result):
        assert wazuh_100001_result.returncode == 0, (
            f"stderr: {wazuh_100001_result.stderr}"
        )

    def test_all_archetypes_present(self, wazuh_100001_result):
        """Every archetype file in archetypes/ must appear in resolver output."""
        out = wazuh_100001_result.stdout
        for name in self.EXPECTED_ARCHETYPES:
            marker = (
                f"<!-- source: knowledge/signatures/wazuh-rule-100001/"
                f"archetypes/{name}.md -->"
            )
            assert marker in out, f"Missing archetype marker: {name}"

    def test_archetype_content_present(self, wazuh_100001_result):
        """Archetype bodies (not just headers) must be in the output."""
        out = wazuh_100001_result.stdout
        # Story content from each archetype — distinct phrases
        assert "Operator Runtime Debug" in out
        assert "Post-Exploit Interactive Shell" in out
        assert "operator's session is bounded" in out
        assert "Application-Spawned Shell" in out
        assert "Container Init Script" in out
        assert "Kubernetes Exec Probe" in out
        assert "CI/CD Pipeline Exec" in out

    def test_archetypes_sorted_deterministic(self, wazuh_100001_result):
        """Archetype order is alphabetical (deterministic across runs)."""
        out = wazuh_100001_result.stdout
        positions = []
        for name in self.EXPECTED_ARCHETYPES:
            marker = f"archetypes/{name}.md -->"
            positions.append(out.index(marker))
        assert positions == sorted(positions), (
            "Archetypes are not in alphabetical order"
        )

    def test_archetypes_between_playbook_and_checklist(self, wazuh_100001_result):
        """Output order: context -> playbook -> archetypes -> checklist."""
        out = wazuh_100001_result.stdout
        ctx_pos = out.index("context.md -->")
        pb_pos = out.index("playbook.md -->")
        first_arch_pos = out.index("archetypes/app-spawned-shell.md -->")
        last_arch_pos = out.index("archetypes/post-exploit-interactive.md -->")
        cl_pos = out.index("checklist.md -->")
        assert ctx_pos < pb_pos < first_arch_pos < last_arch_pos < cl_pos

    def test_signature_without_archetypes_dir_still_works(self, tmp_path):
        """Signatures without an archetypes/ directory output as before.

        All real signatures now have an archetypes/ directory; use a synthetic
        signature to verify the legacy code path still works.
        """
        sig_dir = SOC_AGENT_ROOT / "knowledge" / "signatures" / "_test-legacy-shape"
        sig_dir.mkdir(exist_ok=True)
        try:
            (sig_dir / "context.md").write_text(
                "---\nsignature_id: _test-legacy-shape\nname: NoArchTest\n"
                "severity: low\ndata_sources: [test]\n---\n# NoArch Context\n"
            )
            (sig_dir / "playbook.md").write_text(
                "---\nsignature_id: _test-legacy-shape\nlast_updated: 2026-01-01\n"
                "total_investigations: 0\nresolution_rate: null\n---\n"
                "# NoArch Playbook\n\n### lead-1\nQuery something.\n"
            )

            result = run_resolver("_test-legacy-shape")
            assert result.returncode == 0, f"stderr: {result.stderr}"
            assert "archetypes/" not in result.stdout
        finally:
            import shutil
            shutil.rmtree(sig_dir, ignore_errors=True)


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

    def test_path_traversal_rejected(self):
        """Signature IDs with path traversal must be rejected."""
        result = run_resolver("../../.claude/settings")
        assert result.returncode == 1
        assert "traversal" in result.stderr.lower() or "not found" in result.stderr.lower()

    def test_path_traversal_with_existing_dir(self):
        """Even paths that resolve to existing dirs outside signatures/ must fail."""
        result = run_resolver("../common")
        assert result.returncode == 1


class TestExtractImports:
    """Unit tests for the import extraction logic."""

    def test_extract_imports(self):
        text = """
### source-reputation
See @import:ip-classification for classification rules.

### authentication-history
Query patterns: @import:wazuh-queries
"""
        imports = extract_imports(text)
        assert imports == ["ip-classification", "wazuh-queries"]

    def test_extract_deduplicates(self):
        text = "@import:foo and @import:bar and @import:foo again"
        imports = extract_imports(text)
        assert imports == ["foo", "bar"]

    def test_extract_empty(self):
        text = "No imports here."
        imports = extract_imports(text)
        assert imports == []

    def test_moved_import_no_longer_resolves(self):
        """ip-classification was moved to environment/context/, no longer importable."""
        path = resolve_import("ip-classification")
        assert path is None

    def test_resolve_import_missing(self):
        path = resolve_import("nonexistent-atom-xyz")
        assert path is None


class TestEndToEndResolve:
    """End-to-end tests verifying the full resolve pipeline produces correct output."""

    def test_output_contains_actual_file_contents(self, wazuh_5710_result):
        """Resolved output must contain actual content from each source file, not just headers."""
        out = wazuh_5710_result.stdout

        # context.md content
        assert "Invalid user" in out
        assert "data.srcip" in out

        # playbook.md content — starter hypothesis names + the lead name
        assert "?monitoring-probe" in out
        assert "authentication-history" in out
        # Archetype content (external-bruteforce replaced the ?brute-force story)
        assert "External Brute-Force" in out

        # checklist.md content
        assert "adversarial hypothesis" in out.lower()
        assert "Common Mistakes" in out

    def test_output_has_all_source_markers(self, wazuh_5710_result):
        """Each included file must have a source comment marker."""
        out = wazuh_5710_result.stdout
        expected_markers = [
            "knowledge/signatures/wazuh-rule-5710/context.md",
            "knowledge/signatures/wazuh-rule-5710/playbook.md",
            "knowledge/common-investigation/checklist.md",
        ]
        for marker in expected_markers:
            assert f"<!-- source: {marker} -->" in out, f"Missing source marker: {marker}"

    def test_output_is_valid_markdown(self, wazuh_5710_result):
        """Output should have markdown headers from each included file."""
        out = wazuh_5710_result.stdout
        # Each source file starts with a heading
        assert "# Wazuh Rule 5710" in out
        assert "# Investigation Playbook" in out
        assert "# Investigation Checklist" in out

    def test_synthetic_playbook_without_imports(self, tmp_path):
        """Create a minimal signature without @import refs and verify resolver output."""
        sig_dir = SOC_AGENT_ROOT / "knowledge" / "signatures" / "_test-synthetic"
        sig_dir.mkdir(exist_ok=True)

        try:
            (sig_dir / "context.md").write_text(
                "---\nsignature_id: _test-synthetic\nname: Test\nseverity: low\n"
                "data_sources: [test]\n---\n# Test Context\nSynthetic test signature.\n"
            )
            (sig_dir / "playbook.md").write_text(
                "---\nsignature_id: _test-synthetic\nlast_updated: 2026-01-01\n"
                "total_investigations: 0\nresolution_rate: null\n---\n"
                "# Test Playbook\n\n"
                "### lead-1\nQuery auth events.\n"
            )

            result = run_resolver("_test-synthetic")
            assert result.returncode == 0, f"stderr: {result.stderr}"

            out = result.stdout
            assert "# Test Context" in out
            assert "# Test Playbook" in out
            assert "# Investigation Checklist" in out

            # Verify correct ordering
            ctx_pos = out.index("Test Context")
            pb_pos = out.index("Test Playbook")
            cl_pos = out.index("Investigation Checklist")
            assert ctx_pos < pb_pos < cl_pos
        finally:
            import shutil
            shutil.rmtree(sig_dir, ignore_errors=True)

    def test_unresolvable_import_warns(self, tmp_path):
        """An @import that can't be resolved should produce a warning comment, not a failure."""
        sig_dir = SOC_AGENT_ROOT / "knowledge" / "signatures" / "_test-bad-import"
        sig_dir.mkdir(exist_ok=True)

        try:
            (sig_dir / "context.md").write_text(
                "---\nsignature_id: _test-bad-import\nname: Test\nseverity: low\n"
                "data_sources: [test]\n---\n# Test\n"
            )
            (sig_dir / "playbook.md").write_text(
                "---\nsignature_id: _test-bad-import\nlast_updated: 2026-01-01\n"
                "total_investigations: 0\nresolution_rate: null\n---\n"
                "# Playbook\nSee @import:nonexistent-atom-xyz\n"
            )

            result = run_resolver("_test-bad-import")
            assert result.returncode == 0  # Partial success, not failure
            assert "<!-- warning: @import:nonexistent-atom-xyz could not be resolved -->" in result.stdout
        finally:
            import shutil
            shutil.rmtree(sig_dir, ignore_errors=True)
