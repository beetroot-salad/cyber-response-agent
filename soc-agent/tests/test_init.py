"""Tests for scripts/init.sh — git init, gitignore, directory scaffold, idempotence.

init.sh runs from the soc-agent root. To test it hermetically we copy it into
a scratch directory that impersonates a fresh plugin checkout, invoke it
there, and inspect the result. We do NOT run init.sh against the real repo.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
REAL_INIT = SOC_AGENT_ROOT / "scripts" / "init.sh"


@pytest.fixture
def fake_workspace(tmp_path):
    """A scratch directory with scripts/init.sh copied in at the right path.

    Mirrors the layout init.sh expects: {root}/scripts/init.sh, and init.sh
    derives SOC_AGENT_DIR as `$(dirname $0)/..`.
    """
    root = tmp_path / "workspace"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    target = scripts / "init.sh"
    shutil.copy2(REAL_INIT, target)
    target.chmod(target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return root


def run_init(workspace: Path) -> subprocess.CompletedProcess:
    """Invoke init.sh inside `workspace`. Returns the CompletedProcess."""
    return subprocess.run(
        ["bash", str(workspace / "scripts" / "init.sh")],
        capture_output=True,
        text=True,
        cwd=str(workspace),
        env={**os.environ, "HOME": str(workspace)},  # keep git config isolated
    )


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


class TestInitScaffold:
    def test_exits_zero_on_fresh_workspace(self, fake_workspace):
        result = run_init(fake_workspace)
        assert result.returncode == 0, result.stderr

    def test_creates_git_repo(self, fake_workspace):
        run_init(fake_workspace)
        assert (fake_workspace / ".git").is_dir()

    def test_creates_expected_directories(self, fake_workspace):
        run_init(fake_workspace)
        for rel in [
            "knowledge/environment/context",
            "knowledge/environment/data-sources",
            "knowledge/environment/operations",
            "knowledge/environment/systems",
            "scripts/tools",
            "runs",
        ]:
            d = fake_workspace / rel
            assert d.is_dir(), f"expected directory {rel} to exist"
            # .gitkeep marker so git tracks the empty dir.
            assert (d / ".gitkeep").exists(), f"expected .gitkeep in {rel}"

    def test_writes_expected_gitignore_entries(self, fake_workspace):
        run_init(fake_workspace)
        gitignore = (fake_workspace / ".gitignore").read_text().splitlines()
        for entry in [
            "runs/",
            ".env",
            "__pycache__/",
            ".venv/",
            "*.pyc",
            "knowledge/environment/systems/*/config.env",
        ]:
            assert entry in gitignore, f"missing {entry} in .gitignore"

    def test_prints_next_steps(self, fake_workspace):
        result = run_init(fake_workspace)
        assert "/connect" in result.stdout
        assert "preflight" in result.stdout


# ---------------------------------------------------------------------------
# Idempotence
# ---------------------------------------------------------------------------


class TestInitIdempotence:
    def test_second_run_is_clean(self, fake_workspace):
        first = run_init(fake_workspace)
        assert first.returncode == 0
        second = run_init(fake_workspace)
        assert second.returncode == 0, second.stderr

    def test_second_run_does_not_reinit_git(self, fake_workspace):
        run_init(fake_workspace)
        # Sentinel: touch a file in .git and verify it survives.
        sentinel = fake_workspace / ".git" / "SENTINEL"
        sentinel.write_text("keep me")
        run_init(fake_workspace)
        assert sentinel.exists(), ".git was reinitialized — init is not idempotent"

    def test_second_run_does_not_duplicate_gitignore_entries(self, fake_workspace):
        run_init(fake_workspace)
        run_init(fake_workspace)
        entries = (fake_workspace / ".gitignore").read_text().splitlines()
        # Each pattern should appear exactly once.
        for entry in [
            "runs/",
            ".env",
            "__pycache__/",
            ".venv/",
            "*.pyc",
            "knowledge/environment/systems/*/config.env",
        ]:
            assert entries.count(entry) == 1, f"{entry} duplicated in .gitignore"

    def test_preserves_user_added_gitignore_entries(self, fake_workspace):
        run_init(fake_workspace)
        gitignore = fake_workspace / ".gitignore"
        gitignore.write_text(gitignore.read_text() + "my-secret-dir/\n")
        run_init(fake_workspace)
        assert "my-secret-dir/" in gitignore.read_text()


# ---------------------------------------------------------------------------
# Existing-repo behavior
# ---------------------------------------------------------------------------


class TestInitExistingRepo:
    def test_respects_existing_git_repo(self, fake_workspace):
        """If the target is already a git repo, init.sh must not reinit."""
        subprocess.run(
            ["git", "init", "-q"],
            cwd=str(fake_workspace),
            check=True,
            env={**os.environ, "HOME": str(fake_workspace)},
        )
        marker = fake_workspace / ".git" / "MARKER"
        marker.write_text("preexisting")
        result = run_init(fake_workspace)
        assert result.returncode == 0
        assert marker.exists()
        assert "skipping git init" in result.stdout

    def test_leaves_preexisting_directories_alone(self, fake_workspace):
        """init.sh must not wipe .gitkeep-less directories the user already has."""
        existing = fake_workspace / "scripts" / "tools"
        existing.mkdir(parents=True)
        user_file = existing / "splunk_cli.py"
        user_file.write_text("# user adapter\n")
        run_init(fake_workspace)
        assert user_file.exists()
        assert user_file.read_text() == "# user adapter\n"
        # No .gitkeep added to an already-populated directory.
        assert not (existing / ".gitkeep").exists()
