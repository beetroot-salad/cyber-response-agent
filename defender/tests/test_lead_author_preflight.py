"""Lead-author pre-flight: lock + clean-scope + idempotency."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import yaml

from defender.learning import lead_author


def _setup_catalog_repo(tmp_repo) -> None:
    """Seed the tmp repo with a minimal catalog so clean-scope passes.

    The base ``tmp_repo`` fixture creates ``defender/lessons/``; lead-author
    cares about ``defender/skills/gather/queries/``.
    """
    repo = tmp_repo.root
    catalog = repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\ng\n"
    )
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", "seed catalog")


def _rebind_paths(monkeypatch, tmp_repo) -> None:
    """Point lead_author's module globals at the tmp tree."""
    repo = tmp_repo.root
    learning = repo / "defender" / "learning"
    catalog = repo / "defender" / "skills" / "gather" / "queries"
    pending = learning / "_pending_leads"
    monkeypatch.setattr(lead_author, "REPO_ROOT", repo)
    monkeypatch.setattr(lead_author, "LEARNING_DIR", learning)
    monkeypatch.setattr(lead_author, "CATALOG_DIR", catalog)
    monkeypatch.setattr(lead_author, "PENDING_DIR", pending)
    monkeypatch.setattr(lead_author, "LOCK_FILE", pending / ".lock")
    monkeypatch.setattr(
        lead_author, "LEAD_AUTHOR_PROMPT", learning / "lead_author.md"
    )


# ---------------------------------------------------------------------------
# Lock
# ---------------------------------------------------------------------------


def test_lock_blocks_second_acquirer(tmp_repo, monkeypatch):
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)

    fh1 = lead_author.acquire_lock()
    assert fh1 is not None
    try:
        fh2 = lead_author.acquire_lock()
        assert fh2 is None
    finally:
        lead_author.release_lock(fh1)

    # After release, the lock is acquirable again.
    fh3 = lead_author.acquire_lock()
    assert fh3 is not None
    lead_author.release_lock(fh3)


# ---------------------------------------------------------------------------
# Clean-scope
# ---------------------------------------------------------------------------


def test_clean_catalog_passes(tmp_repo, monkeypatch):
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)

    # No untracked or modified files under the catalog — pre-flight passes.
    lead_author.assert_catalog_clean()


def test_modified_catalog_file_refused(tmp_repo, monkeypatch):
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)
    # Mutate a tracked template — should be flagged.
    tpl = (
        tmp_repo.root
        / "defender"
        / "skills"
        / "gather"
        / "queries"
        / "wazuh"
        / "auth-events.md"
    )
    tpl.write_text(tpl.read_text() + "\nextra\n")

    with pytest.raises(lead_author.LeadAuthorError, match="uncommitted"):
        lead_author.assert_catalog_clean()


def test_untracked_catalog_file_refused(tmp_repo, monkeypatch):
    """Bare ``git diff --quiet`` would miss this — porcelain catches it."""
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)
    catalog = (
        tmp_repo.root / "defender" / "skills" / "gather" / "queries" / "wazuh"
    )
    (catalog / "rogue.md").write_text("---\nid: wazuh.rogue\n---\n\n## Goal\n\ng\n")

    with pytest.raises(lead_author.LeadAuthorError, match="uncommitted or untracked"):
        lead_author.assert_catalog_clean()


# ---------------------------------------------------------------------------
# Idempotency sentinel
# ---------------------------------------------------------------------------


def test_done_sentinel_blocks_re_run(tmp_repo, monkeypatch, tmp_path):
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)
    run_dir = tmp_path / "case"
    run_dir.mkdir()
    (run_dir / "lead_author").mkdir()
    (run_dir / "lead_author" / "done").write_text("2026-05-15T00:00:00+00:00")

    with pytest.raises(lead_author.LeadAuthorError, match="already processed"):
        lead_author.assert_run_not_done(run_dir)


# ---------------------------------------------------------------------------
# base_sha capture
# ---------------------------------------------------------------------------


def test_git_head_sha_returns_full_sha(tmp_repo, monkeypatch):
    _setup_catalog_repo(tmp_repo)
    _rebind_paths(monkeypatch, tmp_repo)
    sha = lead_author.git_head_sha()
    assert len(sha) == 40
    # Verify it agrees with git directly.
    direct = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_repo.root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert sha == direct
