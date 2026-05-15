"""Lead-author post-flight: HEAD invariants + scope + executed_leads validation."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.learning import lead_author


def _setup(tmp_repo, monkeypatch) -> tuple[Path, Path]:
    """Seed catalog + rebind paths. Return (repo, catalog/wazuh)."""
    repo = tmp_repo.root
    catalog = repo / "defender" / "skills" / "gather" / "queries" / "wazuh"
    catalog.mkdir(parents=True)
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\ng\n"
    )
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", "seed")

    learning = repo / "defender" / "learning"
    cat_root = catalog.parent
    monkeypatch.setattr(lead_author, "REPO_ROOT", repo)
    monkeypatch.setattr(lead_author, "LEARNING_DIR", learning)
    monkeypatch.setattr(lead_author, "CATALOG_DIR", cat_root)
    pending = learning / "_pending_leads"
    monkeypatch.setattr(lead_author, "PENDING_DIR", pending)
    monkeypatch.setattr(lead_author, "LOCK_FILE", pending / ".lock")
    return repo, catalog


def _commit(tmp_repo, message: str = "lead-author edit") -> str:
    tmp_repo.run_git("add", "-A")
    tmp_repo.run_git("commit", "-q", "-m", message)
    return tmp_repo.run_git("rev-parse", "HEAD").stdout.strip()


# ---------------------------------------------------------------------------
# No-op branch
# ---------------------------------------------------------------------------


def test_no_op_with_empty_actions_passes(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": [
            {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
        ],
    }
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
    ]
    verified = lead_author.verify_agent_result(
        result, base_sha=base, expected_executed=expected
    )
    assert verified["commit_sha"] is None
    assert verified["executed_leads"] == expected


def test_no_op_but_head_advanced_rejected(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    # Sneak in a commit while the agent supposedly did nothing.
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedited\n"
    )
    _commit(tmp_repo)

    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="HEAD advanced"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


def test_actions_without_commit_sha_rejected(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    result = {
        "commit_sha": None,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="non-empty commit_sha"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


def test_actions_without_pass_verdict_rejected(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedited\n"
    )
    sha = _commit(tmp_repo)
    result = {
        "commit_sha": sha,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "fail",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="tier1_verdict='pass'"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


# ---------------------------------------------------------------------------
# Commit branch — HEAD invariants
# ---------------------------------------------------------------------------


def test_single_commit_with_parent_at_base_passes(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedited\n"
    )
    sha = _commit(tmp_repo)
    result = {
        "commit_sha": sha,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [
            {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
        ],
    }
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
    ]
    verified = lead_author.verify_agent_result(
        result, base_sha=base, expected_executed=expected
    )
    assert verified["commit_sha"] == sha


def test_multi_commit_history_rejected(tmp_repo, monkeypatch):
    """Two commits since base_sha must be rejected — parent != base_sha."""
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedit 1\n"
    )
    _commit(tmp_repo, "edit 1")
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedit 2\n"
    )
    sha = _commit(tmp_repo, "edit 2")

    result = {
        "commit_sha": sha,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="multi-commit"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


def test_commit_outside_catalog_rejected(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    # Edit a file outside the catalog.
    (repo / "defender" / "lessons" / "rogue.md").write_text(
        "---\nname: rogue\n---\n\nbody\n"
    )
    sha = _commit(tmp_repo, "rogue edit")

    result = {
        "commit_sha": sha,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="outside"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


def test_short_commit_sha_is_canonicalized(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nedited\n"
    )
    sha = _commit(tmp_repo)
    short = sha[:8]
    result = {
        "commit_sha": short,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [
            {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
        ],
    }
    verified = lead_author.verify_agent_result(
        result,
        base_sha=base,
        expected_executed=[
            {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"}
        ],
    )
    assert verified["commit_sha"] == sha


def test_invalid_commit_sha_rejected(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    # Non-hex garbage — git rev-parse --verify rejects it outright.
    result = {
        "commit_sha": "not-a-sha-at-all",
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="rev-parse rejects"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


# ---------------------------------------------------------------------------
# Catalog cleanliness post-flight
# ---------------------------------------------------------------------------


def test_unstaged_edit_after_commit_rejected(tmp_repo, monkeypatch):
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\ncommitted\n"
    )
    sha = _commit(tmp_repo)
    # Leave an unstaged extra edit behind.
    (catalog / "auth-events.md").write_text(
        "---\nid: wazuh.auth-events\n---\n\n## Goal\n\nextra dirty\n"
    )

    result = {
        "commit_sha": sha,
        "actions": [{"kind": "fold", "template_id": "wazuh.auth-events"}],
        "tier1_verdict": "pass",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="uncommitted edits"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


def test_unstaged_file_after_noop_rejected(tmp_repo, monkeypatch):
    """Even on the no-op branch, leftover dirt fails."""
    repo, catalog = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    (catalog / "rogue.md").write_text(
        "---\nid: wazuh.rogue\n---\n\n## Goal\n\nrogue\n"
    )
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": [],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="uncommitted edits"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=[]
        )


# ---------------------------------------------------------------------------
# executed_leads cross-check
# ---------------------------------------------------------------------------


def test_executed_leads_matching_set_passes_regardless_of_order(
    tmp_repo, monkeypatch
):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"},
        {"position": 1, "query_index": 0, "query_id": "wazuh.sudo-commands"},
    ]
    # Agent returns them in reverse order — must still pass.
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": list(reversed(expected)),
    }
    verified = lead_author.verify_agent_result(
        result, base_sha=base, expected_executed=expected
    )
    # Driver overwrites with its canonical ordering.
    assert verified["executed_leads"] == expected


def test_executed_leads_missing_position_fails(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"},
        {"position": 1, "query_index": 0, "query_id": "wazuh.sudo-commands"},
    ]
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": expected[:1],  # missing position=1
    }
    with pytest.raises(lead_author.LeadAuthorError, match="disagree"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=expected
        )


def test_executed_leads_extra_position_fails(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"},
    ]
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": expected
        + [
            {"position": 99, "query_index": 0, "query_id": "wazuh.fake"},
        ],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="disagree"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=expected
        )


def test_executed_leads_wrong_query_id_fails(tmp_repo, monkeypatch):
    repo, _ = _setup(tmp_repo, monkeypatch)
    base = lead_author.git_head_sha()
    expected = [
        {"position": 0, "query_index": 0, "query_id": "wazuh.auth-events"},
    ]
    result = {
        "commit_sha": None,
        "actions": [],
        "tier1_verdict": "not_run",
        "executed_leads": [
            {"position": 0, "query_index": 0, "query_id": "wazuh.sudo-commands"},
        ],
    }
    with pytest.raises(lead_author.LeadAuthorError, match="disagree"):
        lead_author.verify_agent_result(
            result, base_sha=base, expected_executed=expected
        )
