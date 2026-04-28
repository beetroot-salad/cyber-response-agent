"""Integration tests for `scripts.postmortem.leads.run`.

Drives `main()` against a tmpdir-init'd git repo with a fake run dir,
stubbing the agent spawn and the push+PR step. No network. No LLM.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.postmortem.leads import run as run_module


def _init_repo(repo_root: Path) -> None:
    soc_root = repo_root / "soc-agent"
    soc_root.mkdir()
    (soc_root / "knowledge").mkdir()
    leads_dir = soc_root / "knowledge" / "common-investigation" / "leads"
    leads_dir.mkdir(parents=True)
    # Catalog seed — one templated lead so we can exercise the
    # template-missing branch in extraction.
    auth = leads_dir / "authentication-history"
    auth.mkdir()
    (auth / "definition.md").write_text(
        "---\nname: authentication-history\ndata_tags: [auth-events]\n"
        "baseline: required\n---\n"
    )
    (auth / "templates").mkdir()
    (auth / "templates" / "wazuh.md").write_text("# wazuh template\n")

    subprocess.run(["git", "init", "-q", "-b", "main", str(repo_root)], check=True)
    for kv in (("user.email", "test@example.com"), ("user.name", "Test")):
        subprocess.run(
            ["git", "-C", str(repo_root), "config", *kv], check=True
        )
    subprocess.run(
        ["git", "-C", str(repo_root), "add", "-A"], check=True
    )
    subprocess.run(
        ["git", "-C", str(repo_root), "commit", "-q", "-m", "seed"], check=True
    )


def _materialize_run_dir(repo_root: Path, fixture_path: Path) -> Path:
    run_dir = repo_root.parent / "run"
    run_dir.mkdir()
    (run_dir / "investigation.md").write_text(fixture_path.read_text())
    (run_dir / "meta.json").write_text(
        json.dumps({"signature_id": "wazuh-rule-100001", "salt": "x"})
    )
    return run_dir


@pytest.fixture
def repo_with_run(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Returns `(repo_root, run_dir, out_dir)`."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _init_repo(repo_root)
    fixtures = (
        Path(__file__).parent / "fixtures" / "postmortem_leads"
    )
    run_dir = _materialize_run_dir(repo_root, fixtures / "inv_with_adhoc.md")
    out_dir = tmp_path / "out"
    return repo_root, run_dir, out_dir


def _argv(repo_root: Path, run_dir: Path, out_dir: Path) -> list[str]:
    return [
        "--run-dir", str(run_dir),
        "--out-dir", str(out_dir),
        "--repo-root", str(repo_root),
    ]


def _stub_agent_commit(prompt_seen: list[str]):
    """Returns a `_spawn_agent` replacement that synthesizes a real
    commit in the worktree (so `_has_new_commit` returns True) and
    captures the prompt for assertions."""

    def stub(worktree_path: Path, prompt: str) -> int:
        prompt_seen.append(prompt)
        # Touch a file in the worktree, stage and commit so HEAD advances.
        marker = worktree_path / "AGENT_RAN"
        marker.write_text("ok\n")
        subprocess.run(
            ["git", "-C", str(worktree_path), "add", "AGENT_RAN"], check=True
        )
        subprocess.run(
            ["git", "-C", str(worktree_path), "commit", "-q", "-m", "agent edits"],
            check=True,
        )
        return 0

    return stub


def _stub_agent_no_commit():
    def stub(worktree_path: Path, prompt: str) -> int:
        return 1
    return stub


def _stub_push_and_pr(captured: list[dict[str, Any]]):
    def stub(worktree_path: Path, branch_name: str, base_branch: str) -> str:
        captured.append({
            "worktree": str(worktree_path),
            "branch": branch_name,
            "base": base_branch,
        })
        return f"https://example.invalid/pr/1?branch={branch_name}"
    return stub


class TestEndToEnd:
    def test_success_path(
        self,
        repo_with_run: tuple[Path, Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo_root, run_dir, out_dir = repo_with_run
        prompts: list[str] = []
        prs: list[dict[str, Any]] = []
        monkeypatch.setattr(run_module, "_spawn_agent", _stub_agent_commit(prompts))
        monkeypatch.setattr(run_module, "_push_and_pr", _stub_push_and_pr(prs))

        rc = run_module.main(_argv(repo_root, run_dir, out_dir))
        assert rc == 0

        status = json.loads((out_dir / "status.json").read_text())
        assert status["status"] == "ok"
        assert status["branch"] == f"postmortem-leads/{run_dir.name}"
        assert status["worktree"] == str(out_dir / "worktree")
        assert status["pr_url"].startswith("https://example.invalid/pr/")
        assert len(status["leads"]) == 3
        # `failed` marker must not appear on success
        assert not (out_dir / "failed").exists()
        # Worktree must remain in place (recovery requirement)
        assert (out_dir / "worktree").is_dir()
        # PR was attempted with the right args
        assert prs == [{
            "worktree": str(out_dir / "worktree"),
            "branch": f"postmortem-leads/{run_dir.name}",
            "base": "main",
        }]
        # Prompt got rendered with the leads
        assert "correlated-falco-events" in prompts[0]
        assert "selection_rationale" in prompts[0]

    def test_no_findings_skips(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo_root = tmp_path / "repo"
        repo_root.mkdir()
        _init_repo(repo_root)
        fixtures = Path(__file__).parent / "fixtures" / "postmortem_leads"
        run_dir = _materialize_run_dir(repo_root, fixtures / "inv_no_adhoc.md")
        out_dir = tmp_path / "out"

        # Set signature_id to something whose template ships, so the
        # no-adhoc fixture really yields zero ad-hoc findings.
        (run_dir / "meta.json").write_text(
            json.dumps({"signature_id": "wazuh-rule-5710", "salt": "x"})
        )

        called = []
        monkeypatch.setattr(
            run_module, "_spawn_agent",
            lambda *a, **kw: called.append("spawn") or 0,
        )
        monkeypatch.setattr(
            run_module, "_push_and_pr",
            lambda *a, **kw: called.append("pr") or "url",
        )
        rc = run_module.main(_argv(repo_root, run_dir, out_dir))
        assert rc == 0
        assert called == []  # neither agent nor PR was invoked
        status = json.loads((out_dir / "status.json").read_text())
        assert status["status"] == "skipped"

    def test_agent_no_commit_fails_loud(
        self,
        repo_with_run: tuple[Path, Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo_root, run_dir, out_dir = repo_with_run
        monkeypatch.setattr(run_module, "_spawn_agent", _stub_agent_no_commit())
        push_called = []
        monkeypatch.setattr(
            run_module, "_push_and_pr",
            lambda *a, **kw: push_called.append("pr") or "url",
        )

        rc = run_module.main(_argv(repo_root, run_dir, out_dir))
        assert rc == 1
        assert (out_dir / "failed").exists()
        assert "agent did not produce a commit" in (out_dir / "failed").read_text()
        assert not (out_dir / "status.json").exists()
        assert push_called == []

    def test_branch_collision_fails_loud(
        self,
        repo_with_run: tuple[Path, Path, Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        repo_root, run_dir, out_dir = repo_with_run
        # Pre-create the collision branch
        subprocess.run(
            ["git", "-C", str(repo_root), "branch",
             f"postmortem-leads/{run_dir.name}"],
            check=True,
        )
        monkeypatch.setattr(run_module, "_spawn_agent", _stub_agent_commit([]))

        rc = run_module.main(_argv(repo_root, run_dir, out_dir))
        assert rc == 1
        assert (out_dir / "failed").exists()
        assert "worktree create failed" in (out_dir / "failed").read_text()
