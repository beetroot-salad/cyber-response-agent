"""Shared fixtures for defender learning-loop tests.

Each test gets an isolated tmp git repo with the
``defender/learning/`` source files copied in. Tests then monkeypatch
``author.REPO_ROOT`` (and friends) to point at the tmp tree, plus
``author.invoke_agent`` to a stub that plays the role of the curator
without spawning ``claude``.
"""
from __future__ import annotations

import importlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"

sys.path.insert(0, str(LEARNING_SRC))


@pytest.fixture
def tmp_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Build an isolated git repo with the learning module mounted in.

    Returns a namespace with ``root`` (tmp repo path), ``author``
    (the imported author module rebound to tmp paths), and ``run_git``
    (helper to run git inside the tmp repo).
    """
    repo = tmp_path / "repo"
    (repo / "defender" / "learning").mkdir(parents=True)
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / ".gitkeep").write_text("")

    # Copy learning module so author.py / verify_forward.py / *.md exist
    # at the same relative paths as in the real repo.
    for name in (
        "author.py",
        "author.md",
        "verify_forward.py",
        "verify_forward.md",
    ):
        shutil.copy2(LEARNING_SRC / name, repo / "defender" / "learning" / name)

    def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            check=check,
        )

    # Mirror the real repo's gitignore so transient state under
    # _pending/ and runs/ doesn't sneak into git add -A.
    (repo / ".gitignore").write_text(
        "defender/learning/_pending/\ndefender/learning/runs/\n"
    )

    run_git("init", "-q", "-b", "main")
    run_git("config", "user.email", "test@example.com")
    run_git("config", "user.name", "Test")
    run_git("add", "-A")
    run_git("commit", "-q", "-m", "init")

    # Re-import author with REPO_ROOT pointed at the tmp tree.
    import author as author_mod  # type: ignore[import-not-found]

    importlib.reload(author_mod)
    monkeypatch.setattr(author_mod, "REPO_ROOT", repo)
    monkeypatch.setattr(author_mod, "LEARNING_DIR", repo / "defender" / "learning")
    monkeypatch.setattr(author_mod, "LESSONS_DIR", repo / "defender" / "lessons")
    monkeypatch.setattr(author_mod, "RUNS_DIR", repo / "defender" / "learning" / "runs")
    monkeypatch.setattr(author_mod, "PENDING_DIR", repo / "defender" / "learning" / "_pending")
    monkeypatch.setattr(
        author_mod,
        "PENDING_FILE",
        repo / "defender" / "learning" / "_pending" / "findings.jsonl",
    )
    monkeypatch.setattr(
        author_mod,
        "CONSUMED_FILE",
        repo / "defender" / "learning" / "_pending" / "consumed.jsonl",
    )
    monkeypatch.setattr(
        author_mod,
        "LOCK_FILE",
        repo / "defender" / "learning" / "_pending" / ".lock",
    )
    monkeypatch.setattr(
        author_mod,
        "HELD_REPORT",
        repo / "defender" / "learning" / "_pending" / "held_report.log",
    )

    class Ctx:
        def __init__(self) -> None:
            self.root = repo
            self.author = author_mod
            self.run_git = run_git

    return Ctx()


def write_finding(
    pending_file: Path,
    *,
    finding_id: str,
    run_id: str,
    type_: str = "lead-set",
    subject: str = "subj",
    finding: str = "narrative",
) -> dict:
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    import json
    entry = {
        "schema_version": 1,
        "finding_id": finding_id,
        "run_id": run_id,
        "alert_rule_key": "rule-5710",
        "type": type_,
        "subject": subject,
        "finding": finding,
        "judge_outcome": "survived",
        "citations": [{"source": "investigation", "quote": "..."}],
        "source_run_dir": f"defender/learning/runs/{run_id}/",
    }
    with pending_file.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")
    return entry


def write_source_refs(runs_dir: Path, run_id: str, disposition: str) -> None:
    import yaml
    rd = runs_dir / run_id
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "investigation.md").write_text("transcript stub")
    (rd / "source_refs.yaml").write_text(
        yaml.safe_dump(
            {
                "paths": {},
                "normalized_disposition": disposition,
                "alert_rule_key": "rule-5710",
            }
        )
    )


@pytest.fixture
def helpers():
    class H:
        write_finding = staticmethod(write_finding)
        write_source_refs = staticmethod(write_source_refs)
    return H()
