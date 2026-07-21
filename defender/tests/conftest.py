"""Shared fixtures for defender learning-loop tests.

Each test gets an isolated tmp git repo with the ``defender/learning/`` source
files copied in. The fixture builds one ``LoopPaths(repo_root=tmp)`` and an
``AuthorConfig`` from it (``ctx.paths`` / ``ctx.cfg``); tests thread those into
``author.run_batch(paths=…, cfg=…)`` and inject a fake curator via
``dataclasses.replace(cfg, invoke_agent=fake)`` — no module-global setattr, no
``importlib.reload``.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"



@pytest.fixture
def tmp_repo(tmp_path: Path):
    """Build an isolated git repo with the learning module mounted in.

    Returns a namespace with ``root`` (tmp repo path), ``author``
    (the imported author module rebound to tmp paths), and ``run_git``
    (helper to run git inside the tmp repo).
    """
    repo = tmp_path / "repo"
    (repo / "defender" / "learning").mkdir(parents=True)
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / ".gitkeep").write_text("")

    for rel in (
        "author/lessons/run.py",
        "author/lessons/prompt.md",
        "author/shared.py",
        "author/verify_forward/forward.py",
        "author/verify_forward/forward.md",
    ):
        dst = repo / "defender" / "learning" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(LEARNING_SRC / rel, dst)

    def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            check=check,
        )

    (repo / ".gitignore").write_text(
        "defender/learning/_pending/\n"
        "defender/learning/_author.lock\n"
        "defender/learning/runs/\n"
    )

    run_git("init", "-q", "-b", "main")
    run_git("config", "user.email", "test@example.com")
    run_git("config", "user.name", "Test")
    run_git("add", "-A")
    run_git("commit", "-q", "-m", "init")

    from defender.learning.author.lessons import run as author_mod  # type: ignore[import-not-found]
    from defender.learning.core.config import LoopPaths  # type: ignore[import-not-found]

    paths = LoopPaths(repo_root=repo)
    cfg = author_mod.build_author_config(paths)

    class Ctx:
        def __init__(self) -> None:
            self.root = repo
            self.author = author_mod
            self.paths = paths
            self.cfg = cfg
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
    direction: str = "adversarial",
) -> dict:
    pending_file.parent.mkdir(parents=True, exist_ok=True)
    import json
    entry = {
        "schema_version": 1,
        "finding_id": finding_id,
        "run_id": run_id,
        "alert_rule_key": "rule-5710",
        "direction": direction,
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
