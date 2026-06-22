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

# The workspace root is on sys.path via `pythonpath = [".."]` in pyproject.toml's
# [tool.pytest.ini_options], so `defender.*` namespace imports resolve. Note that
# learning/ is intentionally NOT on the path: a bare `import author` must fail
# loudly so a missed migration surfaces instead of silently creating a second
# module object (defender.learning.author vs author) that monkeypatch misses.


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
        "_author_shared.py",
        "_author_runner.py",
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
        "defender/learning/_pending/\n"
        "defender/learning/_author.lock\n"
        "defender/learning/runs/\n"
    )

    run_git("init", "-q", "-b", "main")
    run_git("config", "user.email", "test@example.com")
    run_git("config", "user.name", "Test")
    run_git("add", "-A")
    run_git("commit", "-q", "-m", "init")

    from defender.learning import _author_shared as shared_mod  # type: ignore[import-not-found]
    from defender.learning import author as author_mod  # type: ignore[import-not-found]
    from defender.learning._loop_config import LoopPaths  # type: ignore[import-not-found]

    # No importlib.reload: every module binds `AuthorError = _shared.AuthorError` once
    # at import and never rebinds, so a single stable class object lives for the whole
    # session and `except shared.AuthorError` can't diverge. Tests reference
    # ``shared.AuthorError`` live (never a collection-time alias).
    #
    # `_author_shared`'s git layer takes ``repo_root`` by param everywhere; only its
    # generation counters + repo-lock still read module globals, so point that one
    # residual seam at the tmp tree. Everything else flows through the injected
    # ``LoopPaths`` / ``AuthorConfig`` (``ctx.paths`` / ``ctx.cfg``) below.
    monkeypatch.setattr(shared_mod, "REPO_ROOT", repo)
    monkeypatch.setattr(shared_mod, "LEARNING_DIR", repo / "defender" / "learning")
    monkeypatch.setattr(
        shared_mod, "REPO_LOCK_FILE", repo / "defender" / "learning" / "_author.lock"
    )

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
    # Mirror loop.append_actor_observations' row layout — every real finding
    # carries `direction` (after `alert_rule_key`); the author gate reads it
    # fail-loud, so the fixture must too.
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
