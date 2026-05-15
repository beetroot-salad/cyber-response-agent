"""Shared fixtures for defender learning-loop tests.

Each test gets an isolated tmp git repo with the ``defender/learning/``
source files copied in. Tests then monkeypatch
``author.REPO_ROOT`` (and friends) to point at the tmp tree, plus
``author.invoke_agent`` to a stub that plays the role of the curator
without spawning ``claude``.

Layout notes
------------
* The real workspace root (``REAL_REPO``, two parents up from this
  file) is inserted on ``sys.path`` so absolute imports of the form
  ``from defender.learning import _agent_stream`` resolve. This
  replaces the v0 conftest's ``LEARNING_SRC`` insertion, which only
  worked for top-level ``import author``.
* The ``tmp_repo`` fixture prepends the tmp repo onto ``sys.path``,
  purges any cached ``defender*`` modules so the import machinery
  picks up the tmp tree's copies, imports ``defender.learning.author``
  fresh, and restores sys.path / sys.modules on teardown so test
  ordering doesn't bleed.
* As each PR introduces a new ``defender/learning/`` module, the
  copy list grows below. Every script the tests ``import`` or
  subprocess-invoke must be present in tmp_repo or those tests fail
  with ``ModuleNotFoundError`` / ``FileNotFoundError`` at runtime.
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

# Make the workspace root importable so ``from defender.learning import X``
# resolves against the real source tree. Tests that need the tmp tree
# instead use the ``tmp_repo`` fixture, which prepends its own path.
if str(REAL_REPO) not in sys.path:
    sys.path.insert(0, str(REAL_REPO))


# Files copied into each tmp_repo's defender/learning/. Grows across PRs.
LEARNING_FILES = (
    "__init__.py",
    "_agent_stream.py",
    "author.py",
    "author.md",
    "verify_forward.py",
    "verify_forward.md",
)


def _purge_defender_modules() -> None:
    """Drop cached ``defender*`` modules so the next import picks up the
    leading sys.path entry (the tmp repo, or the real repo on teardown)."""
    for name in list(sys.modules):
        if name == "defender" or name.startswith("defender."):
            del sys.modules[name]


@pytest.fixture
def tmp_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Build an isolated git repo with the learning module mounted in.

    Returns a namespace with ``root`` (tmp repo path), ``author``
    (the imported author module rebound to tmp paths), and ``run_git``
    (helper to run git inside the tmp repo).
    """
    repo = tmp_path / "repo"
    learning_dir = repo / "defender" / "learning"
    learning_dir.mkdir(parents=True)
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / ".gitkeep").write_text("")
    # Package marker for defender/ itself.
    (repo / "defender" / "__init__.py").write_text("")

    # Copy learning module so author.py / verify_forward.py / *.md exist
    # at the same relative paths as in the real repo.
    for name in LEARNING_FILES:
        shutil.copy2(LEARNING_SRC / name, learning_dir / name)

    def run_git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            check=check,
        )

    # Mirror the real repo's gitignore so transient state under
    # _pending/ and runs/ doesn't sneak into git add -A. ``__pycache__``
    # also has to be ignored because importing ``defender.learning.X``
    # as a package writes ``.pyc`` files alongside the source — without
    # this, ``git add -A`` in the test agent's commit picks them up and
    # ``head_changed_only_lessons`` flags the commit as out-of-scope.
    (repo / ".gitignore").write_text(
        "defender/learning/_pending/\n"
        "defender/learning/runs/\n"
        "__pycache__/\n"
    )

    run_git("init", "-q", "-b", "main")
    run_git("config", "user.email", "test@example.com")
    run_git("config", "user.name", "Test")
    # Disable commit signing in test repos — environments that configure
    # a global signing tool (devcontainers, signed-commit policies) would
    # otherwise fail the test setup commit.
    run_git("config", "commit.gpgsign", "false")
    run_git("add", "-A")
    run_git("commit", "-q", "-m", "init")

    # Re-import author against the tmp tree. We prepend the tmp repo to
    # sys.path, purge cached defender* modules, then import fresh — the
    # default sys.path search will hit the tmp copy first. Teardown
    # restores the original sys.path and sys.modules state so tests
    # don't bleed into each other.
    orig_path = list(sys.path)
    orig_modules = dict(sys.modules)
    sys.path.insert(0, str(repo))
    _purge_defender_modules()
    from defender.learning import author as author_mod  # type: ignore[import-not-found]

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

    try:
        yield Ctx()
    finally:
        # Restore sys.path/sys.modules so the next test re-imports
        # against its own tmp_repo (or the real repo for tests that
        # don't use this fixture).
        sys.path[:] = orig_path
        _purge_defender_modules()
        # Re-instate any modules that were resident before this fixture
        # ran (other than defender ones, which we deliberately purged).
        for name, mod in orig_modules.items():
            if name not in sys.modules and not (
                name == "defender" or name.startswith("defender.")
            ):
                sys.modules[name] = mod


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


# ---------------------------------------------------------------------------
# Query-catalog fixture (used by Tier 1 tests starting in PR 1)
# ---------------------------------------------------------------------------


_MINIMAL_TEMPLATE = """---
id: wazuh.{name}
---

## Goal

{goal}

## What to characterize

- something

## Query

```bash
python3 defender/scripts/tools/wazuh_cli.py query \\
  --query 'rule.id:1234${{host_clause}}' \\
  --window ${{window}} \\
  --run-dir ${{run_dir}}
```

`${{host_clause}}` is `" AND agent.name:<host>"` when filtering by host,
empty otherwise.

## Filter binding

- `host` → `agent.name:<hostname>`.

## Common pitfalls

- nothing yet
"""


@pytest.fixture
def queries_dir(tmp_path: Path) -> Path:
    """Seed a minimal wazuh template catalog inside a tmp tree.

    Returns the path to ``defender/skills/gather/queries/wazuh/`` with
    two well-formed templates. Tests can drop additional ``.md`` files
    in alongside.
    """
    qdir = tmp_path / "defender" / "skills" / "gather" / "queries" / "wazuh"
    qdir.mkdir(parents=True)
    (qdir / "alpha.md").write_text(
        _MINIMAL_TEMPLATE.format(name="alpha", goal="Goal text for alpha.")
    )
    (qdir / "beta.md").write_text(
        _MINIMAL_TEMPLATE.format(name="beta", goal="Goal text for beta.")
    )
    return qdir
