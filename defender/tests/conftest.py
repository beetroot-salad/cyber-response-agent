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

_CI_WORKFLOW = REAL_REPO / ".github" / "workflows" / "ci.yml"


def _code_smells_step_names() -> list[str]:
    """The `name:` of every step in CI's `code-smells` job, read off the workflow file.

    A plain line walk rather than a YAML parse: the job is found by its indentation-two key
    and ends at the next one, and a step name is the text after `- name: `. That is all the
    marker check below needs, and it keeps this conftest free of a yaml dependency."""
    names: list[str] = []
    in_job = False
    for line in _CI_WORKFLOW.read_text(encoding="utf-8").splitlines():
        if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
            in_job = line.strip() == "code-smells:"
            continue
        if in_job and line.strip().startswith("- name: "):
            names.append(line.strip()[len("- name: "):])
    return names


def pytest_collection_modifyitems(config, items):
    """`gate` is not a way to skip a test. The marker's contract (pyproject's `markers`) is
    that the marked test re-asserts EXACTLY what a blocking step in CI's `code-smells` job
    already asserts, so the `test` job can stop paying for the copy — and that the test NAMES
    that step. Ninety-two spec tests once carried the marker at module level with no such
    step, which deselected them from every CI job and from the local gate command at once;
    they ran nowhere. So the name is now the marker's argument, and a marker that names no
    step, or a step the job does not have, is a collection error rather than a silent skip."""
    step_names: list[str] | None = None
    problems: list[str] = []
    for item in items:
        marker = item.get_closest_marker("gate")
        if marker is None:
            continue
        if step_names is None:
            step_names = _code_smells_step_names()
        covered_by = marker.args[0] if marker.args else None
        if not isinstance(covered_by, str) or not covered_by:
            problems.append(
                f"{item.nodeid}: `gate` names no covering step — write "
                f"`@pytest.mark.gate(\"<code-smells step name>\")` on the one test the step "
                f"duplicates, never `pytestmark` on a module"
            )
        elif not any(name.startswith(covered_by) for name in step_names):
            problems.append(
                f"{item.nodeid}: `gate` names {covered_by!r}, which is not the start of any "
                f"step name in ci.yml's code-smells job"
            )
    if problems:
        raise pytest.UsageError("\n".join(problems))


@pytest.fixture(scope="session")
def checkout_roster():
    """The real checkout's adapters roster, read ONCE per session — the value a production
    process reads at its composition root and hands down."""
    from defender._paths import PATHS
    from defender.runtime.verbs import read_roster

    return read_roster(PATHS.adapters_dir)


@pytest.fixture(autouse=True)
def _held_capabilities(checkout_roster):
    """Every test starts with the `nothing-to-try` gate HOLDING the real checkout's roster,
    the way a production process does at its start (`_adapters_at_run_start` →
    `hold_capabilities`), and ends with it released, so a test that drove the gate to another
    tree cannot leak that tree to the next test in the worker. A test that must observe the
    unheld state calls `release_capabilities()` itself; the gate never reads for itself, so
    without this a document with a `nothing-to-try` receipt would raise `CapabilitiesNotRead`
    out of every validator call in the suite."""
    from defender.skills.invlang.validate import hold_capabilities, release_capabilities

    hold_capabilities(checkout_roster)
    try:
        yield
    finally:
        release_capabilities()



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
