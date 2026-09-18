"""Shared fixtures for defender learning-loop tests.

Each test gets an isolated tmp git repo with the ``defender/learning/`` source
files copied in. The fixture builds one ``LoopPaths(repo_root=tmp)`` and an
``AuthorConfig`` from it (``ctx.paths`` / ``ctx.cfg``); tests thread those into
``author.run_batch(paths=…, cfg=…)`` and inject a fake curator via
``dataclasses.replace(cfg, invoke_agent=fake)`` — no module-global setattr, no
``importlib.reload``.
"""
from __future__ import annotations

import ctypes
import shutil
import subprocess
from pathlib import Path

import pytest


REAL_REPO = Path(__file__).resolve().parents[2]
LEARNING_SRC = REAL_REPO / "defender" / "learning"


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


def _resolve_malloc_trim():
    """Bind glibc's `malloc_trim`, or a no-op off glibc (musl has no such symbol)."""
    try:
        trim = ctypes.CDLL("libc.so.6").malloc_trim
    except (OSError, AttributeError):
        return lambda: None
    trim.argtypes = [ctypes.c_size_t]
    trim.restype = ctypes.c_int
    return lambda: trim(0)


_malloc_trim = _resolve_malloc_trim()


@pytest.fixture(scope="module", autouse=True)
def _return_freed_arenas():
    """Hand freed allocator arenas back to the OS at every module boundary.

    xdist workers are persistent and `--dist loadfile` keeps feeding them new files, so one
    transient peak raises that worker's floor for the rest of the run: the memory is already
    free to Python, but glibc keeps the arenas. The three files that drive the runtime loop to
    its request limit each cost 150-250 MB this way, and a single trim returns essentially all
    of it (one measured case: 157 MB grown, 152 MB returned). Runs after the module's own
    fixtures tear down, so what it reclaims is genuinely dead.
    """
    yield
    _malloc_trim()



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
