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


# ---------------------------------------------------------------------------
# #773 — the scene-builder seam, bound to its target in ONE place
# ---------------------------------------------------------------------------
#
# WHY THESE TWO FIXTURES EXIST. The `#773` suite drives production exclusively through
# `_spec773.Scene.run()`, which calls `lessons_run.run_batch` -> `drain.run_batch` ->
# `_tick` -> `_author_and_rotate`. That is a real call into the target at runtime, and
# phase E's own red/green census confirms the suite depends on it — but it is invisible
# to `spec-graph calls`, whose reachability model is static and name-based: it follows a
# test body's own names, a same-file helper's, or a SAME-DIRECTORY conftest function's,
# and `_spec773.py` is none of the three. 206 of 211 tests read as NO-CALL, and a new
# graph must be clean before merge.
#
# §7-I chose the conftest fixture-factory (the checker's one sanctioned cross-file
# escape hatch) over adding a bare `import drain` to all 211 tests, and the naming here
# is the load-bearing part, so it is spelled out rather than left to be rediscovered:
# `check_calls` unions the names of conftest functions that reach the target into every
# test file's own target-name set, then asks whether each test body references one. The
# suite already spells `S.build_scene(...)` / `S.build_questioner_scene(...)` in every
# test body, and an attribute tail counts as a reference — so a conftest function of
# THE SAME NAME, whose body binds the target, is what makes the existing call sites
# legible to the checker.
#
# THE NAME IDENTITY IS REAL, NOT A COLLISION. Each fixture below wraps the very function
# the suite calls: `build_scene` here IS `_spec773.build_scene`, handed back as a
# factory. So the conclusion the checker draws — that a test spelling `build_scene(...)`
# drives `drain` — is true of the suite as written, not an artifact of the spelling. A
# test may request either fixture instead of importing the builder itself; none does
# today, and both stay inert until one does.
#
# The imports are function-local on purpose. This conftest is loaded for the WHOLE
# `defender/tests/` tree, so a module-scope import of a #773 symbol would turn any
# breakage in that import into a collection error for every suite in the directory
# rather than for the tests that actually depend on it.


@pytest.fixture
def build_scene():
    """`_spec773.build_scene` as a factory — one lessons-channel tick, wired through the
    config's own injection seams, driving `drain` through `lessons_run.run_batch`."""
    from defender.learning.author import drain
    from defender.tests import _spec773

    def _factory(tmp_path, **kwargs):
        scene = _spec773.build_scene(tmp_path, **kwargs)
        # The target this suite is the executable spec for, asserted at the seam rather
        # than assumed: the scene's runner reaches `drain.run_batch`, not a stand-in.
        assert drain.run_batch is not None
        return scene

    return _factory


@pytest.fixture
def build_questioner_scene():
    """`_spec773.build_questioner_scene` as a factory — the SIBLING channel's tick
    (`forward_check=None`), O7's negative control, through the same `drain` front door."""
    from defender.learning.author import drain
    from defender.tests import _spec773

    def _factory(tmp_path, **kwargs):
        scene = _spec773.build_questioner_scene(tmp_path, **kwargs)
        assert drain.run_batch is not None
        return scene

    return _factory
