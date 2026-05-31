"""Shared fixtures for the flow-map test suite.

Two tiers of tests:
  * unit  — synthetic Python modules written to tmp_path; exercise the tool
            logic in isolation, independent of any real repo.
  * golden — run against the real defender-v2-tree; skipped automatically when
            that tree is absent (so the suite still passes on a fresh checkout).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"

# make `import flowmap` work without installing the package
sys.path.insert(0, str(SKILL_ROOT))

# Real defender tree (golden tests). Override with FLOWMAP_DEFENDER_ROOT.
import os  # noqa: E402

_DEFENDER_ROOT = Path(
    os.environ.get("FLOWMAP_DEFENDER_ROOT", "/workspace/defender-v2-tree")
)


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def defender_root() -> Path:
    loop = _DEFENDER_ROOT / "defender" / "learning" / "loop.py"
    if not loop.is_file():
        pytest.skip(f"defender tree not present at {_DEFENDER_ROOT}")
    return _DEFENDER_ROOT


@pytest.fixture
def loop_module(defender_root: Path) -> Path:
    return defender_root / "defender" / "learning" / "loop.py"


# --------------------------------------------------------------------------- #
# Synthetic package: a miniature of the defender dispatch idioms, written to a
# real temp dir so ConstResolver's on-disk path math and sibling-module lookup
# behave exactly as in production.
# --------------------------------------------------------------------------- #

_MAIN_MODULE = '''\
"""Synthetic orchestrator for flow-map tests."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "pkg"
ACTOR_PROMPT = PKG / "actor.md"
PROJECT_SCRIPT = ROOT / "tools" / "do_thing.py"

import helper


def entry(x):
    """Top-level entry point."""
    _local_helper(x)
    invoke_actor()
    run_script()
    trigger("worker")          # dynamic dispatch target = "worker"
    helper.assist()            # static cross-module call


def _local_helper(x):
    """A local helper with a branch."""
    if x:
        return 1
    return 0


def invoke_actor():
    return _run_claude(ACTOR_PROMPT, "hi")


def run_script():
    subprocess.run([str(PROJECT_SCRIPT), "--go"])


def trigger(module_name):
    mod = __import__(module_name)
    return mod.run_batch()


def _run_claude(prompt_path, user):
    return ""
'''

_HELPER = '"""Helper sibling."""\n\n\ndef assist():\n    """Assist."""\n    return 7\n'
_WORKER = '"""Worker sibling."""\n\n\ndef run_batch():\n    """Run a batch."""\n    return 0\n'


@pytest.fixture
def synth_pkg(tmp_path: Path) -> dict:
    """Write a synthetic package and return key paths."""
    learn = tmp_path / "learn"
    learn.mkdir()
    (tmp_path / "pkg").mkdir()
    (tmp_path / "tools").mkdir()

    main = learn / "main.py"
    main.write_text(_MAIN_MODULE)
    (learn / "helper.py").write_text(_HELPER)
    (learn / "worker.py").write_text(_WORKER)
    (tmp_path / "pkg" / "actor.md").write_text("# actor prompt\n")
    (tmp_path / "tools" / "do_thing.py").write_text("def main():\n    pass\n")

    return {"root": tmp_path, "module": main}
