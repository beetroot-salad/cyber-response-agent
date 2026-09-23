"""The shared import blocker's own pins: that it blocks, that it does not over-block, and
that it says so through a mechanism the current interpreter actually calls.

A blocker that silently stops blocking is the worst outcome available here, because every
test built on it keeps passing while asserting nothing. Three of the six hand-rolled copies
this helper replaced were one Python release away from exactly that.
"""
from __future__ import annotations

import subprocess
import sys

import pytest

from defender.tests._by_path import WORKTREE as REPO_ROOT
from defender.tests._import_blocker import blocker_source, run_blocked


def test_the_blocker_actually_blocks():
    """The positive control, run against a module that is certainly importable: if the finder
    were ignored — as a `find_module`-only finder is from 3.12 — this import would succeed and
    every test built on the helper would pass having blocked nothing."""
    done = run_blocked("import json\nprint('IMPORTED')\n", block=("json",))
    assert done.returncode != 0, (
        f"`json` imported under a blocker that names it: {done.stdout!r}")
    assert b"refused by the test import blocker" in done.stderr, done.stderr


def test_the_blocker_leaves_everything_else_alone():
    """The negative control: blocking one name does not break the interpreter."""
    done = run_blocked("import json, pathlib\nprint(json.dumps({'ok': True}))\n",
                       block=("pydantic",))
    assert done.returncode == 0, done.stderr
    assert b'{"ok": true}' in done.stdout


def test_a_submodule_is_refused_through_its_blocked_parent():
    """Matching is on the top-level name, so a submodule import is refused — at the parent,
    which is what the interpreter reaches for first, and which is why the message names it."""
    done = run_blocked("import json.decoder\n", block=("json",))
    assert done.returncode != 0, done.stdout
    assert b"'json' is refused" in done.stderr, done.stderr


def test_an_allowed_top_level_name_carries_its_submodules():
    """The other direction, and the one the closure test depends on: allowing this tree lets a
    module deep inside it import, rather than only the bare top-level package."""
    done = run_blocked("from defender.runtime import box_codec\nprint(box_codec.REQUEST_MAGIC)\n",
                       allow_only=("defender",), cwd=REPO_ROOT,
                       env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr
    assert b"DFB1" in done.stdout, done.stdout


def test_a_star_entry_is_a_prefix_over_the_whole_family():
    """One caller blocks `pydantic*` — five installed distributions, not the three that the
    sibling copies happened to name. Collapsing that to an explicit list would have weakened
    it silently."""
    src = blocker_source(block=("pydantic*",))
    assert "startswith(('pydantic',))" in src, src
    done = run_blocked("import pydantic_core\n", block=("pydantic*",))
    assert done.returncode != 0, done.stdout


def test_allow_only_refuses_a_package_nobody_listed():
    """The allowlist's whole point: a dependency added later, that no denylist names, fails."""
    done = run_blocked("import pydantic\n", allow_only=("defender",))
    assert done.returncode != 0, done.stdout
    done = run_blocked("import json\nprint('OK')\n", allow_only=("defender",))
    assert done.returncode == 0, done.stderr
    assert b"OK" in done.stdout


def test_the_two_modes_are_mutually_exclusive():
    with pytest.raises(ValueError, match="exactly one"):
        blocker_source()
    with pytest.raises(ValueError, match="exactly one"):
        blocker_source(block=("json",), allow_only=("defender",))


def test_the_helper_emits_no_retired_import_hook():
    """`find_module` was removed from the import system in 3.12 and this project's
    `requires-python` admits 3.12, so a finder relying on it blocks nothing there."""
    src = blocker_source(block=("pydantic",))
    assert "find_module" not in src, src
    assert "find_spec" in src
    done = subprocess.run(
        [sys.executable, "-W", "error::ImportWarning", "-c", src + "import json\n"],
        capture_output=True, timeout=180)
    assert done.returncode == 0, done.stderr
