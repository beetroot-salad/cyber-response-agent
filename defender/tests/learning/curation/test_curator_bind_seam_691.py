"""Curator binding seam: bind returns a corpus-scoped CuratorDeps with retained roots and the generic tool-config slot."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.tests.support.learning.curation._curator_691_harness import (  # noqa: E402
    bind_curator,
    corpus,
    make_worktree,
    pending_run_dir,
    rel,
    write_file,
)


# #0 — the binding seam returns a corpus-scoped curator deps

def test_bind_returns_a_corpus_scoped_curator_deps(tmp_path):
    """Binding the curator BY NAME against its worktree returns a CuratorDeps whose compiled write
    scope roots at ``<worktree>/defender/<corpus>``, NOT at run_dir — the whole point of #0."""
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    write_file(deps, rel("lessons", "m.md"))                       # own corpus → lands
    assert (corpus(wt, "lessons") / "m.md").read_text() == "body\n"
    with pytest.raises(ModelRetry):
        write_file(deps, str(rd / "scratch.md"))                   # run_dir → DENY


def test_a_bound_deps_is_copied_with_one_field_replaced(tmp_path):
    wt, rd = make_worktree(tmp_path), pending_run_dir(tmp_path)
    deps = bind_curator(wt, rd, "lessons")
    copy = replace(deps, run_id="other-run")
    assert copy.policy == deps.policy
    assert copy.roots == deps.roots            # provisional M6 field — retained, copied through


# M6 / M1 — retained roots + the corpus found by NAME


# M4 / M5 — the named tool-config slot: inert-by-default, unpopulated by this role since #773


def test_importing_runtime_does_not_import_the_learning_stages():
    code = (
        "import defender.runtime.tools, sys; "
        "leaked = [m for m in sys.modules if m.startswith('defender.learning.author')]; "
        "assert not leaked, leaked"
    )
    repo_root = Path(__file__).resolve().parents[4]
    env = {**os.environ, "PYTHONPATH": str(repo_root)}
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
