"""#691 §7 scope-expansion pins (D4): the two OBSERVABLES the human pinned beyond bindability
whose MECHANISM is left to the implementer — MD-8 (F11, the forward-check verifier's tree) and
MD-9 (F37/S120, the post-run audit's corpus derivation).

Both pin an observable, not a mechanism (70-resolutions Red flags): MD-8's fix may be
``requires_explicit_tree`` on ``VERIFY_DEF`` OR threading the curator's tree; MD-9's may be
unify-lists OR reconcile-prefix. Each test therefore drives the REAL primitive and asserts the
observable outcome, never a presumed implementation.

MD-10 (F40, concurrent same-corpus spawns into the shared ``_pending`` sink) is DELIBERATELY
ABSENT: no executed ledger claim establishes a single-writer lock or a deterministic interleaving,
so per the author charge (fault hierarchy rule 3) it is red-flagged and a probe requested rather
than written as an invented timing test. See 80-author-digest.md ``## Red flags``.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from _curator_691_harness import SHIPPED, make_worktree, pending_run_dir

from defender._paths import PATHS  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.learning.author.verify_forward.engine import VERIFY_DEF  # noqa: E402


# MD-8 (F11) — the forward-check verifier must not reach the MAIN checkout

def test_the_forward_check_verifier_does_not_reach_the_main_checkout(tmp_path):
    """MD-8 (F11, §7 D4): a forward-check verifier spawned from a WORKTREE curator must not resolve
    its roots to the MAIN checkout. ``verify_forward/engine.py:59`` binds
    ``bind(VERIFY_DEF, source_run_dir)`` with NO tree, and ``VERIFY_DEF.requires_explicit_tree`` is
    False, so today it silently falls back to ``PATHS.defender_dir`` (the MAIN checkout) even while
    the curator itself authors a worktree (g19/P6 executed). The OBSERVABLE is pinned; the mechanism
    (``requires_explicit_tree`` on ``VERIFY_DEF`` vs threading the curator's tree) is the
    implementer's — so this asserts the negative directly: a no-tree verifier bind must NOT yield a
    MAIN-checkout-rooted deps (it either refuses, or roots at the worktree)."""
    wt = make_worktree(tmp_path)
    run_dir = pending_run_dir(tmp_path)
    # engine.py:59's exact call — the curator's forward-check spawns the verifier with no tree.
    try:
        deps = bind(VERIFY_DEF, run_dir)
    except ValueError:
        pass  # the requires_explicit_tree mechanism: a no-tree verifier is refused — negative met
    else:
        assert deps.defender_dir.resolve() != PATHS.defender_dir.resolve(), (
            "a worktree curator's forward-check verifier resolved its tree to the MAIN checkout "
            "(PATHS.defender_dir) — F11's security asymmetry"
        )
    # Positive control: bound WITH the worktree tree, the verifier roots at the worktree — the
    # observation channel can see the difference (this is not a blanket 'always refuses').
    control = bind(VERIFY_DEF, run_dir, defender_dir=wt / "defender")
    assert control.defender_dir.resolve() == (wt / "defender").resolve()


# MD-9 (F37/S120) — the post-run audit agrees with the write-lane gate

def _git_repo(tmp_path: Path) -> Path:
    """A worktree-shaped git repo with the three corpora + a non-lesson dir, one commit deep, so
    ``git status`` reports the probe files as untracked (the shape ``changes_outside`` reads)."""
    repo = tmp_path / "wt"
    for name in (*SHIPPED, "docs"):
        (repo / "defender" / name).mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "README").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    return repo


