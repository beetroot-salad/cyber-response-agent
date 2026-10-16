"""#691 §7 scope-expansion pin (D4): an OBSERVABLE the human pinned beyond bindability whose
MECHANISM is left to the implementer — MD-9 (F37/S120, the post-run audit's corpus derivation).
(MD-8, the forward-check verifier's tree, went with the verifier in #1166.)

It pins an observable, not a mechanism (70-resolutions Red flags): MD-9's fix may be
unify-lists OR reconcile-prefix. The test therefore drives the REAL primitive and asserts the
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

from _curator_691_harness import SHIPPED



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


