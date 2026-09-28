#!/usr/bin/env python3
"""What git ignores — so a lint sees the same tree CI does.

`lint_ci_hygiene` and `lint_shippable_surface` walk `defender/` with `rglob("*")` and scope
themselves by a hand-maintained `EXCLUDED_PREFIXES`, which cannot list the directories a run
writes (`defender/learning/runs/`, `author-queue/`, `learn-queue/`, all gitignored). Without
this, a working tree that has executed the loop reports hundreds of findings that a fresh CI
checkout does not — and a gate that is red locally and green in CI teaches people to
disbelieve it.

Asking git is what the list was approximating: generated artifacts are already declared in
`.gitignore`, so a directory invented by a future stage is scoped correctly from day one.

Ignored-ness, not tracked-ness: an untracked file about to be committed must still be linted.

Fails open: no git, a non-repo, or a broken invocation returns "nothing is ignored" and the
caller lints everything. A lint that silently stopped looking because a subprocess failed
would be worse than the noise.
"""
from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

_BATCH = 4000


def git_ignored(root: Path, paths: Iterable[Path]) -> frozenset[Path]:
    """The subset of `paths` that git ignores, per `git check-ignore`.

    Batched (`_BATCH` paths per subprocess): callers pass every entry under `defender/`, and a
    fork per file turns a sub-second lint into a minute.
    """
    candidates = [Path(p) for p in paths]
    if not candidates:
        return frozenset()
    ignored: set[Path] = set()
    for start in range(0, len(candidates), _BATCH):
        batch = candidates[start:start + _BATCH]
        ignored |= _check_ignore(root, batch)
    return frozenset(ignored)


def _check_ignore(root: Path, batch: list[Path]) -> set[Path]:
    payload = "\0".join(str(p) for p in batch)
    try:
        # lint-git: ok — asking git what git ignores; re-implementing .gitignore precedence
        # (negations, nested files, core.excludesFile) is the bug this exists to stop.
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
            input=payload, capture_output=True, text=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()  # fail open — lint everything
    # 0 = some path ignored, 1 = none ignored (NOT an error), anything else = real failure.
    if proc.returncode not in (0, 1):
        return set()
    return {Path(line) for line in proc.stdout.split("\0") if line}
