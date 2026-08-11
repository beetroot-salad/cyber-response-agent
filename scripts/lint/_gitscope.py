#!/usr/bin/env python3
"""What git ignores — so a lint sees the same tree CI does.

The problem this solves. `lint_ci_hygiene` and `lint_shippable_surface` walk `defender/` with
`rglob("*")` and scope themselves by a hand-maintained `EXCLUDED_PREFIXES` tuple. That tuple
lists directories someone thought of; it cannot list the ones a run WRITES. So a working tree
that has ever executed `run.py` or the learning loop accumulates `defender/learning/runs/`,
`author-queue/` and `learn-queue/` — all gitignored, none in the tuple — and the lints report
hundreds of NEW findings and exit 1, while CI on a fresh checkout reports zero and exits 0.

That divergence is worse than a missed finding. A gate that is red locally and green in CI
teaches its readers to disbelieve it, and the only way to tell a real regression from the noise
is to stash the working tree and re-run — which is exactly what the noise then costs, every time.

Asking git is not one more entry in the list; it is the thing the list was approximating. A
generated artifact is already declared in `.gitignore`, so nothing has to be remembered twice,
and a directory invented by a future stage is scoped correctly on the day it first appears.

Deliberately IGNORED-ness, not tracked-ness: a file staged for a commit but not yet added is
untracked and MUST still be linted — catching it before it lands is the point of a pre-commit
gate. Only what git is told to ignore is out of scope.

Fails OPEN. No git, a non-repo, a broken invocation — every one returns "nothing is ignored" and
the caller lints everything, i.e. exactly today's behaviour. A lint that silently stopped
looking because a subprocess failed would be a worse failure than the noise it replaces.
"""
from __future__ import annotations

import subprocess
from collections.abc import Iterable
from pathlib import Path

_BATCH = 4000


def git_ignored(root: Path, paths: Iterable[Path]) -> frozenset[Path]:
    """The subset of `paths` that git ignores, resolved by `git check-ignore` itself.

    One subprocess per `_BATCH` paths rather than one per path: the callers hand this every
    entry under `defender/`, and a fork per file turns a sub-second lint into a minute.
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
        # lint-git: ok — asking git what git ignores. The scope question this answers has no
        # non-git answer: re-implementing .gitignore precedence (negations, nested files,
        # core.excludesFile) is the bug this exists to stop.
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
