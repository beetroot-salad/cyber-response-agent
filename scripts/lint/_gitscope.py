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

import os
import re
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
    # Bytes, not text: a filename that is not valid UTF-8 round-trips through os.fsencode /
    # os.fsdecode, where a text pipe would raise UnicodeEncodeError and crash the gate.
    payload = b"\0".join(os.fsencode(p) for p in batch)
    try:
        # lint-git: ok — asking git what git ignores; re-implementing .gitignore precedence
        # (negations, nested files, core.excludesFile) is the bug this exists to stop.
        proc = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
            input=payload, capture_output=True, timeout=60, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return set()  # fail open — lint everything
    # 0 = some path ignored, 1 = none ignored (NOT an error), anything else = real failure.
    if proc.returncode not in (0, 1):
        return set()
    return {Path(os.fsdecode(line)) for line in proc.stdout.split(b"\0") if line}


#: git's notice that it listed past a directory it could not open (exit status stays 0).
_UNOPENED = re.compile(r"^warning: could not open directory '(.*)': ")


def git_listed(root: Path) -> tuple[list[str], list[str]] | None:
    """What git puts in the tree under `root`: tracked files plus untracked files it does not
    ignore (`git ls-files --cached --others --exclude-standard`), as paths relative to `root`,
    and the directories git could not open while listing. Git never enters an ignored
    directory, so nothing under one is ever touched.

    None when git cannot answer — not a repo, git missing, a failed run — and the caller lists
    by walking instead.
    """
    try:
        # lint-git: ok — asking git for the tree it would commit; re-deriving it from
        # .gitignore precedence is the bug this module exists to stop.
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"],
            capture_output=True, timeout=120, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    rels = [os.fsdecode(line) for line in proc.stdout.split(b"\0") if line]
    unopened = [m.group(1) for line in os.fsdecode(proc.stderr).splitlines()
                if (m := _UNOPENED.match(line))]
    return rels, unopened
