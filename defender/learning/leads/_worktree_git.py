"""The lead-author and pitfalls lanes' git over the drain's worktree (#1175).

The agent writes into `skills/`, and git opens a worktree `.gitignore` or `.gitattributes` when
it walks or hashes there: one left as a FIFO blocks that call for good, a plain one rewrites
what the lanes' checks see (a `*` hides every new file from `status`) or what git hashes. Every
git call here therefore opens neither:

- attributes come from HEAD's tree (`_git.committed_view_env`);
- the "what changed" reader lists tracked paths with `status --untracked-files=no` (no folder
  walk) and new files under `skills/` with `ls-files --others`, filtered by HEAD's root
  `.gitignore` read from the commit, never from the worktree;
- the commit stages exactly the admitted paths with `add -f` (no ignore rules);
- the cleanup's `clean` runs with `-x` (no ignore rules), scoped to `skills/`.

Each call is bounded as a backstop, and an overrun is `GitOverran`: a `GitError`, so it ends the
tick as a systemic fault (`core/faults.SYSTEMIC_FAULTS`) rather than charging the claim, and
not a `SubprocessError`, which `core/drains._run_curator_module` would swallow as a transient. A
FIFO git never opens is left standing; git does not list special files, and the end-of-batch
scrub refuses the tree.
"""
from __future__ import annotations

import logging
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TypeVar

from defender import _git
from defender._env import FatalConfigError
from defender.learning.author._config import GIT_TIMEOUT_SECONDS
from defender.learning.core.lane_trees import KIND_ABSENT, TreeFor, kind_at
from defender.learning.leads.path_validation import SKILLS_REL

# `GIT_TIMEOUT_SECONDS` is re-exported as the lanes' default bound: the curator's (#1134).
__all__ = [
    "GIT_TIMEOUT_SECONDS", "GitOverran", "changes_outside_skills", "commit_admitted",
    "discard_changes", "worktree_changes",
]

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")


class GitOverran(_git.GitError):
    """A lane git call that did not answer within its bound."""

    def __init__(self, args: Sequence[str], timeout: float | None) -> None:
        self.returncode = -1
        self.stderr = ""
        self.timeout = timeout
        RuntimeError.__init__(
            self, f"git {' '.join(args)} did not answer within {timeout}s — refusing the tick")


def _or_overran(fn: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """`fn(*args, **kwargs)`, its `GitTimeout` re-raised as `GitOverran`."""
    try:
        return fn(*args, **kwargs)
    except _git.GitTimeout as e:
        cmd = e.cmd if isinstance(e.cmd, list) else [str(e.cmd)]
        raise GitOverran([str(c) for c in cmd[1:]], e.timeout) from e


def _refuse_ignore_files_beside_root(repo_root: Path, timeout: float) -> None:
    """Refuse when HEAD commits a `.gitignore` on the path to `skills/` or inside it: the reader
    applies the root file's rules only, and silently dropping another's would list what it
    ignores as strays. None is committed there today."""
    parts = SKILLS_REL.strip("/").split("/")
    ancestors = ["/".join(parts[:i]) + "/.gitignore" for i in range(1, len(parts))]
    listing = _or_overran(
        _git.git, ["ls-tree", "-r", "-z", "--full-name", "--name-only", "HEAD", "--",
                   *ancestors, SKILLS_REL],
        cwd=repo_root, timeout=timeout,
    )
    found = sorted(p for p in listing.split("\0") if p.rsplit("/", 1)[-1] == ".gitignore")
    if found:
        raise FatalConfigError(
            f"a .gitignore is committed on the path to or inside {SKILLS_REL}: {found}; the "
            "lanes read only the root .gitignore's rules from HEAD — refusing the tick"
        )


def worktree_changes(repo_root: Path, *, timeout: float) -> list[tuple[str, str]]:
    """The lanes' one view of what changed, as `(XY, path)` records: tracked paths anywhere in
    the repo, and new files under `skills/` as `??`.

    Untracked files outside `skills/` are not listed: the agent cannot write there, and listing
    them would walk `skills/` under the worktree's own ignore files (#1175 N1)."""
    env = _git.committed_view_env()
    records = _or_overran(_git.git_status, repo_root, untracked="no", timeout=timeout, env=env)
    _refuse_ignore_files_beside_root(repo_root, timeout)
    rules = _git.git_show_file(repo_root, "HEAD", ".gitignore") or ""
    with tempfile.TemporaryDirectory() as tmp:
        # Outside the worktree, so the rules file is never itself a new file.
        exclude_from = Path(tmp) / "exclude"
        exclude_from.write_bytes(rules.encode("utf-8", "surrogateescape"))  # lint-unguarded-tree-write: ok — a private temp dir outside every shared tree
        untracked = _or_overran(_git.git_untracked, repo_root, SKILLS_REL,
                             exclude_from=exclude_from, timeout=timeout, env=env)
    return [*records, *(("??", path) for path in untracked)]


def changes_outside_skills(repo_root: Path, *, timeout: float) -> list[str]:
    """The paths `worktree_changes` lists that are not a `skills/*.md`: the before-agent
    baseline the scope check subtracts."""
    return [
        path for _xy, path in worktree_changes(repo_root, timeout=timeout)
        if not (path.startswith(SKILLS_REL) and path.endswith(".md"))
    ]


def commit_admitted(
    repo_root: Path, admitted: list[str], message: str, *, tree_for: TreeFor, timeout: float,
) -> str | None:
    """Commit exactly `admitted`, the paths the scope check let through; `None` when nothing
    changed.

    Which still stand is asked of the lane's held mounts (`kind_at`), as the curator's
    `commit_corpus_paths` does (#1134): anything but `KIND_ABSENT` is staged as present."""
    present = [p for p in admitted if kind_at(repo_root, tree_for, p) != KIND_ABSENT]
    absent = [p for p in admitted if p not in present]
    return _or_overran(
        _git.git_commit_paths, repo_root, present, absent, message,
        env=_git.committed_view_env(), force_add=True, timeout=timeout,
    )


def discard_changes(repo_root: Path, *, timeout: float, in_flight: bool) -> None:
    """Put the worktree back to HEAD between claims: `reset --hard`, then `clean -x` over
    `skills/` (whole-repo `-x` would delete ignored worktree state such as the `.venv` link).

    With a fault `in_flight`, a failure here is logged and passed over, so the fault being
    unwound keeps its routing. After a clean exit it is raised: the next claim would otherwise
    run, and commit, over this one's leftovers."""
    if not (repo_root / ".git").exists():
        return
    env = _git.committed_view_env()
    try:
        for args in (["reset", "--hard", "--quiet"], ["clean", "-fdqx", "--", SKILLS_REL]):
            _or_overran(_git.git, args, cwd=repo_root, timeout=timeout, env=env)
    except _git.GitError as e:
        if not in_flight:
            raise
        _logger.error(f"worktree cleanup failed under an in-flight fault: {e}")
