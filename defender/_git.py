"""Single canonical git-subprocess surface shared by learning/, evals/, scripts/, and run.py.

One contract for "run a git argv, check the return code, return stdout" — plus the
`-z` `git status --porcelain` reader, the worktree add/remove/prune helpers, and the
pathspec-scoped commit-with-trailers — so the copies (the primitive was reinvented
~8×, with three porcelain parsers and two worktree managers) can't drift apart again.

The functions return parsed Python values, not ``subprocess`` objects: ``git_status``
yields ``[(XY, path)]`` records, ``git_rev_list_count`` an ``int``, ``git_commit`` the
new sha or ``None``. Domain logic composes these and keeps its own knowledge out of
here — e.g. the learning loop's generation counters call ``git_rev_list_count(grep=…)``
and add their ``+1``; the author scope gate filters ``git_status``.

``GitError`` is the layer-neutral *condition* — "an expected git command failed". It
subclasses ``RuntimeError`` so an uncaught one fails loud with a named message
(argv + rc + stderr) rather than an opaque traceback. The *disposition* lives at the
catch site, not here: the learning drains enroll it alongside ``StageAbort`` as a
systemic fault (``learning.core.orchestrate`` → exit 2), since a failed local-state git
op (status/commit/worktree) dooms the whole batch; the remote/forge retry lane
(``branch.py`` push + ``Forge``) catches it separately. This module only knows what a
*failed* git command looks like.

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420 namespace
package) like ``defender._io`` / ``defender._env`` (see the ``_frontmatter`` precedent,
#322/#323), so every layer imports it flat (``from defender._git import git_status``)
without a layering inversion or a ``sys.path`` dance.
"""
from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class GitError(RuntimeError):
    """An expected git command exited nonzero (and ``check`` was on). Names the argv in
    its message and carries the return code and stderr as attributes, so the failure is
    named, not an opaque traceback. Layer-neutral and loud-by-default; the learning drains
    map it to the contracted exit 2 by enrolling it alongside ``StageAbort``."""

    def __init__(self, args: Sequence[str], returncode: int, stderr: str) -> None:
        self.returncode = returncode
        self.stderr = stderr.strip()
        super().__init__(
            f"git {' '.join(args)} failed (rc={returncode}): {self.stderr}"
        )


def _run(
    args: Sequence[str],
    *,
    cwd: Path,
    check: bool = True,
    timeout: float | None = None,
    input: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """The single ``subprocess.run(["git", …])`` site. Raises ``GitError`` on a nonzero
    return when ``check`` (the default). Returns the completed process so the typed
    helpers below can read ``stdout``/``returncode`` without re-stripping ``-z`` output.

    Decodes with ``errors="surrogateescape"``: ``git status … -z`` emits raw, *unquoted*
    pathname bytes (the ``-z`` form turns off ``core.quotePath``), so a strict UTF-8 decode
    would crash on a non-UTF-8 filename (e.g. a stray latin-1 untracked file) anywhere in
    the tree — taking the author scope gate (``git_status``) down with it. Surrogate-escape
    round-trips arbitrary bytes the way ``os.fsdecode`` does; a mangled path simply reads as
    out-of-corpus and the scope gate quarantines it (fail-safe). The non-``-z`` reader this
    replaced was immune because git quoted such paths to pure ASCII."""
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        errors="surrogateescape",
        timeout=timeout,
        input=input, encoding="utf-8"
    )
    if check and proc.returncode != 0:
        raise GitError(args, proc.returncode, proc.stderr)
    return proc


def git(
    args: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    check: bool = True,
    timeout: float | None = None,
    input: str | None = None,
) -> str:
    """Run a git argv and return stripped stdout. Raises ``GitError`` on a nonzero exit
    when ``check`` (the default); with ``check=False`` returns stdout regardless. The
    escape hatch for one-off commands — prefer the named helpers below where one fits."""
    return _run(args, cwd=cwd, check=check, timeout=timeout, input=input).stdout.strip()


def git_ok(args: Sequence[str], *, cwd: Path = REPO_ROOT) -> bool:
    """True iff the git command exits 0 — the predicate form (never raises) for
    existence/state checks like ``cat-file -e <rev>:<path>`` or ``symbolic-ref``."""
    return _run(args, cwd=cwd, check=False).returncode == 0


def git_status(cwd: Path, *, pathspec: Path | str | None = None) -> list[tuple[str, str]]:
    """``[(XY, path)]`` from ``git status --porcelain --untracked-files=all -z`` at ``cwd``.

    The single status reader (was three: ``shared.changes_outside`` without ``-z``,
    ``shared.corpus_dir_clean`` as a boolean, ``path_validation._porcelain_records`` with
    ``-z``). The ``-z`` form is the correct one — each NUL-separated field is one
    ``XY␣path`` record, so paths with spaces survive and no shell quoting/`" -> "` rename
    parsing is needed (a staged rename's source field reads as its own out-of-corpus
    record, which the scope gate quarantines rather than mis-committing).
    ``--untracked-files=all`` lists each untracked file individually. Pass ``pathspec`` to
    scope to a directory (for the corpus-clean predicates)."""
    args = ["status", "--porcelain", "--untracked-files=all", "-z"]
    if pathspec is not None:
        args += ["--", str(pathspec)]
    out = _run(args, cwd=cwd).stdout  # raw — do NOT strip; a leading " M" status would lose its space
    records: list[tuple[str, str]] = []
    for rec in out.split("\0"):
        if len(rec) < 3:  # subsumes the empty trailing field after the final NUL
            continue
        records.append((rec[:2], rec[3:] if rec[2] == " " else rec[2:]))
    return records


def git_head_sha(cwd: Path) -> str:
    """The HEAD commit sha at ``cwd``."""
    return git(["rev-parse", "HEAD"], cwd=cwd)


def git_rev_list_count(
    cwd: Path, *, grep: str | None = None, rev_range: str = "HEAD"
) -> int:
    """``git rev-list --count [--grep=<grep>] <rev_range>`` as an int.

    ``grep`` filters by commit-message pattern (the trailer-counting generation readers);
    ``rev_range`` defaults to ``HEAD`` (``commits_ahead`` passes ``origin/main..HEAD``)."""
    args = ["rev-list", "--count"]
    if grep is not None:
        args.append(f"--grep={grep}")
    args.append(rev_range)
    # check=True guarantees a successful exit here, and `rev-list --count` always prints an
    # integer line on success, so git() is never empty — int() can take it directly.
    return int(git(args, cwd=cwd))


def git_commit(
    cwd: Path,
    pathspec: Path | str,
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
) -> str | None:
    """Stage ``pathspec``, commit it **pathspec-scoped** (``git commit -- <pathspec>``),
    return the new sha — or ``None`` when nothing was staged (empty diff → no commit).

    Pathspec-scoping is load-bearing: a plain index-global commit would sweep in whatever
    else sits staged in the worktree (e.g. a sibling curator's edits earlier in the same
    drain). ``trailers`` go on at creation via ``--trailer`` (no commit→amend split). The
    caller owns any guard against a ``message`` that already carries a trailer key — that's
    domain policy, not git. Raises ``GitError`` if staging or committing fails."""
    git(["add", "--", str(pathspec)], cwd=cwd)
    staged = _run(
        ["diff", "--cached", "--quiet", "--", str(pathspec)], cwd=cwd, check=False
    )
    if staged.returncode == 0:
        return None  # nothing staged — no commit
    if staged.returncode != 1:  # 0=no diff, 1=diff, >1=git error (don't commit blind)
        raise GitError(["diff", "--cached", "--quiet"], staged.returncode, staged.stderr)
    trailer_args: list[str] = []
    for key, val in trailers or []:
        trailer_args += ["--trailer", f"{key}: {val}"]
    git(
        ["commit", "-F", "-", *trailer_args, "--", str(pathspec)],
        cwd=cwd,
        input=message,
    )
    return git_head_sha(cwd)


def git_fetch(cwd: Path) -> None:
    """``git fetch origin`` at ``cwd`` — refresh the remote-tracking refs the author
    drains branch off (``origin/main``). Raises ``GitError`` on failure."""
    git(["fetch", "origin"], cwd=cwd)


def git_push(cwd: Path, branch: str) -> None:
    """``git push --set-upstream origin <branch>`` from the checkout at ``cwd`` — the
    first push of a fresh author batch/revert branch (sets the upstream). Raises
    ``GitError`` on failure.

    The remote (``origin``) and ``--set-upstream`` are fixed: both call sites push a
    brand-new batch/revert branch. A ``remote=`` / flag knob earns its place only once a
    second caller varies it (the same "no speculative parameter" bar that kept
    ``git_checkout`` out — its sites are migrating to ``git_worktree_add``, #477/#478)."""
    git(["push", "--set-upstream", "origin", branch], cwd=cwd)


def git_worktree_add(
    cwd: Path,
    path: Path | str,
    ref: str,
    *,
    branch: str | None = None,
    detach: bool = False,
) -> None:
    """``git worktree add`` a checkout of ``ref`` at ``path``. Pass ``branch`` to create/reset
    a branch there (``-B <branch>`` — the author batch worktree off ``origin/main``), or
    ``detach=True`` for a detached HEAD (the evals frozen-generation replay at a sha)."""
    args = ["worktree", "add"]
    if branch is not None:
        args += ["-B", branch]
    if detach:
        args.append("--detach")
    args += [str(path), ref]
    git(args, cwd=cwd)


def git_worktree_remove(cwd: Path, path: Path | str, *, force: bool = True) -> None:
    """``git worktree remove [--force] <path>``."""
    args = ["worktree", "remove"]
    if force:
        args.append("--force")
    args.append(str(path))
    git(args, cwd=cwd)


def git_worktree_prune(cwd: Path) -> None:
    """``git worktree prune`` — clear stale worktree registrations (crashed-batch
    stragglers). Callers that want it best-effort suppress ``GitError`` themselves."""
    git(["worktree", "prune"], cwd=cwd)
