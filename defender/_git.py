from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class GitError(RuntimeError):

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
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="surrogateescape",
        timeout=timeout,
        input=input,
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
    return _run(args, cwd=cwd, check=check, timeout=timeout, input=input).stdout.strip()


def git_ok(args: Sequence[str], *, cwd: Path = REPO_ROOT) -> bool:
    return _run(args, cwd=cwd, check=False).returncode == 0


def git_status(
    cwd: Path, *, pathspec: Path | str | None = None, timeout: float | None = None,
    no_renames: bool = False,
) -> list[tuple[str, str]]:
    """The working tree's status as `(XY, path)` records.

    `no_renames` turns OFF git's rename detection, which is what a caller COUNTING the paths a
    sha does not name has to do: `git mv a b` is reported as one `R  b` record whose original
    `a` this parser consumes as the record's second field and drops, so two paths that differ
    from HEAD are counted once and the vanished one is never named. With the flag, the same
    move reports `D  a` and `A  b` — two records, two paths, which is the honest answer.
    """
    args = ["status", "--porcelain", "--untracked-files=all", "-z"]
    if no_renames:
        args.append("--no-renames")
    if pathspec is not None:
        args += ["--", str(pathspec)]
    out = _run(args, cwd=cwd, timeout=timeout).stdout
    fields = out.split("\0")
    records: list[tuple[str, str]] = []
    i = 0
    while i < len(fields):
        rec = fields[i]
        i += 1
        if len(rec) < 4:
            # `XY <path>` — the shortest real record is 3 chars of prefix plus a name.
            continue
        xy, path = rec[:2], rec[3:]
        records.append((xy, path))
        if xy[0] in "RC" or xy[1] in "RC":
            # A rename/copy record is FOLLOWED by its `<origPath>` as a field of its own.
            # Consuming it here stops it being read as a record whose status is the first two
            # characters of a path.
            i += 1
    return records


def git_show_head(cwd: Path, path: str) -> str | None:
    """`path`'s content at HEAD, or `None` when HEAD does not carry it.

    `check=False` and a `None` return rather than a `GitError`, because "the file is new in this
    batch" is an ORDINARY answer here — a promoted template and a deleted draft are read through
    the same call, and only one is expected to exist at HEAD. Unstripped: the caller parses
    frontmatter out of this, and `strip()` would eat the leading `---` delimiter's line
    structure.
    """
    proc = _run(["show", f"HEAD:{path}"], cwd=cwd, check=False)
    return proc.stdout if proc.returncode == 0 else None


def git_head_sha(cwd: Path, *, timeout: float | None = None) -> str:
    return git(["rev-parse", "HEAD"], cwd=cwd, timeout=timeout)


def git_show_file(cwd: Path, rev: str, path: str) -> str | None:
    """The text a path carries at `rev`, or `None` when it is not there.

    Deliberately NOT `git()`: that helper strips the output, and a caller comparing a committed
    document against a working-tree one needs the bytes as committed — a stripped trailing
    newline reads as an edit nobody made."""
    proc = _run(["show", f"{rev}:{path}"], cwd=cwd, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_rev_list_count(
    cwd: Path, *, grep: str | None = None, rev_range: str = "HEAD"
) -> int:
    args = ["rev-list", "--count"]
    if grep is not None:
        args.append(f"--grep={grep}")
    args.append(rev_range)
    return int(git(args, cwd=cwd))


def git_commit(
    cwd: Path,
    pathspec: Path | str,
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
) -> str | None:
    git(["add", "--", str(pathspec)], cwd=cwd)
    staged = _run(
        ["diff", "--cached", "--quiet", "--", str(pathspec)], cwd=cwd, check=False
    )
    if staged.returncode == 0:
        return None
    if staged.returncode != 1:
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
    git(["fetch", "origin"], cwd=cwd)


def git_push(cwd: Path, branch: str) -> None:
    git(["push", "--set-upstream", "origin", branch], cwd=cwd)


def git_worktree_add(
    cwd: Path,
    path: Path | str,
    ref: str,
    *,
    branch: str | None = None,
    detach: bool = False,
) -> None:
    args = ["worktree", "add"]
    if branch is not None:
        args += ["-B", branch]
    if detach:
        args.append("--detach")
    args += [str(path), ref]
    git(args, cwd=cwd)


def git_worktree_remove(cwd: Path, path: Path | str, *, force: bool = True) -> None:
    args = ["worktree", "remove"]
    if force:
        args.append("--force")
    args.append(str(path))
    git(args, cwd=cwd)


def git_worktree_prune(cwd: Path) -> None:
    git(["worktree", "prune"], cwd=cwd)
