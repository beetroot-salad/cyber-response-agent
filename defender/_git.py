from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The variables that decide WHICH repository git acts on whatever `cwd=` says: an exported
#: `GIT_DIR` points every call at that repository (J-PO1, executed).
REPO_LOCATING_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_PREFIX",
)


def env_for_cwd() -> dict[str, str]:
    """This process's environment without the variables that would override `cwd=`, for a
    call that must act on the repository at its `cwd` and nowhere else (a tenant's own repo,
    never the product checkout an operator's shell may have exported)."""
    return {k: v for k, v in os.environ.items() if k not in REPO_LOCATING_ENV}


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
    env: Mapping[str, str] | None = None,
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
        env=None if env is None else dict(env),
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
    env: Mapping[str, str] | None = None,
) -> str:
    return _run(
        args, cwd=cwd, check=check, timeout=timeout, input=input, env=env).stdout.strip()


def git_ok(args: Sequence[str], *, cwd: Path = REPO_ROOT) -> bool:
    return _run(args, cwd=cwd, check=False).returncode == 0


def git_status(
    cwd: Path, *, pathspec: Path | str | None = None, timeout: float | None = None,
    no_renames: bool = False,
) -> list[tuple[str, str]]:
    """The working tree's status as `(XY, path)` records.

    `no_renames` turns off rename detection, for callers counting changed paths: otherwise
    `git mv a b` is one `R  b` record and `a` is dropped; with it, `D  a` and `A  b`.
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
            # A rename/copy record is followed by its `<origPath>` as a separate field; skip it.
            i += 1
    return records


def git_show_head(cwd: Path, path: str) -> str | None:
    """`path`'s content at HEAD, or `None` when HEAD does not carry it.

    Absence is an ordinary answer (a file new in this batch), not a `GitError`. Unstripped,
    since callers parse frontmatter out of it.
    """
    proc = _run(["show", f"HEAD:{path}"], cwd=cwd, check=False)
    return proc.stdout if proc.returncode == 0 else None


def git_head_sha(cwd: Path, *, timeout: float | None = None) -> str:
    return git(["rev-parse", "HEAD"], cwd=cwd, timeout=timeout)


def git_show_file(cwd: Path, rev: str, path: str) -> str | None:
    """The text a path carries at `rev`, or `None` when it is not there.

    Not `git()`, which strips output: a stripped trailing newline would read as an edit when
    compared against the working tree."""
    proc = _run(["show", f"{rev}:{path}"], cwd=cwd, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_show_file_bytes(cwd: Path, rev: str, path: str) -> bytes | None:
    """The raw bytes a path carries at `rev`, or `None` when it is not there. Use for
    byte-identity checks: `git_show_file` decodes with universal newlines, so CRLF and LF
    compare equal there."""
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=cwd, capture_output=True, check=False,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_blob_bytes(cwd: Path, sha: str, *, env: Mapping[str, str] | None = None) -> bytes:
    """The raw bytes of the blob `sha` (`cat-file blob`): no filter, no line-ending
    conversion and no configured command applied. `GitError` when git cannot answer."""
    proc = subprocess.run(  # noqa: S603 — fixed argv
        ["git", "cat-file", "blob", sha], cwd=cwd, capture_output=True, check=False,
        env=None if env is None else dict(env),
    )
    if proc.returncode != 0:
        raise GitError(["cat-file", "blob", sha], proc.returncode,
                       proc.stderr.decode("utf-8", "replace"))
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


def git_commit_paths(
    cwd: Path,
    paths: Sequence[str],
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
) -> str | None:
    """Stage exactly `paths` (including deletions) and commit them; `None` if nothing changed.

    An empty `paths` returns `None` without calling git: `git commit -F - --` with an empty
    pathspec would commit the whole index, sweeping in whatever else is staged."""
    if not paths:
        return None
    # `git add` refuses the whole call if any path is gone from both worktree and index
    # ("did not match any files"), so absent paths go through `git rm --cached
    # --ignore-unmatch`, which is a no-op when the index no longer has them.
    present = [p for p in paths if (cwd / p).exists()]
    absent = [p for p in paths if p not in present]
    if present:
        git(["add", "--", *present], cwd=cwd)
    if absent:
        git(["rm", "--cached", "--ignore-unmatch", "-q", "--", *absent], cwd=cwd)
    staged = _run(["diff", "--cached", "--quiet", "--", *paths], cwd=cwd, check=False)
    if staged.returncode == 0:
        return None
    if staged.returncode != 1:
        raise GitError(["diff", "--cached", "--quiet"], staged.returncode, staged.stderr)
    trailer_args: list[str] = []
    for key, val in trailers or []:
        trailer_args += ["--trailer", f"{key}: {val}"]
    git(["commit", "-F", "-", *trailer_args, "--", *paths], cwd=cwd, input=message)
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
