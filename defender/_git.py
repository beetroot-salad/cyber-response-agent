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


def git_status(cwd: Path, *, pathspec: Path | str | None = None) -> list[tuple[str, str]]:
    args = ["status", "--porcelain", "--untracked-files=all", "-z"]
    if pathspec is not None:
        args += ["--", str(pathspec)]
    out = _run(args, cwd=cwd).stdout
    records: list[tuple[str, str]] = []
    for rec in out.split("\0"):
        if len(rec) < 3:
            continue
        records.append((rec[:2], rec[3:] if rec[2] == " " else rec[2:]))
    return records


def git_head_sha(cwd: Path) -> str:
    return git(["rev-parse", "HEAD"], cwd=cwd)


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
