from __future__ import annotations

import os
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: The variables that decide WHICH repository git acts on whatever `cwd=` says: an exported
#: `GIT_DIR` points every call at that repository (J-PO1, executed).
REPO_LOCATING_ENV = (
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE", "GIT_PREFIX",
)


def committed_view_env(rev: str = "HEAD") -> dict[str, str]:
    """This process's environment for a git call that must see the repository as `rev` commits
    it: attributes from `rev`'s tree (`GIT_ATTR_SOURCE`, git 2.42+), never from a
    `.gitattributes` in the worktree, and replace objects ignored (`GIT_NO_REPLACE_OBJECTS`).

    A worktree `.gitattributes` is opened by every git call that hashes or writes a file there,
    so one that is a FIFO blocks it for good, and its rules would convert what git hashes; a
    `refs/replace` entry would stand another object in for the commit's own (#1134, aligned with
    #1120's committed read)."""
    return {**os.environ, "GIT_ATTR_SOURCE": rev, "GIT_NO_REPLACE_OBJECTS": "1"}


def env_for_cwd() -> dict[str, str]:
    """This process's environment without the variables that would override `cwd=`, for a
    call that must act on the repository at its `cwd` and nowhere else (a tenant's own repo,
    never the product checkout an operator's shell may have exported)."""
    return {k: v for k, v in os.environ.items() if k not in REPO_LOCATING_ENV}


#: What a git call bounded by `timeout=` raises when git does not answer in time: subprocess's own
#: class, unconverted (`scripts/tenant.py` catches it by that name), named here so a caller of this
#: facade catches it beside `GitError` without importing subprocess.
GitTimeout = subprocess.TimeoutExpired


def unstarted(e: OSError) -> str:
    """Why git did not start, for a caller that caught the `OSError` a git call raises then:
    absent from PATH, or there but not runnable (no execute permission)."""
    return ("git is not available on PATH" if isinstance(e, FileNotFoundError)
            else "git cannot be run")


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


def git_z(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float | None = None,
    input: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[str]:
    """The NUL-separated fields of a `-z` git call's output, unstripped (`git()` strips, which
    would eat whitespace that belongs to the first or last name), with the empty tail dropped."""
    out = _run(args, cwd=cwd, timeout=timeout, input=input, env=env).stdout
    fields = out.split("\0")
    return fields[:-1] if fields and fields[-1] == "" else fields


def git_ok(
    args: Sequence[str], *, cwd: Path = REPO_ROOT, timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    return _run(args, cwd=cwd, check=False, timeout=timeout, env=env).returncode == 0


def git_status(
    cwd: Path, *, pathspec: Path | str | None = None, timeout: float | None = None,
    no_renames: bool = False, env: Mapping[str, str] | None = None,
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
    out = _run(args, cwd=cwd, timeout=timeout, env=env).stdout
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


def git_blob_bytes(cwd: Path, sha: str, *, env: Mapping[str, str] | None = None,
                   timeout: float | None = None) -> bytes:
    """The raw bytes of the blob `sha` (`cat-file blob`): no filter, no line-ending
    conversion and no configured command applied. `GitError` when git cannot answer."""
    return _run_bytes(["cat-file", "blob", sha], cwd=cwd, env=env, timeout=timeout)


#: `ls-tree` modes of a regular file blob: the only entries a before-state restores as a file
#: (a symlink, 120000, and a submodule, 160000, never are).
_REGULAR_BLOB_MODES = frozenset({"100644", "100755"})


def _run_bytes(
    args: Sequence[str], *, cwd: Path, input: bytes | None = None,
    env: Mapping[str, str] | None = None, timeout: float | None = None,
) -> bytes:
    """`git <args>` with raw bytes in and out (no decoding, no newline translation); a non-zero
    exit raises `GitError`, a `timeout` that passes first `subprocess.TimeoutExpired`."""
    proc = subprocess.run(  # noqa: S603 — fixed argv
        ["git", *args], cwd=cwd, capture_output=True, input=input, check=False,
        env=None if env is None else dict(env), timeout=timeout,
    )
    if proc.returncode != 0:
        raise GitError(args, proc.returncode, proc.stderr.decode("utf-8", "surrogateescape"))
    return proc.stdout


def _regular_blobs(
    cwd: Path, rev: str, pathspec: str, *, timeout: float | None,
) -> list[tuple[str, str]]:
    """`(oid, repo-relative path)` of every regular-file blob under `pathspec` at `rev`, nested
    folders included (`ls-tree -r -z`, the pathspec taken literally); a symlink or submodule
    entry is left out. An unknown `rev` raises `GitError`."""
    listing = _run_bytes(["--literal-pathspecs", "ls-tree", "-r", "-z", "--full-name", rev,
                          "--", pathspec], cwd=cwd, env=committed_view_env(rev),
                         timeout=timeout)
    wanted: list[tuple[str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _tab, raw_path = record.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split(" ")
        if kind == "blob" and mode in _REGULAR_BLOB_MODES:
            wanted.append((oid, raw_path.decode("utf-8", "surrogateescape")))
    return wanted


def git_tree_blobs(
    cwd: Path, rev: str, pathspec: str, *, timeout: float | None = None,
) -> dict[str, bytes]:
    """Every regular-file blob under `pathspec` at `rev`, nested folders included, by its
    repo-relative path, with its exact stored bytes (`ls-tree -r` then one `cat-file --batch`):
    git's own read of a commit (#1134 addendum 2 correction, C1), which no worktree entry can
    redirect. A symlink (mode 120000) or submodule entry is left out, so nothing restores it as a
    file. A `pathspec` `rev` does not carry answers `{}`; an unknown `rev` or a missing object
    raises `GitError`. The bytes are the blob's, unfiltered, and the commit's own: replace objects
    are ignored (`committed_view_env`). `timeout` bounds each git process; `TimeoutExpired`."""
    wanted = _regular_blobs(cwd, rev, pathspec, timeout=timeout)
    if not wanted:
        return {}
    batch_args = ["cat-file", "--batch"]
    out = _run_bytes(batch_args, cwd=cwd, input="".join(f"{oid}\n" for oid, _ in wanted).encode(),
                     env=committed_view_env(rev), timeout=timeout)
    blobs: dict[str, bytes] = {}
    pos = 0
    for oid, path in wanted:
        end = out.index(b"\n", pos)
        header = out[pos:end].decode("ascii").split(" ")
        if len(header) != 3 or header[0] != oid:
            raise GitError(batch_args, 0, f"{oid}: {' '.join(header[1:]) or 'no answer'}")
        size = int(header[2])
        blobs[path] = out[end + 1:end + 1 + size]
        pos = end + 1 + size + 1
    return blobs


#: `git diff`'s options for a comparison of raw bytes: the executable bit ignored (a mode-only
#: change is no content change), no end-of-line conversion from config, a symlink kept a symlink,
#: and the stat-dirty but identical file re-hashed rather than reported.
_RAW_COMPARE = ("-c", "core.fileMode=false", "-c", "core.autocrlf=false",
                "-c", "core.symlinks=true", "-c", "diff.autoRefreshIndex=true",
                "--literal-pathspecs")


def git_unchanged_since(
    cwd: Path, rev: str, pathspec: str, *, timeout: float | None = None,
) -> frozenset[str]:
    """The repo-relative paths of the regular files `rev` carries under `pathspec` (nested
    included) that git still finds unchanged in the working tree: still a regular file, with the
    same bytes. Git's own comparison (#1134 addendum 3, D1; N-a): it lstats each entry, so a
    symlink is a type change and a FIFO, a folder or nothing at the name is a change, none of them
    followed or opened; it hashes a regular file's content, a hard link's included. The executable
    bit is ignored, and attributes come from `rev`'s tree (`GIT_ATTR_SOURCE`, git 2.42+), never
    from a `.gitattributes` in the worktree, so no end-of-line conversion makes changed bytes
    compare equal; replace objects are ignored, so the comparison is with the commit's own blobs
    (`committed_view_env`). A path `rev` does not carry as a regular file is never in the answer.
    A git failure (an unknown `rev`, an unreadable index, no repository) raises `GitError`;
    `timeout` bounds each git process (`TimeoutExpired`)."""
    carried = {path for _oid, path in _regular_blobs(cwd, rev, pathspec, timeout=timeout)}
    if not carried:
        return frozenset()
    args = [*_RAW_COMPARE, "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff",
            "--no-textconv", rev, "--", pathspec]
    out = _run_bytes(args, cwd=cwd, env=committed_view_env(rev), timeout=timeout)
    changed = {p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p}
    return frozenset(carried - changed)


def git_worktree_files(cwd: Path, pathspec: str, *, timeout: float | None = None) -> list[str]:
    """Every file under `pathspec` in the working tree that `.gitignore` does not exclude, by its
    repo-relative path, nested folders included: git's own walk of the worktree (`ls-files
    --others --exclude-standard`) run against an index file that does not exist, which git reads
    as an empty index — so the repo's real index is never opened and every such file counts as
    "other". For a caller whose `git status` failed on a broken index (#1134 addendum 2
    correction, C1: git names the names; nothing here lists a folder in Python). The index path
    is a fresh name in the repo's git dir, never written (`ls-files` writes no index). A git
    failure raises `GitError`; `timeout` bounds each git process (`TimeoutExpired`: a FIFO at a
    `.gitignore` blocks the walk)."""
    absent_index = git(["rev-parse", "--path-format=absolute", "--git-path",
                        f"curator-absent-index-{uuid.uuid4().hex}"], cwd=cwd, timeout=timeout)
    args = ["ls-files", "--others", "--exclude-standard", "-z", "--", pathspec]
    out = _run_bytes(args, cwd=cwd, env={**os.environ, "GIT_INDEX_FILE": absent_index},
                     timeout=timeout)
    return [p.decode("utf-8", "surrogateescape") for p in out.split(b"\0") if p]


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
    present: Sequence[str],
    absent: Sequence[str],
    message: str,
    *,
    trailers: list[tuple[str, str]] | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """Stage exactly `present` (added) and `absent` (deleted) and commit them; `None` if nothing
    changed. `env` is every git call's environment (`None`: this process's).

    The caller says which paths still stand in the worktree: this module asks the filesystem
    nothing (#1134 — the drain judges present from absent through its mount handle). `git add`
    refuses the whole call if any path is gone from both worktree and index ("did not match any
    files"), so absent paths go through `git rm --cached --ignore-unmatch`, a no-op when the
    index no longer has them. Nothing to stage returns `None` without calling git: `git commit
    -F - --` with an empty pathspec would commit the whole index, sweeping in whatever else is
    staged."""
    paths = [*present, *absent]
    if not paths:
        return None
    if present:
        git(["add", "--", *present], cwd=cwd, env=env)
    if absent:
        git(["rm", "--cached", "--ignore-unmatch", "-q", "--", *absent], cwd=cwd, env=env)
    staged = _run(["diff", "--cached", "--quiet", "--", *paths], cwd=cwd, check=False, env=env)
    if staged.returncode == 0:
        return None
    if staged.returncode != 1:
        raise GitError(["diff", "--cached", "--quiet"], staged.returncode, staged.stderr)
    trailer_args: list[str] = []
    for key, val in trailers or []:
        trailer_args += ["--trailer", f"{key}: {val}"]
    git(["commit", "-F", "-", *trailer_args, "--", *paths], cwd=cwd, input=message, env=env)
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
