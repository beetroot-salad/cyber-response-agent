from __future__ import annotations

import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from defender.execution._process_group import kill_group

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


#: What a git call bounded by `timeout=` raises when git does not answer in time: subprocess's own
#: class, unconverted (`cli/tenant.py` catches it by that name), named here so a caller of this
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
    pass_fds: Sequence[int] = (),
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
        pass_fds=tuple(pass_fds),
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
    pass_fds: Sequence[int] = (),
) -> str:
    """`git <args>`, its trimmed output; a non-zero exit raises `GitError` when `check`.
    `pass_fds` are descriptors the git process (and what it spawns) inherits, as
    `subprocess.run` passes them."""
    return _run(args, cwd=cwd, check=check, timeout=timeout, input=input, env=env,
                pass_fds=pass_fds).stdout.strip()


def git_network(
    args: Sequence[str], *, cwd: Path, env: Mapping[str, str], timeout: float,
    pass_fds: Sequence[int] = (),
) -> str:
    """`git <args>` for a call that talks to a remote (a fetch, `ls-remote`, a push), its
    trimmed output. Git runs in a session of its own, so it and every process it starts (its
    `git-remote-http`, a credential helper) form one process group; the call is bounded by a
    wall `timeout`, and on any way out of it (git's exit, the timeout, or an exception or
    interrupt raised into the wait) that whole group is killed before anything surfaces. A
    kill of git alone (`subprocess.run(timeout=)`) leaves its helper running, orphaned, still
    talking to the remote (#1108 amendment 3, C4). A non-zero exit raises `GitError`; the
    timeout, `GitTimeout`. `pass_fds` are descriptors git and its children inherit."""
    with subprocess.Popen(  # noqa: S603 — fixed argv
            ["git", *args], cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=tuple(pass_fds),
            start_new_session=True) as proc:
        try:
            out, err = proc.communicate(timeout=timeout)
        finally:
            # The group is git's own session (`start_new_session`), its id git's pid. On a
            # timeout, exception or interrupt git is not yet reaped, so the id is still its
            # own; after git's exit (reaped) it is held by any member still alive, and with
            # none the kill finds no group.
            kill_group(proc.pid)
    if proc.returncode != 0:
        raise GitError(args, proc.returncode, err.decode("utf-8", "surrogateescape"))
    return out.decode("utf-8", "surrogateescape").strip()


def git_ok(
    args: Sequence[str], *, cwd: Path = REPO_ROOT, timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> bool:
    return _run(args, cwd=cwd, check=False, timeout=timeout, env=env).returncode == 0


def git_status(
    cwd: Path, *, pathspec: Path | str | None = None, timeout: float | None = None,
    no_renames: bool = False, env: Mapping[str, str] | None = None, untracked: str = "all",
) -> list[tuple[str, str]]:
    """The working tree's status as `(XY, path)` records.

    `no_renames` turns off rename detection, for callers counting changed paths: otherwise
    `git mv a b` is one `R  b` record and `a` is dropped; with it, `D  a` and `A  b`.

    `untracked` is `--untracked-files`: `"no"` lists tracked paths only, and then git walks no
    folder for new files, so it opens no worktree `.gitignore` (#1175).
    """
    args = ["status", "--porcelain", f"--untracked-files={untracked}", "-z"]
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


def git_head_sha(cwd: Path, *, timeout: float | None = None) -> str:
    return git(["rev-parse", "HEAD"], cwd=cwd, timeout=timeout)


def git_show_file(
    cwd: Path, rev: str, path: str, *, timeout: float | None = None,
    env: Mapping[str, str] | None = None,
) -> str | None:
    """The text a path carries at `rev`, or `None` when it is not there.

    Not `git()`, which strips output: a stripped trailing newline would read as an edit when
    compared against the working tree."""
    proc = _run(["show", f"{rev}:{path}"], cwd=cwd, check=False, timeout=timeout, env=env)
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_blob_bytes(cwd: Path, sha: str, *, env: Mapping[str, str] | None = None,
                   timeout: float | None = None) -> bytes:
    """The raw bytes of the blob `sha` (`cat-file blob`): no filter, no line-ending
    conversion and no configured command applied. `GitError` when git cannot answer."""
    return _run_bytes(["cat-file", "blob", sha], cwd=cwd, env=env, timeout=timeout)


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


def git_bytes(
    args: Sequence[str], *, cwd: Path, input: bytes | None = None,
    env: Mapping[str, str] | None = None, timeout: float | None = None,
) -> bytes:
    """`git <args>` with raw bytes in and out, untrimmed: for blob bytes and NUL-framed
    listings, where a stripped or decoded answer would change what was stored. A non-zero
    exit raises `GitError`; `timeout` passing first, `subprocess.TimeoutExpired`."""
    return _run_bytes(args, cwd=cwd, input=input, env=env, timeout=timeout)


def tree_records(listing: bytes, *, errors: str = "surrogateescape") -> list[tuple[str, str, str, str]]:
    """`(mode, kind, oid, path)` of every record of a NUL-framed `ls-tree -z` listing, in its
    order: no path is quoted or trimmed, and each is decoded as UTF-8 under `errors` (`strict`
    for a caller that refuses a name git cannot be given as text)."""
    records = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _tab, raw_path = record.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split(" ")
        records.append((mode, kind, oid, raw_path.decode("utf-8", errors)))
    return records


def blob_batch(args: Sequence[str], out: bytes, oids: Sequence[str]) -> list[bytes]:
    """Each blob's exact bytes from the output `out` of `git <args>` (a `cat-file --batch` that
    was asked for `oids`, in that order). An answer that is not that blob (missing, another
    object, another kind) raises `GitError` naming it."""
    blobs = []
    pos = 0
    for oid in oids:
        end = out.find(b"\n", pos)
        header = out[pos:end].decode("ascii", "replace").split(" ") if end >= 0 else []
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise GitError(args, 0, f"{oid}: {' '.join(header[1:]) or 'no answer'}")
        size = int(header[2])
        blobs.append(out[end + 1:end + 1 + size])
        pos = end + 1 + size + 1
    return blobs


