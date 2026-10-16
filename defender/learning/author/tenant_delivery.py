"""Dormant tenant delivery (#1108 P3, amendment 2); P4 wires drains and runs onto it.

Boxes see only host-made copies; git and the tenant's forge credential never touch a box's
folders, and only host code here reads or writes git.

- `publish` fetches (no lock held), then under the tenant's knowledge lock fast-forwards the
  clone and writes a `TenantExport` from git objects: `<T>/exports/<commit>/`, immutable, with
  `<T>/exports/current` replaced atomically to name it. `current_export` reads it back without
  git.
- A `Batch` is a host-only worktree of the clone at the export commit, attached to the batch
  branch and never mounted, plus a git-free `Draft` copy of its `agent/` under
  `<T>/drafts/<batch>/`. The box mounts the draft's root read-only (`staged`) and only the
  batch's lanes writable.
- Per claim the host derives a `ChangeSet` (the draft against the worktree: regular files in
  the batch's lanes and nothing else), the commit-maker (`Batch.commit`, the one maker of
  tenant commits) commits it as plain 100644 blobs, and `Batch.reset` re-syncs the draft.
- Every push route (finish, retained deliver, revert) sends only commits the commit-maker made,
  by its record under `<T>/learning/`, which outlives the process that made them.
- Git runs with every credential helper reset and one helper that answers only `get`, only for
  the forge's own scheme, host and port, with the credential `TenantDelivery.open` read (the
  file's single reader), handed over an inherited pipe: never in a process's argument list or
  environment, never in another file. No prompt can run.
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import secrets
import shutil
import stat
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, TYPE_CHECKING
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    import httpx

from defender import _flock, _git, _io
from defender._tenant import Tenant, TenantRefused, parse_tenant_id_bytes
from defender.learning.author.branch import LESSONS_BRANCH_PREFIX
from defender.learning.author.forge import ForgeError, ForgejoForge
from defender.runtime import box
from defender.runtime.box._docker import DockerFn, _docker
from defender.runtime.box._lifecycle import _start_boxed_request

_logger = logging.getLogger(__name__)


class DeliveryRefused(Exception):
    """The tenant cannot safely author or deliver this; the message names why."""


class LockBusy(DeliveryRefused):
    """Another process holds the tenant's knowledge lock: raised at once, naming its pid."""


@contextlib.contextmanager
def _refusals() -> Iterator[None]:
    """Every fault below a public call, as the one refusal type callers handle. A `TypeError`
    (a caller handing the commit-maker something that is not a `ChangeSet`) is a programming
    error and passes through."""
    try:
        yield
    except DeliveryRefused:
        raise
    except (_git.GitError, _git.GitTimeout, ForgeError, TenantRefused, OSError, ValueError) as e:
        raise DeliveryRefused(str(e)) from e


# ==========================================================================================
# Names: a commit's paths, a batch's lanes, a branch word
# ==========================================================================================

#: Names no change may carry at any depth: git's own metadata and the files that reconfigure
#: how git reads a tree (amendment 2, O-C). Compared without case, as a case-folding checkout
#: would read them.
_GIT_CONTROL_NAMES = frozenset({".git", ".gitattributes", ".gitignore", ".gitmodules"})
#: The tenant's identity marker, checked once at publish and never changed by a commit.
_TENANT_ID_PARTS = ("agent", ".tenant-id")
#: What a batch id or a reverted lesson's name may be: one word that is at once a branch-name
#: component, a folder name and a container-name part.
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
#: A full git object id (SHA-1 or SHA-256).
_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
#: Tree entry modes of a regular file.
_REGULAR_MODES = frozenset({"100644", "100755"})


def _plain_component(part: str) -> bool:
    """A path component that names one plain entry: not empty, not a dot segment, no control
    character, not led by whitespace, and UTF-8 (a name that does not encode is refused)."""
    if part in {"", ".", ".."} or part[0].isspace():
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in part):
        return False
    try:
        part.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _agent_path(path: object) -> str:
    """`path` as a commit path: repo-relative POSIX below `agent/`, every component plain, never
    `agent/.tenant-id` and never a git control name at any depth. A refusal names it."""
    if not isinstance(path, str):
        raise TypeError(f"an agent path is a str, not {type(path).__name__}")
    parts = tuple(path.split("/"))
    if len(parts) < 2 or parts[0] != "agent" or not all(_plain_component(p) for p in parts):
        raise DeliveryRefused(f"{path!r} is not a plain path below agent/")
    if parts == _TENANT_ID_PARTS:
        raise DeliveryRefused("agent/.tenant-id is the tenant's identity: no change may touch it")
    if any(part.casefold() in _GIT_CONTROL_NAMES for part in parts):
        raise DeliveryRefused(f"{path!r} names a git control file: no change may carry one")
    return path


def _lane(lane: object) -> tuple[str, ...]:
    """A lane, a folder below `agent/` a batch's box may write, as its components."""
    if not isinstance(lane, str):
        raise TypeError(f"a lane is a str, not {type(lane).__name__}")
    parts = tuple(lane.split("/"))
    if not all(_plain_component(p) for p in parts) or any(
            p.casefold() in _GIT_CONTROL_NAMES for p in parts):
        raise DeliveryRefused(f"lane {lane!r} is not a plain folder below agent/")
    return parts


def _lanes(lanes: object) -> tuple[str, ...]:
    if isinstance(lanes, str) or not isinstance(lanes, Iterable):
        raise TypeError("lanes are a sequence of folder names below agent/")
    declared = tuple(lanes)
    for lane in declared:
        _lane(lane)
    if not declared or len(set(declared)) != len(declared):
        raise DeliveryRefused(f"a batch declares one or more distinct lanes, not {declared!r}")
    return declared


def _in_lanes(path: str, lanes: Sequence[str]) -> bool:
    """`agent/<lane>/...`: strictly below one lane, compared by components, so a sibling whose
    name begins with a lane's (`lessons-questioner` beside `lessons`) is outside it."""
    below = path.split("/")[1:]
    return any(len(below) > len(parts) and tuple(below[:len(parts)]) == parts
               for parts in map(_lane, lanes))


def _require_in_lanes(path: str, lanes: Sequence[str]) -> None:
    if not _in_lanes(path, lanes):
        raise DeliveryRefused(f"{path!r} is outside the lanes {list(lanes)}: no change may carry it")


def _one_word(word: object, what: str) -> str:
    if not isinstance(word, str) or not _WORD.fullmatch(word):
        raise DeliveryRefused(f"{what} {word!r} is not one word of letters, digits, '-' or '_'")
    return word


# ==========================================================================================
# ChangeSet: the commit-maker's sole input
# ==========================================================================================

@dataclass(frozen=True)
class AgentChange:
    """One file's new state: `path` repo-relative POSIX below `agent/`; `content` its exact
    bytes, or `None` when the file is deleted."""

    path: str
    content: bytes | None

    def __post_init__(self) -> None:
        _agent_path(self.path)
        if self.content is not None and not isinstance(self.content, bytes):
            raise TypeError(f"the content of {self.path!r} is bytes or None, not "
                            f"{type(self.content).__name__}")
        # Plain `str` and `bytes`, whatever subclass was given: nothing reachable from a change
        # can be changed after it is built.
        object.__setattr__(self, "path", str.__str__(self.path))
        if self.content is not None:
            object.__setattr__(self, "content", bytes(self.content))


@dataclass(frozen=True)
class ChangeSet:
    """An immutable set of `AgentChange`s, at most one per path: the only thing the
    commit-maker commits. Built from a draft (`Batch.change_set`) or from history (revert)."""

    changes: tuple[AgentChange, ...]

    def __post_init__(self) -> None:
        changes = tuple(self.changes)
        if not all(isinstance(change, AgentChange) for change in changes):
            raise TypeError("a ChangeSet holds AgentChange values only")
        paths = [change.path for change in changes]
        if len(set(paths)) != len(paths):
            raise DeliveryRefused(f"a change set names a path twice: {sorted(paths)}")
        object.__setattr__(self, "changes", changes)

    def __iter__(self) -> Iterator[AgentChange]:
        return iter(self.changes)

    def __len__(self) -> int:
        return len(self.changes)


# ==========================================================================================
# Host-side tree reads and writes, never following a link
# ==========================================================================================

def _regular_files(root: Path) -> dict[str, bytes]:
    """Every regular file below `root`, by POSIX relative path, with its bytes: walked and read
    with no link followed and no FIFO opened, each file under `READ_LIMIT` (`_io.bind`). Any
    other entry (a link, a symlinked folder, a FIFO, socket or device), an oversized file or one
    that cannot be read refuses the whole read, naming it: nothing is skipped."""
    files: dict[str, bytes] = {}
    with _io.bind(root) as bound:
        pending = [""]
        while pending:
            folder = pending.pop()
            listed = _io.stat_entries(bound.under(folder) if folder else bound)
            if listed.stats is None:
                raise DeliveryRefused(f"{root / folder} could not be listed: "
                                      f"{listed.refusal or 'it is absent'}")
            for name, st in sorted(listed.stats.items()):
                rel = f"{folder}/{name}" if folder else name
                if stat.S_ISDIR(st.st_mode):
                    pending.append(rel)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise DeliveryRefused(f"{root / rel} is not a regular file or a folder "
                                          f"(mode {stat.filemode(st.st_mode)}): refused whole")
                if st.st_size > _io.READ_LIMIT:
                    raise DeliveryRefused(f"{root / rel} is larger than {_io.READ_LIMIT} bytes: "
                                          "refused whole")
                read = bound.read_bytes(rel)  # lint-whole-read: ok — `_io.Bound`, which enforces READ_LIMIT and the no-follow guards
                if read.data is None:
                    raise DeliveryRefused(f"{root / rel} could not be read: "
                                          f"{read.refusal or 'it vanished'}: refused whole")
                files[rel] = read.data
    return files


def _folders_of(files: Iterable[str], extra: Iterable[str] = ()) -> frozenset[str]:
    """Every folder (POSIX relative path) holding one of `files` or named in `extra`, with its
    ancestors."""
    folders: set[str] = set()
    for rel in (*(f.rpartition("/")[0] for f in files), *extra):
        parts = [p for p in rel.split("/") if p]
        folders.update("/".join(parts[:n]) for n in range(1, len(parts) + 1))
    return frozenset(folders)


#: A folder opened to work below it: no link followed, never handed to a child.
_FOLDER_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _resync(root: Path, files: dict[str, bytes], folders: frozenset[str]) -> None:
    """Make the real folder `root` hold exactly `files` (as plain files with those bytes) and
    `folders`, in place: what matches stays, everything else is removed as the entry it is (a
    link unlinked, never followed; a FIFO unlinked, never opened; a folder removed with no link
    below it followed), and what is missing is created exclusively. Every step is relative to a
    held, no-follow folder descriptor, so an entry swapped mid-sync is never written through.
    In place, so a writable lane bound into a running box keeps its folder."""
    fd = os.open(root, _FOLDER_FLAGS)
    try:
        _resync_at(fd, "", files, folders)
    finally:
        os.close(fd)


def _resync_at(dir_fd: int, prefix: str, files: dict[str, bytes], folders: frozenset[str]) -> None:
    here_files = {rel[len(prefix):]: data for rel, data in files.items()
                  if rel.startswith(prefix) and "/" not in rel[len(prefix):]}
    here_folders = {rel[len(prefix):] for rel in folders
                    if rel.startswith(prefix) and "/" not in rel[len(prefix):]}
    with os.scandir(dir_fd) as entries:
        present = {entry.name: entry.stat(follow_symlinks=False) for entry in entries}
    kept: set[str] = set()
    for name, st in present.items():
        if ((name in here_folders and stat.S_ISDIR(st.st_mode))
                or (name in here_files and _holds(dir_fd, name, here_files[name]))):
            kept.add(name)
        elif stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=dir_fd)
        else:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(name, dir_fd=dir_fd)
    for name in sorted(here_folders):
        if name not in kept:
            os.mkdir(name, 0o755, dir_fd=dir_fd)  # lint-unguarded-tree-write: ok — made relative to a held no-follow folder descriptor; an entry planted at the name fails it (EEXIST)
        child = os.open(name, _FOLDER_FLAGS, dir_fd=dir_fd)
        try:
            _resync_at(child, f"{prefix}{name}/", files, folders)
        finally:
            os.close(child)
    for name, data in sorted(here_files.items()):
        if name not in kept:
            _create_new_at(dir_fd, name, data)


def _holds(dir_fd: int, name: str, data: bytes) -> bool:
    """Is `name` a plain, single-linked regular file holding exactly `data`? Opened no-follow
    and non-blocking (a link or FIFO is not followed or waited on) and judged on the opened
    descriptor; any fault answers no, and the caller removes the entry."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=dir_fd)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not _io.is_plain_entry(st) or st.st_size != len(data):
            return False
        with os.fdopen(os.dup(fd), "rb") as handle:
            return handle.read(len(data) + 1) == data
    except OSError:
        return False
    finally:
        os.close(fd)


def _create_new_at(dir_fd: int, name: str, data: bytes) -> None:
    """A new plain file `name` holding `data`, created exclusively relative to `dir_fd` with no
    link followed: an entry already at the name fails it."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o644, dir_fd=dir_fd)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


# ==========================================================================================
# Exports and the per-tenant lock
# ==========================================================================================

#: The pointer file in `<T>/exports/` naming the latest published export.
_POINTER = "current"
#: The name an export is written under before it is renamed into place.
_STAGING_PREFIX = ".publishing-"


def _sweep_staging(exports: Path) -> None:
    """Remove every staging folder a publisher cut off left in `exports/`, as the entry it is
    (a folder removed with no link below it followed; anything else unlinked). Called under
    the tenant's lock, so no live publisher is writing one."""
    if not _io.entry_present(exports):
        return
    fd = os.open(exports, _FOLDER_FLAGS)
    try:
        with os.scandir(fd) as entries:
            stale = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in entries
                     if entry.name.startswith(_STAGING_PREFIX)]
        for name, is_folder in stale:
            if is_folder:
                shutil.rmtree(name, dir_fd=fd)
            else:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class TenantExport:
    """The tenant's knowledge at one commit: `path` (`<T>/exports/<commit>/`) holds exactly that
    commit's `agent/` and `settings/` regular blobs, written from git objects by the host and
    never changed once published."""

    commit: str
    path: Path


def current_export(tenant: Tenant) -> TenantExport:
    """The export `<T>/exports/current` names, read from the files alone: no git and no process
    (P4's runs have neither). An absent or empty pointer, one that is not an object id (one
    leading out of `exports/` included), or one naming a missing export is `DeliveryRefused`."""
    exports = tenant.exports
    with _io.bind(exports) as folder:
        # Text, decoded with replacement: an oid is ASCII, so any byte that is not fails the
        # match below rather than the read.
        pointer = folder.read(_POINTER, errors="replace")
        if pointer.text is None:
            why = "it is absent" if pointer.absent else pointer.refusal
            raise DeliveryRefused(f"no export is published for tenant {tenant.id}: "
                                  f"{exports / _POINTER}: {why}")
        commit = pointer.text.removesuffix("\n")
        if not _OID.fullmatch(commit):
            raise DeliveryRefused(f"the export pointer {exports / _POINTER} names no published "
                                  f"export: {pointer.text[:80]!r}")
        found = _io.stat_entry(folder, commit)
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        raise DeliveryRefused(f"the export pointer {exports / _POINTER} names {commit}, which is "
                              "not a published export folder")
    return TenantExport(commit=commit, path=exports / commit)


def _lock_holder(handle: IO[str]) -> str:
    """Who holds the lock, as its holder wrote it: `pid <n>`. A holder writes its pid as soon
    as it has the lock, so an empty file is read again briefly before giving up on naming it."""
    for _attempt in range(25):
        handle.seek(0)
        written = handle.read(32).strip()
        if written.isdigit():
            return f"pid {written}"
        time.sleep(0.02)
    return "another process (its pid is not written yet)"


@contextlib.contextmanager
def tenant_lock(tenant: Tenant) -> Iterator[None]:
    """The tenant's knowledge lock (`<T>/knowledge.lock`, under the tenant's own folder, never
    `forge/`): held for a fast-forward, an export publish and a worktree's creation or removal,
    never across network I/O or a box window. A second taker fails at once with `LockBusy`
    naming the holder's pid; it never waits."""
    path = tenant.knowledge_lock
    with _io.hold(path.parent) as folder:
        handle = _io.open_lock_at(folder, path.name)
    try:
        if not _flock.take(handle, timeout_seconds=0):
            raise LockBusy(f"tenant {tenant.id}'s knowledge lock {path} is held by "
                           f"{_lock_holder(handle)}: another publish, batch or revert is "
                           "changing its clone; try again once it finishes")
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        yield
    finally:
        _flock.release(handle)


# ==========================================================================================
# The commit-maker's record
# ==========================================================================================

@dataclass(frozen=True)
class _Made:
    """One commit the commit-maker made: its lanes, and per path the blob before and after it
    (`None`: absent). Read back by every push route and by revert."""

    commit: str
    lanes: tuple[str, ...]
    changes: tuple[tuple[str, str | None, str | None], ...]


def _record_made(tenant: Tenant, made: _Made) -> None:
    """Append `made` to the tenant's commit-maker record, durably, before the commit is put on
    any branch: a crash in between leaves a recorded commit no branch holds, never a branch
    holding an unrecorded one."""
    row = {"commit": made.commit, "lanes": list(made.lanes),
           "changes": [{"path": p, "before": b, "after": a} for p, b, a in made.changes]}
    record = tenant.commit_record
    _io.rooted_mkdir(record.parent, ".")
    _io.rooted_write(record.parent, record.name, json.dumps(row, sort_keys=True) + "\n",  # lint-jsonl-io: ok — one durable, no-follow append of one JSON row to the host-only commit-maker record
                     mode="append", durable=True)


def _oid_or_none(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and _OID.fullmatch(value):
        return value
    raise ValueError(f"not an object id: {value!r}")


def _parse_made(row: dict) -> _Made:
    """One record row as `_Made`; `ValueError` for a row of any other shape."""
    commit, lanes, changes = row.get("commit"), row.get("lanes"), row.get("changes")
    if (not isinstance(commit, str) or not _OID.fullmatch(commit) or not isinstance(lanes, list)
            or not all(isinstance(lane, str) for lane in lanes) or not isinstance(changes, list)):
        raise ValueError("not a commit-maker record row")
    parsed: list[tuple[str, str | None, str | None]] = []
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("path"), str):
            raise ValueError("not a commit-maker change")
        parsed.append((change["path"], _oid_or_none(change.get("before")),
                       _oid_or_none(change.get("after"))))
    return _Made(commit=commit, lanes=tuple(lanes), changes=tuple(parsed))


def _made_commits(tenant: Tenant) -> list[_Made]:
    """Every commit the commit-maker recorded for this tenant, oldest first. A row of another
    shape records nothing (a torn last line from a crash among them): its commit is then
    refused by every push route, failing closed. An unreadable record refuses."""
    record = tenant.commit_record
    with _io.bind(record.parent) as folder:
        rows, malformed, read = folder.read_jsonl(record.name)
    if read.reason is not None:
        raise DeliveryRefused(f"the commit-maker's record {record} could not be read: "
                              f"{read.refusal}")
    made: list[_Made] = []
    for row in rows:
        try:
            made.append(_parse_made(row))
        except ValueError:
            malformed += 1
    if malformed:
        _logger.warning("the commit-maker's record %s holds %d rows of another shape; their "
                        "commits count as not made by it", record, malformed)
    return made


# ==========================================================================================
# Git: the environment, the credential helper
# ==========================================================================================

#: The most a credential answer may hold: it is written whole into a fresh pipe before git
#: starts, so it must fit the pipe's buffer (64 KiB on Linux) without blocking.
_ANSWER_LIMIT = 16 * 1024


def _credential_helper(fd: int) -> str:
    """The one credential helper git consults (amendment 2, flow 5), as a shell snippet: it
    drains git's request, answers only `get`, by copying out the answer written into the
    inherited pipe `fd` from the credential `TenantDelivery.open` read (`/dev/fd/<fd>`: a
    shell redirection cannot name a descriptor above 9), and ignores `store` and `erase`, so
    no git operation can rewrite or empty the credential file. The snippet holds no
    credential."""
    return f'!f() {{ cat >/dev/null; test "$1" = get || exit 0; cat /dev/fd/{fd}; }}; f'


def _credential_answer(user: str, token: str) -> bytes:
    """What the helper hands git for `get`, in git's credential format."""
    return f"username={user}\npassword={token}\n".encode()


def _local_env() -> dict[str, str]:
    """Every git call's environment: nothing that relocates the repository (`GIT_DIR`,
    `GIT_WORK_TREE`, ...), no replace objects, pathspecs taken literally, and no prompt: an
    empty `GIT_ASKPASS` stops `core.askPass` and `SSH_ASKPASS`, and the terminal prompt is off."""
    env = _git.env_for_cwd()
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_LITERAL_PATHSPECS="1", GIT_TERMINAL_PROMPT="0",
               GIT_ASKPASS="")
    return env


def _cat_blobs(repo: Path, oids: Iterable[str], env: dict[str, str]) -> dict[str, bytes]:
    """Each blob's exact stored bytes, by id, in one `cat-file --batch`."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}
    out = _git.git_bytes(["cat-file", "--batch"], cwd=repo, env=env,
                         input="".join(f"{oid}\n" for oid in wanted).encode("ascii"))
    blobs: dict[str, bytes] = {}
    pos = 0
    for oid in wanted:
        end = out.index(b"\n", pos)
        header = out[pos:end].decode("ascii", "replace").split(" ")
        if len(header) != 3 or header[0] != oid or header[1] != "blob":
            raise DeliveryRefused(f"git could not read the blob {oid}: {' '.join(header[1:])}")
        size = int(header[2])
        blobs[oid] = out[end + 1:end + 1 + size]
        pos = end + 1 + size + 1
    return blobs


def _tree_entries(repo: Path, rev: str, paths: Sequence[str], env: dict[str, str], *,
                  recursive: bool) -> list[tuple[str, str, str, str]]:
    """`(mode, kind, oid, path)` of each entry `rev` holds at `paths` (below them too, when
    `recursive`), NUL-framed so no path is quoted or trimmed."""
    args = ["ls-tree", "-z", "--full-tree", *(["-r"] if recursive else []), rev, "--", *paths]
    entries = []
    for record in _git.git_bytes(args, cwd=repo, env=env).split(b"\0"):
        if not record:
            continue
        meta, _tab, raw_path = record.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split(" ")
        entries.append((mode, kind, oid, raw_path.decode("utf-8")))
    return entries


# ==========================================================================================
# The batch
# ==========================================================================================

@dataclass
class _Line:
    """A host-only worktree of the clone, attached to one branch: where the commit-maker
    commits. `base` is the commit it was cut at, `tip` the last commit the commit-maker put
    on the branch (the base until it has made one)."""

    worktree: Path
    branch: str
    base: str
    tip: str
    lanes: tuple[str, ...]


@dataclass(eq=False)
class Batch:
    """One drain batch: the host-only `worktree` (attached to `branch`, cut at `export`'s
    commit, never mounted) and the git-free draft under `draft_root` its box writes into,
    through `lanes` only."""

    id: str
    branch: str
    export: TenantExport
    worktree: Path
    draft_root: Path
    lanes: tuple[str, ...]
    _delivery: TenantDelivery = field(repr=False)
    _line: _Line = field(repr=False)

    def box_request(self) -> box.BoxRequest:
        """The drain box: product code read-only (`code`), the draft's root read-only (`staged`),
        and each lane writable inside it. Never the worktree, the clone, an export, `settings/`,
        `.git` or `forge/`. `agent/` is the workdir and `DEFENDER_AGENT_DIR`."""
        agent = self.draft_root / "agent"
        code = self._delivery.defender_dir
        mounts = [box.Mount(source=code, target=code, kind="code"),
                  box.Mount(source=self.draft_root, target=self.draft_root, kind="staged"),
                  *(box.Mount(source=agent / lane, target=agent / lane, writable=True)
                    for lane in self.lanes)]
        return box.BoxRequest(
            name=f"defender-tenant-{self._delivery.tenant.id}-{self.id}", mounts=tuple(mounts),
            workdir=agent, defender_dir=code, require_sandbox=True,
            env={"DEFENDER_AGENT_DIR": str(agent)},
        )

    def change_set(self) -> ChangeSet:
        """The claim: the draft's `agent/` against the branch's last commit (the worktree's
        `HEAD`), as changes. The base is read from git's objects, not the worktree's checkout,
        so attributes on `main` (`eol`, `ident`, a filter) never show a change the box did not
        make. Only regular files in the lanes may differ; any other entry anywhere in the
        draft, an oversized file, a change outside the lanes or one touching a forbidden name
        refuses the claim whole."""
        with _refusals():
            draft = _regular_files(self.draft_root / "agent")
            base = self._delivery._agent_blobs(self._line.tip)
            changes = []
            for rel in sorted(draft.keys() | base.keys()):
                if draft.get(rel) == base.get(rel):
                    continue
                change = AgentChange(f"agent/{rel}", draft.get(rel))
                _require_in_lanes(change.path, self.lanes)
                changes.append(change)
            return ChangeSet(tuple(changes))

    def commit(self, change_set: ChangeSet, message: str) -> str:
        """The commit-maker: commit `change_set` on the batch branch, returning the commit."""
        return self._delivery._commit(self._line, change_set, message)

    def reset(self) -> None:
        """Re-sync the draft's `agent/` with the branch's last commit, in place, from git's
        objects: the box's additions removed, its deletions and edits restored, links and
        FIFOs removed without being followed or opened. The lanes stay, so a running box keeps
        its binds."""
        with _refusals():
            files = self._delivery._agent_blobs(self._line.tip)
            _resync(self.draft_root / "agent", files, _folders_of(files, self.lanes))


# ==========================================================================================
# Delivery
# ==========================================================================================

@dataclass(frozen=True, eq=False)
class TenantDelivery:
    """One accepted tenant's host-side delivery, built by `open`; no credential in its repr."""

    tenant: Tenant
    defender_dir: Path
    forge: ForgejoForge = field(repr=False)
    _origin: str = field(repr=False)
    _user: str = field(repr=False)
    _token: str = field(repr=False)
    branch_prefix: str = LESSONS_BRANCH_PREFIX

    @classmethod
    def open(cls, accepted_tenant: Tenant, *, defender_dir: Path,
             client: httpx.Client) -> TenantDelivery:
        """The dormant factory, and the credential file's single reader. Refuses (O9) a tenant
        whose knowledge is not its own git repository, has no `main`, has no network `origin`,
        or has no credential agreeing with that origin's scheme, host and port; then refuses
        unless the forge reports `main` protected and not pushable by the bot (A10)."""
        with _refusals():
            repo = accepted_tenant.knowledge
            env = _local_env()
            top = _git.git(["rev-parse", "--show-toplevel"], cwd=repo, env=env)
            if Path(top).resolve() != repo.resolve():
                raise DeliveryRefused(f"tenant knowledge is not its own versioned git "
                                      f"repository: {repo}")
            for ref in ("refs/heads/main", "refs/remotes/origin/main"):
                if not _git.git_ok(["show-ref", "--verify", "--quiet", ref], cwd=repo, env=env):
                    raise DeliveryRefused(f"tenant repository is missing its main ref {ref}")
            origin = _git.git(["config", "--get", "remote.origin.url"], cwd=repo, env=env)
            user, token, entry = _read_credential(accepted_tenant.forge_credentials)
            forge = ForgejoForge(origin=origin, token=token, client=client)
            if not forge.address.serves(entry):
                raise DeliveryRefused("the tenant credential and its origin must agree on "
                                      "scheme, host and port")
            forge.verify_main_protection()
            return cls(tenant=accepted_tenant, defender_dir=defender_dir, forge=forge,
                       _origin=origin, _user=user, _token=token)

    # -- git, local and over the network ---------------------------------------------------

    def _git(self, args: Sequence[str], *, cwd: Path | None = None, input: str | None = None,
             env: dict[str, str] | None = None) -> str:
        return _git.git(args, cwd=cwd or self.tenant.knowledge, input=input,
                        env=env if env is not None else _local_env())

    def _network(self, args: Sequence[str]) -> str:
        """A fetch or push: every credential helper reset, then the one helper, keyed to the
        forge's own scheme, host and port so it answers no other server (a URL rewritten to
        another host gets nothing), and `core.askPass` emptied. The credential `open` read is
        written into a fresh pipe for this git run alone; git and what it spawns inherit the
        read end, and the helper copies it out. Neither the argument list nor the environment
        of any process holds it, and no file does."""
        read_fd, write_fd = os.pipe()
        try:
            try:
                answer = memoryview(_credential_answer(self._user, self._token))
                while answer:
                    answer = answer[os.write(write_fd, answer):]
            finally:
                os.close(write_fd)
            helper = _credential_helper(read_fd)
            config = ["-c", "credential.helper=",
                      "-c", f"credential.{self.forge.address.origin}.helper={helper}",
                      "-c", "core.askPass="]
            return _git.git([*config, *args], cwd=self.tenant.knowledge, env=_local_env(),
                            pass_fds=(read_fd,))
        finally:
            os.close(read_fd)

    def _check_origin(self) -> None:
        if self._git(["config", "--get", "remote.origin.url"]) != self._origin:
            raise DeliveryRefused("the tenant's origin changed after its credential was accepted")

    def _fetch(self) -> None:
        self._check_origin()
        self._network(["fetch", "origin"])

    def _rev(self, rev: str) -> str:
        return self._git(["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])

    def _has_ref(self, ref: str) -> bool:
        return _git.git_ok(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                           cwd=self.tenant.knowledge, env=_local_env())

    # -- publish ----------------------------------------------------------------------------

    def publish(self) -> TenantExport:
        """Flow 1: fetch (no lock), then under the lock fast-forward the clone to `origin/main`
        and publish its export. Refuses, publishing nothing, a dirty, untracked or diverged
        clone, a tree entry under `agent/` or `settings/` that is not a regular blob, and an
        `agent/.tenant-id` not naming this tenant."""
        with _refusals():
            self._fetch()
            with tenant_lock(self.tenant):
                return self._publish_locked()

    def _publish_locked(self) -> TenantExport:
        """Fast-forward, export, point `current`: the caller holds the tenant's lock."""
        if self._git(["symbolic-ref", "--quiet", "HEAD"]) != "refs/heads/main":
            raise DeliveryRefused("the tenant clone must be on main to fast-forward")
        if self._git(["status", "--porcelain", "--untracked-files=all"]):
            raise DeliveryRefused("the tenant clone is dirty or has untracked files: refusing "
                                  "to fast-forward it")
        head, upstream = self._rev("HEAD"), self._rev("refs/remotes/origin/main")
        if head != upstream and not _git.git_ok(["merge-base", "--is-ancestor", head, upstream],
                                                cwd=self.tenant.knowledge, env=_local_env()):
            raise DeliveryRefused("the tenant clone has diverged from origin/main: it cannot "
                                  "fast-forward")
        files = self._knowledge_at(upstream)
        if head != upstream:
            self._git(["merge", "--ff-only", "--quiet", upstream])
        export = self._write_export(upstream, files)
        if _pointed_at(self.tenant) != upstream:
            _io.write_guarded(self.tenant.exports / _POINTER, f"{upstream}\n", mode="replace")
        return export

    def _knowledge_at(self, commit: str) -> dict[str, bytes]:
        """`agent/` and `settings/` at `commit`, from git objects: every entry a regular blob
        at a plain path, `agent/.tenant-id` naming this tenant through `_tenant`'s parser."""
        env = _local_env()
        entries = _tree_entries(self.tenant.knowledge, commit, ["agent", "settings"], env,
                                recursive=True)
        for mode, kind, _oid, path in entries:
            if kind != "blob" or mode not in _REGULAR_MODES:
                raise DeliveryRefused(f"{commit} holds {path!r} as a {kind} of mode {mode}: only "
                                      "regular blobs are published (no link, no submodule)")
            parts = path.split("/")
            if not all(_plain_component(p) for p in parts) or ".git" in map(str.casefold, parts):
                raise DeliveryRefused(f"{commit} holds {path!r}, which is not a plain path")
        blobs = _cat_blobs(self.tenant.knowledge, (oid for _m, _k, oid, _p in entries), env)
        files = {path: blobs[oid] for _mode, _kind, oid, path in entries}
        marker = "/".join(_TENANT_ID_PARTS)
        if marker not in files:
            raise DeliveryRefused(f"{commit} holds no {marker}: it names no tenant")
        named = parse_tenant_id_bytes(files[marker], Path(marker))
        if named != self.tenant.id:
            raise DeliveryRefused(f"{commit}'s {marker} names tenant {named!r}, not "
                                  f"{self.tenant.id!r}")
        return files

    def _write_export(self, commit: str, files: dict[str, bytes]) -> TenantExport:
        """`<T>/exports/<commit>/`, written whole into a fresh folder beside it and renamed into
        place; an export already there is immutable and kept as it is. The caller holds the
        lock, so any staging folder found is a dead publisher's and is removed first."""
        exports = self.tenant.exports
        _sweep_staging(exports)
        final = exports / commit
        if _io.entry_present(final):
            if not stat.S_ISDIR(final.lstat().st_mode):
                raise DeliveryRefused(f"{final} is not an export folder")
            return TenantExport(commit=commit, path=final)
        staging = f"{_STAGING_PREFIX}{commit}-{secrets.token_hex(4)}"
        try:
            with _io.hold_new(exports, staging, exclusive=True) as folder:
                for path, data in files.items():
                    folder.write(path, data, mode="create")
            os.rename(exports / staging, final)
        except BaseException:
            shutil.rmtree(exports / staging, ignore_errors=True)
            raise
        return TenantExport(commit=commit, path=final)

    # -- batches ----------------------------------------------------------------------------

    def start_batch(self, batch_id: str, *, lanes: Sequence[str]) -> Batch:
        """Flow 3: publish, then under the same lock hold cut a worktree of the clone at the
        export commit, attached to a new batch branch, under the layout's worktree base; then
        (lock released) copy its `agent/` into the git-free draft `<T>/drafts/<batch_id>/`."""
        with _refusals():
            batch_id = _one_word(batch_id, "batch id")
            declared = _lanes(lanes)
            branch = f"{self.branch_prefix}{batch_id}"
            worktree = self.tenant.worktrees / f"{_slug(self.branch_prefix)}-{batch_id}"
            self._fetch()
            with tenant_lock(self.tenant):
                export = self._publish_locked()
                self._cut(worktree, branch, export.commit)
            files = self._agent_blobs(export.commit)
            with _io.hold_new(self.tenant.drafts, batch_id, exclusive=True) as draft:
                draft.mkdir("agent")  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted core's no-follow walk off the held draft root, not a `Path.mkdir`
                for rel, data in files.items():
                    draft.write(f"agent/{rel}", data, mode="create")
                for lane in declared:
                    draft.mkdir(f"agent/{lane}")  # lint-unguarded-tree-write: ok — `Held.mkdir` below the held draft root, no link followed
            line = _Line(worktree=worktree, branch=branch, base=export.commit,
                         tip=export.commit, lanes=declared)
            return Batch(id=batch_id, branch=branch, export=export, worktree=worktree,
                         draft_root=self.tenant.drafts / batch_id, lanes=declared,
                         _delivery=self, _line=line)

    def _agent_blobs(self, commit: str) -> dict[str, bytes]:
        """`agent/` at `commit`, by path below it, each file's exact stored bytes, from git's
        objects: what the draft is copied from, derived against and reset to. An entry that is
        not a regular blob refuses (publish refused it already for an export commit)."""
        env = _local_env()
        entries = _tree_entries(self.tenant.knowledge, commit, ["agent"], env, recursive=True)
        for mode, kind, _oid, path in entries:
            if kind != "blob" or mode not in _REGULAR_MODES:
                raise DeliveryRefused(f"{commit} holds {path!r} as a {kind} of mode {mode}: "
                                      "not a regular file")
        blobs = _cat_blobs(self.tenant.knowledge, (oid for _m, _k, oid, _p in entries), env)
        return {path.removeprefix("agent/"): blobs[oid] for _m, _k, oid, path in entries}

    def _cut(self, worktree: Path, branch: str, base: str) -> None:
        """A new worktree at `base` on a new `branch`: never over an existing branch or folder
        (the commit-maker never takes over a branch it did not start). The caller holds the
        lock."""
        if _io.entry_present(worktree):
            raise DeliveryRefused(f"the worktree {worktree} already exists")
        if self._has_ref(f"refs/heads/{branch}"):
            raise DeliveryRefused(f"the branch {branch} already exists in the tenant clone")
        _io.guarded_mkdir(self.tenant.worktrees, base=self.tenant.dir)
        self._git(["worktree", "add", "--quiet", "-b", branch, str(worktree), base])

    def start_box(self, request: box.BoxRequest, *, docker: DockerFn = _docker) -> box.BoxExecutor:
        """The tenant drain's box: always sandboxed, whatever the operator's opt-out, and never
        over a draft root holding `settings/` (a run copy's half, never a draft's)."""
        for mount in request.mounts:
            if mount.kind == "staged" and _io.entry_present(Path(mount.source) / "settings"):
                raise box.BoxFault(f"the draft root {mount.source} holds settings/: a draft "
                                   "holds agent/ alone")
        return _start_boxed_request(request, docker)

    # -- the commit-maker -------------------------------------------------------------------

    def _commit(self, line: _Line, change_set: ChangeSet, message: str) -> str:
        """The one maker of tenant commits. It takes only a `ChangeSet` within `line`'s lanes,
        builds the commit from git objects on the branch's last own commit (refusing a branch
        moved since, never setting it over another's commit), writes every blob as given with
        mode 100644, records the commit, moves the branch by compare-and-swap, and brings the
        worktree to it."""
        if not isinstance(change_set, ChangeSet):
            raise TypeError(f"the commit-maker takes a ChangeSet, not {type(change_set).__name__}")
        # Re-validated from scratch into a copy the commit-maker alone holds: a change set
        # altered after it was built (past its frozen attributes) is refused or not seen.
        change_set = ChangeSet(tuple(AgentChange(change.path, change.content)
                                     for change in tuple(change_set.changes)))
        with _refusals():
            if not isinstance(message, str) or not message.strip():
                raise DeliveryRefused("a commit needs a message")
            if not len(change_set):
                raise DeliveryRefused("the change set is empty: there is nothing to commit")
            for change in change_set:
                _require_in_lanes(change.path, line.lanes)
            ref = f"refs/heads/{line.branch}"
            tip = self._rev(ref)
            if tip != line.tip or self._git(["rev-parse", "HEAD"], cwd=line.worktree) != tip:
                raise DeliveryRefused(
                    f"the branch {line.branch} moved from the commit-maker's last commit "
                    f"{line.tip} (now {tip}): it builds on nothing it did not make")
            env = _local_env()
            before = {path: oid for mode, kind, oid, path in _tree_entries(
                line.worktree, tip, [change.path for change in change_set], env, recursive=False)
                if kind == "blob" and mode in _REGULAR_MODES}
            for change in change_set:
                if change.content is None and change.path not in before:
                    raise DeliveryRefused(f"{change.path} is not a file {tip} holds: it cannot "
                                          "be deleted")
            tree, after = self._stage(line, tip, change_set, env)
            if tree == self._git(["rev-parse", f"{tip}^{{tree}}"]):
                raise DeliveryRefused("the change set changes nothing")
            commit = self._git(["commit-tree", tree, "-p", tip, "-F", "-"], cwd=line.worktree,
                               input=message)
            _record_made(self.tenant, _Made(commit=commit, lanes=line.lanes, changes=tuple(
                (change.path, before.get(change.path), after[change.path])
                for change in change_set)))
            self._git(["update-ref", "-m", "tenant commit-maker", ref, commit, tip],
                      cwd=line.worktree)
            line.tip = commit
            self._git(["read-tree", "--reset", "-u", commit], cwd=line.worktree)
            return commit

    def _stage(self, line: _Line, tip: str, change_set: ChangeSet,
               env: dict[str, str]) -> tuple[str, dict[str, str | None]]:
        """Write each change's blob (no filter: the bytes as given) and the tree `tip` plus the
        changes makes, in a private index; every file 100644. Answers the tree, and each path's
        new blob (`None`: deleted)."""
        index = Path(self._git(["rev-parse", "--path-format=absolute", "--git-path",
                                f"commit-maker-{secrets.token_hex(8)}.index"], cwd=line.worktree))
        staged = {**env, "GIT_INDEX_FILE": str(index)}
        try:
            self._git(["read-tree", tip], cwd=line.worktree, env=staged)
            zero = "0" * len(tip)
            after: dict[str, str | None] = {}
            rows = []
            for change in sorted(change_set, key=lambda c: c.content is not None):
                if change.content is None:
                    after[change.path] = None
                    rows.append(f"0 {zero}\t{change.path}\0")
                    continue
                oid = _git.git_bytes(["hash-object", "-w", "--no-filters", "--stdin"],
                                     cwd=line.worktree, env=env,
                                     input=change.content).decode("ascii").strip()
                after[change.path] = oid
                rows.append(f"100644 {oid}\t{change.path}\0")
            _git.git_bytes(["update-index", "-z", "--index-info"], cwd=line.worktree, env=staged,
                           input="".join(rows).encode("utf-8"))
            return self._git(["write-tree"], cwd=line.worktree, env=staged), after
        finally:
            index.unlink(missing_ok=True)

    # -- push routes ------------------------------------------------------------------------

    def _require_made(self, base: str, tip: str) -> None:
        """Every commit `tip` would send past `base` is one the commit-maker recorded."""
        commits = self._git(["rev-list", f"{base}..{tip}"]).split()
        made = {m.commit for m in _made_commits(self.tenant)}
        foreign = [commit for commit in commits if commit not in made]
        if foreign:
            raise DeliveryRefused(
                f"{len(foreign)} commit(s) between {base} and {tip} were not made by the "
                f"commit-maker ({', '.join(foreign)}): nothing is pushed")

    def _send(self, branch: str, base: str, tip: str, *, title: str, body: str) -> str:
        """Push `tip` (by id, so a branch moved meanwhile sends nothing new) to the remote
        `branch` once every commit past `base` is the commit-maker's; then the PR found by
        exact head (forks excluded) or opened against `main`."""
        self._require_made(base, tip)
        self._check_origin()
        self._network(["push", "--quiet", "origin", f"{tip}:refs/heads/{branch}"])
        for row in self.forge.list_prs_for_head(branch):
            return str(row["url"])
        return self.forge.open_pr(base="main", head=branch, title=title, body=body)

    def finish(self, batch: Batch) -> str | None:
        """Push the batch branch and find or open its PR; `None` when the batch made no commit.
        A branch moved from the commit-maker's last commit, or holding any commit it did not
        make, is refused before any push."""
        with _refusals():
            line = batch._line
            tip = self._rev(f"refs/heads/{line.branch}")
            if tip != line.tip:
                raise DeliveryRefused(
                    f"the branch {line.branch} moved from the commit-maker's last commit "
                    f"{line.tip} (now {tip}): nothing is pushed")
            if tip == line.base:
                return None
            return self._send(line.branch, line.base, tip, title=_batch_title(batch.id),
                              body=_batch_body(line.branch, line.base))

    def deliver(self, batch_id: str) -> str | None:
        """Deliver a retained batch branch (pushed, or not, before its PR request failed), from
        any later delivery: `None` when the clone holds no such branch or it holds nothing past
        `origin/main`; refused if any commit on it is not the commit-maker's."""
        with _refusals():
            branch = f"{self.branch_prefix}{_one_word(batch_id, 'batch id')}"
            if not self._has_ref(f"refs/heads/{branch}"):
                return None
            self._fetch()
            base, tip = self._rev("refs/remotes/origin/main"), self._rev(f"refs/heads/{branch}")
            if not self._git(["rev-list", f"{base}..{tip}"]):
                return None
            return self._send(branch, base, tip, title=_batch_title(batch_id),
                              body=_batch_body(branch, base))

    # -- revert -----------------------------------------------------------------------------

    def revert(self, lesson_path: str, lesson_name: str) -> str:
        """Flow 4: undo the most recent commit-maker change to `lesson_path` whose result is
        exactly what `origin/main` holds there now, restoring the bytes from before it (or
        deleting the lesson that change created), as one commit-maker commit on `main` pushed
        to a branch of its own with its PR. Refused when no such change exists: a lesson
        changed on `main` since, one the commit-maker never wrote, a path that is not one."""
        with _refusals():
            path = _agent_path(lesson_path)
            name = _one_word(lesson_name, "lesson name")
            self._fetch()
            main = self._rev("refs/remotes/origin/main")
            made, before = self._latest_change_matching(main, path)
            content = None if before is None else _cat_blobs(
                self.tenant.knowledge, [before], _local_env())[before]
            suffix = secrets.token_hex(4)
            branch = f"{self.branch_prefix}revert-{name}-{suffix}"
            worktree = self.tenant.worktrees / f"revert-{name}-{suffix}"
            with tenant_lock(self.tenant):
                self._cut(worktree, branch, main)
            try:
                line = _Line(worktree=worktree, branch=branch, base=main, tip=main,
                             lanes=made.lanes)
                commit = self._commit(line, ChangeSet((AgentChange(path, content),)),
                                      f"revert lesson: {name}")
                tip = self._rev(f"refs/heads/{branch}")
                if tip != commit:
                    raise DeliveryRefused(f"the revert branch {branch} moved from the "
                                          f"commit-maker's commit {commit} (now {tip}): nothing "
                                          "is pushed")
                return self._send(branch, main, tip, title=f"revert lesson: {name}", body=(
                    f"Reverts `{path}` to what it held before the commit-maker's change "
                    f"{made.commit[:12]}, which `main` still holds exactly."))
            finally:
                self._discard(worktree)

    def _latest_change_matching(self, main: str, path: str) -> tuple[_Made, str | None]:
        """The most recent commit-maker change to `path` whose resulting blob is what `main`
        holds there now (absence included), and the blob from before it."""
        found = _tree_entries(self.tenant.knowledge, main, [path], _local_env(), recursive=False)
        if found and (found[0][1] != "blob" or found[0][0] not in _REGULAR_MODES):
            raise DeliveryRefused(f"{path} on main is not a regular file")
        current = found[0][2] if found else None
        for made in reversed(_made_commits(self.tenant)):
            for changed, before, after in made.changes:
                if changed == path and after == current:
                    return made, before
        raise DeliveryRefused(f"no change the commit-maker made to {path} matches what main holds "
                              "there now: nothing to revert")

    def _discard(self, worktree: Path) -> None:
        """Remove a revert's worktree (its branch stays), under the lock; left behind, with a
        warning, when the lock is busy."""
        try:
            with tenant_lock(self.tenant):
                self._git(["worktree", "remove", "--force", str(worktree)])
        except (DeliveryRefused, _git.GitError) as e:
            _logger.warning("the revert worktree %s was left behind: %s", worktree, e)


def _read_credential(path: Path) -> tuple[str, str, str]:
    """The tenant's forge credential (`<T>/forge/git-credentials`, git's credential-store
    format: one `scheme://user:token@host[:port]` line in a regular 0600 file), read once:
    `(user, token, the entry)`. Anything else refuses, naming the file but not its content."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise DeliveryRefused(f"the tenant's forge credential {path} is missing") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise DeliveryRefused(f"the tenant's forge credential {path} must be a regular 0600 file")
    entry = _io.read_plain_bytes(path).decode("utf-8").strip()
    try:
        parts = urlsplit(entry)
        user, token = unquote(parts.username or ""), unquote(parts.password or "")
    except ValueError:
        raise DeliveryRefused(f"the tenant's forge credential {path} is not one URL") from None
    if ("\n" in entry or not user or not token or parts.path not in {"", "/"} or parts.query
            or parts.fragment or any(ord(ch) < 0x20 for ch in user + token)):
        raise DeliveryRefused(f"the tenant's forge credential {path} must be one "
                              "scheme://user:token@host[:port] line")
    if len(_credential_answer(user, token)) > _ANSWER_LIMIT:
        raise DeliveryRefused(f"the tenant's forge credential {path} is longer than "
                              f"{_ANSWER_LIMIT} bytes")
    return user, token, entry


def _pointed_at(tenant: Tenant) -> str | None:
    """The commit `exports/current` names now, or `None` when it names none."""
    try:
        return current_export(tenant).commit
    except DeliveryRefused:
        return None


def _slug(prefix: str) -> str:
    return prefix.rstrip("/").replace("/", "-") or "batch"


def _batch_title(batch_id: str) -> str:
    return f"learning: tenant knowledge batch {batch_id}"


def _batch_body(branch: str, base: str) -> str:
    return (f"Tenant agent knowledge batch `{branch}`, based on `{base[:12]}`. Changes `agent/` "
            "only, every commit made by the host's commit-maker.")

