"""Dormant tenant delivery (#1108 P3, amendments 2 and 3); P4 wires drains and runs onto it.

Boxes see only host-made copies; git and the tenant's forge credential never touch a box's
folders, and only host code here reads or writes git.

- `publish` fetches (no lock held), then under the tenant's knowledge lock sweeps dead draft
  builds, keeps `* -filter` the last line of the clone's `$GIT_DIR/info/attributes` (no filter
  driver the tenant names runs on the host), fast-forwards the clone and writes a
  `TenantExport` from git objects: `<T>/exports/<commit>/`, immutable, with
  `<T>/exports/current` replaced atomically to name it. `current_export` reads it back without
  git.
- A `Batch` is a branch in the tenant clone plus a git-free draft of the export commit's
  `agent/` under `<T>/drafts/<batch>/`, built under the lock in a dot-named temporary and
  renamed into place. No checkout is made for it: the branch exists from the batch's first
  commit on. The box mounts the draft's root read-only (`staged`) and only the batch's lanes
  writable.
- Per claim the host derives a `ChangeSet` (the draft against the blobs of the branch's last
  commit, or of the export commit: regular files in the batch's lanes and nothing else), the
  commit-maker (`Batch.commit`, the one maker of tenant commits) writes it as git objects and
  moves the branch by compare-and-swap (the first commit creates it), with no lock and never
  touching `main`, the clone's index or its checkout; `Batch.reset` re-syncs the draft.
- Truth comes from `main`'s content and the forge's PRs, never from history (amendment 3,
  C1). The commit-maker's record under `<T>/learning/` (it outlives the process that wrote
  it) lists every commit it made, tagged with its batch, and each batch's net change per
  lesson. Every push route (finish, deliver, revert) sends only the batch's own commits, and
  first looks the batch's PR up by its head commit and repository id: a PR found (open,
  merged or closed) is answered, and nothing is pushed or opened again. Revert peels back
  through the agent's own changes, the newest that `main` still holds exactly first.
- Git runs with every credential helper reset and one helper that answers only `get`, only
  for the forge's own scheme, host and port, with the credential `TenantDelivery.open` read
  (the file's single reader), handed over a sealed in-memory file: never in a process's
  argument list or environment, never in a file on disk. No prompt can run. Network git runs
  no hook of the clone's, in a session of its own, bounded by a wall timeout, its process
  group killed on any way out of the call.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import math
import os
import re
import secrets
import shutil
import stat
import time
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import IO, TYPE_CHECKING
from urllib.parse import unquote, urlsplit

if TYPE_CHECKING:
    import httpx

# `_flock` alone on its line: the #1135 front-door census reads every name of a line importing
# it as a lock alias, and only `tenant_lock` takes a lock here.
from defender import _flock
from defender import _git, _io
from defender._tenant import Tenant, TenantRefused, parse_tenant_id_bytes
from defender.learning.author.branch import LESSONS_BRANCH_PREFIX
from defender.learning.author.forge import ForgeError, ForgejoForge, PullRequest
from defender.runtime import box
from defender.runtime.box._docker import DockerFn, _docker

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
_PUBLISHING_PREFIX = ".publishing-"
#: What a draft is built under (`.<id>-<rand>`) before it is renamed into place: a leading dot
#: is outside the batch-id grammar, so no draft is ever named so.
_DRAFT_TEMPORARY = "."
#: The `info/attributes` line that turns every filter driver off (amendment 3, C2).
_FILTERS_OFF = "* -filter"


def _sweep_temporaries(folder: Path, prefix: str) -> None:
    """Remove every entry of `folder` named with `prefix` (a build cut off left it), as the
    entry it is: a folder removed with no link below it followed, anything else unlinked.
    Called under the tenant's lock, so no live builder is writing one."""
    if not _io.entry_present(folder):
        return
    fd = os.open(folder, _FOLDER_FLAGS)
    try:
        with os.scandir(fd) as entries:
            stale = [(entry.name, entry.is_dir(follow_symlinks=False)) for entry in entries
                     if entry.name.startswith(prefix)]
        for name, is_folder in stale:
            if is_folder:
                shutil.rmtree(name, dir_fd=fd)
            else:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def _remove_entry(folder: Path, name: str) -> None:
    """Remove `folder/name` as the entry it is (a folder with no link below it followed,
    anything else unlinked); nothing when it, or `folder`, is absent."""
    try:
        fd = os.open(folder, _FOLDER_FLAGS)
    except FileNotFoundError:
        return
    try:
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)


def _rename_new(folder: Path, source: str, name: str) -> None:
    """Rename `folder/source` to `folder/name`, refusing any entry already at `name` (a plain
    rename would replace an empty folder there). Both relative to one held, no-follow folder
    descriptor. The caller holds the tenant's lock, under which alone such names are made."""
    fd = os.open(folder, _FOLDER_FLAGS)
    try:
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            os.rename(source, name, src_dir_fd=fd, dst_dir_fd=fd)
            return
        raise DeliveryRefused(f"{folder / name} already exists: a draft is never built over "
                              "another entry")
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
    `forge/`): held for a fast-forward, an export publish (its folder and `current`), the
    `* -filter` write to the clone's `info/attributes`, and a draft's build, rename and sweep;
    never across network I/O, a box window or a commit. A second taker fails at once with
    `LockBusy` naming the holder's pid; it never waits."""
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
# The commit-maker's record: provenance, and each batch's net change per lesson
# ==========================================================================================

@dataclass(frozen=True)
class _BatchKey:
    """Which batch a commit-maker commit belongs to: the branch it was made on, the commit the
    batch started from (the export commit for a drain's batch, `main` for a revert), and the
    start's own random word, so a batch id used again is never mistaken for its earlier use."""

    branch: str
    base: str
    start: str


@dataclass(frozen=True)
class _Made:
    """One commit the commit-maker made (one record row): its batch and lanes; per path it
    changed, the blob at the batch's base and the blob it left (`None`: absent); and, for a
    revert commit, the batch change it undoes (`(batch, path)`). A revert commit changes no
    batch's net change: it is provenance only."""

    commit: str
    batch: _BatchKey
    lanes: tuple[str, ...]
    changes: tuple[tuple[str, str | None, str | None], ...]
    reverts: tuple[_BatchKey, str] | None = None


@dataclass(frozen=True)
class _NetChange:
    """A batch's net change to one lesson: the blob at the batch's base (`before`) and the
    blob its last commit-maker commit left (`after`), `None` for absent. A lesson one claim
    created and a later claim changed is one change, absent to the last bytes. `order` is the
    record position of the commit that last touched it (larger is newer)."""

    batch: _BatchKey
    path: str
    before: str | None
    after: str | None
    order: int


def _batch_row(batch: _BatchKey) -> dict:
    return {"branch": batch.branch, "base": batch.base, "start": batch.start}


def _record_made(tenant: Tenant, made: _Made) -> None:
    """Append `made` to the tenant's commit-maker record, durably, before the commit is put on
    any branch: a crash in between leaves a recorded commit no branch holds, never a branch
    holding an unrecorded one."""
    row: dict = {"commit": made.commit, "batch": _batch_row(made.batch), "lanes": list(made.lanes),
                 "changes": [{"path": p, "before": b, "after": a} for p, b, a in made.changes]}
    if made.reverts is not None:
        row["reverts"] = {"batch": _batch_row(made.reverts[0]), "path": made.reverts[1]}
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


def _parse_batch(value: object) -> _BatchKey:
    if not isinstance(value, dict):
        raise ValueError("not a batch")
    branch, base, start = value.get("branch"), value.get("base"), value.get("start")
    if not isinstance(branch, str) or not isinstance(start, str) or not isinstance(base, str) \
            or not _OID.fullmatch(base):
        raise ValueError("not a batch")
    return _BatchKey(branch=branch, base=base, start=start)


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
    reverts = None
    if "reverts" in row:
        target = row["reverts"]
        if not isinstance(target, dict) or not isinstance(target.get("path"), str):
            raise ValueError("not a revert's target")
        reverts = (_parse_batch(target.get("batch")), target["path"])
    return _Made(commit=commit, batch=_parse_batch(row.get("batch")), lanes=tuple(lanes),
                 changes=tuple(parsed), reverts=reverts)


@dataclass(frozen=True)
class _Record:
    """The commit-maker's record as read, oldest row first."""

    made: tuple[_Made, ...]

    @classmethod
    def read(cls, tenant: Tenant) -> _Record:
        """Every row the commit-maker recorded for this tenant. A row of another shape records
        nothing (a torn last line from a crash among them): its commit is then refused by every
        push route, failing closed. An unreadable record refuses."""
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
        return cls(made=tuple(made))

    def commits_of(self, batch: _BatchKey) -> frozenset[str]:
        """Every commit the commit-maker made for `batch`."""
        return frozenset(m.commit for m in self.made if m.batch == batch)

    def batch_holding(self, branch: str, tip: str) -> _BatchKey | None:
        """The batch whose commits hold `tip` on `branch`; failing that (a tip the commit-maker
        did not make), the batch that last committed on `branch`; `None` when none did."""
        mine = [m for m in self.made if m.batch.branch == branch]
        for m in mine:
            if m.commit == tip:
                return m.batch
        return mine[-1].batch if mine else None

    def lanes_of(self, batch: _BatchKey) -> tuple[str, ...]:
        return next(m.lanes for m in self.made if m.batch == batch)

    def net_changes(self, path: str) -> list[_NetChange]:
        """Every batch's net change to `path`, newest first: per batch the blob at its base and
        the blob its last commit touching `path` left."""
        net: dict[_BatchKey, _NetChange] = {}
        for order, m in enumerate(self.made):
            for changed, before, after in m.changes:
                if changed == path:
                    net[m.batch] = _NetChange(batch=m.batch, path=path, before=before,
                                              after=after, order=order)
        return sorted(net.values(), key=lambda change: change.order, reverse=True)

    def reverts_of(self, change: _NetChange) -> list[_Made]:
        """The revert commits made of `change`, oldest first."""
        return [m for m in self.made if m.reverts == (change.batch, change.path)]


# ==========================================================================================
# Git: the environment, the credential, blobs
# ==========================================================================================

#: The most a credential answer may hold.
_ANSWER_LIMIT = 16 * 1024
#: Network git's wall timeout, in seconds, unless `TenantDelivery.open` is given another.
NETWORK_TIMEOUT = 120.0


def _credential_helper(fd: int) -> str:
    """The one credential helper git consults (amendment 2, flow 5), as a shell snippet: it
    drains git's request, answers only `get`, by copying out the sealed in-memory file `fd`
    holding the answer from the credential `TenantDelivery.open` read (`/dev/fd/<fd>`: each
    open starts at its beginning, so every `get` of one git run is answered; a shell
    redirection could not name a descriptor above 9), and ignores `store` and `erase`, so no
    git operation can rewrite or empty the credential file. The snippet holds no credential."""
    return f'!f() {{ cat >/dev/null; test "$1" = get || exit 0; cat /dev/fd/{fd}; }}; f'


def _credential_answer(user: str, token: str) -> bytes:
    """What the helper hands git for `get`, in git's credential format."""
    return f"username={user}\npassword={token}\n".encode()


def _sealed(data: bytes) -> int:
    """A sealed in-memory file holding exactly `data` (amendment 3, C4): no name on any file
    system, and once sealed it can be neither written, grown, shrunk nor unsealed, so the
    child a descriptor of it is handed to can only read it. Close-on-exec: only a child it is
    passed to (`pass_fds`) inherits it."""
    fd = os.memfd_create("tenant-forge-credential", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW
                    | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    except BaseException:
        os.close(fd)
        raise
    return fd


#: Settings every git process on a tenant repository runs with, so none outlives the call
#: that started it: no automatic maintenance or gc (a fetch, merge or commit otherwise spawns
#: `git maintenance run --auto --detach`, which keeps working on the clone after the call
#: returns and the tenant's lock is released), and no file-system monitor daemon.
_NO_BACKGROUND_GIT = (
    ("maintenance.auto", "false"), ("maintenance.autoDetach", "false"),
    ("gc.auto", "0"), ("gc.autoDetach", "false"), ("core.fsmonitor", "false"),
)


def _local_env() -> dict[str, str]:
    """Every git call's environment: nothing that relocates the repository (`GIT_DIR`,
    `GIT_WORK_TREE`, ...), no replace objects, pathspecs taken literally, no prompt (an empty
    `GIT_ASKPASS` stops `core.askPass` and `SSH_ASKPASS`, and the terminal prompt is off), and
    `_NO_BACKGROUND_GIT`, given as environment configuration (after any already there, so it
    wins) so the git processes git itself starts carry it too. A `GIT_CONFIG_COUNT` that is
    not a count is a `ValueError`, as git would refuse it."""
    env = _git.env_for_cwd()
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_LITERAL_PATHSPECS="1", GIT_TERMINAL_PROMPT="0",
               GIT_ASKPASS="")
    count = int(env.get("GIT_CONFIG_COUNT") or 0)
    if count < 0:
        raise ValueError(f"GIT_CONFIG_COUNT is not a count: {count}")
    for key, value in _NO_BACKGROUND_GIT:
        env[f"GIT_CONFIG_KEY_{count}"], env[f"GIT_CONFIG_VALUE_{count}"] = key, value
        count += 1
    env["GIT_CONFIG_COUNT"] = str(count)
    return env


def _cat_blobs(repo: Path, oids: Iterable[str], env: dict[str, str]) -> dict[str, bytes]:
    """Each blob's exact stored bytes, by id, in one `cat-file --batch` read by `_git`'s
    parser."""
    wanted = list(dict.fromkeys(oids))
    if not wanted:
        return {}
    args = ["cat-file", "--batch"]
    out = _git.git_bytes(args, cwd=repo, env=env,
                         input="".join(f"{oid}\n" for oid in wanted).encode("ascii"))
    return dict(zip(wanted, _git.blob_batch(args, out, wanted), strict=True))


def _tree_entries(repo: Path, rev: str, paths: Sequence[str], env: dict[str, str], *,
                  recursive: bool) -> list[tuple[str, str, str, str]]:
    """`(mode, kind, oid, path)` of each entry `rev` holds at `paths` (below them too, when
    `recursive`), NUL-framed (`_git`'s listing parser) so no path is quoted or trimmed; a path
    that is not UTF-8 refuses."""
    args = ["ls-tree", "-z", "--full-tree", *(["-r"] if recursive else []), rev, "--", *paths]
    return _git.tree_records(_git.git_bytes(args, cwd=repo, env=env), errors="strict")


# ==========================================================================================
# What finish, deliver and revert answer
# ==========================================================================================

class DeliveryStatus(StrEnum):
    """Where a batch (or a revert) stands with the forge."""

    OPENED = "opened"
    """A PR this call opened."""
    OPEN = "open"
    """An open PR this call found; nothing was pushed or opened."""
    MERGED = "merged"
    CLOSED = "closed"
    """Closed unmerged: a rejection (D-closed)."""
    NOTHING = "nothing to deliver"
    """No branch, or a branch holding nothing past its base."""


@dataclass(frozen=True)
class Delivered:
    """`status`, and the PR's `url` for `opened` and `open` (also kept for `merged` and
    `closed`)."""

    status: DeliveryStatus
    url: str | None = None


#: When several of the forge's PRs carry a batch's commits, the one answered: an open one
#: first (the live review), then a merged one, then a closed one.
_PRECEDENCE = {"open": 0, "merged": 1, "closed": 2}


#: A PR the forge already has, by its state, as finish, deliver and revert answer it.
_FOUND = {"open": DeliveryStatus.OPEN, "merged": DeliveryStatus.MERGED,
          "closed": DeliveryStatus.CLOSED}


def _answer(pr: PullRequest) -> Delivered:
    return Delivered(status=_FOUND[pr.status], url=pr.url)


# ==========================================================================================
# The batch
# ==========================================================================================

@dataclass
class _Line:
    """Where the commit-maker commits for one batch: its branch and base (`batch`), its lanes,
    and `tip`, the last commit it put on the branch (`None` before the first, when the branch
    does not exist yet)."""

    batch: _BatchKey
    lanes: tuple[str, ...]
    tip: str | None = None

    @property
    def head(self) -> str:
        """What the batch's next commit builds on: its last, or the base."""
        return self.tip or self.batch.base


@dataclass(eq=False)
class Batch:
    """One drain batch: a branch of the tenant clone (`branch`, made by the batch's first
    commit, from `export`'s commit) and the git-free draft under `draft_root` its box writes
    into, through `lanes` only. No checkout is made for it."""

    id: str
    branch: str
    export: TenantExport
    draft_root: Path
    lanes: tuple[str, ...]
    _delivery: TenantDelivery = field(repr=False)
    _line: _Line = field(repr=False)

    def box_request(self) -> box.BoxRequest:
        """The drain box: product code read-only (`code`), the draft's root read-only (`staged`),
        and each lane writable inside it. Never the clone, an export, `settings/`, `.git` or
        `forge/`. `agent/` is the workdir and `DEFENDER_AGENT_DIR`. It requires a sandbox."""
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
        """The claim: the draft's `agent/` against the blobs of the batch's base (its branch's
        last commit, or the export commit before the first), as changes. The base is read from
        git's objects, never a checkout, so attributes on `main` (`eol`, `ident`, a filter)
        never show a change the box did not make. Only regular files in the lanes may differ;
        any other entry anywhere in the draft, an oversized file, a change outside the lanes or
        one touching a forbidden name refuses the claim whole."""
        with _refusals():
            draft = _regular_files(self.draft_root / "agent")
            base = self._delivery._agent_blobs(self._line.head)
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
        """Re-sync the draft's `agent/` with the blobs of the batch's base, in place: the box's
        additions removed, its deletions and edits restored, links and FIFOs removed without
        being followed or opened. The lanes stay, so a running box keeps its binds."""
        with _refusals():
            files = self._delivery._agent_blobs(self._line.head)
            _resync(self.draft_root / "agent", files, _folders_of(files, self.lanes))

    def discard(self) -> None:
        """Remove the draft (no link below it followed). The branch and its commits stay:
        a branch with commits is `deliver`'s to pick up."""
        with _refusals():
            _remove_entry(self.draft_root.parent, self.id)


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
    network_timeout: float = NETWORK_TIMEOUT
    branch_prefix: str = LESSONS_BRANCH_PREFIX

    @classmethod
    def open(cls, accepted_tenant: Tenant, *, defender_dir: Path, client: httpx.Client,
             network_timeout: float = NETWORK_TIMEOUT) -> TenantDelivery:
        """The dormant factory, and the credential file's single reader. Refuses (O9) a tenant
        whose knowledge is not its own git repository, has no `main`, has no network `origin`,
        or has no credential agreeing with that origin's scheme, host and port; reads the
        repository's id (what its PRs' head repositories are compared with); then refuses
        unless the forge reports `main` protected and not pushable by the bot (A10).
        `network_timeout` is network git's wall timeout, in seconds."""
        with _refusals():
            if (isinstance(network_timeout, bool) or not isinstance(network_timeout, (int, float))
                    or not math.isfinite(network_timeout) or network_timeout <= 0):
                raise DeliveryRefused(f"the network timeout must be a positive number of "
                                      f"seconds, not {network_timeout!r}")
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
            user, token, server = _read_credential(accepted_tenant.forge_credentials)
            forge = ForgejoForge(origin=origin, token=token, client=client)
            if not forge.address.serves(server):
                raise DeliveryRefused("the tenant credential and its origin must agree on "
                                      "scheme, host and port")
            forge.repository_id()
            forge.verify_main_protection()
            return cls(tenant=accepted_tenant, defender_dir=defender_dir, forge=forge,
                       _origin=origin, _user=user, _token=token,
                       network_timeout=float(network_timeout))

    # -- git, local and over the network ---------------------------------------------------

    def _git(self, args: Sequence[str], *, input: str | None = None,
             env: dict[str, str] | None = None) -> str:
        return _git.git(args, cwd=self.tenant.knowledge, input=input,
                        env=env if env is not None else _local_env())

    def _network(self, args: Sequence[str]) -> str:
        """A fetch or push: every credential helper reset, then the one helper, keyed to the
        forge's own scheme, host and port so it answers no other server (a URL rewritten to
        another host gets nothing), `core.askPass` emptied, and no hook of the clone's run
        (`core.hooksPath=/dev/null`) while the token is within reach. The credential `open`
        read is put in a sealed in-memory file for this git run alone; git and what it spawns
        inherit its descriptor, and the helper reads it. Neither the argument list nor the
        environment of any process holds it, and no file on disk does. Git runs in its own
        session under the wall timeout, curl giving up on its own on a stalled transfer
        (`http.lowSpeedLimit`/`lowSpeedTime`), its process group killed on any way out."""
        fd = _sealed(_credential_answer(self._user, self._token))
        try:
            config = ["-c", "credential.helper=",
                      "-c", f"credential.{self.forge.address.origin}.helper={_credential_helper(fd)}",
                      "-c", "core.askPass=", "-c", "core.hooksPath=/dev/null",
                      "-c", "http.lowSpeedLimit=1",
                      "-c", f"http.lowSpeedTime={max(1, math.ceil(self.network_timeout))}"]
            return _git.git_network([*config, *args], cwd=self.tenant.knowledge,
                                    env=_local_env(), timeout=self.network_timeout,
                                    pass_fds=(fd,))
        finally:
            os.close(fd)

    def _check_origin(self) -> None:
        if self._git(["config", "--get", "remote.origin.url"]) != self._origin:
            raise DeliveryRefused("the tenant's origin changed after its credential was accepted")

    def _fetch(self) -> None:
        self._check_origin()
        self._network(["fetch", "origin"])

    def _rev(self, rev: str) -> str:
        return self._git(["rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"])

    def _branch_tip(self, branch: str) -> str | None:
        """The commit `refs/heads/<branch>` names, or `None` when the clone has no such
        branch."""
        tip = _git.git(["rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}"],
                       cwd=self.tenant.knowledge, env=_local_env(), check=False)
        return tip or None

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
        """Sweep dead draft builds, turn tenant-named filters off, fast-forward, export, point
        `current`: the caller holds the tenant's lock."""
        _sweep_temporaries(self.tenant.drafts, _DRAFT_TEMPORARY)
        self._filters_off()
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

    def _filters_off(self) -> None:
        """Keep `* -filter` the last line of the clone's `$GIT_DIR/info/attributes`, which
        outranks every `.gitattributes`, so no filter driver the tenant's attributes name runs
        on the host (a later line in one file wins: an operator's line appended after it would
        turn a filter back on, so it is re-appended whenever it is not last). Git's own `eol`
        and `ident` keep applying. The caller holds the tenant's lock."""
        attributes = Path(self._git(["rev-parse", "--path-format=absolute", "--git-path",
                                     "info/attributes"]))
        info = attributes.parent
        _io.rooted_mkdir(info.parent, info.name)
        with _io.bind(info) as folder:
            read = folder.read(attributes.name)
        if read.text is None and not read.absent:
            raise DeliveryRefused(f"{attributes} could not be read: {read.refusal}")
        lines = (read.text or "").splitlines()
        while lines and not lines[-1].strip():
            lines.pop()
        if lines and lines[-1].strip() == _FILTERS_OFF:
            return
        _io.rooted_write(info, attributes.name, "\n".join([*lines, _FILTERS_OFF]) + "\n",
                         mode="replace")

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
        _sweep_temporaries(exports, _PUBLISHING_PREFIX)
        final = exports / commit
        if _io.entry_present(final):
            if not stat.S_ISDIR(final.lstat().st_mode):
                raise DeliveryRefused(f"{final} is not an export folder")
            return TenantExport(commit=commit, path=final)
        staging = f"{_PUBLISHING_PREFIX}{commit}-{secrets.token_hex(4)}"
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
        """Flow 3: refuse at once an id whose draft or branch exists (ids are never retried, so
        a reused one is caught before any box runs); publish; then, under the same lock hold,
        build the git-free draft of the export commit's `agent/` in a dot-named temporary
        under `<T>/drafts/` and rename it to `<T>/drafts/<batch_id>`. A build that fails leaves
        nothing. No checkout is made, and the branch exists from the first commit on."""
        with _refusals():
            batch_id = _one_word(batch_id, "batch id")
            declared = _lanes(lanes)
            branch = f"{self.branch_prefix}{batch_id}"
            self._refuse_taken(batch_id, branch)
            self._fetch()
            with tenant_lock(self.tenant):
                export = self._publish_locked()
                self._refuse_taken(batch_id, branch)
                self._build_draft(batch_id, export.commit, declared)
            line = _Line(batch=_BatchKey(branch=branch, base=export.commit,
                                         start=secrets.token_hex(8)), lanes=declared)
            return Batch(id=batch_id, branch=branch, export=export,
                         draft_root=self.tenant.drafts / batch_id, lanes=declared,
                         _delivery=self, _line=line)

    def _refuse_taken(self, batch_id: str, branch: str) -> None:
        if os.path.lexists(self.tenant.drafts / batch_id):
            raise DeliveryRefused(f"the batch id {batch_id} has a draft already: batch ids are "
                                  "never used again while their draft remains")
        if self._branch_tip(branch) is not None:
            raise DeliveryRefused(f"the branch {branch} already exists in the tenant clone: "
                                  "its commits are deliver's to pick up, and its id is not used "
                                  "again")

    def _build_draft(self, batch_id: str, commit: str, lanes: tuple[str, ...]) -> None:
        """The draft of `commit`'s `agent/` (and each lane's folder), built whole in a fresh
        `<T>/drafts/.<id>-<rand>` and renamed to `<T>/drafts/<id>`, refusing any entry already
        there. A build that fails removes its temporary; one killed leaves only that temporary,
        which the next publish or batch start sweeps. The caller holds the lock."""
        files = self._agent_blobs(commit)
        drafts = self.tenant.drafts
        temporary = f"{_DRAFT_TEMPORARY}{batch_id}-{secrets.token_hex(4)}"
        try:
            with _io.hold_new(drafts, temporary, exclusive=True) as draft:
                draft.mkdir("agent")  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted core's no-follow walk off the held temporary, not a `Path.mkdir`
                for rel, data in files.items():
                    draft.write(f"agent/{rel}", data, mode="create")
                for lane in lanes:
                    draft.mkdir(f"agent/{lane}")  # lint-unguarded-tree-write: ok — `Held.mkdir` below the held temporary, no link followed
            _rename_new(drafts, temporary, batch_id)
        except BaseException:
            _remove_entry(drafts, temporary)
            raise

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

    def start_box(self, request: box.BoxRequest, *, docker: DockerFn = _docker) -> box.BoxExecutor:
        """The tenant drain's box, through `box.start_box`, the one entry: it requires a
        sandbox, so a start fault raises whatever the operator's opt-out says, never an
        unsandboxed executor, and leaves nothing under `<T>/drafts/` (no did-not-run marker).
        Never over a draft root holding `settings/` (a run copy's half, never a draft's)."""
        for mount in request.mounts:
            if mount.kind == "staged" and _io.entry_present(Path(mount.source) / "settings"):
                raise box.BoxFault(f"the draft root {mount.source} holds settings/: a draft "
                                   "holds agent/ alone")
        return box.start_box(replace(request, require_sandbox=True), docker=docker)

    # -- the commit-maker -------------------------------------------------------------------

    def _commit(self, line: _Line, change_set: ChangeSet, message: str, *,
                reverts: tuple[_BatchKey, str] | None = None) -> str:
        """The one maker of tenant commits. It takes only a `ChangeSet` within `line`'s lanes,
        writes git objects only (each blob exactly the change's bytes, mode 100644, in a tree
        built in a private index), records the commit, and moves the branch by compare-and-swap
        from its own last commit, the first commit expecting no branch at all (so it creates
        it, and never takes one over). No lock: the compare-and-swap is enough, and it never
        touches `main`, the clone's index or its checkout."""
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
            branch = line.batch.branch
            tip = self._branch_tip(branch)
            if tip != line.tip:
                raise DeliveryRefused(
                    f"the branch {branch} is at {tip or 'nothing'}, not the commit-maker's last "
                    f"commit {line.tip or '(none yet)'}: it builds on nothing it did not make")
            parent, env = line.head, _local_env()
            paths = [change.path for change in change_set]
            before = self._regular_blobs(parent, paths, env)
            for change in change_set:
                if change.content is None and change.path not in before:
                    raise DeliveryRefused(f"{change.path} is not a file {parent} holds: it "
                                          "cannot be deleted")
            at_base = before if parent == line.batch.base else \
                self._regular_blobs(line.batch.base, paths, env)
            tree, after = self._stage(parent, change_set, env)
            if tree == self._git(["rev-parse", f"{parent}^{{tree}}"]):
                raise DeliveryRefused("the change set changes nothing")
            commit = self._git(["commit-tree", tree, "-p", parent, "-F", "-"], input=message)
            _record_made(self.tenant, _Made(
                commit=commit, batch=line.batch, lanes=line.lanes, reverts=reverts,
                changes=() if reverts is not None else tuple(
                    (path, at_base.get(path), after[path]) for path in paths)))
            self._git(["update-ref", "-m", "tenant commit-maker", f"refs/heads/{branch}", commit,
                       tip or "0" * len(commit)])
            line.tip = commit
            return commit

    def _regular_blobs(self, rev: str, paths: Sequence[str], env: dict[str, str]) -> dict[str, str]:
        """The blob id `rev` holds at each of `paths` that is a regular file there."""
        return {path: oid for mode, kind, oid, path in _tree_entries(
            self.tenant.knowledge, rev, paths, env, recursive=False)
            if kind == "blob" and mode in _REGULAR_MODES}

    def _stage(self, parent: str, change_set: ChangeSet,
               env: dict[str, str]) -> tuple[str, dict[str, str | None]]:
        """Write each change's blob (no filter: the bytes as given) and the tree `parent` plus
        the changes makes, in a private index; every file 100644. Answers the tree, and each
        path's new blob (`None`: deleted)."""
        index = Path(self._git(["rev-parse", "--path-format=absolute", "--git-path",
                                f"commit-maker-{secrets.token_hex(8)}.index"]))
        staged = {**env, "GIT_INDEX_FILE": str(index)}
        try:
            self._git(["read-tree", parent], env=staged)
            zero = "0" * len(parent)
            after: dict[str, str | None] = {}
            rows = []
            for change in sorted(change_set, key=lambda c: c.content is not None):
                if change.content is None:
                    after[change.path] = None
                    rows.append(f"0 {zero}\t{change.path}\0")
                    continue
                oid = _git.git_bytes(["hash-object", "-w", "--no-filters", "--stdin"],
                                     cwd=self.tenant.knowledge, env=env,
                                     input=change.content).decode("ascii").strip()
                after[change.path] = oid
                rows.append(f"100644 {oid}\t{change.path}\0")
            _git.git_bytes(["update-index", "-z", "--index-info"], cwd=self.tenant.knowledge,
                           env=staged, input="".join(rows).encode("utf-8"))
            return self._git(["write-tree"], env=staged), after
        finally:
            index.unlink(missing_ok=True)

    # -- push routes ------------------------------------------------------------------------

    def _forge_prs(self, commits: Iterable[str]) -> list[PullRequest]:
        """Our repository's PRs (open, merged or closed) whose head commit is one of
        `commits`, by the forge's own listing: the branch name and the repository's full name
        play no part (amendment 3, C1)."""
        wanted = frozenset(commits)
        return [pr for pr in self.forge.pull_requests() if pr.head_sha in wanted]

    def _deliver(self, batch: _BatchKey, tip: str, *, title: str, body: str) -> Delivered:
        """Every push route's one path. Each commit between the batch's base and `tip` must be
        one the commit-maker made for this batch (checked before anything else, so a branch
        holding only a foreign commit refuses rather than having nothing to deliver). Then the
        batch's PR is looked up, before any push: one found (open, merged or closed) is
        answered and nothing is pushed or opened (D-closed). With none, a branch at its base
        has nothing to deliver; otherwise `tip` (by id, so a branch moved meanwhile sends
        nothing new) is pushed to the remote branch alone and a PR opened against `main`."""
        mine = _Record.read(self.tenant).commits_of(batch)
        if tip != batch.base:
            sent = self._git(["rev-list", f"{batch.base}..{tip}"]).split()
            foreign = [commit for commit in sent if commit not in mine]
            if foreign or not sent:
                raise DeliveryRefused(
                    f"the branch {batch.branch} at {tip} holds {len(foreign) or 'no'} commit(s) "
                    f"past its base {batch.base} that the commit-maker did not make for it "
                    f"({', '.join(foreign) or 'it does not descend from its base'}): nothing "
                    "is pushed")
        found = sorted(self._forge_prs(mine) if mine else (),
                       key=lambda pr: (_PRECEDENCE[pr.status], -pr.number))
        if found:
            return _answer(found[0])
        if tip == batch.base:
            return Delivered(status=DeliveryStatus.NOTHING)
        self._check_origin()
        self._network(["push", "--quiet", "origin", f"{tip}:refs/heads/{batch.branch}"])
        url = self.forge.open_pr(base="main", head=batch.branch, title=title, body=body)
        return Delivered(status=DeliveryStatus.OPENED, url=url)

    def finish(self, batch: Batch) -> Delivered:
        """Deliver the batch: `nothing to deliver` when it made no commit (it has no branch);
        otherwise its PR's status when the forge has one, or its branch pushed and a PR
        opened. A branch moved from the commit-maker's last commit, or holding any commit it
        did not make for this batch, is refused before any push."""
        with _refusals():
            line = batch._line
            tip = self._branch_tip(line.batch.branch)
            if tip != line.tip:
                raise DeliveryRefused(
                    f"the branch {line.batch.branch} is at {tip or 'nothing'}, not the "
                    f"commit-maker's last commit {line.tip or '(none yet)'}: nothing is pushed")
            if tip is None:
                return Delivered(status=DeliveryStatus.NOTHING)
            return self._deliver(line.batch, tip, title=_batch_title(batch.id),
                                 body=_batch_body(line.batch.branch, line.batch.base))

    def deliver(self, batch_id: str) -> Delivered:
        """Deliver a batch's branch from any later delivery (its draft discarded, its push or
        PR request failed before): the batch is the one the commit-maker's record says made
        the branch's tip. `nothing to deliver` when the clone holds no such branch; refused
        when the record knows no batch of it, or any commit on it past its base is not that
        batch's."""
        with _refusals():
            branch = f"{self.branch_prefix}{_one_word(batch_id, 'batch id')}"
            tip = self._branch_tip(branch)
            if tip is None:
                return Delivered(status=DeliveryStatus.NOTHING)
            batch = _Record.read(self.tenant).batch_holding(branch, tip)
            if batch is None:
                raise DeliveryRefused(f"the branch {branch} holds no commit the commit-maker "
                                      "made: nothing is pushed")
            return self._deliver(batch, tip, title=_batch_title(batch_id),
                                 body=_batch_body(branch, batch.base))

    # -- revert -----------------------------------------------------------------------------

    def revert(self, lesson_path: str, lesson_name: str) -> Delivered:
        """Flow 4, D-peel: undo the newest batch's net change to `lesson_path` whose result
        `origin/main` still holds exactly there (absence included) and which has no merged
        revert, restoring the bytes from before it (or deleting the lesson it created), as one
        commit-maker commit on `main` pushed to a branch of its own with its PR (`opened`).
        That change's last revert decides first: its PR open answers `open` with it; closed is
        a rejection, refused; never a PR (its push or PR request failed) makes the revert
        again. Refused when no change is eligible: a lesson the commit-maker never wrote, one
        a human changed since, one already peeled back to human-written content."""
        with _refusals():
            path = _agent_path(lesson_path)
            name = _one_word(lesson_name, "lesson name")
            self._fetch()
            main = self._rev("refs/remotes/origin/main")
            record = _Record.read(self.tenant)
            change, pending = self._peel(record, path, self._regular_blob_on(main, path))
            if pending is not None:
                if pending.status == "open":
                    return _answer(pending)
                raise DeliveryRefused(
                    f"the revert of {path} the commit-maker last made was closed unmerged "
                    f"({pending.url}): a rejection, so it is not made again")
            content = None if change.before is None else _cat_blobs(
                self.tenant.knowledge, [change.before], _local_env())[change.before]
            line = _Line(batch=_BatchKey(branch=f"{self.branch_prefix}revert-{name}-"
                                                f"{secrets.token_hex(4)}",
                                         base=main, start=secrets.token_hex(8)),
                         lanes=record.lanes_of(change.batch))
            commit = self._commit(line, ChangeSet((AgentChange(path, content),)),
                                  f"revert lesson: {name}", reverts=(change.batch, path))
            tip = self._branch_tip(line.batch.branch)
            if tip != commit:
                raise DeliveryRefused(f"the revert branch {line.batch.branch} moved from the "
                                      f"commit-maker's commit {commit} (now {tip}): nothing is "
                                      "pushed")
            return self._deliver(line.batch, tip, title=f"revert lesson: {name}", body=(
                f"Reverts `{path}` to what it held before the commit-maker's change in batch "
                f"`{change.batch.branch}`, which `main` still holds exactly."))

    def _regular_blob_on(self, rev: str, path: str) -> str | None:
        """The blob `rev` holds at `path`, or `None` when it holds none; refused when the
        entry there is not a regular file."""
        found = _tree_entries(self.tenant.knowledge, rev, [path], _local_env(), recursive=False)
        if found and (found[0][1] != "blob" or found[0][0] not in _REGULAR_MODES):
            raise DeliveryRefused(f"{path} on main is not a regular file")
        return found[0][2] if found else None

    def _peel(self, record: _Record, path: str,
              current: str | None) -> tuple[_NetChange, PullRequest | None]:
        """D-peel: the newest batch's net change to `path` whose result is `current` and which
        has no merged revert (merged by the forge's word on the revert commit's PR, whatever
        the merge style), with its last revert's unmerged PR (`None`: it has no revert, or its
        last revert never had a PR). Refused when there is none."""
        prs: list[PullRequest] | None = None
        for change in record.net_changes(path):
            if change.after != current or change.before == change.after:
                continue
            reverts = record.reverts_of(change)
            if not reverts:
                return change, None
            if prs is None:
                prs = self._forge_prs(m.commit for m in record.made if m.reverts is not None)
            statuses = {m.commit: sorted((pr for pr in prs if pr.head_sha == m.commit),
                                         key=lambda pr: (_PRECEDENCE[pr.status], -pr.number))
                        for m in reverts}
            if any(pr.status == "merged" for found in statuses.values() for pr in found):
                continue
            last = statuses[reverts[-1].commit]
            return change, (last[0] if last else None)
        raise DeliveryRefused(f"no change the commit-maker made to {path} is what main holds "
                              "there now, with no merged revert: nothing to revert")


def _read_credential(path: Path) -> tuple[str, str, str]:
    """The tenant's forge credential (`<T>/forge/git-credentials`, git's credential-store
    format: one `scheme://user:token@host[:port]` line in a regular 0600 file), read once:
    `(user, token, the server it is for)`, the server `scheme://host[:port]` with the host and
    port unquoted (git's store writes `host%3aport`, C5). Anything else refuses, naming the
    file but not its content."""
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
    server = unquote(parts.netloc.rpartition("@")[2])
    if ("\n" in entry or not user or not token or parts.path not in {"", "/"} or parts.query
            or parts.fragment or any(ord(ch) < 0x20 for ch in user + token)
            or not server or any(ch in server for ch in "/?#@\\") or any(
                ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in server)):
        raise DeliveryRefused(f"the tenant's forge credential {path} must be one "
                              "scheme://user:token@host[:port] line")
    if len(_credential_answer(user, token)) > _ANSWER_LIMIT:
        raise DeliveryRefused(f"the tenant's forge credential {path} is longer than "
                              f"{_ANSWER_LIMIT} bytes")
    return user, token, f"{parts.scheme}://{server}"


def _pointed_at(tenant: Tenant) -> str | None:
    """The commit `exports/current` names now, or `None` when it names none."""
    try:
        return current_export(tenant).commit
    except DeliveryRefused:
        return None


def _batch_title(batch_id: str) -> str:
    return f"learning: tenant knowledge batch {batch_id}"


def _batch_body(branch: str, base: str) -> str:
    return (f"Tenant agent knowledge batch `{branch}`, based on `{base[:12]}`. Changes `agent/` "
            "only, every commit made by the host's commit-maker.")
