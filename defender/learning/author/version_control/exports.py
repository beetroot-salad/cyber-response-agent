"""Immutable published knowledge, atomic draft construction and the tenant lock."""

from __future__ import annotations

from defender.records._locations import (_unwrap_exports_root, _unwrap_drafts_root, _unwrap_knowledge_lock)

import contextlib
import os
import secrets
import shutil
import stat
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from defender import _flock, _io
from defender.tenancy._tenant import Tenant, parse_tenant_id_bytes

from .files import _remove_entry, _rename_new, _sweep_temporaries
from .model import (
    _OID,
    _REGULAR_MODES,
    _TENANT_ID_PARTS,
    DeliveryRefused,
    LockBusy,
    _plain_component,
)
from .repository import GitRepository

#: The pointer file in `<T>/exports/` naming the latest published export.
_POINTER = "current"
#: The name an export is written under before it is renamed into place.
_PUBLISHING_PREFIX = ".publishing-"
#: What a draft is built under (`.<id>-<rand>`) before it is renamed into place: a leading dot
#: is outside the batch-id grammar, so no draft is ever named so.
_DRAFT_TEMPORARY = "."


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
    exports = _unwrap_exports_root(tenant.exports)
    with _io.bind(exports) as folder:
        # Text, decoded with replacement: an oid is ASCII, so any byte that is not fails the
        # match below rather than the read.
        pointer = folder.read(_POINTER, errors="replace")
        if pointer.text is None:
            why = "it is absent" if pointer.absent else pointer.refusal
            raise DeliveryRefused(
                f"no export is published for tenant {tenant.id}: "
                f"{exports / _POINTER}: {why}"
            )
        commit = pointer.text.removesuffix("\n")
        if not _OID.fullmatch(commit):
            raise DeliveryRefused(
                f"the export pointer {exports / _POINTER} names no published "
                f"export: {pointer.text[:80]!r}"
            )
        found = _io.stat_entry(folder, commit)
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        raise DeliveryRefused(
            f"the export pointer {exports / _POINTER} names {commit}, which is "
            "not a published export folder"
        )
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
    path = _unwrap_knowledge_lock(tenant.knowledge_lock)
    with _io.hold(path.parent) as folder:
        handle = _io.open_lock_at(folder, path.name)
    try:
        if not _flock.take(handle, timeout_seconds=0):
            raise LockBusy(
                f"tenant {tenant.id}'s knowledge lock {path} is held by "
                f"{_lock_holder(handle)}: another publish, batch or revert is "
                "changing its clone; try again once it finishes"
            )
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()}\n")
        handle.flush()
        yield
    finally:
        _flock.release(handle)


def _pointed_at(tenant: Tenant) -> str | None:
    """The commit `exports/current` names now, or `None` when it names none."""
    try:
        return current_export(tenant).commit
    except DeliveryRefused:
        return None


def publish_locked(tenant: Tenant, repository: GitRepository) -> TenantExport:
    """Sweep dead draft builds, turn tenant-named filters off, fast-forward, export, point
    `current`: the caller holds the tenant's lock."""
    _sweep_temporaries(_unwrap_drafts_root(tenant.drafts), _DRAFT_TEMPORARY)
    upstream = repository.prepare_publish()
    files = knowledge_at(tenant, repository, upstream)
    repository.fast_forward(upstream)
    export = write_export(tenant, upstream, files)
    if _pointed_at(tenant) != upstream:
        _io.write_guarded(_unwrap_exports_root(tenant.exports) / _POINTER, f"{upstream}\n", mode="replace")
    return export


def knowledge_at(
    tenant: Tenant, repository: GitRepository, commit: str
) -> dict[str, bytes]:
    """`agent/` and `settings/` at `commit`, from git objects: every entry a regular blob
    at a plain path, `agent/.tenant-id` naming this tenant through `_tenant`'s parser."""
    entries = repository.entries(commit, ["agent", "settings"], recursive=True)
    for mode, kind, _oid, path in entries:
        if kind != "blob" or mode not in _REGULAR_MODES:
            raise DeliveryRefused(
                f"{commit} holds {path!r} as a {kind} of mode {mode}: only "
                "regular blobs are published (no link, no submodule)"
            )
        parts = path.split("/")
        if not all(_plain_component(p) for p in parts) or ".git" in map(
            str.casefold, parts
        ):
            raise DeliveryRefused(f"{commit} holds {path!r}, which is not a plain path")
    blobs = repository.blobs(oid for _m, _k, oid, _p in entries)
    files = {path: blobs[oid] for _mode, _kind, oid, path in entries}
    marker = "/".join(_TENANT_ID_PARTS)
    if marker not in files:
        raise DeliveryRefused(f"{commit} holds no {marker}: it names no tenant")
    named = parse_tenant_id_bytes(files[marker], Path(marker))
    if named != tenant.id:
        raise DeliveryRefused(
            f"{commit}'s {marker} names tenant {named!r}, not {tenant.id!r}"
        )
    return files


def write_export(tenant: Tenant, commit: str, files: dict[str, bytes]) -> TenantExport:
    """`<T>/exports/<commit>/`, written whole into a fresh folder beside it and renamed into
    place; an export already there is immutable and kept as it is. The caller holds the
    lock, so any staging folder found is a dead publisher's and is removed first."""
    exports = _unwrap_exports_root(tenant.exports)
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


def build_draft(
    tenant: Tenant,
    repository: GitRepository,
    batch_id: str,
    commit: str,
    lanes: tuple[str, ...],
) -> None:
    """The draft of `commit`'s `agent/` (and each lane's folder), built whole in a fresh
    `<T>/drafts/.<id>-<rand>` and renamed to `<T>/drafts/<id>`, refusing any entry already
    there. A build that fails removes its temporary; one killed leaves only that temporary,
    which the next publish or batch start sweeps. The caller holds the lock."""
    files = agent_blobs(repository, commit)
    drafts = _unwrap_drafts_root(tenant.drafts)
    temporary = f"{_DRAFT_TEMPORARY}{batch_id}-{secrets.token_hex(4)}"
    try:
        with _io.hold_new(drafts, temporary, exclusive=True) as draft:
            draft.mkdir(
                "agent"
            )  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted core's no-follow walk off the held temporary, not a `Path.mkdir`
            for rel, data in files.items():
                draft.write(f"agent/{rel}", data, mode="create")
            for lane in lanes:
                draft.mkdir(
                    f"agent/{lane}"
                )  # lint-unguarded-tree-write: ok — `Held.mkdir` below the held temporary, no link followed
        _rename_new(drafts, temporary, batch_id)
    except BaseException:
        _remove_entry(drafts, temporary)
        raise


def agent_blobs(repository: GitRepository, commit: str) -> dict[str, bytes]:
    """`agent/` at `commit`, by path below it, each file's exact stored bytes, from git's
    objects: what the draft is copied from, derived against and reset to. An entry that is
    not a regular blob refuses (publish refused it already for an export commit)."""
    entries = repository.entries(commit, ["agent"], recursive=True)
    for mode, kind, _oid, path in entries:
        if kind != "blob" or mode not in _REGULAR_MODES:
            raise DeliveryRefused(
                f"{commit} holds {path!r} as a {kind} of mode {mode}: "
                "not a regular file"
            )
    blobs = repository.blobs(oid for _m, _k, oid, _p in entries)
    return {path.removeprefix("agent/"): blobs[oid] for _m, _k, oid, path in entries}


def draft_path(tenant: Tenant, batch_id: str) -> Path:
    """One batch's content folder; the tenant's drafts root stays with this owner."""
    if not _plain_component(batch_id):
        raise DeliveryRefused(f"{batch_id!r} is not a plain batch id")
    return _unwrap_drafts_root(tenant.drafts) / batch_id
