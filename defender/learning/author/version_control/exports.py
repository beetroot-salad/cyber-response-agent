"""Knowledge validation, dead-owner sweep and atomic draft construction (SPIKE #1618: the lock, exports and the
`current` pointer are gone)."""

from __future__ import annotations

from defender.records.formats import unwrap_drafts_root

from pathlib import Path

from defender import _io
from defender.tenancy import TenantExport as TenantExport
from defender.tenancy import owned_temporary
from defender.tenancy import remove_entry as _remove_entry
from defender.tenancy import Tenant, parse_tenant_id_bytes

from .files import _rename_new
from .model import (
    _REGULAR_MODES,
    _TENANT_ID_PARTS,
    DeliveryRefused,
    _plain_component,
)
from .owner import write_owner
from .repository import LocalRepository

#: What a draft is built under (`.<id>-<rand>`) before it is renamed into place: a leading dot
#: is outside the batch-id grammar, so no draft is ever named so.
_DRAFT_TEMPORARY = "."


def scratch_name(prefix: str) -> str:
    """A name for scratch this process is about to make: carries its owner from its first instant."""
    return owned_temporary(prefix)


def knowledge_at(
    tenant: Tenant, repository: LocalRepository, commit: str
) -> dict[str, bytes]:
    """`agent/` and `settings/` at `commit`, from git objects: every entry a regular blob
    at a plain path, `agent/.tenant-id` naming this tenant through `_tenant`'s parser."""
    entries = repository.entries(commit, ["agent", "settings"], recursive=True)
    for mode, kind, _oid, path in entries:  # lint-stale-ref: ok — a local name that only shares its spelling with a symbol the retired importer defined
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


#: The folder inside a draft (U9) the box mounts: `agent/` and the box's start token only. The
#: owner record sits beside it, in no mount.
DRAFT_STAGE = "stage"


def build_draft(
    tenant: Tenant,
    repository: LocalRepository,
    batch_id: str,
    commit: str,
    lanes: tuple[str, ...],
) -> None:
    """The draft (U9) `<T>/drafts/<id>/{owner, stage/agent/...}` of `commit`'s `agent/` (and each lane's folder), built
    whole in a fresh `<T>/drafts/<owned temporary>` (owned from its first instant: no lock), then renamed into place,
    refusing any entry already there. `repository` is the caller's private repository, outside `<T>`."""
    files = agent_blobs(repository, commit)
    drafts = unwrap_drafts_root(tenant.drafts)
    temporary = scratch_name(f"{_DRAFT_TEMPORARY}{batch_id}")
    try:
        with _io.hold_new(drafts, temporary, exclusive=True) as draft:
            write_owner(drafts / temporary)
            draft.mkdir(
                f"{DRAFT_STAGE}/agent"
            )  # lint-unguarded-tree-write: ok — `Held.mkdir`, the rooted core's no-follow walk off the held temporary, not a `Path.mkdir`
            for rel, data in files.items():
                draft.write(f"{DRAFT_STAGE}/agent/{rel}", data, mode="create")
            for lane in lanes:
                draft.mkdir(
                    f"{DRAFT_STAGE}/agent/{lane}"
                )  # lint-unguarded-tree-write: ok — `Held.mkdir` below the held temporary, no link followed
        _rename_new(drafts, temporary, batch_id)
    except BaseException:
        _remove_entry(drafts, temporary)
        raise


def agent_blobs(repository: LocalRepository, commit: str) -> dict[str, bytes]:
    """`agent/` at `commit`, by path below it, each file's exact stored bytes, from git's
    objects: what the draft is copied from, derived against and reset to. An entry that is
    not a regular blob refuses (publish refused it already for an export commit)."""
    entries = repository.entries(commit, ["agent"], recursive=True)
    for mode, kind, _oid, path in entries:  # lint-stale-ref: ok — a local name that only shares its spelling with a symbol the retired importer defined
        if kind != "blob" or mode not in _REGULAR_MODES:
            raise DeliveryRefused(
                f"{commit} holds {path!r} as a {kind} of mode {mode}: "
                "not a regular file"
            )
    blobs = repository.blobs(oid for _m, _k, oid, _p in entries)
    return {path.removeprefix("agent/"): blobs[oid] for _m, _k, oid, path in entries}


def draft_path(tenant: Tenant, batch_id: str) -> Path:
    """One batch's draft folder `<T>/drafts/<id>` (its owner record and `stage/`); the tenant's
    drafts root stays with this owner."""
    if not _plain_component(batch_id):
        raise DeliveryRefused(f"{batch_id!r} is not a plain batch id")
    return unwrap_drafts_root(tenant.drafts) / batch_id
