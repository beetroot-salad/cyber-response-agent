"""A tenant's published knowledge, read from files alone: what a run (which has no git, no
network and never imports the delivery package, #1108 P4 P-3) needs to find the export it
copies, its files read whole with no link followed, and who holds the tenant's knowledge lock.
Writing exports is the delivery package's (`learning/author/version_control/exports.py`); this
module only reads."""
from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

from defender import _io
from defender.records._locations import DataRoot, _unwrap_exports_root, _unwrap_knowledge_lock
from defender.tenancy._tenant import Tenant, exports_folder_of


class DeliveryRefused(Exception):
    """The tenant cannot safely author or deliver this; the message names why."""


#: The pointer file in `<T>/exports/` naming the latest published export.
POINTER = "current"
#: A full git object id (SHA-1 or SHA-256).
OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


@dataclass(frozen=True)
class TenantExport:
    """The tenant's knowledge at one commit: `path` (`<T>/exports/<commit>/`) holds exactly that
    commit's `agent/` and `settings/` regular blobs, written from git objects by the host and
    never changed once published."""

    commit: str
    path: Path


def read_export_text(export: TenantExport, rel: str) -> tuple[str | None, str | None]:
    """`(text, None)` for the file `rel` (relative to the export folder, e.g. `agent/...`) of
    `export`, or `(None, why)`: read below the export folder with no link followed."""
    with _io.bind(export.path) as root:
        got = root.read(rel)
    if got.text is None:
        return None, "it is absent" if got.absent else got.reason
    return got.text, None


def current_export(tenant: Tenant) -> TenantExport:
    """The export `<T>/exports/current` names, read from the files alone: no git and no process
    (P4's runs have neither). An absent or empty pointer, one that is not an object id (one
    leading out of `exports/` included), or one naming a missing export is `DeliveryRefused`."""
    return _current_at(_unwrap_exports_root(tenant.exports), tenant.id)


def current_export_of(data_root: DataRoot, tenant_id: str) -> TenantExport:
    """`current_export` of the tenant `tenant_id` names under `data_root`, read from its files
    before (or without) accepting it: a launcher that pins the runs it starts to one commit
    (`evaluations/held_out`, #1108 P4 OD10) reads the pointer, and each run it starts accepts
    the tenant itself. The data root and the tenant's folder meet the layout's own guards."""
    return _current_at(exports_folder_of(data_root, tenant_id), tenant_id)


def _current_at(exports: Path, tenant_id: object) -> TenantExport:
    with _io.bind(exports) as folder:
        # Text, decoded with replacement: an oid is ASCII, so any byte that is not fails the
        # match below rather than the read.
        pointer = folder.read(POINTER, errors="replace")
        if pointer.text is None:
            why = "it is absent" if pointer.absent else pointer.refusal
            raise DeliveryRefused(
                f"no export is published for tenant {tenant_id}: "
                f"{exports / POINTER}: {why}"
            )
        commit = pointer.text.removesuffix("\n")
        if not OID.fullmatch(commit):
            raise DeliveryRefused(
                f"the export pointer {exports / POINTER} names no published "
                f"export: {pointer.text[:80]!r}"
            )
        found = _io.stat_entry(folder, commit)
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        raise DeliveryRefused(
            f"the export pointer {exports / POINTER} names {commit}, which is "
            "not a published export folder"
        )
    return TenantExport(commit=commit, path=exports / commit)


def knowledge_lock_holder(tenant: Tenant) -> int | None:
    """The pid the tenant's knowledge lock file names (its holder writes it on taking the lock),
    or `None` when it names none. Reads the file only: it says who took the lock last, not that
    the lock is held now, so a caller pairs it with whether that process is still running."""
    path = _unwrap_knowledge_lock(tenant.knowledge_lock)
    with _io.bind(path.parent) as folder:
        read = folder.read(path.name, errors="replace")
    return lock_pid(read.text or "")


def lock_pid(written: str) -> int | None:
    """The pid a knowledge lock file's text names (its holder writes it bare), or `None`."""
    written = written.strip()
    return int(written) if written.isdigit() else None


def regular_files(root: Path) -> dict[str, bytes]:
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
                raise DeliveryRefused(
                    f"{root / folder} could not be listed: "
                    f"{listed.refusal or 'it is absent'}"
                )
            for name, st in sorted(listed.stats.items()):
                rel = f"{folder}/{name}" if folder else name
                if stat.S_ISDIR(st.st_mode):
                    pending.append(rel)
                    continue
                if not stat.S_ISREG(st.st_mode):
                    raise DeliveryRefused(
                        f"{root / rel} is not a regular file or a folder "
                        f"(mode {stat.filemode(st.st_mode)}): refused whole"
                    )
                if st.st_size > _io.READ_LIMIT:
                    raise DeliveryRefused(
                        f"{root / rel} is larger than {_io.READ_LIMIT} bytes: "
                        "refused whole"
                    )
                read = bound.read_bytes(
                    rel
                )  # lint-whole-read: ok — `_io.Bound`, which enforces READ_LIMIT and the no-follow guards
                if read.data is None:
                    raise DeliveryRefused(
                        f"{root / rel} could not be read: "
                        f"{read.refusal or 'it vanished'}: refused whole"
                    )
                files[rel] = read.data
    return files


def remove_entry(folder: Path, name: str) -> None:
    """Remove `folder/name` as the entry it is (a folder with no link below it followed,
    anything else unlinked); nothing when it, or `folder`, is absent."""
    try:
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
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
