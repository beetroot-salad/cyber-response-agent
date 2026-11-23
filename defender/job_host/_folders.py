"""The claim's own folders (#1546 A-O1, A-O9): the job's root, its inputs and the helper's spool, under the data root and
outside every tenant's folder, made at the start and removed at the end.

- `<root>/.job-roots/<claim>/`: the job's data root (its container's `DEFENDER_DATA_ROOT`, bound read-write at its own
  path), laid out as `<T>/runs/` and `<T>/episodes/`. What the helper places there (a run's folder, an adoption's clone)
  is written anew, every file of link count 1.
- `<root>/.job-inputs/<claim>/`: what the helper hands the job read-only: a run copy (`run-knowledge/<run id>/`), the
  pinned export (`exports/<commit>/`). Written by the helper alone, each file anew.
- `<root>/.job-spool/<claim>/`: the helper's upload spool; bound into nothing.

Each is made exclusively, mode 0700 and owned by the data root's owner (the container's uid), by `box.make_data_folder`;
the worker removes whatever a dead helper left (`job_socket.CLAIM_ROOTS`)."""
from __future__ import annotations

import contextlib
import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.job_socket import INPUTS_ROOT, ROOTS_ROOT, SPOOL_ROOT

from ._session import Session, StartFailed

RUN_KNOWLEDGE, EXPORTS = "run-knowledge", "exports"


def _give_entry(path: Path, owner: os.stat_result) -> None:
    if os.geteuid() == 0 and (owner.st_uid, owner.st_gid) != (0, 0):
        os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)


def give_tree(session: Session, top: Path) -> None:
    """Everything under `top` (no link followed) given to the data root's owner, the container's uid (a helper run as
    root makes it as root)."""
    owner = os.stat(session.root_folder)
    if os.geteuid() != 0:
        return
    _give_entry(top, owner)
    for folder, dirs, files in os.walk(top):
        for name in (*dirs, *files):
            _give_entry(Path(folder) / name, owner)


def make_claim_folders(session: Session) -> None:
    """The claim's root (with `<T>/runs` and `<T>/episodes`), inputs and spool; `StartFailed` when any cannot be made."""
    from defender.box import make_data_folder

    owner = os.stat(session.root_folder)
    try:
        session.job_root = make_data_folder(session.root_folder, ROOTS_ROOT, session.claim, mode=0o700)
        session.job_inputs = make_data_folder(session.root_folder, INPUTS_ROOT, session.claim, mode=0o700)
        session.job_spool = make_data_folder(session.root_folder, SPOOL_ROOT, session.claim, mode=0o700)
        tenant = session.job_root / session.tenant_id
        for folder in (tenant, tenant / "runs", tenant / "episodes"):
            folder.mkdir(mode=0o700)  # lint-unguarded-tree-write: ok — fresh, under the claim's own root before the job
            _give_entry(folder, owner)
    except OSError as e:
        raise StartFailed(f"the claim's folders could not be made: {e}") from None


def remove_claim_folders(session: Session) -> None:
    """Root, inputs and spool removed, nothing below them followed (a link the job left is removed as the link)."""
    for folder in (session.job_root, session.job_inputs, session.job_spool):
        if folder is not None:
            shutil.rmtree(folder, ignore_errors=True)


def make_input_folder(session: Session, *parts: str) -> Path:
    """`<inputs>/<parts...>/`, made (with any missing parent) by the helper."""
    if session.job_inputs is None:
        raise StartFailed("this job has no inputs folder")
    folder = session.job_inputs.joinpath(*parts)
    folder.mkdir(parents=True, exist_ok=True)  # lint-unguarded-tree-write: ok — the helper's own read-only inputs
    return folder


def write_tree(files: dict[str, bytes], into: Path) -> None:
    """`files` (relative path -> bytes) written anew under the fresh folder `into`: every file a new inode."""
    from defender import _io

    into.mkdir(parents=True, exist_ok=False)  # lint-unguarded-tree-write: ok — the helper's own fresh folder
    for rel, data in sorted(files.items()):
        target = into / rel
        if not target.resolve().is_relative_to(into.resolve()):
            raise StartFailed(f"{rel!r} climbs out of {into}")
        _io.guarded_mkdir(target.parent, base=into)
        with target.open("xb") as out:  # lint-unguarded-tree-write: ok — exclusive, the helper's own fresh folder
            out.write(data)


@dataclass(frozen=True)
class CopyTenant:
    """The tenant a run copy is made for (`run_knowledge.copy_for_run`'s members): its id, where its exports are read
    from, and where the copy is made: the claim's inputs (`<inputs>/run-knowledge/`)."""

    id: Any
    export_at: Any
    run_knowledge: Path

    def export_folder(self, commit: str) -> Path:
        return Path(self.export_at(commit))


def copy_tenant(session: Session, tenant: Any, *, exports_in_inputs: bool = False) -> CopyTenant:
    """A run copy's tenant for the claim: copies under `<inputs>/run-knowledge/`, read from the tenant's exports (or,
    `exports_in_inputs`, from the exports the helper placed in the inputs)."""
    folder = make_input_folder(session, RUN_KNOWLEDGE)
    if exports_in_inputs:
        inputs = make_input_folder(session, EXPORTS)
        return CopyTenant(tenant.id, lambda commit: inputs / commit, folder)
    return CopyTenant(tenant.id, tenant.export_folder, folder)


def place_export(session: Session, tenant: Any, commit: str) -> Path:
    """The export of `commit` placed in the inputs (`<inputs>/exports/<commit>/`, every file written anew) from the
    tenant's published one, materialised from its clone first when absent. Idempotent."""
    from defender.learning.author.version_control import materialise_export
    from defender.tenancy import regular_files

    target = make_input_folder(session, EXPORTS) / commit
    if target.is_dir():
        return target
    export = materialise_export(tenant, commit)
    source = Path(export.path)
    staged = target.with_name(f".{commit}.placing")
    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(staged)
    write_tree(regular_files(source), staged)
    os.rename(staged, target)
    return target
