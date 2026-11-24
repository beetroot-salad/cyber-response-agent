"""The claim's own folders (#1546 A-O1, A-O9): the job's root, its inputs and the helper's spool, under the data root and
outside every tenant's folder, made at the start and removed at the end.

- `<root>/.job-roots/<claim>/`: the job's data root (its container's `DEFENDER_DATA_ROOT`, bound read-write at its own
  path), laid out as `<T>/runs/` and `<T>/episodes/`. What the helper places there (the launch record and the alert, a
  run's folder) is written anew, every file of link count 1.
- `<root>/.job-inputs/<claim>/`: what the helper hands the job read-only: the run copies (`run-knowledge/<run id>/`),
  fetched straight there by the fetch child (#1546 r10). Written by the helper and its fetch child alone, each file anew.
- `<root>/.job-spool/<claim>/`: the helper's upload spool and a learning job's grant read (`grant/`); bound into nothing.

Each is made exclusively, mode 0700 and owned by the data root's owner (the container's uid), by `box.make_data_folder`;
the worker removes whatever a dead helper left (`job_socket.CLAIM_ROOTS`)."""
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.job_socket import INPUTS_ROOT, ROOTS_ROOT, SPOOL_ROOT

from ._session import Session, StartFailed

RUN_KNOWLEDGE = "run-knowledge"


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


@dataclass(frozen=True)
class CopyTenant:
    """The claim's run-copy tenant (#1546 r10, the run-copy rule): the tenant's id and where its run copies are made, the
    claim's inputs (`<inputs>/run-knowledge/`), read as `run_common.resolve_knowledge` and `adopt_copy` read a `Tenant`'s."""

    id: Any
    run_knowledge: Path


def copy_tenant(session: Session, tenant: Any) -> CopyTenant:
    """`tenant`'s run-copy tenant for the claim: its copies made under `<inputs>/run-knowledge/`, never under `<T>`."""
    return CopyTenant(tenant.id, make_input_folder(session, RUN_KNOWLEDGE))
