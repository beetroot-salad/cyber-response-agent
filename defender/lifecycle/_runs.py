"""The one-time upgrade step that makes `<data root>/<T>/runs` for the active tenants made before #1471 (R13-0).

New tenants get the folder from the host's `prepare` step. The job lane never makes it, so a folder missing later is
damage that fails loudly at the worker's claim; this sweep is run by hand (`python -m defender.lifecycle
make-runs-folders`), never by a pass of the host actor."""
from __future__ import annotations

import asyncio
from pathlib import Path

from defender import _io
from defender.lifecycle._host import _RUNS
from defender.tenancy import TenantId, TenantRepository


class RunsFoldersRefused(Exception):
    """One or more active tenants' runs folders could not be made; the text names each tenant and why."""


def _make_one(tenant: str, data_root: Path) -> bool:
    """Make `<T>/runs` guarded; True when it was newly made. Raises when `<T>` is absent or a link, or `runs` is a link."""
    folder = data_root / tenant
    if folder.is_symlink() or not folder.is_dir():
        raise OSError(f"{folder} is not a real directory on this data root")
    runs = folder / _RUNS
    already = runs.exists() or runs.is_symlink()
    _io.guarded_mkdir(runs, base=data_root)
    return not already


async def make_runs_folders(tenants: TenantRepository, *, data_root: Path) -> list[TenantId]:
    """Make `<T>/runs` for every `active` tenant that lacks it; the ids newly made, oldest first.

    Idempotent. A refusal (a link, a `<T>` that is missing or not a real directory, any OS refusal) leaves that tenant
    as found and the sweep goes on; if any tenant refused, the sweep then raises one `RunsFoldersRefused` naming all of
    them and returns no ids. A tenant not `active` is left alone."""
    made: list[TenantId] = []
    refused: list[str] = []
    for record in await tenants.tenants():
        if record.state != "active":
            continue
        try:
            if await asyncio.to_thread(_make_one, record.id, data_root):
                made.append(record.id)
        except OSError as failed:
            refused.append(f"{record.id} ({failed})")
    if refused:
        raise RunsFoldersRefused(f"no runs folder was made for {len(refused)} tenant(s): {'; '.join(refused)}")
    return made
