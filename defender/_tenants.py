"""The per-tenant knowledge folder: `<tenants root>/<tenant id>/{settings,agent}/`.

Lives outside `defender/` because that tree is mounted into every run's box, and the box must
hold no tenant's settings. Two halves:

  * `settings/` — host-only (`config.env`s, `verb-grants.yaml`, `lead-zero.yaml`,
    `systems/case-history/mapping.yaml`). Never a mount source.
  * `agent/` — model-facing, mounted read-only into the run's box.

No reader discovers the tenants root (not from `PATHS`, `__file__`, `DEFENDER_DIR` or the cwd):
an entry point is handed it, or uses `default_tenants_root(<its own checkout>)`, and passes it
down.

`tenant_dir` is the one place a tenant id becomes a path. It checks the id (`TenantId`) and
that the folder and each half resolve to exactly `<root>/<id>/<half>` (catching `A/agent ->
../B/agent`, which stays inside the root), and refuses any link inside the folder, since a
linked file would hand one tenant another's settings. Anything absent is a `TenantDirError`
naming the path, with no fallback.
"""
from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path

from defender._tenant import TenantId, TenantRefused

#: Files required at start, relative to `settings/`. A system's `config.env` is not here: some
#: adapters need none, and its absence is the per-call `ConfigFault` (exit 2, trips the breaker).
REQUIRED_SETTINGS: tuple[str, ...] = (
    "verb-grants.yaml",
    "lead-zero.yaml",
    "systems/case-history/mapping.yaml",
)

SETTINGS_HALF = "settings"
AGENT_HALF = "agent"

#: The template's folder name, beside `tenants/` under `knowledge/`. Creating a tenant means
#: copying it; it is checked by CI like every committed tenant but is never a run's tenant.
TEMPLATE_DIRNAME = "tenant-template"


class TenantDirError(TenantRefused):
    """A tenant id or folder this resolver will not stand behind: a malformed id, an escape
    through a link, or an absent folder, half or required file. Always names the id or path.
    One of the tenant refusals (`_tenant.TenantRefused`), which every entry point catches."""


@dataclasses.dataclass(frozen=True)
class TenantDir:
    """One tenant's two halves, both RESOLVED paths under `<root>/<tenant_id>/`."""

    tenant_id: TenantId
    settings: Path
    agent: Path


def default_tenants_root(repo_root: Path) -> Path:
    """An entry point's default tenants root: `<repo_root>/knowledge/tenants`, from the checkout
    it is handed (so a worktree defaults to the worktree's copy)."""
    return Path(repo_root) / "knowledge" / "tenants"


def template_dir(repo_root: Path) -> Path:
    """The committed template tenant: `<repo_root>/knowledge/tenant-template`."""
    return Path(repo_root) / "knowledge" / TEMPLATE_DIRNAME


def _check_id(tenant_id: object) -> TenantId:
    """The id as a `TenantId` (the one grammar runs and records use too), or `TenantDirError`."""
    try:
        return TenantId(tenant_id)
    except TenantRefused as bad:
        raise TenantDirError(str(bad)) from bad


def _refuse_links(folder: Path, tenant_id: str) -> None:
    """Refuse any symlink or hard-linked file inside a tenant folder. An unreadable directory
    is refused too, since skipping it would hide links below it."""

    def unreadable(error: OSError) -> None:
        raise TenantDirError(
            f"tenant {tenant_id!r}'s folder could not be checked for links: {error}")

    for current, dirnames, filenames in os.walk(folder, onerror=unreadable, followlinks=False):
        for name in (*dirnames, *filenames):
            entry = Path(current) / name
            if entry.is_symlink():
                raise TenantDirError(
                    f"tenant {tenant_id!r}'s folder must hold no links: {entry} is one (to "
                    f"{os.readlink(entry)}) — a link can hand this tenant another's settings "
                    "or knowledge while staying inside the tenants root"
                )
            if name in filenames and entry.lstat().st_nlink > 1:
                raise TenantDirError(
                    f"tenant {tenant_id!r}'s folder must hold no links: {entry} is a hard link "
                    f"({entry.lstat().st_nlink} names for one file) — its bytes may be another "
                    "tenant's"
                )


def _half(tenant_real: Path, tenant_id: str, name: str) -> Path:
    half = tenant_real / name
    if not half.exists():
        raise TenantDirError(f"tenant {tenant_id!r} has no {name}/ half: {half} is missing")
    if half.is_symlink() or not half.is_dir() or half.resolve() != tenant_real / name:
        raise TenantDirError(
            f"tenant {tenant_id!r}'s {name}/ half must be a real directory at {half}; it "
            f"resolves to {half.resolve()}"
        )
    return half


def tenant_dir(tenants_root: Path, tenant_id: object) -> TenantDir:
    """Resolve `tenant_id` under `tenants_root` to its two halves, or raise `TenantDirError`."""
    tenant_id = _check_id(tenant_id)
    root = Path(tenants_root)
    folder = root / tenant_id
    if not folder.exists():
        raise TenantDirError(
            f"no folder for tenant {tenant_id!r}: {folder} does not exist (tenants root {root})"
        )
    root_real = root.resolve()
    folder_real = folder.resolve()
    if folder.is_symlink() or folder_real != root_real / tenant_id or not folder_real.is_dir():
        raise TenantDirError(
            f"tenant {tenant_id!r}'s folder {folder} must be a real directory under the tenants "
            f"root {root_real}; it resolves to {folder_real}"
        )
    settings = _half(folder_real, tenant_id, SETTINGS_HALF)
    agent = _half(folder_real, tenant_id, AGENT_HALF)
    _refuse_links(folder_real, tenant_id)
    for rel in REQUIRED_SETTINGS:
        path = settings / rel
        if not path.exists():
            raise TenantDirError(
                f"tenant {tenant_id!r} is missing a required settings file: {path}"
            )
        if not path.is_file():
            raise TenantDirError(
                f"tenant {tenant_id!r}'s required settings file must be a regular file: {path}"
            )
    return TenantDir(tenant_id=tenant_id, settings=settings, agent=agent)


def add_tenant_arguments(parser: argparse.ArgumentParser, *, reads: str) -> None:
    """`--tenant` and `--tenants-root` for an operator command that reads a tenant's settings.
    `reads` says what the command takes from the tenant's `settings/`, for `--help`."""
    parser.add_argument(
        "--tenant", default=None,
        help=f"the tenant whose settings/ {reads}; required wherever the command reads a "
             "tenant — there is no default tenant")
    parser.add_argument(
        "--tenants-root", type=Path, default=None,
        help="the folder holding one sub-folder per tenant; default <checkout>/knowledge/tenants, "
             "the checkout being the one the command's code tree sits in")


def entry_tenant_args(
    defender_dir: Path, tenants_root: Path | None, tenant_id: str | None,
) -> tuple[Path, str]:
    """An operator command's `(tenants root, tenant id)`, from its own arguments.

    The tenants root defaults to the checkout holding `defender_dir`, so a command pointed at a
    worktree reads that worktree's tenants. The tenant id is the request's own: none is a
    `TenantDirError`, since there is no default tenant."""
    if tenant_id is None:
        raise TenantDirError("--tenant is required: there is no default tenant")
    root = tenants_root if tenants_root is not None else default_tenants_root(
        Path(defender_dir).parent)
    return root, tenant_id


def entry_tenant(
    defender_dir: Path, tenants_root: Path | None, tenant_id: str | None,
) -> TenantDir:
    """An operator command's tenant folder, or `TenantDirError` — for a command that only reads
    a file from it. A command that uses the tenant's grants goes through
    `run_tenant.resolve_tenant`."""
    return tenant_dir(*entry_tenant_args(defender_dir, tenants_root, tenant_id))


__all__ = [
    "AGENT_HALF",
    "REQUIRED_SETTINGS",
    "SETTINGS_HALF",
    "TEMPLATE_DIRNAME",
    "TenantDir",
    "TenantDirError",
    "add_tenant_arguments",
    "default_tenants_root",
    "entry_tenant",
    "entry_tenant_args",
    "tenant_dir",
    "template_dir",
]
