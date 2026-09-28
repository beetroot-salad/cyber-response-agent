"""#1106 — the per-tenant knowledge folder: `<tenants root>/<tenant id>/{settings,agent}/`.

WHY THIS EXISTS. A deployment's settings (each system's `config.env`, `verb-grants.yaml`,
`lead-zero.yaml`, `systems/case-history/mapping.yaml`) used to live under
`defender/knowledge/environment/`, inside the tree mounted read-only into every run's box. The
platform needs one such folder per tenant, and the box must hold none of them. So each tenant
gets a folder OUTSIDE `defender/`, in two halves:

  * `settings/` — HOST-ONLY. Every host-side reader of the four settings kinds reads the run's
    tenant's copy. It is never a mount source.
  * `agent/` — MODEL-FACING. Mounted read-only into the run's box at a fixed target (#1108
    fills it; #1106 creates it empty).

WHERE THE ROOT COMES FROM (D2). No reader finds the tenants root itself — not from the code
tree, `PATHS`, `__file__`, `DEFENDER_DIR` or the cwd. A process entry point is HANDED it (or
takes `default_tenants_root(<its own checkout>)`) and passes it down. Which copy a worktree run
reads is whatever its entry point was given.

ONE RESOLVER. `tenant_dir` is the one place a tenant id becomes a path, so both escapes are
closed here: the id's grammar (no separator, no `..`, no leading dot, not empty) and the link
(the tenant folder must resolve under the root, each half must be a real directory whose
resolved path is exactly `<resolved tenant>/<half>` — which catches `A/agent -> ../B/agent`
and `A/agent -> ../settings`, both of which stay inside the root — and NOTHING inside the
folder may be a link at all: a linked `config.env`, `systems/<sys>/` or knowledge file would
hand one tenant another's endpoints or knowledge while staying inside the root, and a rule
that named the files it covers would miss the next one). The retired bootstrap id `default`
names no tenant on any path (N10). An absent folder, half or required file is a
`TenantDirError` naming the path, with no fallback (D3).
"""
from __future__ import annotations

import argparse
import dataclasses
import os
from pathlib import Path

from defender._tenant import TenantId, TenantRefused

#: D3's files required AT START, relative to a tenant's `settings/`. A system's `config.env`
#: is deliberately not here: some adapters need none, and its absence stays the per-call
#: `ConfigFault` (exit 2, which trips the breaker).
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
    """An entry point's default tenants root: `<repo_root>/knowledge/tenants`.

    Computed from the checkout the entry point is HANDED, never discovered — so a worktree's
    entry point defaults to the worktree's copy, and nothing works out which checkout it is."""
    return Path(repo_root) / "knowledge" / "tenants"


def template_dir(repo_root: Path) -> Path:
    """The committed template tenant: `<repo_root>/knowledge/tenant-template`."""
    return Path(repo_root) / "knowledge" / TEMPLATE_DIRNAME


def _check_id(tenant_id: object) -> TenantId:
    """The id as a `TenantId` — O3's one grammar, the same one a run and the records hold it
    to (it admits no separator, dot or empty name) — or `TenantDirError` naming it."""
    try:
        return TenantId(tenant_id)
    except TenantRefused as bad:
        raise TenantDirError(str(bad)) from bad


def _refuse_links(folder: Path, tenant_id: str) -> None:
    """Refuse any link anywhere inside a tenant folder: a symlink (file or directory, never
    followed) or a hard-linked file (a second name for another tenant's bytes). A directory the
    walk cannot read is refused too — skipped, it would hide whatever links are below it."""

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
    """Resolve `tenant_id` under `tenants_root` to its two halves, or refuse (O4, O5, D3)."""
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
    """`--tenant` and `--tenants-root` for an operator command that reads a tenant's settings
    (#1106). `reads` says what the command takes from the tenant's `settings/`, for `--help`."""
    parser.add_argument(
        "--tenant", default=None,
        help=f"the tenant whose settings/ {reads}; required wherever the command reads a "
             "tenant — there is no default tenant (#1078)")
    parser.add_argument(
        "--tenants-root", type=Path, default=None,
        help="the folder holding one sub-folder per tenant; default <checkout>/knowledge/tenants, "
             "the checkout being the one the command's code tree sits in")


def entry_tenant_args(
    defender_dir: Path, tenants_root: Path | None, tenant_id: str | None,
) -> tuple[Path, str]:
    """An operator command's `(tenants root, tenant id)`, from its own arguments.

    ONE derivation for every such command: the tenants root defaults to the checkout that holds
    `defender_dir`, the code tree the command itself runs against, so a command pointed at a
    worktree's tree reads that worktree's tenants and never another checkout's. The tenant id
    is the request's own, and `TenantDirError` when the command was given none — there is no
    default (#1078)."""
    if tenant_id is None:
        raise TenantDirError("--tenant is required: there is no default tenant")
    root = tenants_root if tenants_root is not None else default_tenants_root(
        Path(defender_dir).parent)
    return root, tenant_id


def entry_tenant(
    defender_dir: Path, tenants_root: Path | None, tenant_id: str | None,
) -> TenantDir:
    """An operator command's tenant FOLDER (`entry_tenant_args`, then `tenant_dir`), or
    `TenantDirError` — for a command that reads a file from it and needs nothing else checked.
    A command that uses the tenant's grants goes through `run_tenant.resolve_tenant`."""
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
