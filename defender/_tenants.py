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
and `A/agent -> ../settings`, both of which stay inside the root — and each required settings
file must resolve to exactly its own place under that half). An absent folder, half or
required file is a `TenantDirError` naming the path, with no fallback (D3).
"""
from __future__ import annotations

import argparse
import dataclasses
from pathlib import Path

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


class TenantDirError(ValueError):
    """A tenant id or folder this resolver will not stand behind: a malformed id, an escape
    through a link, or an absent folder, half or required file. Always names the id or path."""


@dataclasses.dataclass(frozen=True)
class TenantDir:
    """One tenant's two halves, both RESOLVED paths under `<root>/<tenant_id>/`."""

    tenant_id: str
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


def _check_id(tenant_id: str) -> None:
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or tenant_id.startswith(".")
        or "/" in tenant_id
        or "\\" in tenant_id
        or "\0" in tenant_id
        or Path(tenant_id).name != tenant_id
    ):
        raise TenantDirError(
            f"tenant id {tenant_id!r} is not a single plain name (no path separator, no "
            "leading dot, not empty)"
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


def tenant_dir(tenants_root: Path, tenant_id: str) -> TenantDir:
    """Resolve `tenant_id` under `tenants_root` to its two halves, or refuse (O4, O5, D3)."""
    _check_id(tenant_id)
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
    for rel in REQUIRED_SETTINGS:
        path = settings / rel
        if not path.exists():
            raise TenantDirError(
                f"tenant {tenant_id!r} is missing a required settings file: {path}"
            )
        # The halves' rule, one level down: a required file (or a directory on the way to it)
        # that is a link could name another tenant's copy — `A/settings/verb-grants.yaml ->
        # ../../B/settings/verb-grants.yaml` stays inside the root and would hand A B's grants.
        if not path.is_file() or path.resolve() != settings / rel:
            raise TenantDirError(
                f"tenant {tenant_id!r}'s required settings file must be a real file at {path}; "
                f"it resolves to {path.resolve()}"
            )
    return TenantDir(tenant_id=tenant_id, settings=settings, agent=agent)


def add_tenant_arguments(parser: argparse.ArgumentParser, *, reads: str) -> None:
    """`--tenant` and `--tenants-root` for an operator command that reads a tenant's settings
    (#1106). `reads` says what the command takes from the tenant's `settings/`, for `--help`."""
    parser.add_argument(
        "--tenant", default=None,
        help=f"the tenant whose settings/ {reads}; default the bridge's bootstrap tenant "
             "(#1106 D4, until #1078)")
    parser.add_argument(
        "--tenants-root", type=Path, default=None,
        help="the folder holding one sub-folder per tenant; default <checkout>/knowledge/tenants, "
             "the checkout being the one the command's code tree sits in")


def entry_tenant(defender_dir: Path, tenants_root: Path | None, tenant_id: str | None) -> TenantDir:
    """An operator command's tenant, from its own arguments — or `TenantDirError`.

    ONE derivation for every such command: the tenants root defaults to the checkout that holds
    `defender_dir`, the code tree the command itself runs against, so a command pointed at a
    worktree's tree reads that worktree's tenants and never another checkout's. The tenant id
    defaults to the bridge's bootstrap tenant until #1078 puts it on the request."""
    from defender._tenant import DEFAULT_TENANT_ID

    root = tenants_root if tenants_root is not None else default_tenants_root(
        Path(defender_dir).parent)
    return tenant_dir(root, tenant_id if tenant_id is not None else DEFAULT_TENANT_ID)


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
    "tenant_dir",
    "template_dir",
]
