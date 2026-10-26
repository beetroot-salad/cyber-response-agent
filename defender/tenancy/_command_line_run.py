"""A command line's `--tenant T [--episode E] <run_id>`, opened (#1105 PR 2 review).

The lead author, the run page and the workspace map each take a run by id under a requested
tenant. This is their one entry step: the configured data root resolved (its refusal names
`DEFENDER_DATA_ROOT`), then `records.open_requested_run` under it. It lives outside the
runs repository, which resolves nothing (its callers hand it the root), and it is the one place
those three entry points resolve the root (#1120's census: one call per entry module).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.tenancy import _tenant
from defender._shown import escaped

if TYPE_CHECKING:
    from defender.records import Run
    from defender.tenancy._tenant import Tenant


def open_command_line_run(raw_tenant: str, raw_run_id: str, *,
                          episode_id: str | None = None) -> tuple[Tenant, Run] | str:
    """The run the request names, opened, beside its tenant as accepted — or its refusal as one line of text, never raised
    or logged: the data root's own (unset or unusable), or the opener's (the tenant's, the
    run's, the episode's). The command line prints it on stderr and exits with its own status
    (defender/CLAUDE.md: a refusal is a value, not a diagnostic)."""
    from defender.records import open_requested_run

    try:
        data_root = _tenant.resolve_data_root()
    except _tenant.TenantRefused as no_root:
        return escaped(no_root)
    return open_requested_run(data_root, raw_tenant, raw_run_id, episode_id=episode_id)
