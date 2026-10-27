"""A command line's `--tenant T [--episode E] <run_id>`, opened (#1105 PR 2 review).

The lead author, the run page and the workspace map each take a run by id under a requested
tenant. This is their one entry step: the configured data root resolved (its refusal names
`DEFENDER_DATA_ROOT`), then the run opened under it. It lives outside the
runs repository, which resolves nothing (its callers hand it the root), and it is the one place
those three entry points resolve the root (#1120's census: one call per entry module).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.tenancy import _tenant
from defender._shown import escaped, quoted
from defender.records import RunId, RunRefused
from defender.records._episode_handle import EpisodeRefused
from defender.records._tenant_id import TenantRefused

if TYPE_CHECKING:
    from defender.records import Run
    from defender.records._locations import DataRoot
    from defender.tenancy._tenant import Tenant


def open_command_line_run(raw_tenant: str, raw_run_id: str, *,
                          episode_id: str | None = None) -> tuple[Tenant, Run] | str:
    """The run the request names, opened, beside its tenant as accepted — or its refusal as one line of text, never raised
    or logged: the data root's own (unset or unusable), or the opener's (the tenant's, the
    run's, the episode's). The command line prints it on stderr and exits with its own status
    (defender/CLAUDE.md: a refusal is a value, not a diagnostic)."""
    try:
        data_root = _tenant.resolve_data_root()
    except TenantRefused as no_root:
        return escaped(no_root)
    return open_requested_run(data_root, raw_tenant, raw_run_id, episode_id=episode_id)


def open_requested_run(data_root: DataRoot, raw_tenant: str, raw_run_id: str, *,
                        episode_id: str | None = None) -> tuple[Tenant, Run] | str:
    """The run a command line's `--tenant T [--episode E] <run_id>` names, beside T as accepted
    — T accepted under `data_root` (the root its entry point resolved), then the run opened by
    id through T's repository: `runs.open`, or with `episode_id` the episode view's `open` (an
    arm). Neither follows a link at any level below the tenant's folder. The caller gets the
    accepted `Tenant` too, so it never accepts T again (#1279 A4)."""
    try:
        tenant = _tenant.requested_tenant(data_root, raw_tenant)
        runs = tenant.runs_repository()
        run_id = RunId.parse(raw_run_id)
        if episode_id is None:
            return tenant, runs.open(run_id)
        with runs.episode(episode_id) as view:
            return tenant, view.open(run_id)
    except (TenantRefused, RunRefused, EpisodeRefused, OSError) as refused:
        where = f" of episode {quoted(episode_id)}" if episode_id is not None else ""
        return (f"run {quoted(raw_run_id)}{where} of tenant {quoted(raw_tenant)} cannot be "
                f"opened: {escaped(refused)}")
