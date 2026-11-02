"""A command line's `--tenant T [--episode E] <run_id>`, opened (#1105 PR 2 review).

The lead author, the run page and the workspace map each take a run by id under a requested
tenant. Their command function admits the tenant (r10 A1: the host acceptance, held for the
command); this opens the run by id through that accepted tenant's repository (r10.1 C1: the run
opener takes the accepted tenant and never accepts one again). It lives outside the runs
repository, and returns its refusal as one line of text.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender._shown import escaped, quoted
from defender.records import RunId, RunRefused
from defender.records.formats import EpisodeRefused
from defender.records.formats import TenantRefused

if TYPE_CHECKING:
    from defender.records import Run
    from defender.tenancy._tenant import Tenant


def open_command_line_run(tenant: Tenant, raw_run_id: str, *, episode_id: str | None = None) -> Run | str:
    """The run a command line's `--tenant T [--episode E] <run_id>` names, opened by id through
    the accepted `tenant`'s repository: `runs.open`, or with `episode_id` the episode view's
    `open` (an arm). Neither follows a link at any level below the tenant's folder. Its refusal
    (the run's, the episode's) comes back as one line of text, never raised or logged: the
    command line prints it on stderr and exits with its own status (defender/CLAUDE.md: a
    refusal is a value, not a diagnostic)."""
    try:
        runs = tenant.runs_repository()
        run_id = RunId.parse(raw_run_id)
        if episode_id is None:
            return runs.open(run_id)
        with runs.episode(episode_id) as view:
            return view.open(run_id)
    except (TenantRefused, RunRefused, EpisodeRefused, OSError) as refused:
        where = f" of episode {quoted(episode_id)}" if episode_id is not None else ""
        return (f"run {quoted(raw_run_id)}{where} of tenant {quoted(str(tenant.id))} cannot be "
                f"opened: {escaped(refused)}")
