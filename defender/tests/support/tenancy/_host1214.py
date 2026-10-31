"""#1214 r10: the names the design leaves to the implementer, spelled once (A1, A2, A3, O-A5). No test functions.

The host acceptance step (A1): `host_tenant(data_root, raw_id, *, directory=None, defender_dir=..., box_mounted=(),
clone_tree=True)`, a context manager whose value carries `.tenant` (the `Tenant`), `.directory` (the
`TenantDirectory` it was admitted through) and `.wiring` (the forge wiring). It lives above `tenancy` and
`migrations`, next to `systems/run_tenant.entry_directory` (design: "The host acceptance step"); the module and the
name are this sketch's choice. Where the implementer spells them otherwise, only this module changes.
"""
from __future__ import annotations

import importlib
from typing import Any

#: The module the host acceptance step lives in, and its name (A1). Chosen here; the design names neither.
HOST_MODULE = "defender.systems.run_tenant"
HOST_MODULE_PATH = "systems/run_tenant.py"
HOST_ACCEPTANCE = "host_tenant"

#: The fields of the scope's value (design: "`admitted` carries the `Tenant`, the `TenantDirectory` ..., and the
#: forge wiring"). Chosen here.
ADMITTED_TENANT, ADMITTED_DIRECTORY, ADMITTED_WIRING = "tenant", "directory", "wiring"

#: The words the one waiting line carries while acceptance waits on the tenant's host lock (owner ruling: one line
#: naming that it is waiting for tenant T's host lock). The tenant id is asserted beside these.
WAITING_WORDS = ("waiting for tenant", "host lock")

#: The run-end curation request's keyword for the run's accepted tenant (O-A5: "the `enqueue` seam `run.main`
#: injects takes it"). Chosen here.
ENQUEUE_TENANT = "tenant"

#: The raw folder acceptance and every wrapper that reaches it (design: "The census test", first bullet).
RAW_ACCEPTANCE = frozenset({
    "accept_tenant", "requested_tenant", "accept_requested_tenant", "command_line_tenant", "command_line_paths",
    "resolve_tenant", "open_command_line_run", "open_requested_run",
})

#: Where a wrapper itself is defined: its own body may reach the next wrapper down (module -> function names).
WRAPPER_DEFINITIONS = {
    "tenancy/_tenant.py": {"requested_tenant", "accept_requested_tenant"},
    "tenancy/_command_line_run.py": {"open_command_line_run", "open_requested_run"},
    "learning/core/cli.py": {"command_line_tenant", "command_line_paths"},
    "systems/run_tenant.py": {"resolve_tenant"},
}

#: A3: the processes covered by their starter, which load the folder with the folder rules only. Exactly these.
A3_SET = frozenset({
    "learning/author/version_control/publish.py",
    "investigation/publish_launch.py",
    "skills/connect/validate_scaffold.py",
})

#: The entry points that move to the host acceptance step (design: "Callers that move to it").
ENTRY_POINT_MODULES = (
    "run.py",
    "learning/branch/cli.py",
    "cli/policy_cli.py",
    "cli/tenant.py",
    "learning/core/cli.py",
    "learning/core/drains.py",
    "cli/learning/revert_lesson.py",
    "cli/learning/lessons_page.py",
    "learning/leads/lead_author/__init__.py",
    "presentation/visualize_run.py",
    "cli/workspace_map.py",
    "presentation/visualize_episode.py",
    "learning/frontend/serialize.py",
    "cli/learning/trace_lesson.py",
    "cli/retire_legacy_runs.py",
)


def host_tenant(*args: Any, **kwargs: Any) -> Any:
    """The real host acceptance step, imported at call time (a missing target is a red at the case, not at
    collection)."""
    return getattr(importlib.import_module(HOST_MODULE), HOST_ACCEPTANCE)(*args, **kwargs)
