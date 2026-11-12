#!/usr/bin/env python3
"""Operator entry point for the investigation workspace map."""
from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._paths import adapters_under  # noqa: E402
from defender.investigation.workspace_map import DEFENDER_DIR, workspace_map  # noqa: E402
from defender.records.formats import TenantRefused  # noqa: E402

if TYPE_CHECKING:
    from defender.tenancy import Tenant, TenantDirectory


def main(argv: list[str], *, directory: TenantDirectory | None = None) -> int:
    """`workspace_map.py --tenant T <run_id>` (#1105 declared change 10, J8): the map of T's
    run, opened by id through T's repository (a path where the id belongs is refused). T comes
    through the one host acceptance (r10 A1), held while the map is drawn; `directory` is the
    tenant records a test hands in (a production process reads `DEFENDER_DATABASE_DSN`'s). The
    library call (`workspace_map(run_dir, ...)`, the running investigation's) is unchanged."""
    import argparse
    p = argparse.ArgumentParser(prog="workspace_map.py")
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is mapped; required, with no default")
    p.add_argument("run_id", help="the run, by its id")
    ns = p.parse_args(argv[1:])
    from defender import tenancy
    from defender.systems.run_tenant import host_tenant
    from defender.systems.catalog import Catalog, TenantSystems
    from defender.systems.verbs import RegistryError, read_roster

    try:
        admitted = host_tenant(tenancy.resolve_data_root(), ns.tenant, directory=directory)
    except TenantRefused as refused:
        sys.stderr.write(f"workspace_map: {refused}\n")
        return 2
    with admitted:
        run = tenancy.open_command_line_run(admitted.tenant, ns.run_id)
        if isinstance(run, str):
            sys.stderr.write(f"workspace_map: {run}\n")
            return 2
        # The tenant's systems (#1366 O1, DC7): its current enabled records the checkout's
        # catalog carries, plus the platform-served ones; never every adapter of the checkout.
        # An unreadable adapters tree or records that cannot be read are a one-line refusal and
        # exit 2, not a traceback.
        try:
            records = admitted.directory.current_records(admitted.tenant.id)
            roster = TenantSystems.of(records, Catalog(read_roster(adapters_under(DEFENDER_DIR))),
                                     tenant_id=admitted.tenant.id).roster
        except (RegistryError, TenantRefused) as e:
            sys.stderr.write(f"workspace_map: {e}\n")
            return 2
        # Every system the tenant has, not the ones a grant shows: this is an operator's view
        # drawn today, and no record says what the mapped run was granted.
        print(workspace_map(Path(run.run_dir), systems=roster.systems, skills_of=roster.systems,
                            agent_root=_stamped_agent_root(admitted.tenant, Path(run.run_dir))), end="")
    return 0


def _stamped_agent_root(tenant: Tenant, run_dir: Path) -> Path | None:
    """The agent half of the export the run read (#1108 P4: its host-held knowledge record's
    commit, `<T>/exports/<commit>/agent`, under the accepted `tenant`), or `None` when the run
    names none or the export is gone: the map then says it has no tenant knowledge to show."""
    from defender.records.formats import read_knowledge_status
    from defender.records import RunPaths

    paths = RunPaths(run_dir)
    status = read_knowledge_status(paths.knowledge_source(), paths.provenance)
    commit = status.commit if status is not None else None
    if commit is None:
        return None
    agent = tenant.export_folder(commit) / "agent"
    return agent if agent.is_dir() else None


if __name__ == "__main__":  # lint-log-setup: ok — an operator command
    sys.exit(main(sys.argv))
