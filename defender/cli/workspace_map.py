#!/usr/bin/env python3
"""Operator entry point for the investigation workspace map."""
from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._paths import adapters_under  # noqa: E402
from defender.investigation.workspace_map import DEFENDER_DIR, workspace_map  # noqa: E402

def main(argv: list[str]) -> int:
    """`workspace_map.py --tenant T <run_id>` (#1105 declared change 10, J8): the map of T's
    run, opened by id through T's repository (a path where the id belongs is refused). The
    library call (`workspace_map(run_dir, ...)`, the running investigation's) is unchanged."""
    import argparse

    p = argparse.ArgumentParser(prog="workspace_map.py")
    p.add_argument("--tenant", required=True,
                   help="the tenant whose run is mapped; required, with no default")
    p.add_argument("run_id", help="the run, by its id")
    ns = p.parse_args(argv[1:])
    # The CLI reads the checkout's roster itself; an unreadable adapters tree is a one-line
    # refusal and exit 2, not a traceback.
    from defender.tenancy._command_line_run import open_command_line_run
    from defender.systems.verbs import RegistryError, read_roster

    opened = open_command_line_run(ns.tenant, ns.run_id)
    if isinstance(opened, str):
        sys.stderr.write(f"workspace_map: {opened}\n")
        return 2
    _, run = opened
    try:
        roster = read_roster(adapters_under(DEFENDER_DIR))
    except RegistryError as e:
        sys.stderr.write(f"workspace_map: {e}\n")
        return 2
    print(workspace_map(Path(run.run_dir), systems=tuple(roster.accepted),
                        agent_root=_stamped_agent_root(ns.tenant, Path(run.run_dir))), end="")
    return 0


def _stamped_agent_root(raw_tenant: str, run_dir: Path) -> Path | None:
    """The agent half of the export the run read (#1108 P4: its host-held knowledge record's
    commit, `<T>/exports/<commit>/agent`), or `None` when the run names none or the export is
    gone: the map then says it has no tenant knowledge to show."""
    from defender.records._knowledge_status import read_knowledge_status
    from defender.records import RunPaths
    from defender.tenancy import _tenant

    paths = RunPaths(run_dir)
    status = read_knowledge_status(paths.knowledge_source(), paths.provenance)
    commit = status.commit if status is not None else None
    if commit is None:
        return None
    try:
        tenant = _tenant.requested_tenant(_tenant.resolve_data_root(), raw_tenant)
    except _tenant.TenantRefused:
        return None
    agent = tenant.export_folder(commit) / "agent"
    return agent if agent.is_dir() else None


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
