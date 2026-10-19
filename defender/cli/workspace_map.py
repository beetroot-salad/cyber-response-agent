#!/usr/bin/env python3
"""Operator entry point for the investigation workspace map."""
from __future__ import annotations

import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender._paths import adapters_under  # noqa: E402
from defender.presentation.workspace_map import DEFENDER_DIR, workspace_map  # noqa: E402

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
    from defender.execution._command_line_run import open_command_line_run
    from defender.runtime.verbs import RegistryError, read_roster

    run = open_command_line_run(ns.tenant, ns.run_id)
    if isinstance(run, str):
        sys.stderr.write(f"workspace_map: {run}\n")
        return 2
    try:
        roster = read_roster(adapters_under(DEFENDER_DIR))
    except RegistryError as e:
        sys.stderr.write(f"workspace_map: {e}\n")
        return 2
    print(workspace_map(Path(run.run_dir), systems=tuple(roster.accepted)), end="")
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
