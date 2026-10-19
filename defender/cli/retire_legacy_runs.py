#!/usr/bin/env python3
"""Move a tenant's pre-#1187 entries aside, once (#1187 Flow 6).

Since #1187 a run folder is named by a bare UUID, an episode lives at
``<data root>/<T>/episodes/<uuid>/``, and nothing reads ``_tenant.json`` or ``_episodes``. The
tenant's runs listing refuses anything else in ``<T>/runs`` and names this command. It moves,
by rename, with nothing copied or deleted:

  * every entry of ``<T>/runs`` that is not a UUID run folder or a sidecar file of one (old
    run folders and their sidecars, ``_tenant.json``, ``_episodes``) into ``<T>/runs-legacy/``;
  * with ``--old-episodes-root DIR`` (the retired ``DEFENDER_EPISODES_BASE``, named here; no
    environment is read for it), every entry of DIR into ``<T>/episodes-legacy/``, whatever
    tenant it once ran for. An absent DIR is nothing to move.

It reports each move on stdout. A second run finds nothing to move and changes nothing; a run
stopped midway is finished by running it again.

BEFORE IT RUNS: no run, fork (a branch launch) or drain may be in flight on this data root, from
any checkout — the command does not detect one — and no checkout from before #1187 may use the
data root again (it would re-create ``_tenant.json``). Drain or clear the curation queue on the
old code first: the new drain quarantines a queued row naming an old run id.

It refuses before moving anything, listing everything it found, when an entry to move is a link
or anything but a folder or a regular file (remove it by hand: ``rm`` the link), when
``<T>/runs-legacy`` or ``<T>/episodes-legacy`` exists and is not a real folder, when a name is
already taken in its destination, or when DIR (or an entry, or a destination) is on another
filesystem than ``<T>``: the command only renames.

Usage:
  python3 defender/cli/retire_legacy_runs.py --tenant T [--old-episodes-root DIR]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.tenancy._tenant import TenantRefused, requested_tenant, resolve_data_root


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="retire_legacy_runs.py", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tenant", required=True,
                   help="the tenant whose entries move; required, with no default")
    p.add_argument("--old-episodes-root", type=Path, default=None,
                   help="the old shared episodes folder, whose every entry moves into "
                        "<T>/episodes-legacy/ (absent: nothing to move)")
    ns = p.parse_args(argv)
    try:
        tenant = requested_tenant(resolve_data_root(), ns.tenant)
        plan = tenant.runs_repository().retire_plan(ns.old_episodes_root)
    except TenantRefused as refused:
        print(f"retire_legacy_runs: refused, nothing moved: {refused}", file=sys.stderr)
        return 1
    with plan:
        if plan.faults:
            print(f"retire_legacy_runs: refused, nothing moved — {len(plan.faults)} problem(s):",
                  file=sys.stderr)
            for fault in plan.faults:
                print(f"  {fault}", file=sys.stderr)
            return 1
        try:
            moved = plan.act(print)
        except TenantRefused as stopped:
            print(f"retire_legacy_runs: stopped: {stopped}", file=sys.stderr)
            return 1
    print(f"{moved} entr{'y' if moved == 1 else 'ies'} moved")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
