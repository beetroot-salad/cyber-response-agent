#!/usr/bin/env python3
"""Move a tenant's pre-#1187 entries aside, once (#1187 Flow 6)."""
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
