#!/usr/bin/env python3
"""defender/scripts/tenant.py — the tenant lifecycle's operator command (D10).

    python3 defender/scripts/tenant.py setup <tenant-id>

`setup` is the ONLY production caller of `defender._tenant.create_tenant` (D10, driven by
`test_d10_setup_only_production_caller`'s census): a re-run against a data root that is
otherwise still fresh (its own row exists and is valid, nothing foreign has landed beside it)
is a silent success, never a second write. `refuse_foreign_data_root` runs on every call,
before that reuse check — O10's "created only into a fresh data root" is not waived just
because this tenant is already the one occupying it — so a data root that has picked up an
unrelated entry since the first `setup` still refuses, even though the row is already there.
Otherwise `setup` is the owner's row-write, with the owner's own refusal (a bad grammar, a
foreign data root, an unset `DEFENDER_DATA_ROOT`) printed VERBATIM and exit 1 (demand #0,
F0/J29). Its writes go through `create_tenant` alone — no raw mkdir or write of its own (the
ratcheted `lint_unguarded_tree_write` gate).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Hand-rolled rather than `scripts/_venv.reexec_into_venv`, matching `run.py`: this must run
# BEFORE any `defender.*` import resolves, and reaching that helper is itself such an import.
_DEFENDER_DIR = Path(__file__).resolve().parents[1]
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _tenant  # noqa: E402


def setup(tenant_id: str) -> int:
    """A tenant already set up is a silent success ONLY while the data root stays otherwise
    fresh — `refuse_foreign_data_root` runs first, unconditionally, so a foreign entry that
    landed beside this tenant since its first `setup` still refuses the re-run (see
    `test_something_other_than_the_tenant_appears_at_the_data_root_top_level`). A row already
    there is checked, and its own refusal (corrupt, naming another tenant) reported rather than
    read as "already exists". Otherwise create it. The id is checked BEFORE anything under the
    data root is looked at, so a path-shaped id never reaches a listing. Every refusal is the
    owner's `TenantRefused`, printed verbatim, exit 1."""
    try:
        _tenant.refuse_bad_tenant_id(tenant_id)
        root = _tenant.resolve_data_root()
        _tenant.refuse_foreign_data_root(root, tenant_id)
        if os.path.lexists(_tenant.TenantPaths(root, tenant_id).row):
            _tenant.require_tenant(root, tenant_id)
        else:
            _tenant.create_tenant(root, tenant_id)
    except _tenant.TenantRefused as refused:
        print(f"[tenant.py] {refused}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)
    setup_p = sub.add_parser("setup", help="create a tenant, if it does not already exist")
    setup_p.add_argument("tenant_id")
    ns = p.parse_args(argv)
    if ns.command == "setup":
        return setup(ns.tenant_id)
    return 2


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main(sys.argv[1:]))
