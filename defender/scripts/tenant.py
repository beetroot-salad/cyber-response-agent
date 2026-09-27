#!/usr/bin/env python3
"""defender/scripts/tenant.py — the tenant lifecycle's operator command (D10).

    python3 defender/scripts/tenant.py setup <tenant-id>

`setup` is the ONLY production caller of `defender._tenant.create_tenant` (D10, driven by
`test_d10_setup_only_production_caller`'s census): it is idempotent — a tenant already set up
(its row exists and is valid) is a silent success, never a second write — and otherwise the
owner's row-write, with the owner's own refusal (a bad grammar, a foreign data root, an unset
`DEFENDER_DATA_ROOT`) printed VERBATIM and exit 1 (demand #0, F0/J29). Its writes go through
`create_tenant` alone — no raw mkdir or write of its own (the ratcheted `lint_unguarded_tree_
write` gate).
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
    """Idempotent: a tenant already set up is a silent success. Otherwise create it, refusing
    exactly as the owner does (O10's fresh-data-root check lives in `create_tenant` itself), and
    print the owner's own refusal verbatim on failure."""
    try:
        root = _tenant.resolve_data_root()
        _tenant.refuse_foreign_data_root(root, tenant_id)
    except ValueError as refused:
        print(f"[tenant.py] {refused}", file=sys.stderr)
        return 1
    try:
        _tenant.require_tenant(root, tenant_id)
        return 0
    except ValueError:
        pass
    try:
        _tenant.create_tenant(root, tenant_id)
        return 0
    except ValueError as refused:
        print(f"[tenant.py] {refused}", file=sys.stderr)
        return 1


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
    sys.exit(main(sys.argv[1:]))
