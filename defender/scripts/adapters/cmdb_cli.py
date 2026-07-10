#!/usr/bin/env python3
"""CMDB stub CLI — defender-side adapter.

Wraps the v2 playground CMDB stub (FastAPI over hosts/inventory.yaml).
Reads the merged BASE + OVERLAY view — overlay endpoints are chaos-mode
scaffolding and are not exposed by this adapter.

Usage:
    cmdb_cli.py health-check
    cmdb_cli.py get-host web-1
    cmdb_cli.py list-hosts [--role web] [--criticality prod] [--owner team.web]
    cmdb_cli.py list-roles

Exit codes:
    0 — success
    1 — query error (404, bad arg)
    2 — connectivity / docker / upstream 5xx
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
import sys as _sys
from pathlib import Path as _Path
if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.adapters import _stub_transport as transport

SYSTEM = "cmdb"
PREFIX = "CMDB"
DEFAULT_LIST_LIMIT = 50


def cmd_get_host(args, config):
    payload = transport.http_get_obj(config, f"/hosts/{args.name}")
    print(json.dumps(payload))


def cmd_list_hosts(args, config):
    params: dict[str, str] = {}
    if args.role:
        params["role"] = args.role
    if args.criticality:
        params["criticality"] = args.criticality
    if args.owner:
        params["owner"] = args.owner
    payload = transport.http_get(config, "/hosts", params=params or None)
    print(json.dumps(payload))


def cmd_list_roles(args, config):
    payload = transport.http_get(config, "/roles")
    print(json.dumps(payload))


def build_parser():
    p = transport.AdapterArgumentParser(
        description="CMDB stub CLI — host inventory lookups (merged BASE + OVERLAY view).",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    gh = sub.add_parser("get-host", help="Effective record for one host.")
    gh.add_argument("name")

    lh = sub.add_parser("list-hosts", help="All hosts (filterable).")
    lh.add_argument("--role")
    lh.add_argument("--criticality")
    lh.add_argument("--owner")
    lh.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help="Accepted for back-compat; the full JSON payload is always returned (no row cap).",
    )

    sub.add_parser("list-roles", help="Inventory role catalog.")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = transport.load_config(SYSTEM, PREFIX)
    if args.subcommand == "health-check":
        transport.health_check(config, SYSTEM)
    elif args.subcommand == "get-host":
        cmd_get_host(args, config)
    elif args.subcommand == "list-hosts":
        cmd_list_hosts(args, config)
    elif args.subcommand == "list-roles":
        cmd_list_roles(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
