#!/usr/bin/env python3
"""Identity stub CLI — defender-side adapter.

Wraps the v2 playground identity stub (FastAPI over keycloak/realm.yaml ×
hosts/inventory.yaml). Load-bearing for legitimacy checks: "is dev.dana
authorized on db-1?" answers off `can-access`, not `/etc/passwd`.

Usage:
    identity_cli.py health-check
    identity_cli.py can-access dev.dana db-1
    identity_cli.py get-user sre.alice
    identity_cli.py list-authorized-hosts dev.dana
    identity_cli.py list-users [--role developer] [--enabled true]

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

SYSTEM = "identity"
PREFIX = "IDENTITY"
DEFAULT_LIST_LIMIT = 50


def cmd_can_access(args, config):
    payload = transport.http_get_obj(
        config, f"/users/{args.user}/can_access", params={"host": args.host},
    )
    print(json.dumps(payload))


def cmd_get_user(args, config):
    payload = transport.http_get_obj(config, f"/users/{args.user}")
    print(json.dumps(payload))


def cmd_list_authorized_hosts(args, config):
    payload = transport.http_get(config, f"/users/{args.user}/authorized_hosts")
    print(json.dumps(payload))


def cmd_list_users(args, config):
    params: dict[str, str] = {}
    if args.role:
        params["role"] = args.role
    if args.enabled is not None:
        params["enabled"] = "true" if args.enabled else "false"
    payload = transport.http_get(config, "/users", params=params or None)
    print(json.dumps(payload))


def cmd_list_roles(args, config):
    payload = transport.http_get(config, "/roles")
    print(json.dumps(payload))


def build_parser():
    p = transport.AdapterArgumentParser(
        description="Identity stub CLI — realm-role × inventory-role authorization lookups.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    ca = sub.add_parser("can-access", help="Is <user> authorized on <host>?")
    ca.add_argument("user")
    ca.add_argument("host")
    ca.add_argument("--raw", action="store_true")

    gu = sub.add_parser("get-user", help="Full user record incl. authorized_hosts.")
    gu.add_argument("user")
    gu.add_argument("--raw", action="store_true")

    lah = sub.add_parser("list-authorized-hosts", help="Hosts <user> can access.")
    lah.add_argument("user")
    lah.add_argument("--raw", action="store_true")

    lu = sub.add_parser("list-users", help="All users (filterable).")
    lu.add_argument("--role")
    lu.add_argument("--enabled", type=lambda v: v.lower() in ("true", "1", "yes"))
    lu.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help="Accepted for back-compat; the full JSON payload is always returned (no row cap).",
    )
    lu.add_argument("--raw", action="store_true")

    lr = sub.add_parser("list-roles", help="Inventory roles ↔ realm roles mapping.")
    lr.add_argument("--raw", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = transport.load_config(SYSTEM, PREFIX)
    if args.subcommand == "health-check":
        transport.health_check(config, SYSTEM)
    elif args.subcommand == "can-access":
        cmd_can_access(args, config)
    elif args.subcommand == "get-user":
        cmd_get_user(args, config)
    elif args.subcommand == "list-authorized-hosts":
        cmd_list_authorized_hosts(args, config)
    elif args.subcommand == "list-users":
        cmd_list_users(args, config)
    elif args.subcommand == "list-roles":
        cmd_list_roles(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
