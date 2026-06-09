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
"""

from __future__ import annotations

import argparse
import json

import _stub_transport as transport

SYSTEM = "cmdb"
PREFIX = "CMDB"
DEFAULT_LIST_LIMIT = 50


def cmd_get_host(args, config):
    payload = transport.http_get(config, f"/hosts/{args.name}")
    if args.raw:
        print(json.dumps(payload))
        return
    print(f"name: {payload.get('name', '?')}")
    print(f"role: {payload.get('role', '?')}")
    print(f"criticality: {payload.get('criticality', '?')}")
    print(f"owner: {payload.get('owner', '—')}")
    print(f"os: {(payload.get('os') or {}).get('base', '—')}")
    cw = payload.get("change_window")
    if cw:
        print(f"change_window: {cw}")
    te = payload.get("trust_edges_out") or []
    if te:
        print(f"trust_edges_out: {', '.join(te)}")
    print()
    print("full record:")
    print(json.dumps(payload, indent=2))


def cmd_list_hosts(args, config):
    params: dict[str, str] = {}
    if args.role:
        params["role"] = args.role
    if args.criticality:
        params["criticality"] = args.criticality
    if args.owner:
        params["owner"] = args.owner
    payload = transport.http_get(config, "/hosts", params=params or None)
    if args.raw:
        print(json.dumps(payload))
        return
    hosts = payload.get("hosts", []) if isinstance(payload, dict) else []
    total = payload.get("total", len(hosts)) if isinstance(payload, dict) else len(hosts)
    print(f"total: {total}")
    print(f"shown: {min(len(hosts), args.limit)}")
    for h in hosts[: args.limit]:
        print(
            f"- {h.get('name', '?'):<14} "
            f"role:{h.get('role', '?'):<10} "
            f"criticality:{h.get('criticality', '?'):<8} "
            f"owner:{h.get('owner', '—')}"
        )


def cmd_list_roles(args, config):
    payload = transport.http_get(config, "/roles")
    if args.raw:
        print(json.dumps(payload))
        return
    if isinstance(payload, list):
        for r in payload:
            print(f"- {r}")
    else:
        print(json.dumps(payload, indent=2))


def build_parser():
    p = argparse.ArgumentParser(
        description="CMDB stub CLI — host inventory lookups (merged BASE + OVERLAY view).",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    gh = sub.add_parser("get-host", help="Effective record for one host.")
    gh.add_argument("name")
    gh.add_argument("--raw", action="store_true")

    lh = sub.add_parser("list-hosts", help="All hosts (filterable).")
    lh.add_argument("--role")
    lh.add_argument("--criticality")
    lh.add_argument("--owner")
    lh.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help=f"Cap rows shown in text mode (default {DEFAULT_LIST_LIMIT}). Raw mode is uncapped.",
    )
    lh.add_argument("--raw", action="store_true")

    lr = sub.add_parser("list-roles", help="Inventory role catalog.")
    lr.add_argument("--raw", action="store_true")

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
