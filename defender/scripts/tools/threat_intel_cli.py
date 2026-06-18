#!/usr/bin/env python3
"""Threat-intel stub CLI — defender-side adapter.

Wraps the v2 playground threat-intel stub (VT/OTX-shaped offline
reputation lookup).

IMPORTANT semantics:
    `/lookup/{value}` never 404s. A miss returns
    {"value": <q>, "verdict": "unknown", "score": 0, ...}.
    Treat `verdict: unknown` as *absence of signal*, never as
    refutation of a hypothesis.

Usage:
    threat_intel_cli.py health-check
    threat_intel_cli.py lookup 185.220.101.45
    threat_intel_cli.py list-indicators [--verdict malicious] [--type ip]

Exit codes:
    0 — success (including verdict=unknown)
    1 — query error (bad arg)
    2 — connectivity / docker / upstream 5xx
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json
import urllib.parse

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
import sys as _sys
from pathlib import Path as _Path
if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.tools import _stub_transport as transport

SYSTEM = "threat-intel"
PREFIX = "THREAT_INTEL"
DEFAULT_LIST_LIMIT = 50


def cmd_lookup(args, config):
    # /lookup/{value:path} — caller's value may contain dots/colons; quote it.
    quoted = urllib.parse.quote(args.value, safe="")
    payload = transport.http_get(config, f"/lookup/{quoted}")
    if args.raw:
        print(json.dumps(payload))
        return
    verdict = payload.get("verdict", "?")
    print(f"value: {payload.get('value', args.value)}")
    print(f"verdict: {verdict}")
    print(f"score: {payload.get('score', '?')}")
    print(f"type: {payload.get('type', '—')}")
    tags = payload.get("tags") or []
    print(f"tags: {', '.join(tags) or '—'}")
    if verdict == "unknown":
        print()
        print("NOTE: verdict=unknown is a lookup-miss synthetic, not a benign signal.")
        print("Refutation requires verdict in {benign, malicious, suspicious}.")


def cmd_list_indicators(args, config):
    params: dict[str, str] = {}
    if args.verdict:
        params["verdict"] = args.verdict
    if args.type:
        params["type"] = args.type
    if args.tag:
        params["tag"] = args.tag
    payload = transport.http_get(config, "/indicators", params=params or None)
    if args.raw:
        print(json.dumps(payload))
        return
    if isinstance(payload, dict):
        items = payload.get("indicators") or payload.get("items") or []
        total = payload.get("total", len(items))
    else:
        items = payload if isinstance(payload, list) else []
        total = len(items)
    print(f"total: {total}")
    print(f"shown: {min(len(items), args.limit)}")
    for ind in items[: args.limit]:
        print(
            f"- {ind.get('value', '?'):<30} "
            f"verdict:{ind.get('verdict', '?'):<12} "
            f"type:{ind.get('type', '?'):<10} "
            f"score:{ind.get('score', '?')}"
        )


def build_parser():
    p = transport.AdapterArgumentParser(
        description="Threat-intel stub CLI — offline reputation lookups (VT/OTX shape).",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    lk = sub.add_parser("lookup", help="Reputation for one IP/domain/hash.")
    lk.add_argument("value")
    lk.add_argument("--raw", action="store_true")

    li = sub.add_parser("list-indicators", help="All seed indicators (filterable).")
    li.add_argument("--verdict", choices=["benign", "suspicious", "malicious", "unknown"])
    li.add_argument("--type")
    li.add_argument("--tag")
    li.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help=f"Cap rows shown in text mode (default {DEFAULT_LIST_LIMIT}).",
    )
    li.add_argument("--raw", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = transport.load_config(SYSTEM, PREFIX)
    if args.subcommand == "health-check":
        transport.health_check(config, SYSTEM)
    elif args.subcommand == "lookup":
        cmd_lookup(args, config)
    elif args.subcommand == "list-indicators":
        cmd_list_indicators(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
