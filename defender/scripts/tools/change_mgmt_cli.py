#!/usr/bin/env python3
"""Change-mgmt stub CLI — defender-side adapter.

Wraps the v2 playground change-management stub. Read-only verbs only —
the `POST /changes` and transition surfaces are chaos-mode controls,
not investigation reads.

Usage:
    change_mgmt_cli.py health-check
    change_mgmt_cli.py active-changes --host web-1 --at 2026-04-24T12:00:00Z
    change_mgmt_cli.py get-change CHG-1042
    change_mgmt_cli.py list-changes [--status open] [--host web-1]

Exit codes:
    0 — success
    1 — query error (404, bad arg, missing --at)
    2 — connectivity / docker / upstream 5xx
"""

from __future__ import annotations

import argparse
import json
import re
import sys

import _stub_transport as transport

SYSTEM = "change-mgmt"
PREFIX = "CHANGE_MGMT"
DEFAULT_LIST_LIMIT = 50
# UTC ISO 8601 — Z suffix or explicit offset. Loose: caller-side discipline
# is more useful than a strict parser, but reject obvious "2026-04-24" / local
# time forms so missing-Z bugs don't reach the upstream silently.
ISO_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)


def _require_utc(value: str) -> str:
    if not ISO_UTC_RE.match(value):
        sys.exit(
            f"error: --at must be UTC ISO 8601 (e.g. 2026-04-24T12:00:00Z), got: {value!r}\n"
            f"hint: change-mgmt active-window queries are timezone-sensitive — "
            f"pass an explicit Z or +00:00 suffix."
        )
    return value


def cmd_active_changes(args, config):
    params = {"host": args.host, "at": _require_utc(args.at)}
    payload = transport.http_get(config, "/changes/active", params=params)
    if args.raw:
        print(json.dumps(payload))
        return
    if not isinstance(payload, list):
        sys.exit(f"error: expected JSON array, got: {payload!r}")
    print(f"host: {args.host}")
    print(f"at: {args.at}")
    print(f"active CRs: {len(payload)}")
    for cr in payload:
        print(
            f"- {cr.get('id', '?'):<32} "
            f"status:{cr.get('status', '?'):<10} "
            f"window:{cr.get('window_start', '?')} → {cr.get('window_end', '?')}"
        )


def cmd_get_change(args, config):
    payload = transport.http_get(config, f"/changes/{args.cr_id}")
    if args.raw:
        print(json.dumps(payload))
        return
    print(f"id: {payload.get('id', '?')}")
    print(f"status: {payload.get('status', '?')}")
    print(f"summary: {payload.get('summary', '—')}")
    print(f"hosts: {', '.join(payload.get('hosts') or []) or '—'}")
    print(f"window: {payload.get('window_start', '?')} → {payload.get('window_end', '?')}")
    print(f"owner: {payload.get('owner', '—')}")
    print()
    print("full record:")
    print(json.dumps(payload, indent=2))


def cmd_list_changes(args, config):
    params: dict[str, str] = {}
    if args.status:
        params["status"] = args.status
    if args.host:
        params["host"] = args.host
    if args.active_at:
        params["active_at"] = _require_utc(args.active_at)
    payload = transport.http_get(config, "/changes", params=params or None)
    if args.raw:
        print(json.dumps(payload))
        return
    if isinstance(payload, dict):
        items = payload.get("changes") or payload.get("items") or []
        total = payload.get("total", len(items))
    else:
        items = payload if isinstance(payload, list) else []
        total = len(items)
    print(f"total: {total}")
    print(f"shown: {min(len(items), args.limit)}")
    for cr in items[: args.limit]:
        print(
            f"- {cr.get('id', '?'):<32} "
            f"status:{cr.get('status', '?'):<10} "
            f"hosts:{','.join(cr.get('hosts') or []) or '—'}"
        )


def build_parser():
    p = argparse.ArgumentParser(
        description="Change-mgmt stub CLI — authorized-change-window lookups.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    ac = sub.add_parser("active-changes", help="CRs covering <host> at <iso>.")
    ac.add_argument("--host", required=True)
    ac.add_argument("--at", required=True, help="UTC ISO 8601 timestamp.")
    ac.add_argument("--raw", action="store_true")

    gc = sub.add_parser("get-change", help="One CR by id.")
    gc.add_argument("cr_id")
    gc.add_argument("--raw", action="store_true")

    lc = sub.add_parser("list-changes", help="All CRs (filterable).")
    lc.add_argument("--status")
    lc.add_argument("--host")
    lc.add_argument("--active-at", help="UTC ISO 8601 — filter to CRs active at this instant.")
    lc.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help=f"Cap rows shown in text mode (default {DEFAULT_LIST_LIMIT}).",
    )
    lc.add_argument("--raw", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = transport.load_config(SYSTEM, PREFIX)
    if args.subcommand == "health-check":
        transport.health_check(config, SYSTEM)
    elif args.subcommand == "active-changes":
        cmd_active_changes(args, config)
    elif args.subcommand == "get-change":
        cmd_get_change(args, config)
    elif args.subcommand == "list-changes":
        cmd_list_changes(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
