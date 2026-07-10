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
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json
import re
import sys

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
import sys as _sys
from pathlib import Path as _Path
if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.adapters import _stub_transport as transport

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
    print(json.dumps(payload))


def cmd_get_change(args, config):
    payload = transport.http_get_obj(config, f"/changes/{args.cr_id}")
    print(json.dumps(payload))


def cmd_list_changes(args, config):
    params: dict[str, str] = {}
    if args.status:
        params["status"] = args.status
    if args.host:
        params["host"] = args.host
    if args.active_at:
        params["active_at"] = _require_utc(args.active_at)
    payload = transport.http_get(config, "/changes", params=params or None)
    print(json.dumps(payload))


def build_parser():
    p = transport.AdapterArgumentParser(
        description="Change-mgmt stub CLI — authorized-change-window lookups.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    ac = sub.add_parser("active-changes", help="CRs covering <host> at <iso>.")
    ac.add_argument("--host", required=True)
    ac.add_argument("--at", required=True, help="UTC ISO 8601 timestamp.")

    gc = sub.add_parser("get-change", help="One CR by id.")
    gc.add_argument("cr_id")

    lc = sub.add_parser("list-changes", help="All CRs (filterable).")
    lc.add_argument(
        "--status",
        choices=["planned", "approved", "in_progress", "implemented", "cancelled"],
    )
    lc.add_argument("--host")
    lc.add_argument("--active-at", help="UTC ISO 8601 — filter to CRs active at this instant.")
    lc.add_argument(
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help="Accepted for back-compat; the full JSON payload is always returned (no row cap).",
    )

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
