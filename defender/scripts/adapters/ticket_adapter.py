#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from pathlib import Path

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import AdapterFault, UpstreamFault

SYSTEM = "ticket"
PREFIX = "TICKET"

REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "KEY_PATTERN")


def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def key_pattern(ctx: VerbContext) -> str:
    return _config(ctx)["KEY_PATTERN"]


def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, _config(ctx), SYSTEM)


def list_tickets(
    ctx: VerbContext,
    *,
    status: str | None = None,
    label: str | None = None,
    q: str | None = None,
    require_closed: bool = False,
) -> dict | list:
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    if require_closed:
        params["status"] = "closed"
    if label:
        params["label"] = label
    if q:
        params["q"] = q
    return transport.http_get(ctx, _config(ctx), "/tickets", params=params or None)


def get_ticket(ctx: VerbContext, *, key: str, require_closed: bool = False) -> dict:
    payload = transport.http_get_obj(
        ctx, _config(ctx), f"/tickets/{urllib.parse.quote(key, safe='')}",
    )
    if require_closed and payload.get("status") != "closed":
        raise UpstreamFault(
            f"{key} is status={payload.get('status')!r}, not 'closed' (--require-closed)"
        )
    return payload


VERBS = {
    "health-check": health_check,
    "list-tickets": list_tickets,
    "get-ticket": get_ticket,
    "key-pattern": key_pattern,
}




def build_parser():
    p = transport.AdapterArgumentParser(
        description="Ticket-server stub CLI — read-only ticket lookups.",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="GET /health and exit.")

    lt = sub.add_parser("list-tickets", help="All tickets (filterable).")
    lt.add_argument("--status")
    lt.add_argument("--label")
    lt.add_argument("--q", help="Substring on summary or description.")
    lt.add_argument(
        "--require-closed", action="store_true",
        help="Pin status=closed (scoped closed-only list); overrides any other --status.",
    )

    gt = sub.add_parser("get-ticket", help="Full ticket record incl. comments.")
    gt.add_argument("key")
    gt.add_argument(
        "--require-closed", action="store_true",
        help="Exit non-zero unless the ticket is closed (scoped closed-only read).",
    )

    return p


def _cli_context() -> VerbContext:
    defender_dir = Path(os.environ.get("DEFENDER_DIR", Path(__file__).resolve().parents[2]))
    run_dir = Path(os.environ.get("DEFENDER_RUN_DIR", Path.cwd()))
    return VerbContext(defender_dir=defender_dir, run_dir=run_dir, env=dict(os.environ))


def main():
    parser = build_parser()
    args = parser.parse_args()
    ctx = _cli_context()
    payload: dict | list
    try:
        if args.subcommand == "health-check":
            payload = health_check(ctx)
        elif args.subcommand == "list-tickets":
            payload = list_tickets(
                ctx, status=args.status, label=args.label, q=args.q,
                require_closed=args.require_closed,
            )
        else:
            payload = get_ticket(ctx, key=args.key, require_closed=args.require_closed)
    except AdapterFault as e:
        print(f"error: {e.detail}", file=sys.stderr)
        sys.exit(e.exit_code)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
