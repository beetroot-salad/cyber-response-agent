#!/usr/bin/env python3
"""Ticket-server stub CLI — defender-side adapter.

Wraps the v2 ticket-server (the v1 FastAPI app reused under
playground-v2's compose). v1's `playground_ticket_cli.py` is a separate
ActionContract-shaped adapter; this one matches v2 conventions
(_stub_transport + --raw envelopes + docker-exec-curl), and is read-only.

Usage:
    ticket_cli.py health-check
    ticket_cli.py list-tickets [--status open] [--label brute-force] [--q sshd]
    ticket_cli.py get-ticket SOC-1042

Exit codes:
    0 — success
    1 — query error (404, bad arg)
    2 — connectivity / docker / upstream 5xx
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json

import _stub_transport as transport

SYSTEM = "ticket"
PREFIX = "TICKET"
DEFAULT_LIST_LIMIT = 50


def cmd_list_tickets(args, config):
    params: dict[str, str] = {}
    if args.status:
        params["status"] = args.status
    if args.label:
        params["label"] = args.label
    if args.q:
        params["q"] = args.q
    payload = transport.http_get(config, "/tickets", params=params or None)
    if args.raw:
        print(json.dumps(payload))
        return
    tickets = payload.get("tickets", []) if isinstance(payload, dict) else []
    total = payload.get("total", len(tickets)) if isinstance(payload, dict) else len(tickets)
    print(f"total: {total}")
    print(f"shown: {min(len(tickets), args.limit)}")
    for t in tickets[: args.limit]:
        print(
            f"- {t.get('key', '?'):<14} "
            f"status:{t.get('status', '?'):<10} "
            f"labels:{','.join(t.get('labels') or []) or '—':<24} "
            f"summary:{(t.get('summary') or '—')[:60]}"
        )


def cmd_get_ticket(args, config):
    payload = transport.http_get(config, f"/tickets/{args.key}")
    if args.raw:
        print(json.dumps(payload))
        return
    print(f"key: {payload.get('key', '?')}")
    print(f"status: {payload.get('status', '?')}")
    print(f"resolution: {payload.get('resolution', '—')}")
    print(f"summary: {payload.get('summary', '—')}")
    print(f"labels: {', '.join(payload.get('labels') or []) or '—'}")
    print(f"created: {payload.get('created', '?')}")
    print(f"updated: {payload.get('updated', '?')}")
    desc = (payload.get("description") or "").strip()
    if desc:
        print()
        print("description:")
        print(desc)
    comments = payload.get("comments") or []
    if comments:
        print()
        print(f"comments ({len(comments)}):")
        for c in comments:
            print(f"  [{c.get('created', '?')}] {c.get('author', '?')}: {c.get('body', '')[:200]}")


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
        "--limit", type=int, default=DEFAULT_LIST_LIMIT,
        help=f"Cap rows shown in text mode (default {DEFAULT_LIST_LIMIT}).",
    )
    lt.add_argument("--raw", action="store_true")

    gt = sub.add_parser("get-ticket", help="Full ticket record incl. comments.")
    gt.add_argument("key")
    gt.add_argument("--raw", action="store_true")

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = transport.load_config(SYSTEM, PREFIX)
    if args.subcommand == "health-check":
        transport.health_check(config, SYSTEM)
    elif args.subcommand == "list-tickets":
        cmd_list_tickets(args, config)
    elif args.subcommand == "get-ticket":
        cmd_get_ticket(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
