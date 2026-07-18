#!/usr/bin/env python3
"""Ticket-server stub adapter — the `ticket` VERBS registry AND the one surviving CLI.

Wraps the v2 ticket-server (the v1 FastAPI app reused under playground-v2's compose),
read-only.

Two surfaces over ONE implementation. The six other adapters lost their CLI with #611
(nothing invokes them any more); ticket keeps its argparse entry point because three
NON-gather consumers still run it as a subprocess and pin its exit codes:

  - `learning/tickets/ticket_seeds.py`
  - `learning/author/verify_forward/forward.py`
  - the benign judge's pinned bash grant — whose MANDATORY `--require-closed` lookahead is
    its entire answer-key defense. A params-dict cannot express a mandatory flag: a verb's
    `require_closed` param has a default, and the model chooses. Only the grant's argv
    grammar can make it non-optional, so only argv can carry that read.

Both surfaces call `list_tickets` / `get_ticket` — the verbs. `main()` is the sole place
in this package still allowed to exit: it maps a raised fault back to the exit code its
subprocess callers contract on.

Usage (the CLI surface):
    ticket_adapter.py health-check
    ticket_adapter.py list-tickets [--status open] [--label brute-force] [--q sshd]
    ticket_adapter.py get-ticket SOC-1042 [--require-closed]

Exit codes:
    0 — success
    1 — query error (404, bad arg, --require-closed on a non-closed ticket)
    2 — connectivity / docker / config / upstream 5xx
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (see cmdb_adapter.py) or the CLI runs it directly.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import AdapterFault, UpstreamFault

SYSTEM = "ticket"
PREFIX = "TICKET"




def health_check(ctx: VerbContext) -> dict:
    return transport.health_check(ctx, transport.load_config(ctx, SYSTEM, PREFIX), SYSTEM)


def list_tickets(
    ctx: VerbContext,
    *,
    status: str | None = None,
    label: str | None = None,
    q: str | None = None,
    require_closed: bool = False,
) -> dict | list:
    """Tickets, filterable.

    `require_closed` is the structural closed-only guard for the offline benign judge's
    scoped list (#338): it pins status=closed regardless of any `status` value, so a
    stray/duplicate `--status open` (argparse keeps the last, and the grant's shape would
    otherwise admit it) cannot widen the read to the in-flight OPEN ticket.
    """
    params: dict[str, str] = {}
    if status:
        params["status"] = status
    if require_closed:
        params["status"] = "closed"
    if label:
        params["label"] = label
    if q:
        params["q"] = q
    return transport.http_get(ctx, transport.load_config(ctx, SYSTEM, PREFIX), "/tickets", params=params or None)


def get_ticket(ctx: VerbContext, *, key: str, require_closed: bool = False) -> dict:
    """One ticket by key, incl. comments.

    `require_closed` confirms a *cited* closed case, never the in-flight (open) ticket for
    the alert under judgment (#338). Refusing a non-closed ticket HERE means the read scope
    can't reach the in-flight ticket even by key — the refusal is a query error (exit 1),
    the same code the CLI callers already pin.
    """
    payload = transport.http_get_obj(ctx, transport.load_config(ctx, SYSTEM, PREFIX), f"/tickets/{key}")
    if require_closed and payload.get("status") != "closed":
        raise UpstreamFault(
            f"{key} is status={payload.get('status')!r}, not 'closed' (--require-closed)"
        )
    return payload


VERBS = {
    "health-check": health_check,
    "list-tickets": list_tickets,
    "get-ticket": get_ticket,
}


# --- the CLI surface ---------------------------------------------------------


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
    """The CLI's own VerbContext: this is a PROCESS, so its tree and its env are the
    process's — `os.environ` here is the ambient env, which is exactly right for a
    subprocess caller and exactly wrong for the in-process driver (which passes the run's
    scrubbed env instead)."""
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
        # The fault's exit code IS the CLI's exit code: the three subprocess callers (and the
        # circuit breaker behind them) key on it, so the taxonomy is mapped back here rather
        # than re-decided.
        print(f"error: {e.detail}", file=sys.stderr)
        sys.exit(e.exit_code)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
