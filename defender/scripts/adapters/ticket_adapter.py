#!/usr/bin/env python3
"""Ticket-server stub adapter — the `ticket` VERBS registry AND the one surviving CLI.

Wraps the v2 ticket-server (the v1 FastAPI app reused under playground-v2's compose),
read-only.

Two surfaces over ONE implementation. The six other adapters lost their CLI with #611
(nothing invokes them any more); ticket keeps its argparse entry point because two
NON-gather consumers still run it as a subprocess and pin its exit codes:

  - `learning/tickets/ticket_seeds.py`
  - `learning/author/verify_forward/forward.py`

(The benign judge's closed-ticket read was a THIRD subprocess consumer — its pinned bash
grant, whose MANDATORY `--require-closed` lookahead was its answer-key defense. #672 moved
that read off bash into two typed host-side tools that call the verb bodies IN-PROCESS with
`require_closed=True` hard-coded, so closed-only is now unreachable-to-loosen by construction
rather than mandatory in the argv grammar.)

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

#: This system's required config keys: the shared transport template PLUS the store's KEY
#: GRAMMAR. The grammar is an ENVIRONMENT fact — what a ticket key looks like in the deployed
#: store — so it is declared where the environment is described (`TICKET_KEY_PATTERN` in
#: `knowledge/environment/systems/ticket/config.env`), not hardcoded in a consumer. It is
#: REQUIRED, on the same rule as every other value here: absent means the system is down
#: (`ConfigFault`, exit 2), never a silent built-in default that would let a consumer screen
#: keys against a grammar this environment never agreed to. `elastic_adapter` declares its own
#: key set for the same reason.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "KEY_PATTERN")


# Same name in each stub adapter, closing over that module's SYSTEM/PREFIX: the shared
# body already lives once in `transport.load_config`, so this is a zero-argument alias,
# not a copy of any logic.
def _config(ctx: VerbContext) -> dict[str, str]:  # lint-dup: ok — per-module alias over the shared transport.load_config
    return transport.load_config(ctx, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def key_pattern(ctx: VerbContext) -> str:
    """This environment's ticket-key grammar, as an unanchored regex source string.

    A verb rather than an import so every consumer reaches it through the ONE registry seam
    the store is reached through (`verbs=`), and so a screen built on it can be driven with a
    fake registry instead of a real config file. Consumers anchor it themselves — the config
    declares the key SHAPE, not where the match starts and ends.

    The screen that uses it lives at the consumer (the benign judge's `get_closed_ticket`,
    #672 Fork A) rather than here, because that screen owes a RETRY-class response with zero
    store attempts, and a fault raised from this module is by contract an exit-code envelope.
    """
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
    return transport.http_get(ctx, _config(ctx), "/tickets", params=params or None)


def get_ticket(ctx: VerbContext, *, key: str, require_closed: bool = False) -> dict:
    """One ticket by key, incl. comments.

    `require_closed` confirms a *cited* closed case, never the in-flight (open) ticket for
    the alert under judgment (#338). Refusing a non-closed ticket HERE means the read scope
    can't reach the in-flight ticket even by key — the refusal is a query error (exit 1),
    the same code the CLI callers already pin.
    """
    payload = transport.http_get_obj(ctx, _config(ctx), f"/tickets/{key}")
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
