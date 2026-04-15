#!/usr/bin/env python3
"""Playground ticket connector — ActionContract adapter for the FastAPI stub.

Concrete ticketing-family ActionContract implementation that talks to the
playground `ticket-server` container (playground/ticket-server/app.py). Used
by end-to-end investigation validation when we want real
create→close→verify round-trips against a stateful HTTP backend, instead of
the no-op stub_ticket_cli.

Reachable at http://ticket-server:8080 from inside the dev compose network,
or http://localhost:8080 from the host shell. The base URL comes from
config.env (PLAYGROUND_TICKET_BASE_URL); no credentials — the stub is
auth-less by design.

Usage:
    python3 playground_ticket_cli.py health-check
    python3 playground_ticket_cli.py close --ticket-id SEC-1 \\
        --reason "benign-burst (monitoring-probe)" \\
        --author "soc-agent v3.4.0" \\
        --documentation "Investigation: run-abc; archetype: monitoring-probe" \\
        [--run-dir runs/run-abc] [--dry-run|--execute]

Exit codes:
    0 — success (including dry-run)
    1 — usage / contract error (missing flag, mutually exclusive flags)
    2 — connection failure or upstream error on --execute
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SOC_AGENT_DIR = Path(os.environ.get("SOC_AGENT_DIR", SCRIPT_DIR.parent.parent))
CONFIG_PATH = (
    SOC_AGENT_DIR
    / "knowledge"
    / "environment"
    / "systems"
    / "playground-ticket"
    / "config.env"
)

REQUIRED_CONFIG_KEYS = ["PLAYGROUND_TICKET_BASE_URL"]
HTTP_TIMEOUT = 10  # seconds


def load_config() -> dict[str, str]:
    """Load non-secret config from config.env. Env vars override file values."""
    if not CONFIG_PATH.exists():
        print(
            f"error: config file not found: {CONFIG_PATH}\n"
            f"hint: copy the template and fill in your environment values:\n"
            f"  cp knowledge/environment/systems/playground-ticket/config.env.template \\\n"
            f"     knowledge/environment/systems/playground-ticket/config.env",
            file=sys.stderr,
        )
        sys.exit(2)

    config: dict[str, str] = {}
    for line in CONFIG_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"')

    for key in list(config) + REQUIRED_CONFIG_KEYS:
        env_val = os.environ.get(key)
        if env_val is not None:
            config[key] = env_val

    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in config]
    if missing:
        print(
            f"error: missing required keys in {CONFIG_PATH}: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    return config


def _http(
    method: str,
    url: str,
    body: dict | None = None,
) -> tuple[int, dict | None, str | None]:
    """One-shot JSON HTTP call. Returns (status, parsed_body, error_str)."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"content-type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8")
            parsed = json.loads(raw) if raw else None
            return resp.status, parsed, None
    except urllib.error.HTTPError as e:
        try:
            parsed = json.loads(e.read().decode("utf-8"))
        except Exception:
            parsed = None
        return e.code, parsed, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return 0, None, f"connection failed: {e.reason}"
    except Exception as e:
        return 0, None, f"unexpected error: {e}"


# ---------------------------------------------------------------------------
# health-check
# ---------------------------------------------------------------------------


def cmd_health_check(_args: argparse.Namespace) -> int:
    config = load_config()
    base = config["PLAYGROUND_TICKET_BASE_URL"].rstrip("/")
    status, body, err = _http("GET", f"{base}/health")

    if status == 200 and body and body.get("status") == "ok":
        payload = {
            "connected": True,
            "detail": {"base_url": base, "ticket_count": body.get("ticket_count")},
        }
        print(json.dumps(payload))
        return 0

    payload = {
        "connected": False,
        "error": err or f"unexpected response (status={status})",
        "detail": {"base_url": base},
    }
    print(json.dumps(payload))
    return 1


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


def _build_action_result(
    ticket_id: str,
    reason: str,
    author: str,
    documentation: str,
    dry_run: bool,
    success: bool = True,
    error: str | None = None,
    upstream: dict | None = None,
) -> dict:
    return {
        "action": "close_ticket",
        "target": ticket_id,
        "dry_run": dry_run,
        "success": success,
        "error": error,
        "detail": {
            "reason": reason,
            "author": author,
            "documentation": documentation,
            "upstream": upstream,
        },
    }


def cmd_close(args: argparse.Namespace) -> int:
    """Close (or dry-run close) a ticket on the playground ticket-server.

    Dry-run is the default. The dry-run path short-circuits before any
    upstream call, so probes against non-existent IDs (PROBE-0) are safe.
    --execute issues a real POST /tickets/{key}/transitions with status=closed.
    """
    if args.dry_run and args.execute:
        print(
            "error: --dry-run and --execute are mutually exclusive",
            file=sys.stderr,
        )
        return 1

    dry_run = not args.execute

    if dry_run:
        result = _build_action_result(
            ticket_id=args.ticket_id,
            reason=args.reason,
            author=args.author,
            documentation=args.documentation,
            dry_run=True,
        )
        print(json.dumps(result))
        return 0

    config = load_config()
    base = config["PLAYGROUND_TICKET_BASE_URL"].rstrip("/")
    body = {
        "status": "closed",
        "resolution": args.reason,
        "author": args.author,
        "comment": args.documentation,
    }
    status, parsed, err = _http(
        "POST",
        f"{base}/tickets/{args.ticket_id}/transitions",
        body=body,
    )

    if status == 200 and parsed:
        result = _build_action_result(
            ticket_id=args.ticket_id,
            reason=args.reason,
            author=args.author,
            documentation=args.documentation,
            dry_run=False,
            success=True,
            upstream={
                "status": parsed.get("status"),
                "resolution": parsed.get("resolution"),
                "updated": parsed.get("updated"),
            },
        )
        print(json.dumps(result))
        return 0

    error_msg = err or f"upstream returned status={status}"
    if parsed and isinstance(parsed, dict) and "detail" in parsed:
        error_msg = f"{error_msg}: {parsed['detail']}"
    result = _build_action_result(
        ticket_id=args.ticket_id,
        reason=args.reason,
        author=args.author,
        documentation=args.documentation,
        dry_run=False,
        success=False,
        error=error_msg,
    )
    print(json.dumps(result))
    return 2


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Playground ticket connector — ActionContract CLI for the FastAPI stub",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser(
        "health-check",
        help="GET /health on the playground ticket-server",
    )

    c = sub.add_parser(
        "close",
        help="Close a ticket via POST /tickets/{key}/transitions. Defaults to --dry-run.",
    )
    c.add_argument(
        "--ticket-id",
        required=True,
        help="Ticket key to close, e.g. SEC-1 (one per invocation; batch not supported)",
    )
    c.add_argument("--reason", required=True, help="One-line close reason (becomes resolution)")
    c.add_argument("--author", required=True, help="Author string (e.g. soc-agent v3.4.0)")
    c.add_argument(
        "--documentation",
        required=True,
        help="Free-form close documentation (becomes a comment on the ticket)",
    )
    c.add_argument(
        "--run-dir",
        default=None,
        help="Investigation run directory (reads salt from meta.json if wrapping output)",
    )

    mode = c.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Default. Describe what WOULD happen without writing.",
    )
    mode.add_argument(
        "--execute",
        action="store_true",
        help="Actually close the ticket. Only passed by the Stop-stage hook.",
    )

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.subcommand == "health-check":
        return cmd_health_check(args)
    if args.subcommand == "close":
        return cmd_close(args)

    parser.error(f"unknown subcommand: {args.subcommand}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
