#!/usr/bin/env python3
"""Fetch a recent Wazuh alert by rule ID and print the raw _source JSON.

Used to seed `/investigate` runs against real activity from the playground.

Usage:
    fetch_alert.py <rule_id> [--window 4h] [--offset 0]

    # Most recent alert for rule 5710 in the last 4 hours
    fetch_alert.py 5710

    # Look back further
    fetch_alert.py 100110 --window 24h

    # The Nth most recent (0-indexed); useful when you want a different
    # alert than the latest, e.g., for diversity in eval runs
    fetch_alert.py 5710 --offset 3

Output is the raw _source dict (the same shape Wazuh stores in OpenSearch),
suitable to pass to `/investigate <rule_id> <alert_json>`.

Exit codes:
    0 — success, alert printed to stdout
    1 — no matching alert in the window
    2 — connection / config error
"""

import argparse
import json
import sys
from pathlib import Path

# Reuse the wazuh_cli infrastructure for config + client + querying.
SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR / "tools"))

from wazuh_cli import (  # noqa: E402
    compute_time_range,
    get_indexer_client,
    load_config,
    query_alerts,
)


def build_parser():
    p = argparse.ArgumentParser(
        description="Fetch a recent Wazuh alert by rule ID, print raw _source JSON",
    )
    p.add_argument("rule_id", help="Wazuh rule ID (e.g., 5710, 100110, 550)")
    p.add_argument(
        "--window",
        default="4h",
        help="Time window to search backward from now (e.g., 1h, 4h, 24h, 7d). Default: 4h",
    )
    p.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Skip N most-recent matches and return the next one. Default: 0 (most recent)",
    )
    return p


def main():
    args = build_parser().parse_args()

    if args.offset < 0:
        print("error: --offset must be >= 0", file=sys.stderr)
        sys.exit(2)

    # We need (offset + 1) alerts to be able to pick the one at `offset`.
    limit = args.offset + 1

    config = load_config()
    client = get_indexer_client(config)

    # query_alerts uses an args namespace for time range computation.
    class _TimeArgs:
        start = None
        end = None
        window = args.window

    time_start, time_end = compute_time_range(_TimeArgs())

    items, total, _ = query_alerts(
        client,
        config,
        f"rule.id:{args.rule_id}",
        time_start,
        time_end,
        limit=limit,
    )

    if not items:
        print(
            f"error: no alerts for rule.id:{args.rule_id} in window {args.window} "
            f"({time_start} to {time_end})",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(items) <= args.offset:
        print(
            f"error: only {len(items)} alerts for rule.id:{args.rule_id} in window "
            f"{args.window}, cannot return offset {args.offset}",
            file=sys.stderr,
        )
        sys.exit(1)

    alert = items[args.offset]
    # Pretty-print so users can eyeball the alert before passing it on.
    print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
