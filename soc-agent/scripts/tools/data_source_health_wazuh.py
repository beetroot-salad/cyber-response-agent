#!/usr/bin/env python3
"""Wazuh binding for the generic data-source health probe.

Binds `data_source_health.assess_health()` to the Wazuh query CLI by
supplying a `count_fn` that closes over `wazuh_cli.py`. To add another
vendor, copy this file as `data_source_health_{vendor}.py` and swap the
count_fn body to call the vendor's adapter (same contract as the
`/connect` skill generates).

Usage:
    python3 scripts/tools/data_source_health_wazuh.py \\
        --query 'rule.groups:sshd AND agent.name:web-server-01' \\
        --reporting-agent web-server-01 \\
        --incident-start 2026-04-17T11:00:00Z \\
        --incident-end   2026-04-17T12:00:00Z

The query should be the lead's base query with the reporting-agent scoping
baked in but **without** narrow incident-specific entity filters — the goal
is to characterize the source's overall rate for that agent, not the
incident itself.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from data_source_health import HealthVerdict, _iso, assess_health  # noqa: E402


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def _build_wazuh_count_fn(query_string: str):
    # Lazy import so the generic library stays usable in tests without opensearch-py.
    import wazuh_cli  # type: ignore

    config = wazuh_cli.load_config()
    client = wazuh_cli.get_indexer_client(config)

    def count_fn(start: datetime, end: datetime) -> int:
        _, total = wazuh_cli.query_alerts(
            client, config, query_string, _iso(start), _iso(end), limit=0
        )
        return int(total)

    return count_fn


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Data-source health probe (Wazuh binding example) — emits JSON verdict.",
    )
    p.add_argument("--query", "-q", required=True, help="Lucene query identifying the data source (entity/agent scoping included).")
    p.add_argument("--reporting-agent", required=True, help="Agent identifier whose data this probe is checking. Recorded in output for traceability.")
    p.add_argument("--incident-start", required=True, help="Incident window start (ISO 8601 UTC).")
    p.add_argument("--incident-end", required=True, help="Incident window end (ISO 8601 UTC).")
    p.add_argument("--samples", type=int, default=5, help="Number of baseline windows to sample (default: 5).")
    p.add_argument("--lookback-days", type=int, default=10, help="How far back to draw baseline samples from (default: 10). Each baseline window matches the incident window's duration (shift-query pattern).")
    p.add_argument("--exclude-recent-hours", type=int, default=24, help="Buffer between baseline pool and incident start, to avoid contamination (default: 24).")
    p.add_argument("--k", type=float, default=2.0, help="Stdev multiplier for elevated/low thresholds (default: 2.0).")
    p.add_argument("--seed", type=int, help="Optional RNG seed for reproducible sampling.")
    return p


def main() -> int:
    args = build_parser().parse_args()
    incident_window = (_parse_iso(args.incident_start), _parse_iso(args.incident_end))

    try:
        count_fn = _build_wazuh_count_fn(args.query)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(json.dumps({
            "verdict": "broken",
            "trigger": "count_fn_error",
            "reporting_agent": args.reporting_agent,
            "incident_window": {"start": _iso(incident_window[0]), "end": _iso(incident_window[1])},
            "error": f"could not build Wazuh count_fn: {e}",
            "trace": traceback.format_exc(),
        }, indent=2))
        return 1

    verdict: HealthVerdict = assess_health(
        count_fn,
        incident_window,
        args.reporting_agent,
        samples=args.samples,
        lookback_days=args.lookback_days,
        exclude_recent_hours=args.exclude_recent_hours,
        k=args.k,
        seed=args.seed,
    )

    print(json.dumps(verdict.to_dict(), indent=2))
    return 0 if verdict.verdict == "normal" else 1


if __name__ == "__main__":
    sys.exit(main())
