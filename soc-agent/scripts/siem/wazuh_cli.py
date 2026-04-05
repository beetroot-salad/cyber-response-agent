#!/usr/bin/env python3
"""Wazuh SIEM CLI — thin wrapper for query execution.

Alert queries go to the Wazuh Indexer (OpenSearch) via opensearch-py.
Health checks use both the indexer and the Wazuh Manager API.

Usage:
    python3 wazuh_cli.py --query 'rule.id:5710 AND data.srcip:10.0.0.5' \
        --start 2026-04-04T10:00:00Z --window 1h

    python3 wazuh_cli.py --query 'rule.groups:sshd' \
        --start 2026-04-04T10:00:00Z --end 2026-04-04T12:00:00Z

    python3 wazuh_cli.py --health-check

Exit codes:
    0 — success
    1 — query error or degraded health
    2 — connection/auth failure
"""

import argparse
import base64
import json
import os
import sys
import ssl
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from opensearchpy import OpenSearch

SCRIPT_DIR = Path(__file__).resolve().parent
SOC_AGENT_DIR = Path(os.environ.get(
    "SOC_AGENT_DIR", SCRIPT_DIR.parent.parent
))
CONFIG_PATH = SOC_AGENT_DIR / "knowledge" / "environment" / "systems" / "wazuh" / "config.env"


def load_config():
    """Load non-secret config from config.env."""
    config = {
        "WAZUH_INDEX": "wazuh-alerts-*",
        "WAZUH_API_ENDPOINT": "https://wazuh-manager:55000",
        "WAZUH_INDEXER_ENDPOINT": "https://wazuh-indexer:9200",
        "WAZUH_RETENTION_DAYS": "90",
    }
    if CONFIG_PATH.exists():
        for line in CONFIG_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, _, val = line.partition("=")
                config[key.strip()] = val.strip().strip('"')
    return config


def get_indexer_client(config):
    """Create an OpenSearch client for the Wazuh Indexer."""
    user = os.environ.get("WAZUH_INDEXER_USER", "admin")
    password = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not password:
        print("error: WAZUH_INDEXER_PASSWORD environment variable must be set", file=sys.stderr)
        sys.exit(2)

    return OpenSearch(
        hosts=[config["WAZUH_INDEXER_ENDPOINT"]],
        http_auth=(user, password),
        verify_certs=False,
        ssl_show_warn=False,
    )


def parse_duration(s):
    """Parse duration string like '1h', '30m', '7d' to timedelta."""
    units = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    if not s or len(s) < 2 or s[-1] not in units:
        raise ValueError(f"Invalid duration: {s!r}. Use format like '1h', '30m', '7d'.")
    return timedelta(**{units[s[-1]]: int(s[:-1])})


def compute_time_range(args):
    """Compute (start, end) as ISO 8601 UTC strings from CLI args."""
    if args.start and args.end:
        return args.start, args.end

    end = datetime.now(timezone.utc) if not args.end else datetime.fromisoformat(
        args.end.replace("Z", "+00:00")
    )
    window = parse_duration(args.window)
    start = end - window
    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


# ---------------------------------------------------------------------------
# Indexer (OpenSearch) — alert queries
# ---------------------------------------------------------------------------

def query_alerts(client, config, query_string, time_start, time_end, limit=500):
    """Query Wazuh alerts via the indexer. Returns (hits_list, total_count)."""
    body = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": query_string}} if query_string else {"match_all": {}},
                ],
                "filter": [
                    {"range": {"timestamp": {"gte": time_start, "lte": time_end}}},
                ],
            }
        },
    }
    try:
        resp = client.search(index=config["WAZUH_INDEX"], body=body)
    except Exception as e:
        print(f"error: Indexer query failed: {e}", file=sys.stderr)
        sys.exit(2)

    hits = resp.get("hits", {})
    total = hits.get("total", {}).get("value", 0)
    items = [h["_source"] for h in hits.get("hits", [])]
    return items, total


# ---------------------------------------------------------------------------
# Manager API — health check only
# ---------------------------------------------------------------------------

def get_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def authenticate_manager(config):
    """Authenticate against the Wazuh Manager API and return JWT token."""
    user = os.environ.get("WAZUH_API_USER", "wazuh-wui")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not password:
        print("error: WAZUH_API_PASSWORD environment variable must be set", file=sys.stderr)
        sys.exit(2)

    url = config["WAZUH_API_ENDPOINT"].rstrip("/") + "/security/user/authenticate"
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }
    req = urllib.request.Request(url, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("data", {}).get("token", "")
    except urllib.error.URLError as e:
        print(f"error: Manager auth failed: {e}", file=sys.stderr)
        sys.exit(2)


def manager_api_request(endpoint, config, token, timeout=30):
    url = config["WAZUH_API_ENDPOINT"].rstrip("/") + endpoint
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"error: Manager API request failed: {e}", file=sys.stderr)
        sys.exit(2)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_output(query_string, time_start, time_end, config, items, match_count, index_count):
    latest_ts = items[0].get("timestamp", "none") if items else "no matching events"

    if not items:
        sample_text = "(no matching events)"
    else:
        lines = []
        for i, evt in enumerate(items[:5], 1):
            rule = evt.get("rule", {})
            data = evt.get("data", {})
            lines.append(
                f"{i}. [{evt.get('timestamp', '?')}] rule:{rule.get('id', '?')} "
                f"srcip:{data.get('srcip', '?')} srcuser:{data.get('srcuser', '?')} "
                f"agent:{evt.get('agent', {}).get('name', '?')} "
                f"desc:{rule.get('description', '?')[:80]}"
            )
        sample_text = "\n".join(lines)

    if not items:
        breakdown_text = "(no data)"
    else:
        parts = []

        rules = Counter(e.get("rule", {}).get("id", "?") for e in items)
        parts.append("By rule:")
        for rid, cnt in rules.most_common():
            desc = next(
                (e.get("rule", {}).get("description", "") for e in items
                 if e.get("rule", {}).get("id") == rid), ""
            )
            parts.append(f"  rule.id:{rid} ({desc}): {cnt}")

        srcips = Counter(e.get("data", {}).get("srcip", "?") for e in items)
        parts.append(f"By source IP ({len(srcips)} unique):")
        for ip, cnt in srcips.most_common(10):
            parts.append(f"  {ip}: {cnt}")

        users = Counter(e.get("data", {}).get("srcuser", "?") for e in items)
        parts.append(f"By username ({len(users)} unique):")
        for u, cnt in users.most_common(10):
            parts.append(f"  {u}: {cnt}")

        hours = Counter(e.get("timestamp", "")[:13] for e in items)
        parts.append("By hour:")
        for h, cnt in sorted(hours.items()):
            parts.append(f"  {h}: {cnt}")

        breakdown_text = "\n".join(parts)

    return f"""## Query Results
**Query:** {query_string}
**Time range:** {time_start} to {time_end}

### Data Source Health
- **Source:** Wazuh Indexer ({config['WAZUH_INDEXER_ENDPOINT']})
- **Most recent matching event:** {latest_ts}
- **Index event count (unfiltered, same window):** {index_count}

### Summary
- **Matching events:** {match_count}

### Sample Events (first 5)
{sample_text}

### Count Breakdown
{breakdown_text}"""


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def health_check(config):
    """Check both manager API and indexer connectivity."""
    # Manager API
    try:
        token = authenticate_manager(config)
        resp = manager_api_request("/agents?limit=1&sort=-lastKeepAlive", config, token)
        data = resp.get("data", {})
        total = data.get("total_affected_items", 0)
        items = data.get("affected_items", [])
        last_ka = items[0].get("lastKeepAlive", "unknown") if items else "unknown"
        print("manager: healthy")
        print(f"agents: {total}")
        print(f"last_keepalive: {last_ka}")
    except SystemExit:
        print("manager: unreachable")

    # Indexer
    try:
        client = get_indexer_client(config)
        resp = client.search(index=config["WAZUH_INDEX"], body={"size": 0, "query": {"match_all": {}}})
        total_docs = resp.get("hits", {}).get("total", {}).get("value", 0)
        print("indexer: healthy")
        print(f"indexed_alerts: {total_docs}")
    except Exception as e:
        print(f"indexer: unreachable ({e})")
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        description="Wazuh SIEM CLI — execute queries with structured output",
    )
    p.add_argument("--query", "-q", help="Lucene query string (OpenSearch syntax)")
    p.add_argument("--start", help="Start time (ISO 8601 UTC)")
    p.add_argument("--end", help="End time (ISO 8601 UTC, defaults to now)")
    p.add_argument("--window", default="1h", help="Time window duration (e.g. 1h, 30m, 7d). Used when --end is omitted.")
    p.add_argument("--limit", type=int, default=500, help="Max events to return (default: 500)")
    p.add_argument("--raw", action="store_true", help="Output raw JSON instead of formatted text")
    p.add_argument("--health-check", action="store_true", help="Check connectivity and exit")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()

    if args.health_check:
        health_check(config)
        return

    if not args.query:
        parser.error("--query is required (unless using --health-check)")

    if args.end and not args.start:
        parser.error("--end without --start is not supported. Use --start/--end or --start/--window.")

    time_start, time_end = compute_time_range(args)
    client = get_indexer_client(config)

    items, match_count = query_alerts(client, config, args.query, time_start, time_end, limit=args.limit)

    if args.raw:
        print(json.dumps(items, indent=2))
        return

    _, index_count = query_alerts(client, config, "", time_start, time_end, limit=0)

    output = format_output(args.query, time_start, time_end, config, items, match_count, index_count)
    print(output)


if __name__ == "__main__":
    main()
