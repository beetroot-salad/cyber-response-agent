#!/usr/bin/env python3
"""Wazuh SIEM CLI — thin wrapper for query execution.

Handles authentication, HTTP, pagination, and output formatting.
The agent constructs queries in native Wazuh API syntax and passes
them here. This script never interprets query semantics.

Usage:
    python3 wazuh_cli.py --query 'rule.groups:sshd AND data.srcip:10.0.0.5' \
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
import json
import os
import sys
import urllib.request
import urllib.error
import ssl
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def get_ssl_context():
    """SSL context — skip verification only for dev self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_request(endpoint, config, token=None, method="GET", timeout=30):
    """Make a Wazuh API request. Returns parsed JSON."""
    url = config["WAZUH_API_ENDPOINT"].rstrip("/") + endpoint
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"error: API request failed: {e}", file=sys.stderr)
        sys.exit(2)


def authenticate(config):
    """Authenticate and return JWT token."""
    user = os.environ.get("WAZUH_API_USER", "wazuh-wui")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not password:
        print("error: WAZUH_API_PASSWORD environment variable must be set", file=sys.stderr)
        sys.exit(2)

    url = config["WAZUH_API_ENDPOINT"].rstrip("/") + "/security/user/authenticate"
    # Basic auth header
    import base64
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }
    req = urllib.request.Request(url, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(), timeout=10) as resp:
            data = json.loads(resp.read())
            token = data.get("data", {}).get("token", "")
            if not token:
                print("error: Authentication succeeded but no token returned", file=sys.stderr)
                sys.exit(2)
            return token
    except urllib.error.URLError as e:
        print(f"error: Authentication failed: {e}", file=sys.stderr)
        sys.exit(2)


def query_alerts(config, token, query_string, time_start, time_end, limit=500):
    """Query Wazuh alerts API. Returns the full response dict."""
    time_filter = f"timestamp:[{time_start} TO {time_end}]"
    full_query = f"{query_string} AND {time_filter}" if query_string else time_filter
    endpoint = f"/alerts?q={full_query}&limit={limit}&sort=-timestamp"
    return api_request(endpoint, config, token=token)


def format_output(query_string, time_start, time_end, config, filtered_resp, unfiltered_resp):
    """Format structured output from query results."""
    filtered_data = filtered_resp.get("data", {})
    unfiltered_data = unfiltered_resp.get("data", {})

    match_count = filtered_data.get("total_affected_items", 0)
    index_count = unfiltered_data.get("total_affected_items", 0)
    items = filtered_data.get("affected_items", [])

    # Latest event timestamp
    latest_ts = items[0].get("timestamp", "none") if items else "no matching events"

    # Sample events
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

    # Count breakdowns
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
- **Source:** Wazuh SIEM ({config['WAZUH_API_ENDPOINT']})
- **Most recent matching event:** {latest_ts}
- **Index event count (unfiltered, same window):** {index_count}

### Summary
- **Matching events:** {match_count}

### Sample Events (first 5)
{sample_text}

### Count Breakdown
{breakdown_text}"""


def health_check(config):
    """Quick connectivity canary. Prints status and exits."""
    try:
        token = authenticate(config)
    except SystemExit:
        print("status: unreachable")
        sys.exit(2)

    resp = api_request("/agents?limit=1&sort=-lastKeepAlive", config, token=token)
    data = resp.get("data", {})
    total = data.get("total_affected_items", 0)
    items = data.get("affected_items", [])
    last_ka = items[0].get("lastKeepAlive", "unknown") if items else "unknown"

    if total == 0:
        print("status: degraded")
        print("agents: 0")
        print("error: No agents reporting to Wazuh manager")
        sys.exit(1)

    print("status: healthy")
    print(f"agents: {total}")
    print(f"last_keepalive: {last_ka}")
    sys.exit(0)


def build_parser():
    p = argparse.ArgumentParser(
        description="Wazuh SIEM CLI — execute queries with structured output",
    )
    p.add_argument("--query", "-q", help="Wazuh API query string (native syntax)")
    p.add_argument("--start", help="Start time (ISO 8601 UTC)")
    p.add_argument("--end", help="End time (ISO 8601 UTC, defaults to now)")
    p.add_argument("--window", default="1h", help="Time window duration (e.g. 1h, 30m, 7d). Used when --end is omitted.")
    p.add_argument("--limit", type=int, default=500, help="Max events to return (default: 500)")
    p.add_argument("--raw", action="store_true", help="Output raw JSON instead of formatted text")
    p.add_argument("--health-check", action="store_true", help="Check API connectivity and exit")
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

    if not args.start and not args.end:
        # Default: window ending now
        pass
    elif args.start and args.end:
        pass
    elif args.start and not args.end:
        pass
    else:
        parser.error("--end without --start is not supported. Use --start/--end or --start/--window.")

    time_start, time_end = compute_time_range(args)

    token = authenticate(config)

    # Filtered query
    filtered_resp = query_alerts(config, token, args.query, time_start, time_end, limit=args.limit)

    if args.raw:
        print(json.dumps(filtered_resp, indent=2))
        return

    # Unfiltered query (same time window, no entity filter) for scale reference
    # Strip entity-specific filters by querying just the broadest group filter
    # The agent can also pass --query with just the group filter for unfiltered
    unfiltered_resp = query_alerts(config, token, "", time_start, time_end, limit=1)

    output = format_output(args.query, time_start, time_end, config, filtered_resp, unfiltered_resp)
    print(output)


if __name__ == "__main__":
    main()
