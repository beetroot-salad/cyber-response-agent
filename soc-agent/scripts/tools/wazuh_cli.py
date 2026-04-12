#!/usr/bin/env python3
"""Wazuh SIEM CLI — thin wrapper for query execution.

Alert queries go to the Wazuh Indexer (OpenSearch) via opensearch-py.
Health checks use both the indexer and the Wazuh Manager API.

Usage:
    python3 wazuh_cli.py query --query 'rule.id:5710 AND data.srcip:10.0.0.5' \
        --start 2026-04-04T10:00:00Z --window 1h

    python3 wazuh_cli.py query --query 'rule.groups:sshd' \
        --start 2026-04-04T10:00:00Z --end 2026-04-04T12:00:00Z

    python3 wazuh_cli.py health-check

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

try:
    from opensearchpy import OpenSearch
except ImportError:
    print(
        "error: opensearch-py is required for Wazuh indexer queries\n"
        "Run: scripts/tools/setup.sh",
        file=sys.stderr,
    )
    sys.exit(2)

SCRIPT_DIR = Path(__file__).resolve().parent
SOC_AGENT_DIR = Path(os.environ.get(
    "SOC_AGENT_DIR", SCRIPT_DIR.parent.parent
))
CONFIG_PATH = SOC_AGENT_DIR / "knowledge" / "environment" / "systems" / "wazuh" / "config.env"


REQUIRED_CONFIG_KEYS = [
    "WAZUH_INDEX",
    "WAZUH_API_ENDPOINT",
    "WAZUH_INDEXER_ENDPOINT",
    "WAZUH_RETENTION_DAYS",
    "WAZUH_SSL_VERIFY",
]


def load_config():
    """Load non-secret config from config.env.

    All required keys must be present in config.env.  Environment variables
    override individual values (useful for CI or per-run tweaks).
    """
    if not CONFIG_PATH.exists():
        print(
            f"error: config file not found: {CONFIG_PATH}\n"
            f"hint: copy the template and fill in your environment values:\n"
            f"  cp knowledge/environment/systems/wazuh/config.env.template \\\n"
            f"     knowledge/environment/systems/wazuh/config.env",
            file=sys.stderr,
        )
        sys.exit(2)

    config = {}
    for line in CONFIG_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"')

    # Environment variables override config.env
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


def _ssl_verify(config) -> bool:
    if "WAZUH_SSL_VERIFY" not in config:
        print(
            "warning: WAZUH_SSL_VERIFY not set in config, defaulting to verify=False",
            file=sys.stderr,
        )
    return config.get("WAZUH_SSL_VERIFY", "false").lower() in ("true", "1", "yes")


def _ca_cert_path(config) -> str | None:
    path = config.get("WAZUH_CA_CERT", "")
    return path if path else None


def get_indexer_client(config):
    """Create an OpenSearch client for the Wazuh Indexer."""
    user = os.environ.get("WAZUH_INDEXER_USER")
    password = os.environ.get("WAZUH_INDEXER_PASSWORD")
    if not user or not password:
        print(
            "error: WAZUH_INDEXER_USER and WAZUH_INDEXER_PASSWORD must be set as environment variables\n"
            f"hint: export them in your shell, or add them to .env (loaded by docker-compose)\n"
            f"hint: non-secret config is loaded from {CONFIG_PATH}",
            file=sys.stderr,
        )
        sys.exit(2)

    verify = _ssl_verify(config)
    ca_cert = _ca_cert_path(config)
    return OpenSearch(
        hosts=[config["WAZUH_INDEXER_ENDPOINT"]],
        http_auth=(user, password),
        verify_certs=verify,
        ssl_show_warn=verify,
        ca_certs=ca_cert,
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

PAGE_SIZE = 500


def query_alerts(client, config, query_string, time_start, time_end, limit=500):
    """Query Wazuh alerts via the indexer. Returns (hits_list, total_count).

    Automatically paginates using search_after when limit exceeds PAGE_SIZE.
    """
    query = {
        "bool": {
            "must": [
                {"query_string": {"query": query_string}} if query_string else {"match_all": {}},
            ],
            "filter": [
                {"range": {"timestamp": {"gte": time_start, "lte": time_end}}},
            ],
        }
    }
    sort = [{"timestamp": {"order": "desc"}}, {"_id": {"order": "desc"}}]

    # limit=0 means "count only, no results"
    if limit == 0:
        body = {"size": 0, "query": query}
        try:
            resp = client.search(index=config["WAZUH_INDEX"], body=body)
        except Exception as e:
            print(f"error: Indexer query failed: {e}", file=sys.stderr)
            sys.exit(2)
        total = resp.get("hits", {}).get("total", {}).get("value", 0)
        return [], total

    all_items = []
    total = 0
    search_after = None

    while len(all_items) < limit:
        page_size = min(PAGE_SIZE, limit - len(all_items))
        body = {"size": page_size, "sort": sort, "query": query}
        if search_after is not None:
            body["search_after"] = search_after

        try:
            resp = client.search(index=config["WAZUH_INDEX"], body=body)
        except Exception as e:
            print(f"error: Indexer query failed: {e}", file=sys.stderr)
            sys.exit(2)

        hits = resp.get("hits", {})
        page_total = hits.get("total", {}).get("value", 0)
        if search_after is None:
            total = page_total
        page_hits = hits.get("hits", [])

        if not page_hits:
            break

        remaining = limit - len(all_items)
        all_items.extend(h["_source"] for h in page_hits[:remaining])
        search_after = page_hits[-1]["sort"]

    return all_items, total


# ---------------------------------------------------------------------------
# Manager API — health check only
# ---------------------------------------------------------------------------

def get_ssl_context(config):
    """Build SSL context based on WAZUH_SSL_VERIFY and WAZUH_CA_CERT config."""
    if _ssl_verify(config):
        ctx = ssl.create_default_context()
        ca_cert = _ca_cert_path(config)
        if ca_cert:
            ctx.load_verify_locations(ca_cert)
        return ctx
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def authenticate_manager(config):
    """Authenticate against the Wazuh Manager API and return JWT token."""
    user = os.environ.get("WAZUH_API_USER")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not user or not password:
        print(
            "error: WAZUH_API_USER and WAZUH_API_PASSWORD must be set as environment variables\n"
            f"hint: export them in your shell, or add them to .env (loaded by docker-compose)\n"
            f"hint: non-secret config is loaded from {CONFIG_PATH}",
            file=sys.stderr,
        )
        sys.exit(2)

    url = config["WAZUH_API_ENDPOINT"].rstrip("/") + "/security/user/authenticate"
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Basic {credentials}",
    }
    req = urllib.request.Request(url, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=get_ssl_context(config), timeout=10) as resp:
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
        with urllib.request.urlopen(req, context=get_ssl_context(config), timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.URLError as e:
        print(f"error: Manager API request failed: {e}", file=sys.stderr)
        sys.exit(2)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def load_run_salt(run_dir: str | None) -> str | None:
    """Read per-run salt from meta.json. Returns None if unavailable."""
    if not run_dir:
        return None
    meta_path = Path(run_dir) / "meta.json"
    if not meta_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text())
        return meta.get("salt") or None
    except (json.JSONDecodeError, OSError):
        return None


def wrap_with_salt(content: str, salt: str) -> str:
    """Wrap output in salted untrusted-data delimiters."""
    return f"<run-{salt}-siem-data>\n{content}\n</run-{salt}-siem-data>"


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
    sub = p.add_subparsers(dest="subcommand", required=True)

    q = sub.add_parser(
        "query",
        help="Run a Lucene query against the Wazuh indexer",
    )
    q.add_argument("--query", "-q", required=True, help="Lucene query string (OpenSearch syntax)")
    q.add_argument("--start", help="Start time (ISO 8601 UTC)")
    q.add_argument("--end", help="End time (ISO 8601 UTC, defaults to now)")
    q.add_argument("--window", default="1h", help="Time window duration (e.g. 1h, 30m, 7d). Used when --end is omitted.")
    q.add_argument("--limit", type=int, default=500, help="Max events to return (default: 500, max: 10000)")
    q.add_argument("--raw", action="store_true", help="Output raw JSON instead of formatted text")
    q.add_argument("--run-dir", help="Investigation run directory (reads salt from meta.json to wrap output in untrusted-data delimiters)")

    sub.add_parser(
        "health-check",
        help="Verify connectivity to the Wazuh manager and indexer, then exit",
    )

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()

    if args.subcommand == "health-check":
        health_check(config)
        return

    # query subcommand
    if args.end and not args.start:
        parser.error("--end without --start is not supported. Use --start/--end or --start/--window.")

    args.limit = min(args.limit, 10000)

    time_start, time_end = compute_time_range(args)
    client = get_indexer_client(config)

    items, match_count = query_alerts(client, config, args.query, time_start, time_end, limit=args.limit)

    salt = load_run_salt(args.run_dir)

    if args.raw:
        raw_output = json.dumps(items, indent=2)
        print(wrap_with_salt(raw_output, salt) if salt else raw_output)
        return

    _, index_count = query_alerts(client, config, "", time_start, time_end, limit=0)

    output = format_output(args.query, time_start, time_end, config, items, match_count, index_count)
    print(wrap_with_salt(output, salt) if salt else output)


if __name__ == "__main__":
    main()
