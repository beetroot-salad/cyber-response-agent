#!/usr/bin/env python3
"""Elastic Stack CLI — thin wrapper for Elasticsearch + Kibana.

Issues searches directly against Elasticsearch using `query_string` as the
pass-through syntax (Lucene-compatible; KQL-like for the common cases —
see field-notes.md for the handful of divergences). Covers two data
surfaces:

    query   — raw event indices (default pattern: logs-*)
    alerts  — detection-engine signals (.alerts-security.alerts-default)

Alerts are kept on a separate subcommand because they're a distinct data
source (SIEM-generated signals, not raw telemetry) and warrant their own
default index, time field, and field vocabulary.

Usage:
    python3 elastic_cli.py health-check

    # Raw events (logs-* by default; --index overrides the pattern)
    python3 elastic_cli.py query 'event.dataset: "system.auth" AND event.outcome: "failure"' \\
        --start 2026-04-19T10:00:00Z --end 2026-04-19T12:00:00Z --limit 20

    # Detection-engine signals
    python3 elastic_cli.py alerts 'kibana.alert.severity: "high"' --limit 50

Exit codes:
    0 — success
    1 — query error
    2 — connection/auth/config failure
"""

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
SOC_AGENT_DIR = Path(os.environ.get("SOC_AGENT_DIR", SCRIPT_DIR.parent.parent))
CONFIG_PATH = (
    SOC_AGENT_DIR / "knowledge" / "environment" / "systems" / "elastic" / "config.env"
)

REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
    "ELASTIC_SSL_VERIFY",
]

DEFAULT_LIMIT = 500
MAX_LIMIT = 10000
REQUEST_TIMEOUT_SEC = 30
RAW_SAMPLE_COUNT = 3

# Untrusted-data salt wrapper family — `siem-data` matches the convention
# already used by wazuh_cli.py so the tag_tool_results hook and downstream
# prompts don't have to special-case a per-vendor tag.
SALT_TAG = "siem-data"


# ---------------------------------------------------------------------------
# Config + credentials
# ---------------------------------------------------------------------------


def load_config():
    """Load non-secret config from config.env; env vars override keys.

    Credentials (ELASTIC_USERNAME, ELASTIC_PASSWORD) are read from
    os.environ only — never from config.env. Missing either config file
    or required keys exits 2 with a hint pointing at the fix.
    """
    if not CONFIG_PATH.exists():
        print(
            f"error: config file not found: {CONFIG_PATH}\n"
            f"hint: copy the template and fill in your deployment values:\n"
            f"  cp knowledge/environment/systems/elastic/config.env.template \\\n"
            f"     knowledge/environment/systems/elastic/config.env",
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
            config[key.strip()] = val.strip().strip('"').strip("'")

    # Environment variables override config.env (useful for CI / per-run).
    for key in list(config) + REQUIRED_CONFIG_KEYS:
        env_val = os.environ.get(key)
        if env_val is not None:
            config[key] = env_val

    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in config or not config[key]]
    # Recompute strictly — the loop above may read-then-write an empty env var.
    missing = [k for k in REQUIRED_CONFIG_KEYS if not config.get(k)]
    if missing:
        print(
            f"error: missing required keys in {CONFIG_PATH} (or env overrides): "
            f"{', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)

    return config


def get_credentials():
    """Return (username, password) from env or exit 2 with a hint."""
    user = os.environ.get("ELASTIC_USERNAME", "elastic")
    password = os.environ.get("ELASTIC_PASSWORD")
    if not password:
        print(
            "error: ELASTIC_PASSWORD must be set as an environment variable\n"
            "hint: export ELASTIC_PASSWORD=... (or add it to .env / your secret store).\n"
            "      ELASTIC_USERNAME defaults to 'elastic' if unset.\n"
            f"hint: non-secret config lives in {CONFIG_PATH}",
            file=sys.stderr,
        )
        sys.exit(2)
    return user, password


def _ssl_context(config):
    verify = config.get("ELASTIC_SSL_VERIFY", "true").lower() in ("true", "1", "yes")
    if verify:
        ctx = ssl.create_default_context()
        ca_cert = config.get("ELASTIC_CA_CERT", "").strip()
        if ca_cert:
            ctx.load_verify_locations(ca_cert)
        return ctx
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _auth_header(user: str, password: str) -> str:
    credentials = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {credentials}"


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _http_json(method: str, url: str, config, headers=None, body=None, timeout=None):
    """POST/GET JSON helper. Returns (status, parsed_body).

    Raises urllib.error.URLError or ValueError on transport/parse failures;
    callers translate those into exit codes.
    """
    user, password = get_credentials()
    hdrs = {
        "Authorization": _auth_header(user, password),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if headers:
        hdrs.update(headers)

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    ctx = _ssl_context(config) if url.startswith("https://") else None
    try:
        with urllib.request.urlopen(
            req, context=ctx, timeout=timeout or REQUEST_TIMEOUT_SEC
        ) as resp:
            raw = resp.read()
            parsed = json.loads(raw) if raw else {}
            return resp.getcode(), parsed
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read() or b"{}")
        except (ValueError, OSError):
            err_body = {"error": f"HTTP {e.code}"}
        return e.code, err_body


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


def _build_search_body(
    query_string: str, time_start: str | None, time_end: str | None, time_field: str, limit: int
):
    """Build the ES _search request body.

    query_string is passed through to the `query_string` clause unmodified —
    this is the "pass-through native language" contract. Users who want KQL
    should note the KQL / Lucene overlap; see field-notes.md for the
    handful of divergences.
    """
    filters: list[dict] = []
    if time_start or time_end:
        rng: dict[str, str] = {}
        if time_start:
            rng["gte"] = time_start
        if time_end:
            rng["lte"] = time_end
        filters.append({"range": {time_field: rng}})

    # An empty query_string is invalid; fall back to match_all for "give me anything".
    if query_string.strip():
        must = [{"query_string": {"query": query_string}}]
    else:
        must = [{"match_all": {}}]

    body = {
        "size": min(limit, MAX_LIMIT),
        "sort": [{time_field: {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": filters}},
        "track_total_hits": True,
    }
    return body


def search(config, index_pattern: str, query_string: str, time_start, time_end, time_field, limit):
    """Execute a search against Elasticsearch. Returns (hits, total_hits, truncated)."""
    body = _build_search_body(query_string, time_start, time_end, time_field, limit)
    # ignore_unavailable so queries over globbed index patterns don't fail if
    # one concrete data stream is closed or missing — matches Kibana behavior.
    url = (
        f"{config['ELASTICSEARCH_URL'].rstrip('/')}/"
        f"{urllib.parse.quote(index_pattern, safe='-*,.')}/_search"
        f"?ignore_unavailable=true"
    )
    try:
        status, resp = _http_json("POST", url, config, body=body)
    except urllib.error.URLError as e:
        print(f"error: Elasticsearch unreachable: {e}", file=sys.stderr)
        sys.exit(2)

    if status != 200:
        # Auth failures exit 2 to match the contract; query errors (bad syntax,
        # unknown field) exit 1.
        err = resp.get("error", resp)
        msg = err.get("reason") if isinstance(err, dict) else str(err)
        if status in (401, 403):
            print(f"error: Elasticsearch auth failed (HTTP {status}): {msg}", file=sys.stderr)
            sys.exit(2)
        print(f"error: Elasticsearch query failed (HTTP {status}): {msg}", file=sys.stderr)
        sys.exit(1)

    hits_block = resp.get("hits", {})
    total = hits_block.get("total", {})
    total_hits = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    raw_hits = hits_block.get("hits", [])
    docs = [h.get("_source", {}) for h in raw_hits]
    truncated = total_hits > len(docs)
    return docs, total_hits, truncated


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------


def health_check(config):
    """Check Elasticsearch cluster + Kibana API reachability."""
    es_url = config["ELASTICSEARCH_URL"].rstrip("/") + "/_cluster/health"
    try:
        status, body = _http_json("GET", es_url, config, timeout=10)
    except urllib.error.URLError as e:
        print(f"error: elasticsearch unreachable: {e}", file=sys.stderr)
        sys.exit(1)

    if status != 200:
        print(f"error: elasticsearch HTTP {status}: {body}", file=sys.stderr)
        sys.exit(1)

    cluster_status = body.get("status", "unknown")
    print("connected")
    print(f"elasticsearch: {cluster_status}")
    print(f"nodes: {body.get('number_of_nodes', '?')}")

    kb_url = config["KIBANA_URL"].rstrip("/") + "/api/status"
    try:
        kb_status, kb_body = _http_json(
            "GET", kb_url, config, headers={"kbn-xsrf": "true"}, timeout=10
        )
    except urllib.error.URLError as e:
        print(f"kibana: unreachable ({e})")
        # Kibana being down is degraded, not fatal — ES is the primary search surface.
        return

    if kb_status == 200 and isinstance(kb_body, dict):
        overall = kb_body.get("status", {}).get("overall", {}).get("level", "unknown")
        print(f"kibana: {overall}")
    else:
        print(f"kibana: HTTP {kb_status}")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def load_run_salt(run_dir: str | None) -> str | None:
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
    return f"<run-{salt}-{SALT_TAG}>\n{content}\n</run-{salt}-{SALT_TAG}>"


def _trim(s, n=80):
    if not isinstance(s, str):
        s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


def format_events_output(query_string, index_pattern, time_start, time_end, hits, total_hits, truncated):
    latest_ts = hits[0].get("@timestamp", "none") if hits else "no matching events"

    if not hits:
        sample_text = "(no matching events)"
    else:
        lines = []
        for i, e in enumerate(hits[:5], 1):
            ev = e.get("event", {}) or {}
            src = e.get("source", {}) or {}
            usr = e.get("user", {}) or {}
            host = e.get("host", {}) or {}
            lines.append(
                f"{i}. [{e.get('@timestamp', '?')}] "
                f"dataset:{ev.get('dataset', '?')} "
                f"action:{ev.get('action', '?')} "
                f"outcome:{ev.get('outcome', '?')} "
                f"host:{host.get('name', '?')} "
                f"user:{usr.get('name', '?')} "
                f"src.ip:{src.get('ip', '?')}"
            )
        sample_text = "\n".join(lines)

    if not hits:
        raw_text = "(no matching events)"
    else:
        raw_text = json.dumps(hits[:RAW_SAMPLE_COUNT], indent=2, default=str)

    return f"""## Query Results
**Query:** {query_string or '(match all)'}
**Index pattern:** {index_pattern}
**Time range:** {time_start or '(unbounded)'} to {time_end or '(now)'}

### Summary
- **Matching events:** {total_hits}
- **Returned:** {len(hits)}{' (truncated)' if truncated else ''}
- **Most recent matching event:** {latest_ts}

### Sample Events (first 5)
{sample_text}

### Raw Sample Events (first {RAW_SAMPLE_COUNT}, full _source)
Use these for field-level inspection when the summary lines above don't carry
the discriminator you need.

```json
{raw_text}
```"""


def format_alerts_output(query_string, index_pattern, time_start, time_end, hits, total_hits, truncated):
    latest_ts = hits[0].get("@timestamp", "none") if hits else "no matching alerts"

    if not hits:
        sample_text = "(no matching alerts)"
    else:
        lines = []
        for i, a in enumerate(hits[:5], 1):
            alert = a.get("kibana", {}).get("alert", {}) if isinstance(a.get("kibana"), dict) else {}
            name = alert.get("rule", {}).get("name") if isinstance(alert.get("rule"), dict) else None
            severity = alert.get("severity", "?")
            status = alert.get("workflow_status", "?")
            host = (a.get("host") or {}).get("name", "?")
            lines.append(
                f"{i}. [{a.get('@timestamp', '?')}] "
                f"rule:{_trim(name or '?', 50)} "
                f"severity:{severity} "
                f"status:{status} "
                f"host:{host}"
            )
        sample_text = "\n".join(lines)

    if not hits:
        raw_text = "(no matching alerts)"
    else:
        raw_text = json.dumps(hits[:RAW_SAMPLE_COUNT], indent=2, default=str)

    return f"""## Alert Results
**Query:** {query_string or '(match all)'}
**Index pattern:** {index_pattern}
**Time range:** {time_start or '(unbounded)'} to {time_end or '(now)'}

### Summary
- **Matching alerts:** {total_hits}
- **Returned:** {len(hits)}{' (truncated)' if truncated else ''}
- **Most recent alert:** {latest_ts}

### Sample Alerts (first 5)
{sample_text}

### Raw Sample Alerts (first {RAW_SAMPLE_COUNT}, full _source)
```json
{raw_text}
```"""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser():
    p = argparse.ArgumentParser(
        description=(
            "Elastic Stack CLI — search raw events (`query`) and detection-engine "
            "signals (`alerts`) via Elasticsearch. KQL-like syntax is passed "
            "through to the `query_string` clause; see field-notes.md for the "
            "handful of KQL↔Lucene divergences."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser(
        "health-check",
        help="Verify connectivity to Elasticsearch + Kibana, then exit.",
    )

    def _add_common_flags(parser):
        parser.add_argument(
            "--start",
            help="Start time (ISO 8601 UTC, e.g. 2026-04-19T10:00:00Z).",
        )
        parser.add_argument(
            "--end",
            help="End time (ISO 8601 UTC). Defaults to now.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=DEFAULT_LIMIT,
            help=f"Max hits to return (default {DEFAULT_LIMIT}, max {MAX_LIMIT}).",
        )
        parser.add_argument(
            "--raw",
            action="store_true",
            help="Emit raw JSON array of _source docs instead of formatted text.",
        )
        parser.add_argument(
            "--run-dir",
            help=(
                "Investigation run directory — reads salt from meta.json "
                "to wrap output in untrusted-data delimiters."
            ),
        )
        parser.add_argument(
            "--index",
            help="Override the default index pattern for this subcommand.",
        )

    q = sub.add_parser(
        "query",
        help="Search raw event indices (default pattern: logs-*).",
        description=(
            "Search raw event indices with a KQL-like query.\n\n"
            "Examples:\n"
            "  elastic_cli.py query 'event.dataset: \"system.auth\" AND event.outcome: \"failure\"' --limit 20\n"
            "  elastic_cli.py query 'user.name: root AND host.name: target-endpoint' --start 2026-04-19T10:00:00Z\n"
            "  elastic_cli.py query '*' --index 'logs-system.syslog-*' --limit 5"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    q.add_argument(
        "native_query",
        help="KQL-like query string. Passed through to Elasticsearch `query_string`.",
    )
    _add_common_flags(q)

    a = sub.add_parser(
        "alerts",
        help="Search detection-engine signals (.alerts-security.alerts-default).",
        description=(
            "Search the Elastic Security detection engine signal index.\n"
            "Separate from `query` because alerts are SIEM-generated signals with\n"
            "their own index, field vocabulary, and time semantics (kibana.alert.*).\n\n"
            "Examples:\n"
            "  elastic_cli.py alerts 'kibana.alert.severity: \"high\"' --limit 20\n"
            "  elastic_cli.py alerts 'kibana.alert.rule.name: *SSH*' --start 2026-04-19T00:00:00Z\n"
            "  elastic_cli.py alerts '*' --limit 5"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    a.add_argument(
        "native_query",
        help="KQL-like query string over signal fields (kibana.alert.*).",
    )
    _add_common_flags(a)

    return p


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()

    if args.subcommand == "health-check":
        health_check(config)
        return

    # events vs alerts
    if args.subcommand == "query":
        default_index = config["ELASTIC_EVENTS_INDEX"]
        time_field = "@timestamp"
        formatter = format_events_output
    elif args.subcommand == "alerts":
        default_index = config["ELASTIC_ALERTS_INDEX"]
        time_field = "@timestamp"
        formatter = format_alerts_output
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")

    index_pattern = args.index or default_index
    args.limit = min(max(args.limit, 0), MAX_LIMIT)
    time_end = args.end or _now_iso() if args.start else args.end

    hits, total_hits, truncated = search(
        config,
        index_pattern,
        args.native_query,
        args.start,
        time_end,
        time_field,
        args.limit,
    )

    salt = load_run_salt(args.run_dir)

    if args.raw:
        payload = json.dumps(hits, indent=2, default=str)
        print(wrap_with_salt(payload, salt) if salt else payload)
        return

    output = formatter(
        args.native_query,
        index_pattern,
        args.start,
        time_end,
        hits,
        total_hits,
        truncated,
    )
    print(wrap_with_salt(output, salt) if salt else output)


if __name__ == "__main__":
    main()
