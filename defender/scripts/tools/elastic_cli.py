#!/usr/bin/env python3
"""Elastic Stack CLI — defender-side adapter.

Two surfaces in one Elasticsearch instance:

    query   — raw event indices (default pattern: logs-*)
              covers logs-falco.alerts-*, logs-system.auth-*,
              logs-system.syslog-*, logs-elastic_agent.*, etc.
    alerts  — detection-engine signals
              (.internal.alerts-security.alerts-default-*) emitted by the
              custom rules in playground-v2/detection-rules/.

The adapter exposes lucene-via-`query_string` as the pass-through syntax;
KQL covers the same vocabulary for the common case.

Usage:
    elastic_cli.py health-check
    elastic_cli.py query 'process.name:"sshd" AND message:*"Failed password"*' \\
        --start 2026-05-23T18:00:00Z --end 2026-05-23T19:00:00Z --limit 20
    elastic_cli.py alerts 'kibana.alert.rule.rule_id:"v2-sshd-failed-auth-burst"' --limit 50

Exit codes:
    0 — success
    1 — query error (bad syntax, unknown field, partial result)
    2 — connection / auth / config failure
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFENDER_DIR = Path(os.environ.get("DEFENDER_DIR", SCRIPT_DIR.parent.parent))
CONFIG_PATH = (
    DEFENDER_DIR / "knowledge" / "environment" / "systems" / "elastic" / "config.env"
)
# playground-v2 .env lives one level above the worktree on this host.
# Probed for V2_ELASTIC_PASSWORD when the env var isn't already set.
PLAYGROUND_ENV_CANDIDATES = (
    DEFENDER_DIR.parent.parent / "playground-v2" / ".env",
    Path("/workspace/playground-v2/.env"),
)

REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
    "ELASTIC_SSL_VERIFY",
]

# playground-v2 convention: V2_-prefixed to avoid collision with v1 ELASTIC_PASSWORD
# in /workspace/.env (shell env shadows compose .env).
PASSWORD_ENV = "V2_ELASTIC_PASSWORD"
USERNAME_ENV = "V2_ELASTIC_USERNAME"
DEFAULT_USERNAME = "elastic"

DEFAULT_LIMIT = 500
MAX_LIMIT = 10000
REQUEST_TIMEOUT_SEC = 30
RAW_SAMPLE_COUNT = 3


# ---------------------------------------------------------------------------
# Config + credentials
# ---------------------------------------------------------------------------


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(
            f"error: config file not found: {CONFIG_PATH}\n"
            f"hint: this file should ship with the defender-v2-env branch — "
            f"if missing, restore from git or the worktree may be in an unexpected state."
        )

    config: dict[str, str] = {}
    for line in CONFIG_PATH.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            config[key.strip()] = val.strip().strip('"').strip("'")

    # env overrides for ops convenience (CI, per-run overrides).
    for key in list(config) + REQUIRED_CONFIG_KEYS:
        env_val = os.environ.get(key)
        if env_val is not None:
            config[key] = env_val

    missing = [k for k in REQUIRED_CONFIG_KEYS if not config.get(k)]
    if missing:
        sys.exit(
            f"error: missing required config keys in {CONFIG_PATH}: {', '.join(missing)}"
        )
    return config


def _read_password_from_env_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            if key.strip() == PASSWORD_ENV:
                return val.strip().strip('"').strip("'")
    except OSError:
        return None
    return None


def get_credentials() -> tuple[str, str]:
    user = os.environ.get(USERNAME_ENV, DEFAULT_USERNAME)
    password = os.environ.get(PASSWORD_ENV)
    if not password:
        # Fallback: source from playground-v2/.env. Avoids the
        # subshell/source dance that every gather subagent otherwise
        # repeats — see traces of OPT-* runs.
        for candidate in PLAYGROUND_ENV_CANDIDATES:
            password = _read_password_from_env_file(candidate)
            if password:
                break
    if not password:
        searched = ", ".join(str(p) for p in PLAYGROUND_ENV_CANDIDATES)
        sys.exit(
            f"error: {PASSWORD_ENV} not set and not found in any of: {searched}\n"
            f"hint: export {PASSWORD_ENV}=... or restore playground-v2/.env.\n"
            f"      {USERNAME_ENV} defaults to {DEFAULT_USERNAME!r} if unset.\n"
            f"hint: non-secret config lives in {CONFIG_PATH}"
        )
    return user, password


def _ssl_context(config: dict) -> ssl.SSLContext | None:
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
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {creds}"


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _http_json(method, url, config, headers=None, body=None, timeout=None):
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


def _build_search_body(query_string, time_start, time_end, time_field, limit):
    filters: list[dict] = []
    if time_start or time_end:
        rng: dict[str, str] = {}
        if time_start:
            rng["gte"] = time_start
        if time_end:
            rng["lte"] = time_end
        filters.append({"range": {time_field: rng}})

    if query_string.strip():
        must = [{"query_string": {"query": query_string}}]
    else:
        must = [{"match_all": {}}]

    return {
        "size": min(limit, MAX_LIMIT),
        "sort": [{time_field: {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": filters}},
        "track_total_hits": True,
    }


def search(config, index_pattern, query_string, time_start, time_end, time_field, limit):
    body = _build_search_body(query_string, time_start, time_end, time_field, limit)
    url = (
        f"{config['ELASTICSEARCH_URL'].rstrip('/')}/"
        f"{urllib.parse.quote(index_pattern, safe='-*,.')}/_search"
        f"?ignore_unavailable=true"
    )
    try:
        status, resp = _http_json("POST", url, config, body=body)
    except urllib.error.URLError as e:
        sys.exit(f"error: Elasticsearch unreachable: {e}")

    if status != 200:
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
    es_url = config["ELASTICSEARCH_URL"].rstrip("/") + "/_cluster/health"
    try:
        status, body = _http_json("GET", es_url, config, timeout=10)
    except urllib.error.URLError as e:
        sys.exit(f"error: elasticsearch unreachable: {e}")

    if status != 200:
        print(f"error: elasticsearch HTTP {status}: {body}", file=sys.stderr)
        sys.exit(2 if status in (401, 403) else 1)

    print("connected")
    print(f"elasticsearch: {body.get('status', 'unknown')}")
    print(f"nodes: {body.get('number_of_nodes', '?')}")

    kb_url = config["KIBANA_URL"].rstrip("/") + "/api/status"
    try:
        kb_status, kb_body = _http_json(
            "GET", kb_url, config, headers={"kbn-xsrf": "true"}, timeout=10
        )
    except urllib.error.URLError as e:
        print(f"kibana: unreachable ({e})")
        return

    if kb_status == 200 and isinstance(kb_body, dict):
        overall = kb_body.get("status", {}).get("overall", {}).get("level", "unknown")
        print(f"kibana: {overall}")
    else:
        print(f"kibana: HTTP {kb_status}")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


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
            falco = e.get("falco", {}) or {}
            falco_rule = falco.get("rule")
            extra = f" falco.rule:{_trim(falco_rule, 50)}" if falco_rule else ""
            lines.append(
                f"{i}. [{e.get('@timestamp', '?')}] "
                f"dataset:{(e.get('data_stream') or {}).get('dataset') or ev.get('dataset', '?')} "
                f"host:{host.get('name', '?')} "
                f"user:{usr.get('name', '?')} "
                f"src.ip:{src.get('ip', '?')}"
                f"{extra}"
            )
        sample_text = "\n".join(lines)

    raw_text = (
        "(no matching events)" if not hits
        else json.dumps(hits[:RAW_SAMPLE_COUNT], indent=2, default=str)
    )

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
            alert = (a.get("kibana") or {}).get("alert") or {}
            rule = alert.get("rule") or {}
            name = rule.get("name") if isinstance(rule, dict) else None
            rule_id = rule.get("rule_id") if isinstance(rule, dict) else None
            severity = alert.get("severity", "?")
            status = alert.get("workflow_status", "?")
            host = (a.get("host") or {}).get("name", "?")
            lines.append(
                f"{i}. [{a.get('@timestamp', '?')}] "
                f"rule_id:{rule_id or '?'} "
                f"rule:{_trim(name or '?', 40)} "
                f"severity:{severity} "
                f"status:{status} "
                f"host:{host}"
            )
        sample_text = "\n".join(lines)

    raw_text = (
        "(no matching alerts)" if not hits
        else json.dumps(hits[:RAW_SAMPLE_COUNT], indent=2, default=str)
    )

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
            "signals (`alerts`) against the v2 playground Elasticsearch."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("health-check", help="Verify ES + Kibana reachability and exit.")

    def _add_common_flags(parser):
        parser.add_argument("--start", help="Start time (ISO 8601 UTC).")
        parser.add_argument("--end", help="End time (ISO 8601 UTC).")
        parser.add_argument(
            "--limit", type=int, default=DEFAULT_LIMIT,
            help=f"Max hits to return (default {DEFAULT_LIMIT}, max {MAX_LIMIT}).",
        )
        parser.add_argument(
            "--raw", action="store_true",
            help="Emit raw JSON array of _source docs instead of formatted text.",
        )
        parser.add_argument(
            "--index", help="Override the default index pattern for this subcommand.",
        )

    q = sub.add_parser(
        "query",
        help="Search raw event indices (default pattern: logs-*).",
        description=(
            "Search raw event indices with a lucene/KQL query.\n\n"
            "Examples:\n"
            "  elastic_cli.py query 'process.name:\"sshd\" AND message:*\"Failed password\"*' \\\n"
            "      --start 2026-05-23T18:00:00Z --limit 20\n"
            "  elastic_cli.py query 'falco.rule:\"Adding ssh keys to authorized_keys\"' \\\n"
            "      --index 'logs-falco.alerts-*'\n"
            "  elastic_cli.py query '*' --index 'logs-system.syslog-*' --limit 5"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    q.add_argument("native_query", help="Lucene / KQL query string.")
    _add_common_flags(q)

    a = sub.add_parser(
        "alerts",
        help="Search detection-engine signals (.internal.alerts-security.*).",
        description=(
            "Search detection-engine alerts emitted by the v2 custom rules.\n\n"
            "Examples:\n"
            "  elastic_cli.py alerts 'kibana.alert.rule.rule_id:\"v2-sshd-failed-auth-burst\"'\n"
            "  elastic_cli.py alerts 'kibana.alert.severity:\"high\"' --limit 50"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    a.add_argument("native_query", help="Lucene / KQL query string against the alerts index.")
    _add_common_flags(a)

    return p


def cmd_query(args, config):
    index = args.index or config["ELASTIC_EVENTS_INDEX"]
    docs, total, truncated = search(
        config, index, args.native_query, args.start, args.end,
        time_field="@timestamp", limit=args.limit,
    )
    if args.raw:
        print(json.dumps({
            "index": index,
            "total": total,
            "returned": len(docs),
            "truncated": truncated,
            "hits": docs,
        }, default=str))
    else:
        print(format_events_output(
            args.native_query, index, args.start, args.end, docs, total, truncated,
        ))


def cmd_alerts(args, config):
    index = args.index or config["ELASTIC_ALERTS_INDEX"]
    docs, total, truncated = search(
        config, index, args.native_query, args.start, args.end,
        time_field="@timestamp", limit=args.limit,
    )
    if args.raw:
        print(json.dumps({
            "index": index,
            "total": total,
            "returned": len(docs),
            "truncated": truncated,
            "hits": docs,
        }, default=str))
    else:
        print(format_alerts_output(
            args.native_query, index, args.start, args.end, docs, total, truncated,
        ))


def main():
    parser = build_parser()
    args = parser.parse_args()
    config = load_config()
    if args.subcommand == "health-check":
        health_check(config)
    elif args.subcommand == "query":
        cmd_query(args, config)
    elif args.subcommand == "alerts":
        cmd_alerts(args, config)
    else:
        parser.error(f"unknown subcommand: {args.subcommand}")


if __name__ == "__main__":
    main()
