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
    64 — usage error (bad flag / unknown subcommand)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from pathlib import Path

# Put the workspace root on sys.path so `defender.*` namespace imports
# resolve whether this file is imported or run directly (see tests/conftest.py).
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.tools import _stub_transport as transport

SCRIPT_DIR = Path(__file__).resolve().parent
DEFENDER_DIR = Path(os.environ.get("DEFENDER_DIR", SCRIPT_DIR.parent.parent))
CONFIG_PATH = (
    DEFENDER_DIR / "knowledge" / "environment" / "systems" / "elastic" / "config.env"
)
# Note: SSL verification is not configurable here — curl runs container-local
# against the stack's self-signed cert and always passes `-k` (mirrors es.sh), so
# ELASTIC_SSL_VERIFY / ELASTIC_CA_CERT are no longer read and are not required.
REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
]

# The playground stack is reached over the soc-playground docker context using
# the SAME shared transport as the identity/cmdb/host-state adapters
# (`_stub_transport.docker_exec_curl`): we exec `curl` inside the target
# container, where the service answers on its own localhost (ES :9200, Kibana
# :5601) and supplies its own ELASTIC_PASSWORD. This removed the host-side SSH
# tunnel and the V2_ELASTIC_PASSWORD the direct urllib path needed. Mirrors
# infra/bin/es.sh. DOCKER_CONTEXT is the transport's single source of truth.
DOCKER_CONTEXT = transport.DOCKER_CONTEXT
ES_CONTAINER = os.environ.get("SOC_PLAYGROUND_ES_CONTAINER", "elasticsearch")
KIBANA_CONTAINER = os.environ.get("SOC_PLAYGROUND_KIBANA_CONTAINER", "kibana")

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


# Shared with the stub adapters: the docker-exec transport failed (CLI missing,
# exec timeout). Callers map it to exit 2 via `_exit_unreachable`.
TransportError = transport.TransportError


def _exit_unreachable(target: str, url: str, exc: BaseException) -> None:
    """Exit (2) with a useful hint when ES/Kibana can't be reached.

    Transport is the soc-playground docker context — a failure here means the
    context/daemon is down or the target container isn't running, not a missing
    SSH tunnel. Surface the check so it doesn't get rediagnosed every time.
    """
    msg = f"error: {target} unreachable: {exc}"
    msg += (
        f"\nhint: the playground stack is reached via "
        f"`docker --context {DOCKER_CONTEXT} exec`; confirm it is up:"
        f"\n      docker --context {DOCKER_CONTEXT} ps "
        f"| grep -E '{ES_CONTAINER}|{KIBANA_CONTAINER}'"
    )
    # Exit 2 = connection/auth/config failure, per this module's exit-code
    # contract (the direct-urllib path used to exit 1 here — a known mismatch).
    print(msg, file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _container_for(url: str, config: dict) -> str:
    """Which compose container to exec curl inside. ES and Kibana each answer on
    their own localhost port *within their own container* (matching es.sh), so
    route by which configured base URL this request targets."""
    kibana_base = (config.get("KIBANA_URL") or "").rstrip("/")
    if kibana_base and url.startswith(kibana_base):
        return KIBANA_CONTAINER
    return ES_CONTAINER


def _http_json(method, url, config, headers=None, body=None, timeout=None):
    """Issue an HTTP request to ES/Kibana by exec'ing curl inside the target
    container over the soc-playground docker context (mirrors infra/bin/es.sh).
    Returns (http_status:int, parsed_json:dict). Raises TransportError when the
    docker exec itself fails (so a reachable-but-erroring service still returns
    its status + body for the caller to handle)."""
    container = _container_for(url, config)
    secs = int(timeout or REQUEST_TIMEOUT_SEC)
    # `insecure=True`: container-local self-signed cert (matches es.sh). `auth`
    # expands ${ELASTIC_PASSWORD} inside the container's own shell, never on this
    # host. Raises TransportError on a docker-exec failure (CLI missing/timeout),
    # which the callers map to exit 2 via _exit_unreachable.
    rc, stdout, stderr = transport.docker_exec_curl(
        container, url, method=method, headers=headers, body=body,
        timeout_sec=secs, insecure=True, auth="elastic:${ELASTIC_PASSWORD}",
    )
    body_text, status_str = transport.split_status(stdout)
    try:
        status = int(status_str)
    except ValueError as e:
        # No HTTP status line ⇒ curl never completed a request ⇒ transport-level
        # failure (no such container, context down, TLS handshake refused, …).
        detail = stderr.strip() or f"docker exec rc={rc}, no output"
        raise TransportError(detail) from e
    if status == 0:
        # curl reports HTTP 000 when it never received a response (connection
        # refused, DNS failure, TLS handshake rejected, --max-time before any
        # headers). It still writes "\n000" to stdout, so the int() parse above
        # SUCCEEDS — the most common ES-down case. Treat 0 as the transport
        # failure it is, not a real HTTP status, so it routes to exit 2 (and the
        # circuit breaker counts it) instead of being mis-scored as a query error.
        detail = stderr.strip() or f"curl reported HTTP 000 (no response; rc={rc})"
        raise TransportError(detail)

    try:
        parsed = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        parsed = {"error": body_text[:500]}
    return status, parsed


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
    except TransportError as e:
        _exit_unreachable("Elasticsearch", url, e)

    if status != 200:
        err = resp.get("error", resp)
        msg = err.get("reason") if isinstance(err, dict) else str(err)
        if status in (401, 403):
            print(f"error: Elasticsearch auth failed (HTTP {status}): {msg}", file=sys.stderr)
            sys.exit(2)
        if status >= 500:
            # 5xx is the server being unavailable (cluster restarting, no shard,
            # gateway) — an infra failure the breaker should count, not a query
            # error. Mirrors _stub_transport._request's code>=500 → exit 2.
            print(f"error: Elasticsearch server error (HTTP {status}): {msg}", file=sys.stderr)
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
    except TransportError as e:
        _exit_unreachable("elasticsearch", es_url, e)

    if status != 200:
        print(f"error: elasticsearch HTTP {status}: {body}", file=sys.stderr)
        # auth (401/403) and server-unavailable (5xx) are infra → exit 2.
        sys.exit(2 if status in (401, 403) or status >= 500 else 1)

    print("connected")
    print(f"elasticsearch: {body.get('status', 'unknown')}")
    print(f"nodes: {body.get('number_of_nodes', '?')}")

    kb_url = config["KIBANA_URL"].rstrip("/") + "/api/status"
    try:
        kb_status, kb_body = _http_json(
            "GET", kb_url, config, headers={"kbn-xsrf": "true"}, timeout=10
        )
    except TransportError as e:
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
    p = transport.AdapterArgumentParser(
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
