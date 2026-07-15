"""Elastic Stack adapter — the `elastic` VERBS registry.

Two surfaces in one Elasticsearch instance:

    query   — raw event indices (default pattern: logs-*)
              covers logs-falco.alerts-*, logs-system.auth-*,
              logs-system.syslog-*, logs-elastic_agent.*, etc.
    alerts  — detection-engine signals
              (.internal.alerts-security.alerts-default-*) emitted by the
              custom rules in playground-v2/detection-rules/.

`query`/`alerts` take a lucene-via-`query_string` body (`native_query`); KQL covers the
same vocabulary for the common case. `esql` takes an ES|QL pipe (`query`) and returns the
server-side aggregation — the result rows ARE the answer.

Verbs (`VERBS` is the whole model-facing surface — there is no CLI):
    health-check
    query    native_query [start] [end] [limit] [index]
    alerts   native_query [start] [end] [limit] [index]
    esql     query

Faults (`faults.py`): ConfigFault/TransportFault = infra (2, incl. 401/403 and 5xx),
UpstreamFault = query error (1) carrying Elasticsearch's OWN `reason` — the verification
exception naming the column you misspelled is the entire input to the pitfalls lane.
"""

from __future__ import annotations

import json
import urllib.parse

# Put the workspace root on sys.path so `defender.*` namespace imports resolve when the
# verb registry loads this module BY PATH (see cmdb_cli.py).
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import ConfigFault, TransportFault, UpstreamFault

SYSTEM = "elastic"

# Note: SSL verification is not configurable here — curl runs container-local
# against the stack's self-signed cert and always passes `-k` (mirrors es.sh), so
# ELASTIC_SSL_VERIFY / ELASTIC_CA_CERT are no longer read and are not required.
REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
]

DEFAULT_ES_CONTAINER = "elasticsearch"
DEFAULT_KIBANA_CONTAINER = "kibana"

# Non-overridable returned-doc cap. ES computes `hits.total` independently of
# `size` (track_total_hits below), so we ship at most this many _source docs
# while the envelope's `total` stays the EXACT server-side count. The payload is
# therefore a small bounded SAMPLE the agent reads field-shape from; exact
# magnitudes come from `total` (and from re-querying with a narrowing filter and
# reading its `total`), never from pulling-and-counting. The cap is a mechanism,
# not a default: a larger `limit` is clamped to it (widening is futile by
# construction) — which is why an earlier small *default* backfired (the agent
# just widened past it). A 500-doc pull of full _source was multiple MB that
# gather re-jq'd turn after turn — the dominant cost and the >200K context crash.
RETURNED_DOC_CAP = 20
DEFAULT_LIMIT = RETURNED_DOC_CAP
REQUEST_TIMEOUT_SEC = 30


# ---------------------------------------------------------------------------
# Config + credentials
# ---------------------------------------------------------------------------


def _config_path(ctx: VerbContext) -> _Path:
    return ctx.defender_dir / "knowledge" / "environment" / "systems" / "elastic" / "config.env"


def load_config(ctx: VerbContext) -> dict[str, str]:
    """Elastic's config, read from the RUN's tree (`ctx.defender_dir`).

    Elastic keeps its own loader rather than `transport.load_config`: its keys are not the
    URL_BASE/BASTION_HOST/TIMEOUT_SEC template the five stubs share. Everything else is the
    same contract — the RUN's env overrides the file, and an absent file or a missing key is
    a `ConfigFault` (infra, 2): a system with no config is definitionally down.
    """
    path = _config_path(ctx)
    if not path.exists():
        raise ConfigFault(
            f"config file not found: {path} — this file should ship with the "
            f"defender-v2-env branch; if missing, restore from git."
        )

    config: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        config[key.strip()] = val.strip().strip('"').strip("'")

    # The RUN's env overrides the file for ops convenience (CI, per-run overrides).
    for key in list(config) + REQUIRED_CONFIG_KEYS:
        env_val = ctx.env.get(key)
        if env_val is not None:
            config[key] = env_val

    missing = [k for k in REQUIRED_CONFIG_KEYS if not config.get(k)]
    if missing:
        raise ConfigFault(
            f"missing required config keys in {path}: {', '.join(missing)}"
        )
    return config


# The playground stack is reached over the docker context using the SAME shared transport as
# the identity/cmdb/host-state adapters (`_stub_transport.docker_exec_curl`): we exec `curl`
# inside the target container, where the service answers on its own localhost (ES :9200,
# Kibana :5601) and supplies its own ELASTIC_PASSWORD. This removed the host-side SSH tunnel
# and the V2_ELASTIC_PASSWORD the direct urllib path needed. Mirrors infra/bin/es.sh.


def _es_container(ctx: VerbContext) -> str:
    return ctx.env.get("SOC_PLAYGROUND_ES_CONTAINER", DEFAULT_ES_CONTAINER)


def _kibana_container(ctx: VerbContext) -> str:
    return ctx.env.get("SOC_PLAYGROUND_KIBANA_CONTAINER", DEFAULT_KIBANA_CONTAINER)


def _unreachable(ctx: VerbContext, target: str, exc: BaseException) -> TransportFault:
    """The `TransportFault` (infra, 2) for an unreachable ES/Kibana, carrying the check.

    Transport is the docker context — a failure here means the context/daemon is down or the
    target container isn't running, not a missing SSH tunnel. Surface the check so it doesn't
    get rediagnosed every time.
    """
    context = transport.docker_context(ctx)
    return TransportFault(
        f"{target} unreachable: {exc} — the playground stack is reached via "
        f"`docker --context {context} exec`; confirm it is up: "
        f"docker --context {context} ps | grep -E "
        f"'{_es_container(ctx)}|{_kibana_container(ctx)}'"
    )


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _container_for(ctx: VerbContext, url: str, config: dict) -> str:
    """Which compose container to exec curl inside. ES and Kibana each answer on
    their own localhost port *within their own container* (matching es.sh), so
    route by which configured base URL this request targets."""
    kibana_base = (config.get("KIBANA_URL") or "").rstrip("/")
    if kibana_base and url.startswith(kibana_base):
        return _kibana_container(ctx)
    return _es_container(ctx)


def _http_json(ctx, method, url, config, headers=None, body=None, timeout=None):
    """Issue an HTTP request to ES/Kibana by exec'ing curl inside the target
    container over the run's docker context (mirrors infra/bin/es.sh).
    Returns (http_status:int, parsed_json:dict). Raises `TransportFault` when the docker
    exec itself fails or curl never completed a request (so a reachable-but-erroring service
    still returns its status + body for the caller to classify)."""
    container = _container_for(ctx, url, config)
    secs = int(timeout or REQUEST_TIMEOUT_SEC)
    # `insecure=True`: container-local self-signed cert (matches es.sh). `auth`
    # expands ${ELASTIC_PASSWORD} inside the container's own shell, never on this host.
    rc, stdout, stderr = transport.docker_exec_curl(
        ctx, container, url, method=method, headers=headers, body=body,
        timeout_sec=secs, insecure=True, auth="elastic:${ELASTIC_PASSWORD}",
    )
    body_text, status_str = transport.split_status(stdout)
    try:
        status = int(status_str)
    except ValueError as e:
        # No HTTP status line ⇒ curl never completed a request ⇒ transport-level
        # failure (no such container, context down, TLS handshake refused, …).
        detail = stderr.strip() or f"docker exec rc={rc}, no output"
        raise _unreachable(ctx, "Elasticsearch", TransportFault(detail)) from e
    if status == 0:
        # curl reports HTTP 000 when it never received a response (connection
        # refused, DNS failure, TLS handshake rejected, --max-time before any
        # headers). It still writes "\n000" to stdout, so the int() parse above
        # SUCCEEDS — the most common ES-down case. Treat 0 as the transport
        # failure it is, not a real HTTP status, so it routes to infra (2) and the
        # circuit breaker counts it instead of being mis-scored as a query error.
        detail = stderr.strip() or f"curl reported HTTP 000 (no response; rc={rc})"
        raise _unreachable(ctx, "Elasticsearch", TransportFault(detail))

    try:
        parsed = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        parsed = {"error": body_text[:500]}
    return status, parsed


def _raise_on_es_error(status: int, resp: dict, what: str) -> None:
    """The one place ES's status becomes a fault. 401/403 and 5xx are infra (the cluster is
    unusable, and the breaker should count it); everything else >=400 is the agent's query,
    and `detail` carries ES's OWN `reason` — the `verification_exception` naming the column
    it misspelled is the only thing the pitfalls curator ever sees of this failure."""
    if status == 200:
        return
    err = resp.get("error", resp)
    msg = err.get("reason") if isinstance(err, dict) else str(err)
    if status in (401, 403):
        raise TransportFault(f"Elasticsearch auth failed (HTTP {status}): {msg}")
    if status >= 500:
        raise TransportFault(f"Elasticsearch server error (HTTP {status}): {msg}")
    raise UpstreamFault(f"{what} failed (HTTP {status}): {msg}")


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
        # Hard cap, non-overridable: the agent may pass any `limit` but never
        # receives more than RETURNED_DOC_CAP docs. track_total_hits keeps the
        # envelope `total` exact regardless, so counts are unaffected.
        "size": min(limit, RETURNED_DOC_CAP),
        "sort": [{time_field: {"order": "desc"}}],
        "query": {"bool": {"must": must, "filter": filters}},
        "track_total_hits": True,
    }


def _search(ctx, config, index_pattern, query_string, time_start, time_end, time_field, limit):
    body = _build_search_body(query_string, time_start, time_end, time_field, limit)
    url = (
        f"{config['ELASTICSEARCH_URL'].rstrip('/')}/"
        f"{urllib.parse.quote(index_pattern, safe='-*,.')}/_search"
        f"?ignore_unavailable=true"
    )
    status, resp = _http_json(ctx, "POST", url, config, body=body)
    _raise_on_es_error(status, resp, "Elasticsearch query")

    hits_block = resp.get("hits", {})
    total = hits_block.get("total", {})
    total_hits = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
    raw_hits = hits_block.get("hits", [])
    docs = [h.get("_source", {}) for h in raw_hits]
    truncated = total_hits > len(docs)
    return docs, total_hits, truncated


def _search_verb(
    ctx: VerbContext, *, index_key: str, native_query: str,
    start: str | None, end: str | None, limit: int, index: str | None,
) -> dict:
    config = load_config(ctx)
    resolved = index or config[index_key]
    docs, total, truncated = _search(
        ctx, config, resolved, native_query, start, end,
        time_field="@timestamp", limit=limit,
    )
    return {
        "index": resolved,
        "total": total,
        "returned": len(docs),
        "truncated": truncated,
        "hits": docs,
    }


# ---------------------------------------------------------------------------
# The verbs
# ---------------------------------------------------------------------------


def health_check(ctx: VerbContext) -> dict:
    """ES cluster health + Kibana status, as DATA. An unreachable Kibana is reported in the
    payload rather than raised: ES answering is what makes the system usable, and failing the
    whole verb on Kibana would trip the breaker on a live source."""
    config = load_config(ctx)
    es_url = config["ELASTICSEARCH_URL"].rstrip("/") + "/_cluster/health"
    status, body = _http_json(ctx, "GET", es_url, config, timeout=10)
    _raise_on_es_error(status, body, "Elasticsearch health")

    out = {
        "system": SYSTEM,
        "connected": True,
        "elasticsearch": body.get("status", "unknown"),
        "nodes": body.get("number_of_nodes"),
    }

    kb_url = config["KIBANA_URL"].rstrip("/") + "/api/status"
    try:
        kb_status, kb_body = _http_json(
            ctx, "GET", kb_url, config, headers={"kbn-xsrf": "true"}, timeout=10
        )
    except TransportFault as e:
        out["kibana"] = f"unreachable ({e.detail})"
        return out

    if kb_status == 200 and isinstance(kb_body, dict):
        out["kibana"] = kb_body.get("status", {}).get("overall", {}).get("level", "unknown")
    else:
        out["kibana"] = f"HTTP {kb_status}"
    return out


@verb(engine="lucene", body_param="native_query")
def query(
    ctx: VerbContext,
    *,
    native_query: str,
    start: str | None = None,
    end: str | None = None,
    limit: int = DEFAULT_LIMIT,
    index: str | None = None,
) -> dict:
    """Search raw event indices (default pattern from ELASTIC_EVENTS_INDEX) with a
    lucene/KQL query. `limit` is clamped to RETURNED_DOC_CAP; read `total` for magnitudes."""
    return _search_verb(
        ctx, index_key="ELASTIC_EVENTS_INDEX", native_query=native_query,
        start=start, end=end, limit=limit, index=index,
    )


@verb(engine="lucene", body_param="native_query")
def alerts(
    ctx: VerbContext,
    *,
    native_query: str,
    start: str | None = None,
    end: str | None = None,
    limit: int = DEFAULT_LIMIT,
    index: str | None = None,
) -> dict:
    """Search detection-engine signals emitted by the v2 custom rules."""
    return _search_verb(
        ctx, index_key="ELASTIC_ALERTS_INDEX", native_query=native_query,
        start=start, end=end, limit=limit, index=index,
    )


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    """Run an ES|QL pipe (`FROM … | WHERE … | STATS …`) and return the result table.

    The aggregation runs server-side — the result rows ARE the answer; do not pull docs and
    reduce them yourself. The whole query (index, filter, time window, aggregation) lives in
    the pipe, which is why this verb takes no start/end/limit/index. ES|QL caps returned rows
    at 1000 by default, so a wide `BY` is truncated unless you narrow it.
    """
    config = load_config(ctx)
    url = f"{config['ELASTICSEARCH_URL'].rstrip('/')}/_query?format=json"
    status, resp = _http_json(ctx, "POST", url, config, body={"query": query})
    _raise_on_es_error(status, resp, "ES|QL query")

    columns = resp.get("columns", [])
    values = resp.get("values", [])
    names = [c.get("name") for c in columns]
    # Named-dict rows so the agent reads the table directly; this is the answer,
    # not a doc sample. The key is `values` (not in record_query's record-key set),
    # so a small aggregation passes through whole instead of being doc-sampled.
    rows = [dict(zip(names, row, strict=False)) for row in values]
    return {
        "query": query,
        "columns": columns,
        "row_count": len(rows),
        "values": rows,
    }


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
