
from __future__ import annotations

import json
import urllib.parse

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.faults import ConfigFault, TransportFault, UpstreamFault

SYSTEM = "elastic"

REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
]

DEFAULT_ES_CONTAINER = "elasticsearch"
DEFAULT_KIBANA_CONTAINER = "kibana"

RETURNED_DOC_CAP = 20
DEFAULT_LIMIT = RETURNED_DOC_CAP
REQUEST_TIMEOUT_SEC = 30




def _config_path(ctx: VerbContext) -> _Path:
    return ctx.defender_dir / "knowledge" / "environment" / "systems" / "elastic" / "config.env"


def load_config(ctx: VerbContext) -> dict[str, str]:
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




def _es_container(ctx: VerbContext) -> str:
    return ctx.env.get("SOC_PLAYGROUND_ES_CONTAINER", DEFAULT_ES_CONTAINER)


def _kibana_container(ctx: VerbContext) -> str:
    return ctx.env.get("SOC_PLAYGROUND_KIBANA_CONTAINER", DEFAULT_KIBANA_CONTAINER)


def _unreachable(ctx: VerbContext, target: str, exc: BaseException) -> TransportFault:
    context = transport.docker_context(ctx)
    return TransportFault(
        f"{target} unreachable: {exc} — the playground stack is reached via "
        f"`docker --context {context} exec`; confirm it is up: "
        f"docker --context {context} ps | grep -E "
        f"'{_es_container(ctx)}|{_kibana_container(ctx)}'"
    )




def _container_for(ctx: VerbContext, url: str, config: dict) -> str:
    kibana_base = (config.get("KIBANA_URL") or "").rstrip("/")
    if kibana_base and url.startswith(kibana_base):
        return _kibana_container(ctx)
    return _es_container(ctx)


def _http_json(ctx, method, url, config, headers=None, body=None, timeout=None):
    container = _container_for(ctx, url, config)
    secs = int(timeout or REQUEST_TIMEOUT_SEC)
    rc, stdout, stderr = transport.docker_exec_curl(
        ctx, container, url, method=method, headers=headers, body=body,
        timeout_sec=secs, insecure=True, auth="elastic:${ELASTIC_PASSWORD}",
    )
    body_text, status_str = transport.split_status(stdout)
    try:
        status = int(status_str)
    except ValueError as e:
        detail = stderr.strip() or f"docker exec rc={rc}, no output"
        raise _unreachable(ctx, "Elasticsearch", TransportFault(detail)) from e
    if status == 0:
        detail = stderr.strip() or f"curl reported HTTP 000 (no response; rc={rc})"
        raise _unreachable(ctx, "Elasticsearch", TransportFault(detail))

    try:
        parsed = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        parsed = {"error": body_text[:500]}
    return status, parsed


def _raise_on_es_error(status: int, resp: dict, what: str) -> None:
    if status == 200:
        return
    err = resp.get("error", resp)
    msg = err.get("reason") if isinstance(err, dict) else str(err)
    if status in (401, 403):
        raise TransportFault(f"Elasticsearch auth failed (HTTP {status}): {msg}")
    if status >= 500:
        raise TransportFault(f"Elasticsearch server error (HTTP {status}): {msg}")
    raise UpstreamFault(f"{what} failed (HTTP {status}): {msg}")




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




def health_check(ctx: VerbContext) -> dict:
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
    return _search_verb(
        ctx, index_key="ELASTIC_ALERTS_INDEX", native_query=native_query,
        start=start, end=end, limit=limit, index=index,
    )


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    config = load_config(ctx)
    url = f"{config['ELASTICSEARCH_URL'].rstrip('/')}/_query?format=json"
    status, resp = _http_json(ctx, "POST", url, config, body={"query": query})
    _raise_on_es_error(status, resp, "ES|QL query")

    columns = resp.get("columns", [])
    values = resp.get("values", [])
    names = [c.get("name") for c in columns]
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
