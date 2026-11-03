
from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.settings import config_pointer
from defender.kit.verbs import VerbContext, verb
from defender.integrations import _stub_transport as transport
from defender.integrations.confinement import confine_index, guard_outbound
from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "elastic"

REQUIRED_CONFIG_KEYS = [
    "ELASTICSEARCH_URL",
    "KIBANA_URL",
    "ELASTIC_EVENTS_INDEX",
    "ELASTIC_ALERTS_INDEX",
]

RETURNED_DOC_CAP = 20
DEFAULT_LIMIT = RETURNED_DOC_CAP
REQUEST_TIMEOUT_SEC = 30


class OutboundBody:
    """A request body minted by `_search_body` or `_esql_body`, the one door a request body leaves by."""

    payload: dict
    __slots__ = ("payload",)

    def __init__(self, payload: dict) -> None:
        object.__setattr__(self, "payload", payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            f"OutboundBody is immutable (tried to set {name!r}) — mint a new one through "
            f"_search_body or _esql_body")




PREFIX = "ELASTIC"
#: The Elasticsearch container every request execs into — required.
ES_CONTAINER_KEY = "ELASTIC_ES_CONTAINER"
#: The Kibana container `health-check` alone reads — optional (MF-7 c).
KIBANA_CONTAINER_KEY = "ELASTIC_KIBANA_CONTAINER"


def load_config(ctx: VerbContext) -> dict[str, str]:
    """`_record_config` over the call's run record (`ctx.tenant`)."""
    return _record_config(ctx.tenant)


def _record_config(tenant: TenantRecord) -> dict[str, str]:
    """This deployment's elastic config from the run's record (#1107): the keys of
    `systems/elastic/config.env` as written, prefix included. A missing or unusable file, an
    unimplemented access method, or a blank required key is a `ConfigFault` — Elasticsearch is
    not configured for this run (`check_settings` raises it at run start, so elastic is down from
    the start, #1256). The record's `elastic` view judges the
    keys platform code reads; this reader judges the ones IT needs, so each reports its own view
    (MF-7 c)."""
    entry = transport.record_entry(tenant, SYSTEM)
    transport.record_access_context(tenant, SYSTEM)
    config = dict(entry)
    missing = [k for k in REQUIRED_CONFIG_KEYS if not (config.get(k) or "").strip()]
    if missing:
        raise ConfigFault(
            f"missing required config keys in {config_pointer(SYSTEM)}: {', '.join(missing)}")
    return config


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """Elastic's settings check (#1256 O-5): every `ConfigFault` a verb here can raise, over the
    run's record — `load_config`'s (the file, the access method, the four keys), then the
    Elasticsearch container every request execs into (`_http_json` → `_es_container`), which
    `load_config` does not judge. The Kibana container is NOT judged: only `health-check` reads
    it, asks first, and answers its absence as a result (MF-7 c), so an Elasticsearch-only
    tenant's elastic is usable. None when the system is usable."""
    _record_config(tenant)
    _record_container(tenant, ES_CONTAINER_KEY)


def _configured(ctx: VerbContext, key: str) -> str | None:
    """The container named by `key` in the tenant's file, or None when it is absent or blank."""
    return _record_configured(ctx.tenant, key)


def _record_configured(tenant: TenantRecord, key: str) -> str | None:
    value = transport.record_entry(tenant, SYSTEM).get(key)
    return None if value is None or not value.strip() else value


def _record_container(tenant: TenantRecord, key: str) -> str:
    """The container named by `key` (`ELASTIC_ES_CONTAINER` / `ELASTIC_KIBANA_CONTAINER`) in the
    tenant's file — `ConfigFault` naming it when absent or blank. There is no default: a built-in
    `elasticsearch` or `kibana` would address whatever container the host happens to hold of that
    name."""
    value = _record_configured(tenant, key)
    if value is None:
        raise ConfigFault(
            f"{key} is not set — name the container this system is reached through in its "
            "config.env; there is no default")
    return value


def _es_container(ctx: VerbContext) -> str:
    return _record_container(ctx.tenant, ES_CONTAINER_KEY)


def _kibana_container(ctx: VerbContext) -> str:
    return _record_container(ctx.tenant, KIBANA_CONTAINER_KEY)


def _unreachable(ctx: VerbContext, target: str, exc: BaseException) -> TransportFault:
    context = transport.docker_context(ctx, SYSTEM)
    entry = transport.system_entry(ctx, SYSTEM)
    containers = "|".join(
        entry[k] for k in (ES_CONTAINER_KEY, KIBANA_CONTAINER_KEY) if k in entry)
    return TransportFault(
        f"{target} unreachable: {exc} — the stack is reached via "
        f"`docker --context {context} exec`; confirm it is up: "
        f"docker --context {context} ps | grep -E '{containers}'"
    )




def _http_json(  # noqa: PLR0913 — one request's per-call state
    ctx, method, url, config, headers=None, body: OutboundBody | None = None, timeout=None,
    *, kibana: bool = False,
):
    """The one door to Elasticsearch — and, with `kibana=True`, to Kibana. The caller says which
    service it addresses; the container is never guessed from the URL (an Elasticsearch URL that
    happens to start with KIBANA_URL is still Elasticsearch's). `body` is typed rather than a
    bare dict for the reason `OutboundBody` gives."""
    guard_outbound(ctx, SYSTEM, url, method=method)
    container = _kibana_container(ctx) if kibana else _es_container(ctx)
    secs = int(timeout or REQUEST_TIMEOUT_SEC)
    rc, stdout, stderr = transport.docker_exec_curl(
        ctx, container, url, method=method, headers=headers,
        body=None if body is None else body.payload,
        timeout_sec=secs, insecure=True, auth="elastic:${ELASTIC_PASSWORD}", system=SYSTEM,
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




SORT_NEWEST_FIRST = "desc"
SORT_OLDEST_FIRST = "asc"
SORT_ORDERS = (SORT_NEWEST_FIRST, SORT_OLDEST_FIRST)
DEFAULT_SORT = SORT_NEWEST_FIRST


def resolve_sort(sort: str) -> str:
    """The membership test for this adapter's sort vocabulary.

    Results are capped, so the order picks which end of the window comes back: `desc` (default)
    the newest, `asc` the oldest. Not pagination — a middle slice is reached by narrowing the
    window.
    """
    if sort not in SORT_ORDERS:
        raise UpstreamFault(
            f"invalid sort {sort!r}: one of {list(SORT_ORDERS)} — {SORT_NEWEST_FIRST!r} "
            f"returns the newest matching docs in the window, {SORT_OLDEST_FIRST!r} the "
            f"oldest. Neither pages: to reach docs between the two ends, narrow the window."
        )
    return sort


def _bound_set(bound) -> bool:
    """Does this window bound say anything?

    The body builder's one test of "is there a bound to emit?". Falsy means omitted, as
    elsewhere in this adapter (`index=""` means the default), and `validate_params` only
    type-checks, so `""` does arrive.
    """
    return bool(bound)


def _build_search_body(query_string, time_start, time_end, time_field, limit, sort):
    filters: list[dict] = []
    if _bound_set(time_start) or _bound_set(time_end):
        rng: dict[str, str] = {}
        if _bound_set(time_start):
            rng["gte"] = time_start
        if _bound_set(time_end):
            rng["lte"] = time_end
        filters.append({"range": {time_field: rng}})

    if query_string.strip():
        must = [{"query_string": {"query": query_string}}]
    else:
        must = [{"match_all": {}}]

    return {
        "size": min(limit, RETURNED_DOC_CAP),
        "sort": [{time_field: {"order": resolve_sort(sort)}}],
        "query": {"bool": {"must": must, "filter": filters}},
        "track_total_hits": True,
    }


def _search_body(  # noqa: PLR0913 — one search body's parameters, threaded whole
    ctx: VerbContext, *, query_string: str, time_start: str | None, time_end: str | None,
    time_field: str, limit: int, sort: str,
) -> OutboundBody:
    """The search body, as the caller asked it. The adapter knows only its target system: a
    branched run's cut at the branch point is the oracle's (#1385), so nothing here depends on
    the run or its clock."""
    return OutboundBody(_build_search_body(
        query_string, time_start, time_end, time_field, limit, sort))


def _search(
    ctx, config, index_pattern: str, body: OutboundBody,
) -> tuple[list[dict], int, bool]:
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


def _search_verb(  # noqa: PLR0913 — the two search verbs' shared body, one param each
    ctx: VerbContext, *, index_key: str, native_query: str,
    start: str | None, end: str | None, limit: int, index: str | None, sort: str,
) -> dict:
    config = load_config(ctx)
    resolved = index or config[index_key]
    resolved = confine_index(
        resolved, (config["ELASTIC_EVENTS_INDEX"], config["ELASTIC_ALERTS_INDEX"]))
    docs, total, truncated = _search(
        ctx, config, resolved,
        _search_body(
            ctx, query_string=native_query, time_start=start, time_end=end,
            time_field="@timestamp", limit=limit, sort=sort,
        ),
    )
    return search_envelope(resolved, docs, total, truncated, sort)


def search_envelope(index: str, docs: list, total: int, truncated: bool, sort: str) -> dict:
    """The model-facing result shape of `query` / `alerts` — the contract a lead reads and the
    payload on disk keeps."""
    return {
        "index": index,
        "total": total,
        "returned": len(docs),
        # Which end of the window a truncated result came from; echoed, already validated.
        "sort": sort,
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

    # Kibana is optional to this adapter (MF-7 c: an Elasticsearch-only tenant keeps answering),
    # so a missing container is a RESULT here — asked before the call, never a ConfigFault that
    # would discard the Elasticsearch answer above and charge the breaker.
    if _configured(ctx, KIBANA_CONTAINER_KEY) is None:
        out["kibana"] = "not configured (ELASTIC_KIBANA_CONTAINER is not set)"
        return out
    kb_url = config["KIBANA_URL"].rstrip("/") + "/api/status"
    try:
        kb_status, kb_body = _http_json(
            ctx, "GET", kb_url, config, headers={"kbn-xsrf": "true"}, timeout=10, kibana=True,
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
    sort: str = DEFAULT_SORT,
) -> dict:
    return _search_verb(
        ctx, index_key="ELASTIC_EVENTS_INDEX", native_query=native_query,
        start=start, end=end, limit=limit, index=index, sort=sort,
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
    sort: str = DEFAULT_SORT,
) -> dict:
    return _search_verb(
        ctx, index_key="ELASTIC_ALERTS_INDEX", native_query=native_query,
        start=start, end=end, limit=limit, index=index, sort=sort,
    )


def esql_payload(query: str, resp: dict) -> dict:
    """The `esql` verb's payload, shaped from the raw ES|QL response.

    `values` stays as the wire sent it: bare row arrays, cell `i` bound to `columns[i]`.
    Re-zipping into dicts would roughly double what gather records to disk; `defender-sql`
    queries the rows by name under `--rows values --names columns`, which `defender-sql.md`
    teaches.

    Pure and separate from the verb so `evals/oracle_golden/controls.py` can share it.
    """
    values = resp.get("values", [])
    return {
        "query": query,
        "columns": resp.get("columns", []),
        "row_count": len(values),
        "values": values,
    }


def _esql_body(ctx: VerbContext, query: str) -> OutboundBody:
    """The ES|QL request body: the query as asked (the counterpart of `_search_body`)."""
    return OutboundBody({"query": query})


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    config = load_config(ctx)
    url = f"{config['ELASTICSEARCH_URL'].rstrip('/')}/_query?format=json"
    status, resp = _http_json(ctx, "POST", url, config, body=_esql_body(ctx, query))
    _raise_on_es_error(status, resp, "ES|QL query")
    return esql_payload(query, resp)


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
