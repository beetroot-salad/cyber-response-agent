
from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from typing import TYPE_CHECKING

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import VerbContext, verb
from defender.kit import transport
from defender.integrations import esql_text
from defender.integrations.confinement import ConfinementFault, confine_index, confine_read_endpoint
from defender.kit.faults import ConfigFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "elastic"

#: The keys of `systems/elastic/config.env` this adapter requires (prefix stripped).
REQUIRED_CONFIG_KEYS = ("EVENTS_INDEX", "ALERTS_INDEX")
#: The keys whose values go in a request path (a search's index), so each is one segment (T4).
PATH_KEYS = REQUIRED_CONFIG_KEYS

RETURNED_DOC_CAP = 20
DEFAULT_LIMIT = RETURNED_DOC_CAP
#: How long the proxy gives one request (`health-check` gets its own); constants, not settings.
REQUEST_TIMEOUT_SEC = 30
HEALTH_TIMEOUT_SEC = 10
HTTP_FORBIDDEN = 403


PREFIX = "ELASTIC"


def load_config(ctx: VerbContext) -> dict[str, str]:
    """`_record_config` over the call's run record (`ctx.tenant`)."""
    return _record_config(ctx.tenant)


def _record_config(tenant: TenantRecord) -> dict[str, str]:
    """This deployment's elastic config from the run's record (#1107), by the shared rules for a
    proxied system: the two index keys (prefix stripped), each one path segment (#1391 T4); its
    base is its access declaration's (F4). Any other key (a retired base, Kibana or Docker key,
    #1391 Q4), no declaration, or a blank or placeholder index key is a `ConfigFault` —
    Elasticsearch is not configured for this run (`check_settings` raises it at run start, so
    elastic is down from the start, #1256)."""
    return transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS,
                                   path_keys=PATH_KEYS)


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """Elastic's settings check (#1256 O-5): every `ConfigFault` a verb here can raise, over the
    run's record — the file, its keys, the access declaration, the two index keys. None
    when the system is usable."""
    _record_config(tenant)


def _error_detail(body_text: str) -> object:
    """Elasticsearch's own reason from an error body, for the transport: its `error` when it is
    text, else its `error.root_cause` reasons (else `error.reason`), each with its type; any other
    body as the transport reads one (`vendor_detail`)."""
    try:
        payload = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        return transport.vendor_detail(body_text)
    error = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(error, str):  # the plain form, e.g. "no handler found for uri […]"
        return transport.capped_detail(error)
    if isinstance(error, dict):
        causes = [c for c in error.get("root_cause") or [] if isinstance(c, dict)] or [error]
        reasons = [f"{c.get('type')}: {c['reason']}" if c.get("type") else c["reason"]
                   for c in causes if isinstance(c.get("reason"), str)]
        if reasons:
            return transport.capped_detail("; ".join(dict.fromkeys(reasons)))
    return transport.vendor_detail(body_text)


def _http_json(  # noqa: PLR0913 — one request's per-call state
    ctx, method: str, template: str, values: dict[str, str] | None = None, *,
    query: dict[str, str] | None = None, body: dict | None = None,
    timeout_sec: int = REQUEST_TIMEOUT_SEC,
) -> dict:
    """The one door to Elasticsearch: each path value one segment (T2), then its own
    confinement (P3: the endpoint allowlist, matched against the path relative to the declared
    base as the proxy's routes are), then the shared send, capture and fault mapping."""
    given = {name: transport.require_segment(name, value) for name, value in (values or {}).items()}
    confine_read_endpoint(SYSTEM, template.format_map(given), method=method)
    return transport.request(ctx, SYSTEM, method, template, given, query=query, body=body,
                             timeout_sec=timeout_sec, error_detail=_error_detail)


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


def _search(ctx, index_pattern: str, body: dict) -> tuple[list[dict], int, bool]:
    # The index is confined to the configured patterns (`confine_index`), so a 403 is the user
    # lacking `read` on one of them: setup, not the agent's (PR #1409 review).
    with _a_403_is_setup(f"the search of {index_pattern}",
                         "`read` on the configured events and alerts indexes"):
        resp = _http_json(ctx, "POST", "/{index}/_search", {"index": index_pattern},
                          query={"ignore_unavailable": "true"}, body=body)

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
    # One segment first (T2), then the expression's reach (`confine_index`).
    resolved = transport.require_segment("index", index or config[index_key])
    resolved = confine_index(
        resolved, (config["EVENTS_INDEX"], config["ALERTS_INDEX"]))
    docs, total, truncated = _search(
        ctx, resolved,
        _build_search_body(native_query, start, end, "@timestamp", limit, sort),
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




@contextlib.contextmanager
def _a_403_is_setup(what: str, needs: str) -> Iterator[None]:
    """A 403 inside is the read-only user lacking `needs`: a setup mistake, so a `ConfigFault`
    naming it rather than the agent's `UpstreamFault` (D11). Every other reply follows the
    proxy's classification. Only for a request whose targets are confined to the configured
    patterns (`confine_index`), `esql`'s included (#1347 O2a), so the agent cannot cause one."""
    try:
        yield
    except UpstreamFault as e:
        if e.status != HTTP_FORBIDDEN:
            raise
        raise ConfigFault(
            f"Elasticsearch refused {what} (HTTP 403): the user defender reads it as needs "
            f"{needs} — a setup mistake, not the agent's") from e


def health_check(ctx: VerbContext) -> dict:
    """Elasticsearch's cluster health, and nothing else (Kibana is not probed, #1391 D2). A 403 is
    the read-only user lacking the cluster `monitor` privilege (`_a_403_is_setup`)."""
    load_config(ctx)
    with _a_403_is_setup("the health check", "the cluster `monitor` privilege"):
        body = _http_json(ctx, "GET", "/_cluster/health", timeout_sec=HEALTH_TIMEOUT_SEC)
    return {
        "system": SYSTEM,
        "connected": True,
        "elasticsearch": body.get("status", "unknown"),
        "nodes": body.get("number_of_nodes"),
    }


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
        ctx, index_key="EVENTS_INDEX", native_query=native_query,
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
        ctx, index_key="ALERTS_INDEX", native_query=native_query,
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


def _confine_esql(query: str, patterns: tuple[str, str]) -> None:
    """Refuse a query that reads an index outside the configured patterns, or whose sources
    cannot be read (#1347 O2a): the copy a frozen run reads holds only those patterns, so no
    query may tell it from live."""
    named = esql_text.sources(query)
    if named is None:
        raise ConfinementFault("the ES|QL query's sources cannot be read, so it is refused")
    for index in named:
        confine_index(index, patterns)


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    config = load_config(ctx)
    _confine_esql(query, (config["EVENTS_INDEX"], config["ALERTS_INDEX"]))
    with _a_403_is_setup("the ES|QL query", "`read` on the configured events and alerts indexes"):
        resp = _http_json(ctx, "POST", "/_query", query={"format": "json"}, body={"query": query})
    return esql_payload(query, resp)


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
