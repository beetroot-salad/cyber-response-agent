
from __future__ import annotations

import datetime as _dt
import urllib.parse
from typing import TYPE_CHECKING

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender import _clock
from defender.kit.verbs import VerbContext, verb
from defender.integrations import _stub_transport as transport
from defender.integrations.confinement import confine_index, confine_read_endpoint
from defender.integrations.esql_text import opens_with_from, split_first_command
from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "elastic"

#: The keys of `systems/elastic/config.env` this adapter requires (prefix stripped).
REQUIRED_CONFIG_KEYS = ("EVENTS_INDEX", "ALERTS_INDEX")

#: Base keys that no longer exist: the base lives in the access declaration alone (#1391 F4).
RETIRED_BASE_KEYS = ("ELASTICSEARCH_URL", "KIBANA_URL")

RETURNED_DOC_CAP = 20
DEFAULT_LIMIT = RETURNED_DOC_CAP
#: How long the proxy gives one request (`health-check` gets its own); constants, not settings.
REQUEST_TIMEOUT_SEC = 30
HEALTH_TIMEOUT_SEC = 10
HTTP_FORBIDDEN = 403


class OutboundBody:
    """A request body that has already been past the run's clock."""

    payload: dict
    __slots__ = ("payload",)

    def __init__(self, payload: dict) -> None:
        object.__setattr__(self, "payload", payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            f"OutboundBody is immutable (tried to set {name!r}) — mint a new one through "
            f"_search_body or _esql_body, which is what puts the run's clock on it")




PREFIX = "ELASTIC"


def load_config(ctx: VerbContext) -> dict[str, str]:
    """`_record_config` over the call's run record (`ctx.tenant`)."""
    return _record_config(ctx.tenant)


def _record_config(tenant: TenantRecord) -> dict[str, str]:
    """This deployment's elastic config from the run's record (#1107), by the shared rules for a
    proxied system: the two index keys (prefix stripped) and `URL_BASE`, the base of the access
    declaration (which holds the only one, #1391 F4). Elasticsearch is reached only through the
    credential proxy (#1391 O3), so another access method, a retired base key, no declaration, or
    a blank index key is a `ConfigFault` — Elasticsearch is not configured for this run
    (`check_settings` raises it at run start, so elastic is down from the start, #1256)."""
    return transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS,
                                   retired=RETIRED_BASE_KEYS, proxy_only=True)


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """Elastic's settings check (#1256 O-5): every `ConfigFault` a verb here can raise, over the
    run's record — the file, the access method, the access declaration, the two index keys. None
    when the system is usable."""
    _record_config(tenant)


def _http_json(  # noqa: PLR0913 — one request's per-call state
    ctx, method: str, config: dict[str, str], path: str, body: OutboundBody | None = None,
    timeout_sec: int = REQUEST_TIMEOUT_SEC,
) -> dict:
    """The one door to Elasticsearch: its own confinement first (P3: the endpoint allowlist,
    matched against `path` relative to the declared base as the proxy's routes are, before it is
    joined to the base), then the shared send, capture and fault mapping. `body` is typed rather
    than a bare dict for the reason `OutboundBody` gives."""
    confine_read_endpoint(SYSTEM, path, method=method, verb_class="r")
    answer = transport.http_timed(ctx, config, method, path,
                                  None if body is None else body.payload,
                                  system=SYSTEM, timeout_sec=timeout_sec)
    if not isinstance(answer, dict):
        raise TransportFault("non-object JSON response from elastic")
    return answer


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

    Shared by `_bounded_end` ("is the end open?") and the body builder ("is there a bound to
    emit?"); if they disagreed, `end=""` could be treated as present by one and absent by the
    other and a branched run would search with no range filter. Falsy means omitted, as
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
    """The search body, with the window's open end closed at the run's clock.

    The clock is consulted here, where every search body is built, rather than at call sites.
    `_bounded_end` decides what the bound is. A branched read also carries the clock as a
    `post_filter` (`_before_clock`): the caller's own window stays in `query` exactly as spelled
    (R-10=A), and the cluster drops the later hits before it sorts, pages and counts — so a
    page is never emptied, nor its total inflated, by rows past the branch point.
    """
    body = _build_search_body(
        query_string, time_start, _bounded_end(ctx, time_end), time_field, limit, sort)
    at = getattr(ctx, "as_of", None)
    if at is not None:
        body["post_filter"] = _before_clock(time_field, at)
    return OutboundBody(body)


def _before_clock(time_field: str, at: _dt.datetime) -> dict:
    """Hits dated at or before `at`, and undated ones (as `_after_clock` keeps them). Spelled as
    `_bounded_end` and `bounded_esql` spell the clock, so every path cuts at the same moment."""
    return {"bool": {"minimum_should_match": 1, "should": [
        {"range": {time_field: {"lte": _clock.z_seconds(at)}}},
        {"bool": {"must_not": {"exists": {"field": time_field}}}},
    ]}}


def _search(
    ctx, config, index_pattern: str, body: OutboundBody,
) -> tuple[list[dict], int, bool]:
    path = f"/{urllib.parse.quote(index_pattern, safe='-*,.')}/_search?ignore_unavailable=true"
    resp = _http_json(ctx, "POST", config, path, body=body)

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
        resolved, (config["EVENTS_INDEX"], config["ALERTS_INDEX"]))
    docs, total, truncated = _search(
        ctx, config, resolved,
        _search_body(
            ctx, query_string=native_query, time_start=start, time_end=end,
            time_field="@timestamp", limit=limit, sort=sort,
        ),
    )
    # The cluster already dropped later hits (`post_filter`); this is the backstop for one that
    # did not, and finds nothing to drop against Elasticsearch itself.
    kept = [d for d in docs if not _after_clock(ctx, d.get("@timestamp"))]
    return search_envelope(resolved, kept, total - (len(docs) - len(kept)), truncated, sort)


def _after_clock(ctx: VerbContext, stamp: object) -> bool:
    """Is `stamp` dated after the run's clock? A branched read keeps the caller's own window end
    on the wire, however it is spelled (#1224, R-10=A); the cluster drops later hits by
    `post_filter`, and any that still arrive are dropped here. Unbranched runs (no clock) and
    undated rows keep every row."""
    at = getattr(ctx, "as_of", None)
    if at is None:
        return False
    if isinstance(stamp, (int, float)) and not isinstance(stamp, bool):
        moment = _dt.datetime.fromtimestamp(stamp / 1000, _dt.UTC)
    else:
        parsed = _clock.parse_iso_utc(stamp)
        if parsed is None:
            return False
        moment = parsed
    return moment > _clock.as_utc(at)


def _bounded_end(ctx: VerbContext, end: str | None) -> str | None:
    """The window's upper bound, closed at the run's own clock when the caller left it open.

    Without it an unbounded search of this live stream (sorted `desc`, 20-doc cap) returns the
    newest documents right now, so a replayed episode would read a different corpus. "Open" is
    `_bound_set`'s answer.

    A present `end` is never touched: it is a scenario-timeline value, often far from the wall
    clock, and the caller has already bounded the query. The start stays open because the past
    does not change.

    Returns a new value rather than editing `params`, so the caller's params stay as asked.
    """
    at = getattr(ctx, "as_of", None)
    return end if _bound_set(end) or at is None else _clock.z_seconds(at)


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
    """Elasticsearch's cluster health, and nothing else (Kibana is not probed, #1391 D2). A 403 is
    the read-only user lacking the cluster `monitor` privilege: a setup mistake, so it is the
    settings' fault and not the agent's (D11); every other reply follows the proxy's
    classification."""
    config = load_config(ctx)
    try:
        body = _http_json(ctx, "GET", config, "/_cluster/health", timeout_sec=HEALTH_TIMEOUT_SEC)
    except UpstreamFault as e:
        if e.status != HTTP_FORBIDDEN:
            raise
        raise ConfigFault(
            "Elasticsearch refused the health check (HTTP 403): the user defender reads it as "
            "needs the cluster `monitor` privilege — a setup mistake, not the agent's") from e
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


def bounded_esql(ctx: VerbContext, query: str) -> str:
    """`query` with the run's clock as an upper bound, when the run has one."""
    at = getattr(ctx, "as_of", None)
    if at is None or not opens_with_from(query):
        return query
    head, tail = split_first_command(query)
    return f'{head.rstrip()}\n| WHERE @timestamp <= "{_clock.z_seconds(at)}"\n{tail.lstrip()}'


def _esql_body(ctx: VerbContext, query: str) -> OutboundBody:
    """The ES|QL request body, with the run's clock spliced in (the counterpart of
    `_search_body`)."""
    return OutboundBody({"query": bounded_esql(ctx, query)})


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    config = load_config(ctx)
    # The bounded query is sent, but the payload echoes the query as asked: the harness's bound
    # stays out of the run's record, and branched payloads stay byte-comparable with the
    # capture (`stagers/elastic.restore` only repairs the corpus identity in the echo).
    resp = _http_json(ctx, "POST", config, "/_query?format=json", body=_esql_body(ctx, query))
    return esql_payload(query, _esql_within_clock(ctx, resp))


def _esql_within_clock(ctx: VerbContext, resp: dict) -> dict:
    """`resp` with every row whose `@timestamp` column is dated after the run's clock dropped
    (R-10=A): the spliced bound covers only a query opening with `FROM`, this covers any
    source command."""
    columns = resp.get("columns") or []
    names = [c.get("name") if isinstance(c, dict) else None for c in columns]
    if getattr(ctx, "as_of", None) is None or "@timestamp" not in names:
        return resp
    at = names.index("@timestamp")
    values = [row for row in resp.get("values", [])
              if not (isinstance(row, list) and len(row) > at and _after_clock(ctx, row[at]))]
    return {**resp, "values": values}


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
