
from __future__ import annotations

import json
import urllib.parse

import sys as _sys
from collections.abc import Mapping, Sequence
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender import _clock
from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import _stub_transport as transport
from defender.scripts.adapters.confinement import confine_index, guard_outbound
from defender.scripts.adapters.esql_text import opens_with_from, split_first_command
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


class OutboundBody:
    """A request body that has already been past the run's clock.

    The wire (`_http_json`) accepts only this type, and both minting functions (`_search_body`,
    `_esql_body`) take `ctx` and consult the clock, so a new search verb cannot reach
    Elasticsearch with an open window by forgetting a call. An unbounded `desc` read of a live
    stream returns the newest documents right now, which a branched run must not see. Hand
    minting is still possible, just not accidental. Memoised base-tier hits bypass the adapter
    entirely, so this says nothing about them.

    Immutable, so the minted body is the body sent.

    Hand-written rather than a `@dataclass`: adapters are imported by path under a module name
    not in `sys.modules`, and `dataclass` resolving string annotations there raises at import.
    """

    payload: dict
    __slots__ = ("payload",)

    def __init__(self, payload: dict) -> None:
        object.__setattr__(self, "payload", payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            f"OutboundBody is immutable (tried to set {name!r}) — mint a new one through "
            f"_search_body or _esql_body, which is what puts the run's clock on it")




#: This deployment's elastic config, relative to a tenant's `settings/` folder. Named once
#: because one of its three readers has no `VerbContext`.
CONFIG_RELPATH = ("systems", "elastic", "config.env")


def config_path(settings_dir: _Path) -> _Path:
    """The config file under a tenant's `settings_dir`, for callers without a verb context."""
    return _Path(settings_dir).joinpath(*CONFIG_RELPATH)


def _config_path(ctx: VerbContext) -> _Path:
    return config_path(ctx.settings_dir)


def config_from(
    path: _Path, env: Mapping[str, str], *, expected: Sequence[str] = (),
) -> dict[str, str]:
    """This deployment's elastic config: the file, with the environment over it.

    The single parser for all three readers (this adapter, the staging seam, its write door),
    so one `config.env` cannot describe different clusters to different readers. An absent file
    is empty here; only `load_config` must refuse.

    The environment overrides any key the file carries or the caller lists in `expected`, not
    only keys present in the file — otherwise a missing or trimmed file would ignore an
    operator-set `ELASTICSEARCH_URL`.

    One matched pair of surrounding quotes is trimmed; `.strip('"')` would also eat a quote
    that legitimately ends a password or URL.
    """
    values: dict[str, str] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, val = stripped.partition("=")
            raw = val.strip()
            if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
                raw = raw[1:-1]
            values[key.strip()] = raw
    for key in (*values, *expected):
        env_val = env.get(key)
        if env_val is not None:
            values[key] = env_val
    return values


def load_config(ctx: VerbContext) -> dict[str, str]:
    path = _config_path(ctx)
    if not path.exists():
        raise ConfigFault(
            f"config file not found: {path} — this tenant's settings do not configure "
            "this system"
        )
    config = config_from(path, ctx.env, expected=REQUIRED_CONFIG_KEYS)
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


def _http_json(
    ctx, method, url, config, headers=None, body: OutboundBody | None = None, timeout=None,
):
    """The one door to Elasticsearch. `body` is typed rather than a bare dict for the reason
    `OutboundBody` gives."""
    guard_outbound(ctx, SYSTEM, url, method=method)
    container = _container_for(ctx, url, config)
    secs = int(timeout or REQUEST_TIMEOUT_SEC)
    rc, stdout, stderr = transport.docker_exec_curl(
        ctx, container, url, method=method, headers=headers,
        body=None if body is None else body.payload,
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
    `_bounded_end` decides what the bound is.
    """
    return OutboundBody(_build_search_body(
        query_string, time_start, _bounded_end(ctx, time_end), time_field, limit, sort))


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
    # `world_id` lets a branched run's staged world view (named outside every configured
    # pattern) be confined rather than refused. `None` on ordinary runs.
    resolved = confine_index(
        resolved, (config["ELASTIC_EVENTS_INDEX"], config["ELASTIC_ALERTS_INDEX"]),
        world_id=getattr(ctx, "world_id", None),
    )
    docs, total, truncated = _search(
        ctx, config, resolved,
        _search_body(
            ctx, query_string=native_query, time_start=start, time_end=end,
            time_field="@timestamp", limit=limit, sort=sort,
        ),
    )
    return search_envelope(resolved, docs, total, truncated, sort)


def _bounded_end(ctx: VerbContext, end: str | None) -> str | None:
    """The window's upper bound, closed at the run's own clock when the caller left it open.

    Without it an unbounded search of this live stream (sorted `desc`, 20-doc cap) returns the
    newest documents right now, so a replayed episode would read a different corpus. "Open" is
    `_bound_set`'s answer.

    A present `end` is never touched: it is a scenario-timeline value, often far from the wall
    clock, and the caller has already bounded the query. The start stays open because the past
    does not change.

    Returns a new value rather than editing `params`: the estate seam compares
    `prepared != params` to detect staging, and a filled window would make an unstaged call
    look staged.
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


def bounded_esql(ctx: VerbContext, query: str) -> str:
    """`query` with the run's clock as an upper bound, when the run has one.

    The ES|QL counterpart of `_bounded_end`, where the window lives inside the model's query.
    The bound is appended as an independent pipe stage right after the source command, never by
    editing the model's predicate, so it can only narrow the row set (as in
    `evals/oracle_golden/controls.add_esql_window`). The source command is found by ES|QL's own
    separator, not by newline: splicing after a one-line pipeline's `LIMIT` would filter one
    arbitrary row.

    Only applied when the source command is `FROM` (`opens_with_from`): `ROW` or `SHOW` have no
    `@timestamp`, and a blank query would become a bare pipe — either way the sibling would get
    an error its base did not. `lte` matches `_build_search_body`, so a document at the branch
    point is inside both windows. Unbranched runs get the query back untouched.
    """
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
    url = f"{config['ELASTICSEARCH_URL'].rstrip('/')}/_query?format=json"
    # The bounded query is sent, but the payload echoes the query as asked: the harness's bound
    # stays out of the run's record, and branched payloads stay byte-comparable with the
    # capture (`stagers/elastic.restore` only repairs the corpus identity in the echo).
    status, resp = _http_json(ctx, "POST", url, config, body=_esql_body(ctx, query))
    _raise_on_es_error(status, resp, "ES|QL query")
    return esql_payload(query, resp)


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
