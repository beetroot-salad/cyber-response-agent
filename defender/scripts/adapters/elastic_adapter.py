
from __future__ import annotations

import json
import urllib.parse

import sys as _sys
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

    THE TYPE IS THE PROOF, and it exists because bounding a window was a thing an author had
    to remember. Two lanes close an open window — `_bounded_end` where the bound is a
    parameter, `bounded_esql` where it lives inside the ES|QL the model wrote — and both used
    to hand a plain `dict` to `_http_json`. Nothing connected the two facts, so a third search
    verb added later reached Elasticsearch unbounded by simply not calling either, and an
    unbounded read of a live agent stream sorted `desc` under a doc cap returns "the newest
    documents right now": the one answer a branched run may not have, and the exact payload
    `as_of` was threaded through the ctx to remove.

    A lint could ask whether the clamp was called. A type makes the question unaskable: the
    wire takes `OutboundBody` and nothing else, and both functions that mint one take `ctx` and
    consult the clock on the way, so the bound cannot be dropped at a CALL SITE — the place it
    was droppable. Minting one by hand is still possible, because Python has no private
    constructor; what it is not is accidental. That is the whole of what this buys and all it
    claims. It says nothing about the tiers ABOVE the adapter: a memoised base-tier hit is
    served without the adapter running at all, so the clock is not consulted there and this
    type does not reach it.

    Immutable, so the body a caller minted is the body that goes out — a payload edited
    between the mint and the wire would leave the type asserting something no longer true.

    HAND-WRITTEN RATHER THAN A `@dataclass`, which is the shape this would otherwise be. The
    scaffold rules import every adapter BY PATH, under a module name that is not registered in
    `sys.modules`; `dataclass` resolves a `ClassVar`/`InitVar` annotation by looking its class's
    module up there, and this file is `from __future__ import annotations`, so every annotation
    is a string and that lookup runs. It returns `None` and the decorator raises
    `AttributeError` at IMPORT — which the rules layer reports as "adapter for system 'elastic'
    failed to import", a message naming nothing that is actually wrong with the adapter.
    """

    payload: dict
    __slots__ = ("payload",)

    def __init__(self, payload: dict) -> None:
        object.__setattr__(self, "payload", payload)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(
            f"OutboundBody is immutable (tried to set {name!r}) — mint a new one through "
            f"_search_body or _esql_body, which is what puts the run's clock on it")




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


def _http_json(
    ctx, method, url, config, headers=None, body: OutboundBody | None = None, timeout=None,
):
    """The one door to Elasticsearch. `body` is typed rather than a bare dict for the reason
    `OutboundBody` gives: this is the frame a forgotten window would have escaped through."""
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
    """THE membership test for this adapter's sort vocabulary, so no caller re-derives what a
    value in `SORT_ORDERS` means.

    Because results are capped, the order decides WHICH end of the window comes back — `desc`
    (the default) the newest matching docs, `asc` the oldest. Deliberately not pagination:
    those are the only two ends a bounded window has, and reaching a middle slice is the
    window's job, not a cursor's.
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

    THE ONE PREDICATE, because two frames decide about the same value and a disagreement
    between them is invisible. `_bounded_end` asks "did the caller leave the end open, so the
    run's clock should close it"; the body builder below asks "is there a bound to emit". Those
    have to be the same question, and they were not: `is not None` there against truthiness
    here let `end=""` be *present* to the filler and *absent* to the builder, so a branched
    run's unbounded search reached Elasticsearch with no range filter at all — the live tail,
    which is the exact payload `as_of` was threaded through the ctx to remove.

    FALSY IS OMITTED is the adapter's own established reading of a bound-shaped param —
    `_search_verb` resolves `index or config[index_key]`, so `index=""` addresses the
    configured default exactly as an absent one does — and a model spelling "no upper bound"
    as `""` passes `validate_params`, which only type-checks.
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

    THE CLOCK IS CONSULTED HERE, not at the call site, because here is the only place a search
    body is built and `OutboundBody` is the only thing the wire accepts — so the two facts
    cannot drift apart. `_bounded_end` still decides WHAT the bound is (and leaves a present
    one alone); this decides only that it is asked.
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
    # `world_id` rides through so a BRANCHED run's staged read is confined rather than
    # refused. A world view is named outside every configured pattern on purpose, so reach
    # alone cannot admit it; passing the world declares the two names it may carry, and no
    # sibling's. `None` on every ordinary run, which is the whole of the behaviour there.
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

    `_build_search_body` emits NO range filter at all when both bounds are falsy, and this
    index is a live agent stream sorted `desc` under a 20-doc cap — so an unbounded search
    returns "the newest documents right now". That is the elastic twin of the host-state
    adapter's wall-clock `captured_at`: a served payload that is not a function of the question
    asked, and the reason an episode replayed a week later reads a different corpus.

    "OPEN" IS `_bound_set`'s ANSWER, not a second reading of it — see that predicate for the
    `end=""` hole a private one left.

    A PRESENT `end` is never touched. It is a scenario-timeline value the model chose — the
    corpus routinely puts it months from the wall clock — so clamping it to `as_of` would
    truncate the alert's own window in service of a determinism the caller had already bought
    by bounding the query.

    THE START IS LEFT OPEN on purpose. An absent lower bound means "from the beginning of the
    index", and the past does not change; only the open END admits documents that did not exist
    when the branch point was written.

    A NEW LOCAL rather than rebinding `end`, so the parameter keeps meaning what the caller
    passed — and, downstream, so `params` is never perturbed: the estate seam reads
    `prepared != params` to decide whether STAGING moved a call, and a window filled here would
    make an unstaged call look staged, widening the world declaration and writing an
    `asked_params` column whose whole meaning is "staging moved it".
    """
    at = getattr(ctx, "as_of", None)
    return end if _bound_set(end) or at is None else _clock.z_seconds(at)


def search_envelope(index: str, docs: list, total: int, truncated: bool, sort: str) -> dict:
    """The model-facing result shape of `query` / `alerts` — named rather than inlined because
    it is the contract a lead reads and a payload on disk keeps, not an assembly detail."""
    return {
        "index": index,
        "total": total,
        "returned": len(docs),
        # WHICH end of the window these docs came from: `truncated` says a slice was taken,
        # and without the order a later reader of the payload on disk cannot tell whether the
        # 20 it holds are the window's first or its last. Echoed, not re-resolved —
        # `_build_search_body` already ran the one membership test, before the request.
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

    `values` is left AS THE WIRE SENT IT: rows are bare arrays, cell `i` binding to
    `columns[i]`. Do not re-zip them into per-row dicts — that restates every field name on
    every row, and on the payload class gather reads most it roughly doubles what is recorded
    to disk. The binding is not lost, it is DERIVED at read time from `columns`, which the
    wire states once. `sql.py`'s ES|QL hint and `defender-sql.md`'s idiom both document this
    positional form.

    Pure, and separate from the verb, so `evals/oracle_golden/controls.py` can produce the
    same shape through the same code, and so the shape is testable without an HTTP seam.
    """
    values = resp.get("values", [])
    return {
        "query": query,
        "columns": resp.get("columns", []),
        "row_count": len(values),
        "values": values,
    }


def bounded_esql(ctx: VerbContext, query: str) -> str:
    """`query` with the run's own clock as an upper bound, when the run has one.

    THE `query`/`alerts` FILL, for the verb whose window is not a parameter. `_bounded_end`
    closes an open upper bound where the bound is an argument; here it lives inside the
    ES|QL the model wrote, so the bound is added as its own pipe stage instead.

    APPENDED, NEVER EDITED, and that distinction is the whole safety argument. This does not
    read, parse or rewrite the predicate the model authored — it splices an independent
    command in after the source, so it can only NARROW the row set and can never widen one.
    That is `evals/oracle_golden/controls.add_esql_window`'s property and its reasoning, on
    the same `split_first_command`; a rewrite that had to understand the existing `WHERE`
    could half-apply, which is what the surrounding module refuses everywhere.

    AFTER THE SOURCE COMMAND, found by ES|QL's own separator rather than by newline: a query
    may write its whole pipeline on one line, and splicing after the first LINE would put the
    clause after a `LIMIT` — taking one arbitrary row and only then filtering it, which is not
    a narrower row set but an empty one.

    `@timestamp` is safe to name ONLY WHERE THE SOURCE COMMAND IS `FROM`, and that is checked
    rather than assumed. A data stream requires the field, but `esql` applies no index
    confinement, so the model is free to open with `ROW` (literal rows) or `SHOW` (cluster
    metadata) — neither has an `@timestamp` column, and bounding one does not narrow its rows,
    it turns a query the source run answered into `Unknown column [@timestamp]`. That lands as
    an `UpstreamFault` in the SIBLING and not in its base, which is the base-vs-sibling
    contamination this whole seam exists to exclude, arriving from the clock added to prevent a
    different one. A blank query is left alone for the same reason: splicing into one yields a
    query opening with a bare pipe, so a refusal the source run got as "empty query" comes back
    as a parse error naming a clause the model never wrote. `opens_with_from` answers both,
    beside `split_first_command`, because a second spelling of "does this open with FROM" is
    the drift `esql_text` exists to prevent.

    `lte`, matching `_build_search_body`'s spelling for the parameter path, so a document
    written exactly at the branch point is inside both windows rather than inside one.

    An UNBRANCHED run has no clock and gets its query back untouched.
    """
    at = getattr(ctx, "as_of", None)
    if at is None or not opens_with_from(query):
        return query
    head, tail = split_first_command(query)
    return f'{head.rstrip()}\n| WHERE @timestamp <= "{_clock.z_seconds(at)}"\n{tail.lstrip()}'


def _esql_body(ctx: VerbContext, query: str) -> OutboundBody:
    """The ES|QL request body, with the run's clock spliced in as its own pipe stage.

    The ES|QL twin of `_search_body`, and here for the same reason: the mint is what the wire
    takes, so the bound rides every request rather than every call site remembering it.
    """
    return OutboundBody({"query": bounded_esql(ctx, query)})


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002 — shadows the `query` verb by design
    config = load_config(ctx)
    url = f"{config['ELASTICSEARCH_URL'].rstrip('/')}/_query?format=json"
    # THE BOUND RIDES THE WIRE, NOT THE EVIDENCE. `esql_payload` echoes the query into the
    # payload, so a bounded form handed to it would put a clause the model never wrote into
    # the record every reader treats as what this lead asked — and `stagers/elastic.restore`
    # repairs the corpus identity in that echo, not an inserted stage. Sending the bounded
    # form and echoing the asked one keeps the harness's bound out of the run's own account of
    # itself, and keeps a branched payload byte-comparable with the capture it came from.
    status, resp = _http_json(ctx, "POST", url, config, body=_esql_body(ctx, query))
    _raise_on_es_error(status, resp, "ES|QL query")
    return esql_payload(query, resp)


VERBS = {
    "health-check": health_check,
    "query": query,
    "alerts": alerts,
    "esql": esql,
}
