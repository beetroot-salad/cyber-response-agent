"""Vendor-neutral filter-contract recovery for the oracle router.

A gather query template declares its *locator contract* in `filter_keys`
frontmatter: the index it hits, the time-window parameter names, and the
locator predicates that map a **footprint event attribute** (`container_id`,
`rule`, `host`, `source_ip`, …) to the `${param}` that pins it. At
lead-sequence assembly time we recover each predicate's *bound value* by
reverse-aligning the rendered query against the template's **own body** —
the template is the parser, so there is no fixed query-language grammar
anywhere and the recovery works for whatever dialect a template is written
in (Lucene today, SPL/Kusto for a future system). The structured
`filters` block we emit lets the oracle router match footprint events by
plain containment, never by parsing a vendor query string.

A query whose template carries no `filter_keys` (ad-hoc / un-promoted
coined ids, or non-event-stream systems like cmdb) recovers to ``None``;
the router reports those leads as ``unrouted`` rather than guessing.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml

QUERIES_DIR = Path(__file__).resolve().parent.parent / "skills" / "gather" / "queries"

_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
_QUERY_BLOCK_RE = re.compile(
    r"^## Query\s*\n+```[a-zA-Z]*\n(.*?)\n```", re.DOTALL | re.MULTILINE
)
_TOKEN_RE = re.compile(r"\$\{[^}]*\}")


def _template_path(query_id: str) -> Path | None:
    """Resolve a ``{system}.{template-id}`` id to its catalog file.

    Checks the established location then the lead-author's ``_draft/``
    staging dir, so a coined id that has been minted but not yet promoted
    still resolves.
    """
    system, _, template = query_id.partition(".")
    if not template:
        return None
    base = QUERIES_DIR / system
    for cand in (base / f"{template}.md", base / "_draft" / f"{template}.md"):
        if cand.is_file():
            return cand
    return None


def load_contract(query_id: str) -> tuple[dict, str] | None:
    """Return ``(filter_keys, query_body)`` for a template, or ``None``.

    ``None`` means "no declared locator contract" — either the template
    does not exist (ad-hoc / non-event-stream) or it carries no
    ``filter_keys`` frontmatter yet.

    Cached: a run reuses a handful of templates across many queries, so this
    re-read + YAML parse is memoized on ``(query_id, QUERIES_DIR)``. Including
    ``QUERIES_DIR`` in the key keeps tests (which monkeypatch it to a tmp dir)
    isolated. The returned ``filter_keys`` dict is shared — read-only by design;
    callers build fresh predicate dicts and never mutate it.
    """
    return _load_contract_cached(query_id, str(QUERIES_DIR))


@lru_cache(maxsize=None)
def _load_contract_cached(query_id: str, _queries_dir: str) -> tuple[dict, str] | None:
    path = _template_path(query_id)
    if path is None:
        return None
    text = path.read_text()
    fm_match = _FRONTMATTER_RE.match(text)
    if not fm_match:
        return None
    try:
        frontmatter = yaml.safe_load(fm_match.group(1)) or {}
    except yaml.YAMLError:
        return None
    filter_keys = frontmatter.get("filter_keys")
    if not isinstance(filter_keys, dict):
        return None
    body_match = _QUERY_BLOCK_RE.search(text)
    body = body_match.group(1).strip() if body_match else ""
    return filter_keys, body


def _ws_flexible(literal: str) -> str:
    """Escape a raw literal into a regex where each whitespace run matches any
    whitespace, so recovery is insensitive to how the rendered query was spaced.

    Escape per non-whitespace chunk and rejoin with ``\\s+`` — escaping the
    whole string first would let ``re.escape``'s own whitespace escaping
    collide with the substitution.
    """
    chunks = [re.escape(c) for c in re.split(r"\s+", literal) if c]
    return r"\s+".join(chunks)


def _build_extractor(body: str, param: str) -> re.Pattern | None:
    """Build a one-capture regex that lifts ``${param}``'s value back out of a
    rendered query, using the literal text the template puts around the hole.

    Two anchors come straight from the template body: the literal run
    immediately *before* the ``${param}`` (back to the previous hole or clause
    start — carries the field token + operator + any opening quote) and the
    literal run immediately *after* it (forward to the next hole — carries the
    closing quote / bracket / ``TO`` separator). The capture is bounded by
    those two literals, so it never needs to understand the query language. The
    left anchor is kept short (a trailing window) so a query the model rendered
    with a slightly different *earlier* clause still aligns on the local token.
    """
    token = "${" + param + "}"
    idx = body.find(token)
    if idx < 0:
        return None
    left_lit = _TOKEN_RE.split(body[:idx])[-1][-40:]
    # Anchor on the *local* clause only: drop everything up to the last boolean
    # join so a divergently-rendered EARLIER clause (e.g. the model wrote
    # `evt.type` where the template has `output_fields.evt.type`) doesn't break
    # alignment on this token. Splitting here, not on brackets/quotes, keeps the
    # field's own `[`/`"` as part of the anchor.
    local = re.split(r"\s+(?i:AND|OR)\s+", left_lit)[-1]
    if local.strip():
        left_lit = local
    right_lit = _TOKEN_RE.split(body[idx + len(token):])[0]
    if not left_lit.strip():
        return None  # no field anchor -> too ambiguous to recover safely

    left = _ws_flexible(left_lit)
    # Pick the tightest right delimiter the template offers.
    if left_lit.rstrip().endswith('"'):
        # Quoted value: capture up to the closing quote.
        return re.compile(left + r'([^"]*)"')
    stripped = right_lit.lstrip()
    if stripped[:1] in '"]),':
        delim = re.escape(stripped[0])
    elif stripped:
        delim = _ws_flexible(stripped.split()[0])
    else:
        return None
    return re.compile(left + r"(.+?)\s*" + delim)


def _recover_value(body: str, param: str, params: dict) -> str | None:
    """Bound value of ``${param}``: prefer a same-named executed-query param
    (window flags arrive as ``--start``/``--end``), else lift it from the
    rendered query string via the template-derived extractor.

    Returns ``None`` when recovery is *unsafe*: no match, an empty capture, or
    an **ambiguous** one (the extractor matches more than one distinct value
    across the params, e.g. two IPs in an ``OR`` clause). Guessing one of them
    would silently mis-target the predicate, so we abstain and let
    ``recover_filters`` route the query as unrouted instead.
    """
    direct = params.get(param)
    if isinstance(direct, str) and direct.strip():
        return direct
    extractor = _build_extractor(body, param)
    if extractor is None:
        return None
    found: set[str] = set()
    for value in params.values():
        if isinstance(value, str):
            for captured in extractor.findall(value):
                cleaned = captured.strip()
                if cleaned:
                    found.add(cleaned)
    return next(iter(found)) if len(found) == 1 else None


def _build_predicate(pred: dict, body: str, params: dict) -> dict | None:
    """Turn a declared predicate into a value-bound one for the router.

    Constant predicates (``value`` / ``values`` in the declaration) pass
    through. A ``param`` predicate recovers its value; returns ``None`` if
    recovery fails — the caller treats that as "this declared locator can't be
    faithfully applied" and marks the whole query unrouted, rather than dropping
    the predicate (which would widen the filter into false coverage).
    """
    out: dict = {"op": pred.get("op", "eq")}
    if "event_attr" in pred:
        out["event_attr"] = pred["event_attr"]
    if "values" in pred:
        out["values"] = pred["values"]
    elif "value" in pred:
        out["value"] = pred["value"]
    elif "param" in pred:
        value = _recover_value(body, pred["param"], params)
        if value is None:
            return None
        out["value"] = value
    return out


def recover_filters(query_id: str, params: dict) -> dict | None:
    """Structured locator filters for one executed query, or ``None``.

    Shape::

        {"index": "logs-falco.alerts-*",
         "window": {"start": "...", "end": "..."},
         "predicates": [{"event_attr": "container_id", "op": "eq", "value": "ffbff…"}]}

    ``None`` when the query has no declared contract (router → ``unrouted``),
    **or** when the template declares a locator (a time ``window`` or a
    ``param`` predicate) whose bound value can't be recovered. A
    half-recovered filter is worse than none: dropping a declared predicate or
    window widens the lead so the router over-claims coverage and hides a real
    gap. So a declared-but-unbindable locator routes the query as unrouted (the
    judge then assesses it from the raw query) rather than silently widening it.
    """
    contract = load_contract(query_id)
    if contract is None:
        return None
    filter_keys, body = contract

    out: dict = {}
    if filter_keys.get("index"):
        out["index"] = filter_keys["index"]

    window = filter_keys.get("window")
    if isinstance(window, dict):
        start = _recover_value(body, window.get("start", ""), params)
        end = _recover_value(body, window.get("end", ""), params)
        if not (start and end):
            return None  # declared window we couldn't bind -> don't route blind
        out["window"] = {"start": start, "end": end}

    predicates = []
    for pred in filter_keys.get("predicates") or []:
        if not isinstance(pred, dict):
            continue
        built = _build_predicate(pred, body, params)
        if built is None:
            return None  # declared predicate we couldn't bind -> unroute, don't widen
        predicates.append(built)
    if predicates:
        out["predicates"] = predicates

    return out or None
