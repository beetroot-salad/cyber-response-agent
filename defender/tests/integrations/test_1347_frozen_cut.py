"""#1347 O2/P5/D5/D12: every Elasticsearch read in a cut run is cut by event time and by arrival
time as one filter clause beside the caller's own query, never spliced into it."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.integrations import elastic_adapter  # noqa: E402
from defender._io import read_jsonl_rows  # noqa: E402
from defender.systems.verb_grant import VerbGrant  # noqa: E402
from defender.systems.verbs import ModuleVerbRegistry, ReadCut, VerbContext, read_roster  # noqa: E402
from defender.tests.learning.branch.test_947_clock import (  # noqa: E402
    DOCKER_LOG,
    _fixture_tenant,
    clause_keeps,
    fake_docker,
    range_bounds,
    range_filter,
    search_body,
)

pytestmark = pytest.mark.e2e

MOMENT = dt.datetime(2026, 10, 20, 8, 0, 0, tzinfo=dt.UTC)
AS_OF = MOMENT + dt.timedelta(hours=1)  # moment + grace (D11)
ARRIVED_BY = dt.datetime(2026, 10, 20, 9, 3, 17, tzinfo=dt.UTC)

#: Documents the cuts must sort: (name, @timestamp, event.ingested or None, kept by both cuts).
DOCS = [
    ("in-window", "2026-10-20T08:30:00Z", "2026-10-20T08:30:05Z", True),
    ("late-arrival", "2026-10-20T08:30:00Z", "2026-10-20T09:10:00Z", False),
    ("after-grace", "2026-10-20T09:01:00Z", "2026-10-20T09:01:30Z", False),
    ("alert-no-ingested", "2026-10-20T08:00:00Z", None, True),
    ("on-both-cuts", "2026-10-20T09:00:00Z", "2026-10-20T09:03:17Z", True),
    ("undated", None, None, True),
]


def _doc(ts: str | None, ingested: str | None) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    if ts is not None:
        doc["@timestamp"] = ts
    if ingested is not None:
        doc["event.ingested"] = ingested
    return doc


def _kept(clause: dict) -> dict[str, bool]:
    return {name: clause_keeps(clause, _doc(ts, ing)) for name, ts, ing, _ in DOCS}


EXPECTED_KEPT = {name: kept for name, _, _, kept in DOCS}
#: The same documents under the event-time cut alone: arrival is not asked.
EXPECTED_EVENT_TIME_ONLY = {**EXPECTED_KEPT, "late-arrival": True}


def _ms(moment: dt.datetime) -> str:
    return moment.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def cut_ctx(tmp_path: Path, *, as_of: dt.datetime | None = AS_OF,
            arrived_by: dt.datetime | None = ARRIVED_BY,
            canned: Any = None) -> VerbContext:
    """A call context carrying the cuts; `canned` is the response body the cluster gives back."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    env = {"PATH": str(fake_docker(tmp_path)), "DOCKER_CALL_LOG": str(tmp_path / DOCKER_LOG)}
    if canned is not None:
        reply = tmp_path / "canned.json"
        reply.write_text(json.dumps(canned), encoding="utf-8")
        env["DOCKER_CANNED"] = str(reply)
    return VerbContext(defender_dir=tmp_path / "defender", run_dir=run_dir,
                       tenant=_fixture_tenant(tmp_path), env=env,
                       as_of=as_of, arrived_by=arrived_by)


def _ranges(clause: Any) -> dict[str, list[str]]:
    """Every gte/gt/lte/lt bound the clause spells, by field: pins the spelling, not the nesting;
    keys like `format` / `time_zone` are the builder's and are not bounds."""
    return range_bounds(clause)


def test_the_clause_oracles_ignore_range_keys_that_are_not_bounds():
    """FR13 self-check: a clause carrying `format` / `time_zone` reads the same as one without."""
    bare = {"range": {"@timestamp": {"lte": "2026-10-20T09:00:00.000Z"}}}
    decorated = {"range": {"@timestamp": {"lte": "2026-10-20T09:00:00.000Z",
                                          "format": "strict_date_optional_time",
                                          "time_zone": "+00:00"}}}

    assert _ranges(decorated) == _ranges(bare) == {"@timestamp": ["2026-10-20T09:00:00.000Z"]}
    assert clause_keeps(decorated, {"@timestamp": "2026-10-20T08:59:59Z"})
    assert not clause_keeps(decorated, {"@timestamp": "2026-10-20T09:00:01Z"})


# the public pure builder (D12): (as_of, arrived_by) -> clause

def test_the_cut_clause_keeps_what_both_cuts_allow_and_drops_the_rest():
    """D12/O2: event time at as_of, arrival at arrived_by; a field-absent document passes each."""
    clause = elastic_adapter.cut_clause(AS_OF, ARRIVED_BY)

    assert _kept(clause) == EXPECTED_KEPT


def test_the_cut_clause_without_an_arrival_cut_asks_event_time_only():
    """D5/O2: branched runs (as_of alone) get the event-time half and nothing about arrival."""
    clause = elastic_adapter.cut_clause(AS_OF, None)

    assert _kept(clause) == EXPECTED_EVENT_TIME_ONLY
    assert "event.ingested" not in _ranges(clause)


def test_both_cuts_are_inclusive_to_the_millisecond():
    """D12 (ms precision): the document AT a cut passes, one millisecond later does not."""
    as_of = dt.datetime(2026, 10, 20, 9, 0, 0, 250000, tzinfo=dt.UTC)
    arrived_by = dt.datetime(2026, 10, 20, 9, 3, 17, 750000, tzinfo=dt.UTC)
    clause = elastic_adapter.cut_clause(as_of, arrived_by)

    def kept(ts: str, ingested: str) -> bool:
        return clause_keeps(clause, {"@timestamp": ts, "event.ingested": ingested})

    assert kept("2026-10-20T09:00:00.250Z", "2026-10-20T09:03:17.750Z")
    assert kept("2026-10-20T09:00:00.249Z", "2026-10-20T09:03:17.749Z")
    assert not kept("2026-10-20T09:00:00.251Z", "2026-10-20T09:00:00.000Z"), (
        "event time one millisecond past as_of was served: the cut lost sub-second precision")
    assert not kept("2026-10-20T09:00:00.000Z", "2026-10-20T09:03:17.751Z"), (
        "arrival one millisecond past arrived_by was served: the cut lost sub-second precision")


def test_a_cut_finer_than_a_millisecond_is_never_rounded_up_past_the_instant():
    """D12 (ms precision): a sub-millisecond cut truncates, so no document dated after the
    instant is served; the next millisecond up is outside both cuts."""
    as_of = dt.datetime(2026, 10, 20, 9, 0, 0, 250900, tzinfo=dt.UTC)
    arrived_by = dt.datetime(2026, 10, 20, 9, 3, 17, 750900, tzinfo=dt.UTC)
    clause = elastic_adapter.cut_clause(as_of, arrived_by)

    def kept(ts: str, ingested: str) -> bool:
        return clause_keeps(clause, {"@timestamp": ts, "event.ingested": ingested})

    assert kept("2026-10-20T09:00:00.250Z", "2026-10-20T09:03:17.750Z")
    assert not kept("2026-10-20T09:00:00.251Z", "2026-10-20T09:03:17.000Z"), (
        "event time after as_of was served: the cut was rounded up to the next millisecond")
    assert not kept("2026-10-20T09:00:00.000Z", "2026-10-20T09:03:17.751Z"), (
        "arrival after arrived_by was served: the cut was rounded up to the next millisecond")


def test_the_cut_clause_is_the_same_instant_whatever_offset_the_caller_spells_it_in():
    """D12 (UTC): an aware datetime in another zone cuts at the same instant."""
    east = dt.timezone(dt.timedelta(hours=2))
    clause = elastic_adapter.cut_clause(AS_OF.astimezone(east), ARRIVED_BY.astimezone(east))

    assert _kept(clause) == EXPECTED_KEPT
    assert clause == elastic_adapter.cut_clause(AS_OF, ARRIVED_BY)


def test_the_cut_clause_spells_each_bound_in_milliseconds_and_utc_z():
    """D12 agent decision: `YYYY-MM-DDTHH:MM:SS.mmmZ` on `@timestamp` and `event.ingested`."""
    assert _ranges(elastic_adapter.cut_clause(AS_OF, ARRIVED_BY)) == {
        "@timestamp": [_ms(AS_OF)], "event.ingested": [_ms(ARRIVED_BY)]}
    assert _ms(AS_OF) == "2026-10-20T09:00:00.000Z"
    assert _ms(ARRIVED_BY) == "2026-10-20T09:03:17.000Z"


# the reads: search post_filter and ES|QL filter are that same clause (P5)

@pytest.mark.parametrize("verb", ["query", "alerts"])
def test_a_cut_search_carries_both_cuts_and_keeps_the_callers_window(tmp_path, verb):
    """O2: `post_filter` is the cut clause; the caller's own window stays in `query` as written."""
    ctx = cut_ctx(tmp_path)

    getattr(elastic_adapter, verb)(ctx, native_query="event.action:ssh_login",
                                   start="2026-10-01T00:00:00Z", end="2026-10-25T00:00:00Z")

    body = search_body(tmp_path)
    assert range_filter(body) == {"gte": "2026-10-01T00:00:00Z", "lte": "2026-10-25T00:00:00Z"}, (
        "the caller's window was rewritten")
    assert body["query"]["bool"]["must"] == [
        {"query_string": {"query": "event.action:ssh_login"}}]
    assert _kept(body["post_filter"]) == EXPECTED_KEPT
    assert body["post_filter"] == elastic_adapter.cut_clause(AS_OF, ARRIVED_BY), (
        "the read sends a clause other than the builder's (P5: one clause for every consumer)")


@pytest.mark.parametrize("asked", [
    pytest.param('FROM logs-system.auth-*\n'
                 '| WHERE @timestamp >= "2026-10-01T00:00:00Z"\n'
                 '| STATS n = COUNT(*) BY user.name', id="multi-line"),
    pytest.param("FROM logs-zeek.ssh-* | LIMIT 1", id="one-line"),
    pytest.param("FROM logs-x-* METADATA _id | LIMIT 5\n", id="suffix-and-trailing-newline"),
    pytest.param("  // look\nFROM logs-zeek.ssh-*", id="leading-comment"),
    pytest.param("TS logs-metrics-* | LIMIT 1", id="non-FROM-source"),
    pytest.param("ROW a = 1", id="no-source"),
])
def test_a_cut_esql_sends_the_query_as_written_with_the_cut_as_the_request_filter(
    tmp_path, asked,
):
    """O2/P4: the text reaching the cluster is byte-identical to the agent's; the same cut
    clause travels as the request body's `filter`."""
    ctx = cut_ctx(tmp_path)

    payload = elastic_adapter.esql(ctx, query=asked)
    esql_body = search_body(tmp_path)

    assert esql_body["query"] == asked, "the query text sent is not the text the agent wrote"
    assert payload["query"] == asked
    assert _kept(esql_body["filter"]) == EXPECTED_KEPT
    assert esql_body["filter"] == elastic_adapter.cut_clause(AS_OF, ARRIVED_BY), (
        "ES|QL is cut through a different clause than search (P5)")


def test_esql_and_search_are_cut_through_one_clause_in_every_cut_combination(tmp_path):
    """P5: whichever cuts are set, the ES|QL `filter` equals the search `post_filter`."""
    for arrived_by in (ARRIVED_BY, None):
        ctx = cut_ctx(tmp_path, arrived_by=arrived_by)
        elastic_adapter.esql(ctx, query="FROM logs-zeek.ssh-* | LIMIT 1")
        esql_cut = search_body(tmp_path)["filter"]
        elastic_adapter.query(ctx, native_query="event.action:ssh_login")
        search_cut = search_body(tmp_path)["post_filter"]

        assert esql_cut == search_cut == elastic_adapter.cut_clause(AS_OF, arrived_by)


def test_a_branched_run_with_only_as_of_cuts_by_event_time_through_the_request_filter(tmp_path):
    """O2/D5: as_of alone uses the same request filter with the event-time half only; no splice."""
    ctx = cut_ctx(tmp_path, arrived_by=None)
    asked = "FROM logs-zeek.ssh-* | LIMIT 1"

    elastic_adapter.esql(ctx, query=asked)
    body = search_body(tmp_path)

    assert body["query"] == asked
    assert _kept(body["filter"]) == EXPECTED_EVENT_TIME_ONLY


def test_an_ordinary_run_sends_no_cut_at_all(tmp_path):
    """O2 control: no cut set, no `filter` / `post_filter` key and the query text untouched."""
    ctx = cut_ctx(tmp_path, as_of=None, arrived_by=None)
    asked = "FROM logs-zeek.ssh-* | LIMIT 1"

    elastic_adapter.esql(ctx, query=asked)
    esql_body = search_body(tmp_path)
    elastic_adapter.query(ctx, native_query="event.action:ssh_login")
    searched = search_body(tmp_path)

    assert esql_body["query"] == asked
    assert "filter" not in esql_body
    assert "post_filter" not in searched
    assert range_filter(searched) is None


# the row backstop keeps the event-time cut

def test_the_row_backstop_still_drops_search_hits_dated_after_as_of(tmp_path):
    """O2: a hit the cluster let through past as_of is dropped client-side; in-window ones stay."""
    hits = [{"_source": {"@timestamp": "2026-10-20T08:59:59Z", "event.ingested": "2026-10-20T09:00:01Z",
                         "n": "kept"}},
            {"_source": {"@timestamp": "2026-10-20T09:00:00Z", "n": "at-as-of"}},
            {"_source": {"@timestamp": "2026-10-20T09:00:01Z", "n": "past"}},
            {"_source": {"n": "undated"}}]
    ctx = cut_ctx(tmp_path, canned={"hits": {"total": {"value": 4}, "hits": hits}})

    out = elastic_adapter.query(ctx, native_query="*")

    assert [h["n"] for h in out["hits"]] == ["kept", "at-as-of", "undated"], (
        "the backstop is inclusive: a hit dated exactly as_of is served")
    assert out["total"] == 3


def test_the_row_backstop_still_drops_esql_rows_dated_after_as_of(tmp_path):
    """O2: ES|QL rows past as_of are dropped from the payload; the rest are served as returned."""
    canned = {"columns": [{"name": "@timestamp", "type": "date"}, {"name": "n", "type": "keyword"}],
              "values": [["2026-10-20T08:59:59.000Z", "kept"],
                         ["2026-10-20T09:00:00.000Z", "at-as-of"],
                         ["2026-10-20T09:00:01.000Z", "past"],
                         [None, "undated"]]}
    ctx = cut_ctx(tmp_path, canned=canned)

    payload = elastic_adapter.esql(ctx, query="FROM logs-zeek.ssh-*")

    assert [row[1] for row in payload["values"]] == ["kept", "at-as-of", "undated"], (
        "the backstop is inclusive: a row dated exactly as_of is served")
    assert payload["row_count"] == 3


# the base registry sets the cut on every system's calls

_RECORDING_ADAPTER = '''\
"""Verb bodies that record the cut their ctx carried."""
from __future__ import annotations

import json
from pathlib import Path

from defender.kit.verbs import VerbContext, verb


def _record(ctx: VerbContext, name: str) -> dict:
    row = {"verb": name,
           "as_of": None if ctx.as_of is None else ctx.as_of.isoformat(),
           "arrived_by": None if ctx.arrived_by is None else ctx.arrived_by.isoformat()}
    with (Path(ctx.run_dir) / "seen.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\\n")
    return {"ok": True}


@verb()
def get_host(ctx: VerbContext, *, host: str) -> dict:
    return _record(ctx, "get-host")


@verb()
def health_check(ctx: VerbContext) -> dict:
    return _record(ctx, "health-check")


VERBS = {"get-host": get_host, "health-check": health_check}
'''


def _registry(tmp_path: Path, cut: ReadCut | None) -> ModuleVerbRegistry:
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for system in ("cmdb", "elastic"):
        (adapters / f"{system}_adapter.py").write_text(_RECORDING_ADAPTER, encoding="utf-8")
    grant = VerbGrant(role="gather", entries=(("cmdb", "get-host", "r"), ("elastic", "health-check", "r")))
    return ModuleVerbRegistry(read_roster(adapters), grant, cut=cut)


@pytest.mark.parametrize(("system", "verb", "params"), [
    pytest.param("cmdb", "get-host", {"host": "web-1"}, id="a-system-of-record"),
    pytest.param("elastic", "health-check", {}, id="elastic"),
])
@pytest.mark.parametrize("cut", [ReadCut(AS_OF, ARRIVED_BY), ReadCut(AS_OF)],
                         ids=["as-of-and-arrived-by", "as-of-alone"])
def test_every_system_body_is_handed_the_runs_cut_on_a_context_that_carried_none(
    tmp_path, system, verb, params, cut,
):
    """Product-side cut: the base registry sets as_of and arrived_by on the ctx of every call,
    whichever system it addresses, so no verb body reads uncut."""
    ctx = cut_ctx(tmp_path, as_of=None, arrived_by=None)

    _registry(tmp_path, cut).verbs(system)[verb](ctx, **params)

    assert read_jsonl_rows(ctx.run_dir / "seen.jsonl") == [
        {"verb": verb, "as_of": cut.as_of.isoformat(),
         "arrived_by": None if cut.arrived_by is None else cut.arrived_by.isoformat()}]


def test_a_registry_with_no_cut_hands_every_body_the_context_as_built(tmp_path):
    """Product-side cut control: an ordinary run's calls reach the body with no cut on them."""
    ctx = cut_ctx(tmp_path, as_of=None, arrived_by=None)

    _registry(tmp_path, None).verbs("cmdb")["get-host"](ctx, host="web-1")

    assert read_jsonl_rows(ctx.run_dir / "seen.jsonl") == [
        {"verb": "get-host", "as_of": None, "arrived_by": None}]
