"""#1347 O2/P5: a frozen run's Elasticsearch reads are cut by event time AND arrival time, as one
filter clause beside the caller's own query, never spliced into it."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.integrations import elastic_adapter  # noqa: E402
from defender.systems.verbs import VerbContext  # noqa: E402
from defender.tests.learning.branch.test_947_clock import (  # noqa: E402
    DOCKER_LOG,
    _fixture_tenant,
    fake_docker,
    range_filter,
    search_body,
)

pytestmark = pytest.mark.e2e

MOMENT = dt.datetime(2026, 10, 20, 8, 0, 0, tzinfo=dt.UTC)
AS_OF = MOMENT + dt.timedelta(hours=1)  # moment + grace (D1)
CAPTURED_AT = dt.datetime(2026, 10, 20, 9, 3, 17, tzinfo=dt.UTC)


def _z(text: str) -> dt.datetime:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


#: Documents the frozen cut must sort: (name, @timestamp, event.ingested or None, kept?).
DOCS = [
    ("in-window", "2026-10-20T08:30:00Z", "2026-10-20T08:30:05Z", True),
    ("late-arrival", "2026-10-20T08:30:00Z", "2026-10-20T09:10:00Z", False),
    ("after-grace", "2026-10-20T09:01:00Z", "2026-10-20T09:01:30Z", False),
    ("alert-no-ingested", "2026-10-20T08:00:00Z", None, True),
    ("on-both-cuts", "2026-10-20T09:00:00Z", "2026-10-20T09:03:17Z", True),
]


def _doc(ts: str, ingested: str | None) -> dict[str, Any]:
    doc: dict[str, Any] = {"@timestamp": ts}
    if ingested is not None:
        doc["event.ingested"] = ingested
    return doc


def _matches(clause: dict, doc: dict[str, Any]) -> bool:
    """Elasticsearch's own reading of the few Query DSL forms a cut can use (bool, range, exists),
    over a flat doc. Test oracle for the clause's meaning, so its nesting is not pinned."""
    (kind, body), = clause.items()
    if kind == "exists":
        return body["field"] in doc
    if kind == "range":
        (field, bounds), = body.items()
        if field not in doc:
            return False
        value = _z(doc[field])
        ops = {"lte": value.__le__, "lt": value.__lt__, "gte": value.__ge__, "gt": value.__gt__}
        return all(ops[op](_z(bound)) for op, bound in bounds.items())
    if kind == "match_all":
        return True
    assert kind == "bool", f"a cut clause uses a form this oracle does not read: {kind}"

    def many(key: str) -> list[dict]:
        got = body.get(key, [])
        return got if isinstance(got, list) else [got]

    if not all(_matches(c, doc) for c in many("must") + many("filter")):
        return False
    if any(_matches(c, doc) for c in many("must_not")):
        return False
    should = many("should")
    floor = body.get("minimum_should_match", 0 if many("must") + many("filter") else 1)
    return not should or sum(_matches(c, doc) for c in should) >= int(floor)


def _kept(clause: dict) -> dict[str, bool]:
    return {name: _matches(clause, _doc(ts, ing)) for name, ts, ing, _ in DOCS}


EXPECTED_KEPT = {name: kept for name, _, _, kept in DOCS}


def frozen_ctx(tmp_path: Path) -> VerbContext:
    """A frozen run's call context: the event-time cut (`as_of`) and the arrival cut."""
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return VerbContext(
        defender_dir=tmp_path / "defender", run_dir=run_dir, tenant=_fixture_tenant(tmp_path),
        env={"PATH": str(fake_docker(tmp_path)), "DOCKER_CALL_LOG": str(tmp_path / DOCKER_LOG)},
        as_of=AS_OF, captured_at=CAPTURED_AT,
    )


def test_a_frozen_search_cuts_by_event_time_and_arrival_and_keeps_the_callers_window(tmp_path):
    """O2: the search `post_filter` cuts at moment+grace and at captured_at (field-absent passes);
    the caller's own window stays in `query` as written."""
    ctx = frozen_ctx(tmp_path)

    elastic_adapter.query(ctx, native_query="event.action:ssh_login",
                          start="2026-10-01T00:00:00Z", end="2026-10-25T00:00:00Z")

    body = search_body(tmp_path)
    assert range_filter(body) == {"gte": "2026-10-01T00:00:00Z", "lte": "2026-10-25T00:00:00Z"}, (
        "the caller's window was rewritten")
    assert body["query"]["bool"]["must"] == [
        {"query_string": {"query": "event.action:ssh_login"}}]
    assert _kept(body["post_filter"]) == EXPECTED_KEPT


def test_a_frozen_esql_sends_the_query_as_written_with_the_cut_as_the_request_filter(tmp_path):
    """O2/P4: the ES|QL text reaching the cluster is byte-identical to the agent's; the same cut
    travels as the request body's `filter` (P5: the search's `post_filter`, the same clause)."""
    ctx = frozen_ctx(tmp_path)
    asked = ('FROM logs-system.auth-*\n'
             '| WHERE @timestamp >= "2026-10-01T00:00:00Z"\n'
             '| STATS n = COUNT(*) BY user.name')

    payload = elastic_adapter.esql(ctx, query=asked)
    esql_body = search_body(tmp_path)
    elastic_adapter.query(ctx, native_query="event.action:ssh_login")
    searched = search_body(tmp_path)

    assert esql_body["query"] == asked, "the query text sent is not the text the agent wrote"
    assert payload["query"] == asked
    assert _kept(esql_body["filter"]) == EXPECTED_KEPT
    assert esql_body["filter"] == searched["post_filter"], (
        "ES|QL and search are served through different cut clauses (P5)")
