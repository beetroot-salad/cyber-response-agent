"""#1138 — through a real gather run: the query tool reads the granted verb's `aggregates`
declaration and hands it to the payload view, so an oversized result from an aggregating verb
points back at its query while the same payload from a plain verb keeps the `defender-sql` route.
"""
from __future__ import annotations

import re

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime.verbs import VerbContext, verb  # noqa: E402
from defender.scripts.adapters.elastic_adapter import esql_payload  # noqa: E402
from defender.tests.e2e._replay_harness import FakeVerbs  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q, run_gather  # noqa: E402

pytestmark = pytest.mark.e2e

PAYLOAD = esql_payload("FROM logs-* | STATS c = COUNT(*) BY host", {
    "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
    "values": [[f"host-{i:04d}", i] for i in range(1000)],
})


def _last_result(seen: str) -> str:
    """The last framed tool result in gather's history — the rendered view and its footer —
    so the assertions cannot be satisfied or broken by skill text elsewhere in the prompt."""
    frames = re.findall(r"<run-[0-9a-f]+-untrusted>(.*?)</run-[0-9a-f]+-untrusted>", seen, re.S)
    assert frames, "no framed tool result reached gather"
    return frames[-1]


def _registry() -> FakeVerbs:
    @verb(engine="esql", body_param="query", aggregates=True)
    def esql(ctx: VerbContext, *, query: str) -> dict:  # noqa: A002
        return PAYLOAD

    def plain(ctx: VerbContext, *, native_query: str) -> dict:
        return PAYLOAD

    return FakeVerbs({"elastic": {"esql": esql, "plain": plain}})


def test_an_aggregating_verbs_oversized_result_reaches_gather_pointing_at_its_query(tmp_path):
    r = run_gather(tmp_path, verbs=_registry(), turns=[
        q("elastic", "esql", {"query": "FROM logs-* | STATS c = COUNT(*) BY host"}), DONE,
    ])
    seen = _last_result(r.gather_saw)
    assert "<<ELIDED" in seen, "the fixture stopped exceeding the view ceiling"
    assert "re-run the query" in seen
    assert "defender-sql" not in seen


def test_the_same_payload_from_a_plain_verb_still_offers_sql(tmp_path):
    r = run_gather(tmp_path, verbs=_registry(), turns=[
        q("elastic", "plain", {"native_query": "host:*"}), DONE,
    ])
    seen = _last_result(r.gather_saw)
    assert "<<ELIDED" in seen, "the fixture stopped exceeding the view ceiling"
    assert "defender-sql" in seen
    assert "re-run the query" not in seen
