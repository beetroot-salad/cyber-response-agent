"""#1138 — an oversized result from a verb whose query language aggregates points back at the
query, not at `defender-sql`.

In the step-zero runs of `experiments/sql-time-contract`, 52 of 107 `defender-sql` calls ran over
a saved ES|QL payload, and each did something ES|QL does itself (filter, re-group, sum, min/max).
The model's stated reason was size. The footer under an elided ES|QL payload was what
handed it `cat <path> | defender-sql 'DESCRIBE data'`. The verb declares whether its language
aggregates (`@verb(aggregates=True)`), so the view stays vendor-neutral: it never names an engine
and never reads a payload's key names to decide.
"""
from __future__ import annotations

import json

from defender.runtime.verbs import aggregates_of
from defender.scripts.adapters import elastic_adapter
from defender.scripts.adapters.elastic_adapter import esql_payload
from defender.scripts.gather_tools import payload_view as pv

RUN = "gather_raw/l-001/0.json"


def _oversized_esql() -> str:
    payload = esql_payload("FROM logs-* | STATS c = COUNT(*) BY host", {
        "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
        "values": [[f"host-{i:04d}", i] for i in range(1000)],
    })
    return json.dumps(payload)


def test_an_aggregating_verbs_oversized_result_is_sent_back_to_its_query(tmp_path):
    text = _oversized_esql()
    view = pv.render(text, RUN, tmp_path, ceiling=8192, aggregating=True)

    assert pv.ELISION_PREFIX in view, "the fixture stopped exceeding the ceiling"
    assert "defender-sql" not in view, "the view still hands an aggregating result to SQL"
    assert "compute them over the file" not in view, \
        "the prose still tells the lead to compute over the file"
    assert "re-run the query" in view, "nothing tells the lead to narrow the query instead"
    assert str(tmp_path / RUN) in view, "the file on disk is no longer named"


def test_the_same_payload_from_a_verb_that_does_not_aggregate_keeps_the_sql_route(tmp_path):
    """The control: the decision is the verb's declaration, not the payload's shape."""
    view = pv.render(_oversized_esql(), RUN, tmp_path, ceiling=8192)

    assert "defender-sql" in view
    assert "re-run the query" not in view


def test_only_the_esql_verb_declares_that_it_aggregates():
    declared = {name for name, fn in elastic_adapter.VERBS.items() if aggregates_of(fn)}
    assert declared == {"esql"}
