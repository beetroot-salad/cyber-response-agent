"""#869 M3/O2 at the SINK — what a real granted call actually records.

One demand of `spec-flow/specs/spec_graph_869.yaml`
(`queries_row_records_dispatched_system`), driven end to end because the demand is about the
row the writer PERSISTS, not about the screen's return value: `test_869_query_id.py` pins
`resolve_query_id` at the seam, and a screen that returned the right string while the writer
recorded a different one would satisfy that and leave the table wrong.

Everything between the two replay models is production code — the dispatch, the grant, the
query tool, the capture path, the two tables. The injected registry is a fault-free fake whose
verb records what it was handed; it classifies nothing, so every exit code, error class and
recorded value in the assertions below is the writer's own work.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.e2e.test_pitfalls_input_823 import _dispatch, _run  # noqa: E402
from defender.tests.e2e._replay_harness import Turn, VerbRecorder  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, elastic_ok, q  # noqa: E402

pytestmark = pytest.mark.e2e

PARAMS = {"native_query": "FROM logs"}


def test_granted_call_records_its_own_system(tmp_path):
    """A granted, successful query dispatched to `elastic` and tagged
    `query_id='fakesys.hunt-creds'` writes a row whose `query_id` names the system the call
    was DISPATCHED to, never the one the model coined.

    O2 at the sink: `defender/CLAUDE.md` already states the schema — `query_id` is
    `{system}.{kebab-name}` — and nothing enforces it, so a granted call to `elastic` tagged
    with a phantom records the phantom verbatim, and the table is append-only and read by
    later ticks, which is M4's whole reason to exist. The row is checked against the DISPATCH
    ARGUMENTS rather than against the table it is drawn from, so the assertion cannot recover
    its own expectation from the thing it is judging.

    The positive control is in the same drive and on the same address: a second call tagged
    with its OWN system keeps its coined id, so the rule refuses a disagreeing prefix rather
    than model-supplied ids as a class, and it establishes that this run's rows can differ
    from `{system}.{verb}` at all.
    """
    rec = VerbRecorder()
    res = _run(
        tmp_path,
        turns=[
            q("elastic", "query", PARAMS, query_id="fakesys.hunt-creds"),
            q("elastic", "query", PARAMS, query_id="elastic.hunt-creds"),
            DONE,
        ],
        run_id="qid-869",
        verbs=elastic_ok(rec),
        main_turns=[
            Turn(tool_calls=[_dispatch()]), Turn(text="Investigation complete."),
        ],
    )

    dispatched = _dispatch()[1]["system"]
    granted = [r for r in res.own_rows if r["exit_code"] == 0]
    assert len(rec.calls) == 2, "the verb was not reached, so no call was granted and executed"
    assert len(granted) == 2

    refused, kept = granted
    assert refused["system"] == dispatched
    assert refused["query_id"] == f"{dispatched}.{refused['verb']}"
    assert "fakesys" not in refused["query_id"]

    assert kept["query_id"] == "elastic.hunt-creds"

    # And nothing else this run wrote disagrees with its own dispatched system either.
    for row in res.own_rows:
        if row["query_id"].startswith("∅."):
            continue          # a writer-only sentinel names no system by construction
        assert row["query_id"].split(".", 1)[0] == row["system"]
