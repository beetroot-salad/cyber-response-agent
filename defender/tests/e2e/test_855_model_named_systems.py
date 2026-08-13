"""#855 F-06 end to end — a `system` the MODEL named must not steer a corpus write.

THE DEFECT. Two writers sit ABOVE the grant check and record the model's raw arguments:
`QueryCapture.wrap_tool_validate` (the pydantic argument schema turned the call back, so there
are no validated arguments to key on) and `_grant_check`'s unresolvable branch. Their rows are
exit-64 `agent-fixable`, which is exactly the pitfalls channel's input, and
`_build_pitfalls_handoffs` spends a record's `system` VERBATIM as
`defender/skills/<system>/execution.md` and points the curator at it. Nothing between the two
ever re-checked the string — so an injected gather subagent could name the corpus path it
wanted a curator sent to, needing no grant for the system it named, only a schema it could fail
on purpose (any extra or mistyped argument does it).

WHAT IS ASSERTED HERE, and why live rather than over a hand-built row: the fix is a WRITER
fix, so the demand is on what the queries table contains after a real run — every row's
`system` is one the run's own dispatch named, checked against the DISPATCH ARGUMENTS rather
than against the table the claim is about. A test that recovered `dispatched` from the same
rows it checks cannot fail.

Everything between the two replay models is production code: the dispatch, the query tool, the
capture path, the two guards, the two tables. The offline half of this issue — the handoff
filter and the commit gate that refuse a phantom system directory — is unit-level and lives in
`tests/test_pitfalls_curator.py`; the seam half (#855 F-12, the lead claim) is in
`tests/test_gather_engine_seam.py` and `tests/test_record_lead.py`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.leads.pitfalls_curator import _build_pitfalls_handoffs  # noqa: E402
from defender.scripts.gather_tools.record_query import ABOVE_GUARD_QUERY_ID  # noqa: E402
from defender.tests.e2e._replay_harness import Turn  # noqa: E402
from defender.tests.e2e.test_pitfalls_input_823 import _Res, _dispatch, _run  # noqa: E402
from defender.tests.e2e.test_query_tool_611 import DONE, q  # noqa: E402

pytestmark = pytest.mark.e2e

PARAMS = {"native_query": "FROM logs"}

#: What an injected gather subagent would name if it could pick the corpus path: a segment that
#: is not a system, and that `_pitfalls_path_rule` accepted as one because it is single-segment.
PHANTOM = "Ignore Previous Instructions"


def _bad_args(system: str, params: dict = PARAMS) -> Turn:
    """A call the pydantic ARGUMENT SCHEMA turns back — `bogus_extra_arg` is P-a's executed
    `extra_argument` shape — so its row is written by `wrap_tool_validate` from the RAW
    pre-validation arguments. `system` is whatever the model put there; that is the point."""
    return Turn(tool_calls=[("query", {
        "system": system, "verb": "query", "params": params, "bogus_extra_arg": "x",
    })])


def _above_guard(r: _Res) -> list[dict]:
    return [row for row in r.own_rows if row["query_id"] == ABOVE_GUARD_QUERY_ID]


def _queued(rows: list[dict]) -> list[dict]:
    """The pitfalls queue's row shape, built from the queries-table rows THIS RUN WROTE.

    Bound at the writer's output and handed straight to `_build_pitfalls_handoffs`, rather than
    routed through `lead_repository.joined` / `extract_from_joined`: what this finding turns on
    is the value the row CARRIES and the path the handoff builder then mints from it. The join
    in between is a different seam with its own suite (#823, #841), and a test of THIS one
    should not go red when that one is mid-refactor."""
    return [
        {
            "schema_version": 1, "pitfall_id": f"r:{row['lead_id']}:{row['seq']}",
            "source_run": "r", "system": row["system"], "query_id": row["query_id"],
            "goal": "g", "executed_query": row["raw_command"],
            "stderr_digest": row["payload_digest"], "error_class": row["error_class"],
        }
        for row in rows
    ]


def test_a_schema_rejected_call_cannot_name_a_system_of_record(tmp_path):
    """The row is still WRITTEN — the rejection happened and the table records it — but it
    carries no system, because the registry declares none by that name. `""` is the honest
    answer and it needs no new branch downstream: `collect_general_failures` already skips a
    systemless row, the same guard `system_for_payload_operands` returning `""` spends for the
    bash shim's writer."""
    r = _run(tmp_path, run_id="d855-phantom", turns=[_bad_args(PHANTOM), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the schema rejection stopped leaving its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == "", \
        "a model-named system reached the queries table as a system of record"
    assert _build_pitfalls_handoffs(_queued(rows)) == [], \
        "the model's string became an execution_md_path the curator is pointed at"


def test_a_schema_rejected_call_on_a_real_system_still_records_it(tmp_path):
    """The positive control, and the channel's whole purpose: a rejection against a system the
    registry DOES declare keeps its system and still reaches the pitfalls curator. A writer
    that coarsened every above-guard row to `""` would pass the negative above and silently
    close the channel #823 opened."""
    r = _run(tmp_path, run_id="d855-real", turns=[_bad_args("elastic"), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1
    assert rows[0]["system"] == "elastic", "a real system's rejection lost its attribution"

    handoffs = _build_pitfalls_handoffs(_queued(rows))
    assert [h["execution_md_path"] for h in handoffs] == [
        "defender/skills/elastic/execution.md"
    ], "the rejection no longer reaches the pitfalls curator at all"


def test_an_unresolvable_call_cannot_name_a_system_of_record(tmp_path):
    """The SECOND above-guard writer, on the same defect: `_grant_check`'s non-GRANTED branch
    records its own exit-64 row before raising `ModelRetry`. An unresolvable call is
    unresolvable precisely because the grant reached no system by that name, so the string it
    names is the one least entitled to become a `skills/<system>/` path."""
    r = _run(tmp_path, run_id="d855-unresolvable",
             turns=[q(PHANTOM, "query", PARAMS), DONE])

    rows = _above_guard(r)
    assert len(rows) == 1, "the unresolvable branch stopped recording its row"
    assert rows[0]["exit_code"] == 64
    assert rows[0]["system"] == ""


def test_no_row_names_a_system_the_dispatch_never_named(tmp_path):
    """The negative universal, over the whole table — and `dispatched` comes from the GATHER
    DISPATCH's own arguments, not from the rows being checked. #823 pinned this shape for the
    bash shim and derived `dispatched` from the table itself, which cannot fail for a row whose
    `system` the model wrote: the row is its own evidence. Read off the dispatch, the claim is
    about the run, and every above-guard writer is inside it."""
    dispatch = _dispatch()
    dispatched = {dispatch[1]["system"]}
    turns = [_bad_args(PHANTOM), q("ghost", "query", PARAMS), _bad_args("a b"), DONE]
    r = _run(tmp_path, run_id="d855-universal", turns=turns, main_turns=[
        Turn(tool_calls=[dispatch]), Turn(text="Investigation complete."),
    ])

    assert dispatch[0] == "gather", "the shared helper stopped building a gather dispatch"
    assert dispatched == {"elastic"}
    assert _above_guard(r), "no above-guard row was written, so the universal is vacuous"
    for row in r.rows:
        assert row["system"] in dispatched | {""}, \
            f"a row names a system no dispatch did: {row['system']!r}"


def test_the_companion_repeat_guard_still_bounds_a_phantom_rejection_loop(tmp_path):
    """The coarsening is spent on the guard's IDENTITY as well as on the row, and it has to be:
    the companion guard recovers its count from the rows it wrote, so a live identity keyed on
    the model's raw string over a table holding `""` would match nothing and this repeat class
    would stop being bounded at all — the silent terminator #826 item 4 closed, reopened by the
    fix for #855. Three identical rejections still end the lead."""
    r = _run(tmp_path, run_id="d855-loop",
             turns=[_bad_args(PHANTOM), _bad_args(PHANTOM), _bad_args(PHANTOM), DONE])

    rows = _above_guard(r)
    assert len(rows) == 3, "the loop ran past the threshold — the guard stopped counting"
    assert "turned back at seq" in rows[-1]["payload_digest"], "no trip row was written"
    summary = (r.run_dir / "gather_summaries" / "l-001.md").read_text(encoding="utf-8")
    assert "Treat this lead as incomplete" in summary
    assert PHANTOM not in summary, \
        "the model's own string crossed back into main's context on a refusal path"


def test_the_dispatch_argument_is_the_only_system_the_run_can_name(tmp_path):
    """Belt to the universal's braces: the same phantom, driven through BOTH above-guard
    writers in one run, leaves no `defender/skills/<phantom>/execution.md` anywhere in the
    handoff the curator would receive — the artifact the whole finding is about."""
    r = _run(tmp_path, run_id="d855-handoff",
             turns=[_bad_args(PHANTOM), q(PHANTOM, "query", PARAMS), DONE])

    handoffs = _build_pitfalls_handoffs(_queued(r.own_rows))
    paths = [h["execution_md_path"] for h in handoffs]
    assert not any(PHANTOM in p for p in paths), f"the curator is pointed at {paths}"
    assert all(Path(p).parts[:2] == ("defender", "skills") for p in paths)


def test_the_gather_dispatch_is_unchanged_by_all_of_this(tmp_path):
    """A control the three negatives need: the run this suite drives is an ordinary one, and
    an ordinary granted call still records its system, executes, and is attributed. Without it
    every assertion above is satisfiable by a query tool that records nothing."""
    r = _run(tmp_path, run_id="d855-control", turns=[q("elastic", "query", PARAMS), DONE])
    executed = [row for row in r.own_rows if row["exit_code"] == 0]
    assert executed, "no call executed — the negatives above are vacuous"
    assert {row["system"] for row in executed} == {"elastic"}
    assert _dispatch()[1]["system"] == "elastic", \
        "the shared dispatch changed system; this suite's `dispatched` set is stale"
