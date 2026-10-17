"""#870 M5′ — the lane opens on the sentinel id, and on nothing else."""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import collect_general_failures
from defender.runtime import tools
from defender.runtime.circuit_breaker import error_class_for_exit
from defender.runtime.query_tool import resolve_query_id
from defender.runtime.sql_engine import sql as defender_sql
from defender._query_rules import ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID
from defender.tests._declared870 import (
    BINDER,
    by_surface,
    shim_lead,
    shim_row,
)

RUN = Path("reviewer-measure-0807-b")
DECLARED = frozenset({"elastic", "cmdb"})


def _collect(*leads):
    """The real collector over an empty catalog — the seam M5′ edits, driven directly."""
    return collect_general_failures(list(leads), RUN, catalog=[])


# O3 / O3b — the row reaches the queue, normalized, whatever it was attributed to.


def test_shim_row_enqueues_with_its_system_normalized():
    """`collect_general_failures` over an agent-fixable `∅.bash-shim` ExecutedLead carrying
    `system='elastic'` emits ONE queue row whose `system` is `""` and whose `query_id` is the
    sentinel.

    The sentinel test is UNCONDITIONAL, so attribution succeeding does not change where the
    mistake belongs (F1): a `defender-sql` mistake is the reducer's, not elastic's, and the
    row that carries it says so in the one field every downstream reader keys on. The row is
    normalized WHERE IT IS COLLECTED (F2), so the queue on disk already carries the merge key
    the curation seams will group by.

    Against HEAD this row carries `system='elastic'` (C10, executed) — the population the
    doc's `system == ""` routing would have left mis-routed.
    """
    rows = _collect(shim_lead(system="elastic"))
    assert len(rows) == 1, "the sentinel row never reached the queue"
    assert rows[0]["system"] == "", "the attributed system survived onto the queued row"
    assert rows[0]["query_id"] == BASH_SHIM_QUERY_ID
    assert rows[0]["pitfall_id"] == f"{RUN.name}:l-003:0"
    assert rows[0]["stderr_digest"] == BINDER, "the adapter's own diagnosis is the lesson"


def test_an_unattributed_shim_row_reaches_the_queue():
    """The same lead with `system=''` ALSO emits a row — the sentinel test runs BEFORE the
    systemless guard at `lead_extraction.py:111`.

    That guard drops it today (C10, executed: `''` and `'  '` both yield zero rows), so no
    `∅.bash-shim` row from a reduce that opened no run payload has ever enqueued, and the
    failure that is hardest to attribute is the one the channel has never seen. Whitespace
    rides with the empty string: it is the same unattributed reduce wearing a different value.
    """
    for system in ("", "  ", "gather"):
        rows = _collect(shim_lead(system=system))
        assert len(rows) == 1, f"the systemless guard still swallowed system={system!r}"
        assert rows[0]["system"] == ""


def test_the_new_lane_admits_only_the_shim_sentinel():
    """A systemless `∅.above-repeat-guard` row and a systemless ordinary row still enqueue
    nothing, and neither reaches the reducer surface.

    M5′ opens ONE lane keyed on ONE sentinel: N1's dispatch-level rejections stay
    unattributable, and the mistake there is at least as likely to be evidence about us as
    about the agent.

    N1 IS DRIVEN HERE AS RESTATED, NOT AS WRITTEN (FK-8). G12 refuted its stated fact for the
    ATTRIBUTED half: a `∅.above-repeat-guard` row carrying a declared system already reaches
    the queue today, and every `∅.repeat-trip` row carries one by construction. So the
    attributed sentinels are driven ALONGSIDE as this negative's own positive evidence — they
    still enqueue, still carry their declared system, and still fold into THAT system's
    `execution.md`, unaffected by this round. What N1 now says is that they are not routed to
    the reducer surface; documenting the rest of their behaviour is filed as its own issue.

    REJECTED: admitting every sentinel row now that the systemless guard has an exception; and
    widening the round to route the attributed half of the other two sentinels through the
    reducer lane (declined at FK-8).
    """
    for query_id in (ABOVE_GUARD_QUERY_ID, REPEAT_TRIP_QUERY_ID, "elastic.esql"):
        assert _collect(shim_lead(system="", query_id=query_id)) == [], query_id

    attributed = _collect(
        shim_lead(system="elastic", query_id=ABOVE_GUARD_QUERY_ID, lead_id="l-011"),
        shim_lead(system="elastic", query_id=REPEAT_TRIP_QUERY_ID, lead_id="l-012"),
    )
    assert [r["system"] for r in attributed] == ["elastic", "elastic"], (
        "the attributed half of the other two sentinels stops enqueueing — G12 says it "
        "reaches the queue today and M5′ neither causes nor fixes that"
    )
    surfaces = by_surface(
        pitfalls_curator._build_pitfalls_handoffs(attributed, systems=DECLARED)
    )
    assert surfaces["reducer"] == [], "a non-shim sentinel was routed to the reducer surface"
    assert [e["system"] for e in surfaces["system"]] == ["elastic"]


def test_an_infra_shim_failure_never_reaches_the_queue():
    """A `∅.bash-shim` row from a reducer that exited `EXIT_NO_RUNTIME` carries
    `error_class='infra'` and enqueues nothing, while the same row at exit 2 (→64) and exit 1
    both enqueue.

    A broken deployment is not a lesson any corpus file should carry (N9, C20 executed:
    2 → 64 → agent-fixable; 1 → 1 → agent-fixable; 69 → 2 → infra). The class is derived here
    through the REAL translation table rather than asserted, so the demand is about the
    pipeline and not about a string this test chose.
    """
    infra = error_class_for_exit(tools._shim_exit_code(defender_sql.EXIT_NO_RUNTIME))
    assert infra == "infra"
    assert _collect(shim_lead(error_class=infra)) == [], "an infra-classed reduce enqueued a row"

    for rc in (defender_sql.EXIT_INPUT_ERROR, 1):
        klass = error_class_for_exit(tools._shim_exit_code(rc))
        assert klass == "agent-fixable", rc
        assert len(_collect(shim_lead(error_class=klass))) == 1, rc


def test_no_model_supplied_query_id_reaches_the_reducer_surface():
    """U3's break attempt: for every model-supplied `query_id` the value recorded on the row
    is the untagged `'elastic.esql'`, and the one well-formed near-miss the model CAN spell is
    routed as an ordinary elastic pitfall — never to the reducer surface.

    The routing key is EQUALITY with `BASH_SHIM_QUERY_ID`, not a suffix, a substring or an
    `is_sentinel` test alone: `'elastic.bash-shim'` passes `resolve_query_id` VERBATIM (C15,
    executed), is one substring away from the sentinel, and is entirely model-chosen.

    THE NEAR MISS IS ASKED AT THE SEAM THAT OWNS THE ROUTING KEY, not at the collector.
    `_draft_candidate_segments('elastic.bash-shim', 'bash', …)` splits it into
    `('elastic', 'bash-shim')`, so `collect_general_failures`' fourth guard diverts the row to
    DRAFT SYNTHESIS before the lane question is reached — a correct build and an
    `endswith`-buggy one both collect nothing there, which is no test at all. So the collector
    arm asserts the diversion it really produces, and the routing question is put to
    `_build_pitfalls_handoffs` over a queued row carrying the near miss: it is a system
    pitfall under elastic's `execution.md`, and no reducer entry exists for it.

    `reducer_handoff_names_the_surface` is this negative's positive control: the genuine
    sentinel DOES reach the reducer surface, so a router that refused everything would not
    pass the pair.
    """
    for spelled in (BASH_SHIM_QUERY_ID, ABOVE_GUARD_QUERY_ID, "∅", "∅.BASH-SHIM",
                    "../x", "", None):
        assert resolve_query_id("elastic", "esql", spelled) == "elastic.esql", spelled

    near_miss = resolve_query_id("elastic", "esql", "elastic.bash-shim")
    assert near_miss == "elastic.bash-shim", "C15's near miss no longer passes through"

    rows = _collect(shim_lead(system="elastic", query_id=near_miss))
    assert rows == [], (
        "the near miss is a DRAFT candidate — diverted before the lane question is asked"
    )
    surfaces = by_surface(pitfalls_curator._build_pitfalls_handoffs(
        [shim_row("r:l-009:0", system="elastic") | {"query_id": near_miss}],
        systems=DECLARED,
    ))
    assert surfaces["reducer"] == []
    assert [e["path"] for e in surfaces["system"]] == [
        "defender/skills/elastic/execution.md"
    ]


