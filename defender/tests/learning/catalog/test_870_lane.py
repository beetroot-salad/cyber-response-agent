"""#870 M5′ — the lane opens on the sentinel id, and on nothing else."""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import pitfalls_curator
from defender.learning.leads.lead_extraction import collect_general_failures
from defender.runtime import tools
from defender.runtime.circuit_breaker import error_class_for_exit
from defender.runtime.query_tool import resolve_query_id
from defender.runtime.sql_engine import sql as defender_sql
from defender.knowledge._query_rules import ABOVE_GUARD_QUERY_ID, BASH_SHIM_QUERY_ID, REPEAT_TRIP_QUERY_ID
from defender.tests.support.learning.core._declared870 import (
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
    rows = _collect(shim_lead(system="elastic"))
    assert len(rows) == 1, "the sentinel row never reached the queue"
    assert rows[0]["system"] == "", "the attributed system survived onto the queued row"
    assert rows[0]["query_id"] == BASH_SHIM_QUERY_ID
    assert rows[0]["pitfall_id"] == f"{RUN.name}:l-003:0"
    assert rows[0]["stderr_digest"] == BINDER, "the adapter's own diagnosis is the lesson"


def test_an_unattributed_shim_row_reaches_the_queue():
    for system in ("", "  ", "gather"):
        rows = _collect(shim_lead(system=system))
        assert len(rows) == 1, f"the systemless guard still swallowed system={system!r}"
        assert rows[0]["system"] == ""


def test_the_new_lane_admits_only_the_shim_sentinel():
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
    infra = error_class_for_exit(tools._shim_exit_code(defender_sql.EXIT_NO_RUNTIME))
    assert infra == "infra"
    assert _collect(shim_lead(error_class=infra)) == [], "an infra-classed reduce enqueued a row"

    for rc in (defender_sql.EXIT_INPUT_ERROR, 1):
        klass = error_class_for_exit(tools._shim_exit_code(rc))
        assert klass == "agent-fixable", rc
        assert len(_collect(shim_lead(error_class=klass))) == 1, rc


def test_no_model_supplied_query_id_reaches_the_reducer_surface():
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
    # #1108 P4 (OD6): handoff paths are spelled repo-relative to the tenant repo.
    assert [e["path"] for e in surfaces["system"]] == [
        "agent/skills/elastic/execution.md"
    ]
