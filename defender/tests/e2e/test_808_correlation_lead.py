"""The harness-dispatched correlation lead `l-00c` — what #808 pinned that #1222's suite does not.

#1222 retired item 1 (the ancestor fetch) and with it the scenarios built on it
(`test_808_ancestor_resolution`, `_lead_zero_contract`, `_orient_framing`, `_run_dir_tables`,
`_downstream_readers` and the item-1 halves of this file). What survives are the three
properties of the lead's dispatch that no #1222 test observes: its grant stays narrower than
MAIN's leads' (`esql` is denied), its own ceiling is eight requests while MAIN's leads keep
their forty, and a session cut at that ceiling reads back as cut. Driven through the #1222
front door (`S.run_alert`), so admission, the record and the one deadline are production's.
"""
from __future__ import annotations

import sqlite3

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import circuit_breaker, session_store  # noqa: E402
from defender.runtime.driver import GATHER_REQUEST_LIMIT  # noqa: E402
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests.alert_front_door_1222 import _spec1222 as S  # noqa: E402

pytestmark = pytest.mark.e2e


def _alerts(i: int) -> S.Turn:
    """One DISTINCT query turn — three identical requests trip the repeat guard's dead end."""
    return S.query("elastic", "alerts", {"native_query": f'user.name:"dev.dana" AND seq:{i}'})


def test_correlation_lead_is_bound_to_the_alerts_index_only(tmp_path):
    """The correlation lead is dispatched with a narrowed verb grant that excludes `esql`: an
    ES|QL call from it is denied and recorded as a policy denial, while its granted verb runs."""
    d = S.run_alert(tmp_path, tenant=S.plant_tenant(), run_id=fixture_uuid("b808-grant"), leads={S.L3: [
        S.query("elastic", "esql", {"query": "FROM logs-* | LIMIT 1"}),
        _alerts(0), S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    assert d.raised is None, d.raised
    assert d.rc == 0, d.refusal
    rows = d.rows_for(S.L3)
    codes = [r.get("exit_code") for r in rows]
    assert circuit_breaker.DENIED_EXIT_CODE in codes, f"esql was not denied for l-00c: {rows}"
    assert 0 in codes, f"the granted verb did not run for l-00c: {rows}"
    assert [c.verb for c in d.backend.rec.calls] == ["elastic.alerts"], (
        f"the denied esql reached the backend: {[c.verb for c in d.backend.rec.calls]}")


def test_correlation_ceiling_is_eight_and_mains_leads_keep_forty(tmp_path):
    """The lead is stopped at its eighth request; a lead MAIN dispatches is not held to eight."""
    over = S.CORRELATION_REQUEST_LIMIT + 4
    d = S.run_alert(
        tmp_path, tenant=S.plant_tenant(), run_id=fixture_uuid("b808-limit"),
        main=[S.gather("l-001", "elastic"), S.text(S.DONE)],
        leads={S.L3: [_alerts(i) for i in range(over)],
               "l-001": [_alerts(100 + i) for i in range(over)] + [S.text("main lead done")]})
    assert d.raised is None, d.raised
    assert d.rc == 0, d.refusal
    assert d.router.requests(S.L3) == S.CORRELATION_REQUEST_LIMIT, (
        f"l-00c made {d.router.requests(S.L3)} requests, not {S.CORRELATION_REQUEST_LIMIT}")
    assert S.CORRELATION_REQUEST_LIMIT < d.router.requests("l-001") <= GATHER_REQUEST_LIMIT, (
        f"MAIN's lead made {d.router.requests('l-001')} requests: it was held to l-00c's ceiling")


def test_correlation_session_cut_at_its_ceiling_reads_back_as_cut(tmp_path):
    """The correlation lead's session ends with the same terminator bookkeeping every lead
    gets: one cut off at its ceiling is distinguishable in the store from one that finished."""
    stores: list = []
    d = S.run_alert(
        tmp_path, tenant=S.plant_tenant(), run_id=fixture_uuid("b808-stamp"),
        leads={S.L3: [_alerts(i) for i in range(S.CORRELATION_REQUEST_LIMIT + 4)]},
        store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    assert d.raised is None, d.raised
    assert d.rc == 0, d.refusal
    assert stores, "the run opened no session store"
    con = sqlite3.connect(str(stores[-1].path))
    try:
        endings = dict(con.execute("SELECT agent_id, truncated_by FROM session").fetchall())
    finally:
        con.close()
    assert endings.get(f"gather:{S.L3}") == session_store.TRUNCATED_BY_REQUEST_LIMIT, endings
    assert endings.get("main") is None, f"MAIN's session reads as cut: {endings}"
