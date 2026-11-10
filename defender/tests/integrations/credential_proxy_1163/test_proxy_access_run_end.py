"""#1363 O7: a run that loses its access to the credential proxy ends `proxy-access`, its own non-zero
exit class, silent, with no system marked down; a fault with no origin is unchanged. A fault with origin
`request` is an uncharged failed call of its own exit class (r8.4, O7a). Driven through `run.main` with
the real investigation (`_spec1222.run_alert`), the ProviderDown suite's door."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

import pytest

from defender import run as run_mod
from defender.investigation import ticket_writer
from defender.kit.faults import AdapterFault, ConfigFault, ConfinementFault, TransportFault, UpstreamFault
from defender.knowledge import REPEAT_TRIP_QUERY_ID
from defender.records import run_end
from defender.run_common import learning_refusal_gate
from defender.systems import circuit_breaker, system_status
from defender.tests.runtime.providers import _spec1243 as P
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.shared import _request_cut1363 as RC
from defender.tests.support.shared.filesystem import _spec1047 as T47
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

PROXY_ACCESS = P.PROXY_ACCESS
#: The new ending's exit code (left to the contract by the design): the next free one in the table.
PROXY_ACCESS_EXIT = P.PROXY_ACCESS_EXIT
LEAD = "l-001"
CORR = "CORR-1363: correlation summary delivered."
#: Names no proxy itself, so an ending that only echoes it does not name the credential proxy.
DETAIL = "PROXY-ACCESS-1363: the request token has expired"
KINDS = {"config": ConfigFault, "transport": TransportFault, "upstream": UpstreamFault}


def _proxied_fault(origin: str | None, kind: type[AdapterFault] = ConfigFault, detail: str = DETAIL) -> Any:
    """The fault the proxy client raises for a call it could not make: `kind` carrying `origin`
    (`None` is the same fault from before origins, the control)."""
    def make() -> BaseException:
        fault = kind(detail)
        if origin is not None:
            fault.origin = origin
        return fault
    return make


def _drive(tmp_path: Path, origin: str | None, kind: type[AdapterFault] = ConfigFault, *,
           detail: str = DETAIL, **kw: Any) -> S.Drive:
    return S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)],
               LEAD: [S.query("cmdb", "get-host", {"host": "web-1"}), S.text("Summary: unreached.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault(origin, kind, detail)),
        **kw)


def _cmdb_rows(d: S.Drive) -> list[dict]:
    return [r for r in d.rows if r.get("system") == "cmdb"]


@pytest.mark.parametrize("kind", list(KINDS))
def test_1363_o7_an_access_fault_mid_run_ends_it_proxy_access_silent_and_non_zero(tmp_path: Path, kind: str) -> None:
    """Whatever kind it carries, an `access` fault ends the run `proxy-access` naming the credential proxy
    and the detail: no report, no row for the call, no system down, no charge, the class's own exit. #1363 O7, D4."""
    stores: list = []
    d = _drive(tmp_path, "access", KINDS[kind], store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    P.assert_ended_proxy_access(d)
    assert DETAIL in str((d.summary or {}).get("exit_reason")), (d.summary or {}).get("exit_reason")
    assert d.router.requests(LEAD) == 1, "the lead was asked again after its access was lost"
    assert _cmdb_rows(d) == [], "the lost call wrote a query row"
    assert system_status.down_cause(d.run_state, "cmdb") is None, "our access loss marked cmdb down"
    assert d.breaker.get("total_failures", 0) == 0, d.breaker
    assert run_end.exit_code_of(PROXY_ACCESS) == PROXY_ACCESS_EXIT
    assert ticket_writer.comments_on(PROXY_ACCESS, closed_before_cut=False) is False
    ended = P.sessions(stores[-1].path)
    assert ended.get("main") == PROXY_ACCESS, ended
    assert ended.get(P.gather_agent(LEAD)) == PROXY_ACCESS, ended


CONTROLS = [(ConfigFault, None), (ConfigFault, "system"), (TransportFault, None), (TransportFault, "system")]


@pytest.mark.parametrize(("kind", "origin"), CONTROLS, ids=[f"{k.__name__}-{o}" for k, o in CONTROLS])
def test_1363_o7_control_a_fault_not_ours_keeps_its_old_handling_and_the_run_goes_on(
        tmp_path: Path, kind: type[AdapterFault], origin: str | None) -> None:
    """Positive control on the same channels: the same fault with no origin or the system's keeps its row; a
    config fault marks cmdb down uncharged, a transport fault is charged. (`request` no longer belongs
    here: it is an uncharged failed call of its own class, below.) #1363 O7."""
    d = _drive(tmp_path, origin, kind)
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") != PROXY_ACCESS, d.summary
    assert [r.get("exit_code") for r in _cmdb_rows(d)] == [kind.exit_code], "control: the call's row is written"
    if kind is ConfigFault:
        assert system_status.down_cause(d.run_state, "cmdb") is not None, "control: the channel shows a down system"
        assert d.breaker.get("total_failures", 0) == 0, d.breaker
    else:
        assert system_status.down_cause(d.run_state, "cmdb") is None
        assert d.breaker.get("total_failures", 0) == 1, d.breaker
    assert d.rc == 0, d.rc


def test_1363_o7_the_correlation_lead_losing_access_ends_the_run_proxy_access_before_main(tmp_path: Path) -> None:
    """The correlation lead's own `access` fault ends the run `proxy-access` before MAIN is asked, not as a
    named lead ending. Control: the same call failing as the system's lets MAIN run. #1363 O7."""
    def drive(where: Path, origin: str) -> S.Drive:
        return S.run_alert(
            where, main=[S.text(S.DONE)],
            leads={S.L3: [S.query("elastic", "alerts", {"native_query": 'host.hostname:"app-7"'}), S.text(CORR)]},
            backend=S.Backend(fault=T.Fault(fail_on=("elastic.alerts",)), exc=_proxied_fault(origin, TransportFault)))

    d = drive(tmp_path / "access", "access")
    P.assert_ended_proxy_access(d)
    assert d.main.requests == 0, f"MAIN was asked {d.main.requests} time(s) after the correlation lead lost access"
    ctl = drive(tmp_path / "system", "system")
    assert ctl.raised is None, (ctl.raised, ctl.rc)
    assert ctl.rc == 0, (ctl.raised, ctl.rc)
    assert ctl.main.requests >= 1, "control: MAIN ran after the correlation lead's system failure"


def test_1363_o7_concurrent_calls_losing_access_together_end_the_run_once_proxy_access(tmp_path: Path) -> None:
    """Several calls of one turn each meeting the lost access reach the driver as a group and still end
    the run `proxy-access`, exit 8. #1363 O7, D10."""
    parallel = S.Turn(tool_calls=tuple(
        ("query", {"system": "cmdb", "verb": "get-host", "params": {"host": f"host-{i}"}}) for i in range(3)))
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)], LEAD: [parallel, S.text("Summary: unreached.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault("access", TransportFault)))
    P.assert_ended_proxy_access(d)
    assert _cmdb_rows(d) == [], d.rows


def test_1363_o7_a_run_that_lost_access_leaves_the_case_without_a_comment(tmp_path: Path) -> None:
    """A real run with the real ticket writer over a recording store makes no store call when it ends
    `proxy-access`; control: the same run ending normally comments. #1363 O7 (silent), C1."""
    def drive(where: Path, origin: str) -> S.Drive:
        return _drive(where, origin, tenant=S.ticket_the_tenant(S.plant_tenant()), alert=S.ticketed_alert(),
                      tickets=S.ticket_writer(S.TicketStore(where)), update_ticket=True)

    lost = drive(tmp_path / "lost", "access")
    P.assert_ended_proxy_access(lost)
    assert lost.tickets.store.calls == [], f"a proxy-access run reached the case system: {lost.tickets.store.calls}"
    ok = drive(tmp_path / "ok", "system")
    assert ok.raised is None, (ok.raised, ok.summary)
    assert (ok.summary or {}).get("truncated_by") is None, (ok.raised, ok.summary)
    assert ok.tickets.store.comment_payloads, "control: the run's own comment did not reach the store"


@pytest.mark.parametrize("report", [False, True])
def test_1363_o7_the_ticket_lane_leaves_a_proxy_access_ticket_open_with_no_call(tmp_path: Path, report: bool) -> None:
    """The record step makes no call at all for a proxy-access run that reached no verdict, with or
    without a report on disk. #1363 O7, C1."""
    run_dir = T47.closed_run_dir(tmp_path, report=report)
    fake = T47.record_ticket(run_dir, truncated_by=PROXY_ACCESS, closed_before_cut=False)
    assert fake.calls == [], f"the lane made {fake.calls} for a proxy-access run"
    assert T47.receipt(run_dir) is None


def test_1363_o7_a_run_that_had_closed_with_a_verdict_before_access_was_lost_still_comments(tmp_path: Path) -> None:
    """A proxy-access run whose model had already closed records its verdict; control: an uncut run records.
    #1363 O7, C1."""
    run_dir = T47.closed_run_dir(tmp_path / "cut", disposition="malicious")
    fake = T47.record_ticket(run_dir, truncated_by=PROXY_ACCESS, closed_before_cut=True)
    assert len(fake.records) == 1, f"a closed-before-cut proxy-access run recorded {fake.calls}"
    assert "malicious" in fake.records[0].text()
    assert fake.transitions == []
    assert ticket_writer.comments_on(PROXY_ACCESS, closed_before_cut=True) is True
    uncut = T47.record_ticket(T47.closed_run_dir(tmp_path / "uncut", disposition="malicious"), truncated_by=None)
    assert len(uncut.records) == 1, "control: an uncut run records"


def test_1363_o7_a_proxy_access_run_hands_its_class_to_the_post_steps(tmp_path: Path) -> None:
    """Curation is handed `truncated_by=proxy-access` and refused for a cut run; control: an uncut run is
    handed none. #1363 O7."""
    from defender import run_common

    def drive(where: Path, origin: str) -> S.Drive:
        return _drive(where, origin, no_learn=False, enqueue=run_common.enqueue_curation)

    d = drive(tmp_path / "lost", "access")
    P.assert_ended_proxy_access(d)
    assert d.enqueued, "run.py never reached its curation step on a proxy-access run"
    assert all(kw.get("truncated_by") == PROXY_ACCESS for _a, kw in d.enqueued), d.enqueued
    ok = drive(tmp_path / "ok", "system")
    assert ok.enqueued, "control: the uncut run reached curation"
    assert all(kw.get("truncated_by") is None for _a, kw in ok.enqueued), ok.enqueued
    reason = learning_refusal_gate(T47.closed_run_dir(tmp_path / "gate", report=False), truncated_by=PROXY_ACCESS)
    assert reason is not None, reason
    assert PROXY_ACCESS in reason, reason


def test_1363_o7_proxy_access_is_a_word_of_the_run_end_vocabulary_and_its_code_is_its_own() -> None:
    """The ending is a run-end word the session store, run end and job end validate; it forces no close, is
    not escalated, and its exit code is the table's own. #1363 O7, D10."""
    assert getattr(run_end, "TRUNCATED_BY_PROXY_ACCESS", None) == PROXY_ACCESS
    assert PROXY_ACCESS in run_end.TRUNCATED_BY_VALUES
    assert run_end.normalized_truncated_by(PROXY_ACCESS) == PROXY_ACCESS
    assert PROXY_ACCESS not in run_end.FORCED_CLOSE_EXITS
    assert PROXY_ACCESS not in run_end.ESCALATED_EXITS
    assert run_end.parse_record({"truncated_by": PROXY_ACCESS, "closed_before_cut": False}) is not None
    assert run_end.parse_record({"truncated_by": "proxy_access", "closed_before_cut": False}) is None
    assert json.loads(json.dumps(run_end.RunEnd(PROXY_ACCESS, False).doc())) == run_end.RunEnd(PROXY_ACCESS, False).doc()
    others = {c.exit_code for word, c in run_end.EXIT_CLASSES.items() if word != PROXY_ACCESS}
    assert PROXY_ACCESS_EXIT not in others | P.TAKEN_EXITS | {run_mod.UNSERVABLE_EXIT}, others
    assert run_end.exit_code_of(PROXY_ACCESS) == PROXY_ACCESS_EXIT
    assert run_end.exit_code_of("provider-down") == P.PROVIDER_DOWN_EXIT, "control: another class keeps its own code"


def test_1363_o7_a_sibling_world_ending_proxy_access_exits_8(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A sibling whose run loses its access ends `proxy-access` and exits 8; control: a budget end exits 0.
    #1363 O7, D6."""
    from defender.hooks.budget_enforcer import BudgetKill

    for ends, rc, fault in (("proxy-access", PROXY_ACCESS_EXIT, P.proxy_access_fault()),
                            ("budget", 0, lambda: BudgetKill("world budget spent"))):
        ep = P.sibling_episode(tmp_path / ends, monkeypatch)
        main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=fault))
        d = P.run_sibling(tmp_path / ends / "sibling", ep, main)
        assert d.raised is None, f"the sibling crashed instead of ending {ends}: {d.raised!r}"
        assert (d.summary or {}).get("truncated_by") == ends, d.summary
        assert d.rc == rc, f"a sibling world that ended {ends} exited {d.rc!r}, not {rc}"


def test_1363_d6_a_sibling_exiting_proxy_access_did_not_finish_at_the_launcher(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The launcher records the world that exited 8 as `did not finish`, as for any non-zero exit; the
    sibling that exited 0 gets none. Green at the base by the generic rule. #1363 D6."""
    from defender.learning.branch import cli
    from defender.learning.branch.outcome import DID_NOT_FINISH
    from defender.records._episode_handle import Episode

    _base, src, _root = T.configured_layout(tmp_path, monkeypatch)
    spawn = T.FakeSpawn(exits={"b": PROXY_ACCESS_EXIT})
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src.resolve())))
    with Episode.open(ep) as episode:
        T.episode_view(episode)
        exits = cli.start_family(
            episode, [T.world_id(ep, label) for label in ("a", "b")], spawn=spawn, tenant_id=T.SOURCE_TENANT)
    assert exits.get(T.world_id(ep, "b")) == PROXY_ACCESS_EXIT
    records = {p.stem: p.read_text(encoding="utf-8") for p in ep.rglob("world_records/*.yaml")}
    assert T.world_id(ep, "b") in records, f"no world record for the sibling that exited 8: {sorted(records)}"
    assert DID_NOT_FINISH in records[T.world_id(ep, "b")]
    assert T.world_id(ep, "a") not in records, "a sibling that exited 0 was recorded as failed"


def test_1363_b6_a_job_whose_run_was_cut_short_by_proxy_access_ends_failed_no_report_naming_it() -> None:
    """The job-end record carries `proxy-access` as `cut_short` and the worker ends the job `failed`
    (`no_report`) saying the run was cut short (proxy-access); control: `provider-down` reads alike.
    #1363 B6. Postgres-gated worker rows are not run locally."""
    from defender.records import job_facts, job_lane
    from defender.worker._worker import _ending_from

    def ending(word: str) -> Any:
        end = job_lane.JobEnd(setup=job_facts.SETUP_DONE, box=job_facts.BOX_STARTED, report_committed=False,
                              scrub_verified=False, cut_short=word)
        parsed = job_lane.JobEnd.parse(end.text())
        assert parsed is not None, f"the job-end record refuses {word!r}"
        assert parsed.cut_short == word, f"the job-end record refuses {word!r}"
        return _ending_from(parsed, PROXY_ACCESS_EXIT, lambda: None)

    got = ending(PROXY_ACCESS)
    assert got.failure_reason == "no_report"
    assert "cut short (proxy-access)" in got.failure_message, got.failure_message
    assert got.decided_by_run is False
    assert "cut short (provider-down)" in ending("provider-down").failure_message, "control"


# --- r8.4, O7a: a `request`-origin fault is an uncharged failed call of its own exit class ----------------
#
# The exit code of such a row is `RC.REQUEST_CUT_EXIT`: the code stage must use that value, or the constant
# must be re-pointed (the design leaves the number to the contract).

#: Names no proxy, no system and no "not configured", so an agent text that holds them said it itself.
CUT = "REQCUT-1363: this one call was cut"
#: The proxy's own words for the request it could not read (oversize, did not arrive, caller left), then
#: synthetic ones for the kinds the proxy words differently.
REQUEST_CASES = [pytest.param(kind, detail, id=name) for name, (kind, detail) in RC.real_proxy_request_faults().items()] + [
    pytest.param(ConfigFault, "REQCUT-1363: the path is not under the system's base", id="config-locate"),
    pytest.param(TransportFault, CUT, id="transport"),
    pytest.param(ConfinementFault, "REQCUT-1363: GET /x is not a declared route", id="confinement"),
]
#: What an agent must never be told about a request that was only cut or malformed.
WRONG_STORY = re.compile(r"unreachable|not configured|credential proxy", re.IGNORECASE)


@pytest.mark.parametrize(("kind", "detail"), REQUEST_CASES)
def test_1363_o7a_a_request_fault_is_an_uncharged_failed_call_of_its_own_exit_class_and_the_run_goes_on(
        tmp_path: Path, kind: type[AdapterFault], detail: str) -> None:
    """A fault with origin `request`, of any kind, writes the call's row with the dedicated exit class, charges
    neither the system nor the run, marks no system down and does not end the run: the lead is asked again.
    The code stage must use `RC.REQUEST_CUT_EXIT` (or the constant is re-pointed). #1363 O7a, D12."""
    d = _drive(tmp_path, "request", kind, detail=detail)
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") is None, d.summary
    assert [r.get("exit_code") for r in _cmdb_rows(d)] == [RC.REQUEST_CUT_EXIT], \
        f"{kind.__name__} request fault: the call's row is not the dedicated class: {_cmdb_rows(d)}"
    assert system_status.down_cause(d.run_state, "cmdb") is None, "a request fault marked cmdb down"
    assert d.run_state.breaker_failures("cmdb") == 0, f"charged to the system: {d.breaker}"
    assert d.breaker.get("total_failures", 0) == 0, f"charged to the run: {d.breaker}"
    assert d.router.requests(LEAD) == 2, "the lead was not asked again after the cut call"
    assert d.rc == 0, d.rc


@pytest.mark.parametrize(("kind", "detail"), REQUEST_CASES)
def test_1363_o7a_the_agent_is_told_the_faults_own_detail_not_that_the_system_is_down_or_the_proxy_failed(
        tmp_path: Path, kind: type[AdapterFault], detail: str) -> None:
    """The failed call's result to the agent carries the fault's own detail, on the proxy's real strings
    for the oversize, late and abandoned request too, and says neither that the system is unreachable or
    not configured nor names the credential proxy. #1363 O7a, D12."""
    d = _drive(tmp_path, "request", kind, detail=detail)
    seen = d.router.seen(LEAD)
    assert len(seen) >= 2, "the lead was never answered"
    told = "\n".join(seen[1].tool_returns)
    assert detail in told, f"the fault's own detail is missing from the agent's result: {told!r}"
    assert WRONG_STORY.search(told) is None, f"the agent was told the wrong story: {told!r}"


def test_1363_o7a_a_second_distinct_call_to_the_same_system_reaches_the_backend(tmp_path: Path) -> None:
    """After a request fault on cmdb the system is still callable: a different verb's call reaches the backend and
    answers. Control: the call that was cut did reach it (so the backend is the one that failed). #1363 O7a."""
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)],
               LEAD: [S.query("cmdb", "get-host", {"host": "web-1"}), S.query("cmdb", "health-check"),
                      S.text("Summary: carried on.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault("request", TransportFault, CUT)))
    assert d.raised is None, d.raised
    assert d.backend.rec.verbs == ["cmdb.get-host", "cmdb.health-check"], d.backend.rec.verbs
    assert [r.get("exit_code") for r in _cmdb_rows(d)] == [RC.REQUEST_CUT_EXIT, 0], _cmdb_rows(d)
    assert d.rc == 0, d.rc


@pytest.mark.parametrize("kind", [ConfigFault, TransportFault, ConfinementFault])
def test_1363_o7a_request_faults_beyond_the_run_failure_limit_do_not_abort_the_run(
        tmp_path: Path, kind: type[AdapterFault]) -> None:
    """More request-origin failures than the run's failure limit (distinct calls, so the repeat guard stays out of
    it) write their rows uncharged: no `RunAborted`, no ending, the system never trips. #1363 O7a."""
    n = circuit_breaker.RUN_FAIL_KILL_LIMIT + 2
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)],
               LEAD: [*[S.query("cmdb", "get-host", {"host": f"web-{i}"}) for i in range(n)], S.text("Summary: went on.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault("request", kind, CUT)))
    assert d.raised is None, d.raised
    assert (d.summary or {}).get("truncated_by") is None, d.summary
    assert [r.get("exit_code") for r in _cmdb_rows(d)] == [RC.REQUEST_CUT_EXIT] * n, _cmdb_rows(d)
    assert d.breaker.get("total_failures", 0) == 0, d.breaker
    assert d.run_state.breaker_failures("cmdb") == 0, d.breaker
    assert d.rc == 0, d.rc


@pytest.mark.parametrize("kind", [ConfigFault, TransportFault, ConfinementFault])
def test_1363_o7a_each_request_fault_is_one_warning_naming_system_origin_and_detail_never_an_adapter_defect_error(
        tmp_path: Path, caplog: pytest.LogCaptureFixture, kind: type[AdapterFault]) -> None:
    """One record at WARNING or above per fault naming the system, the origin and the detail; for a configuration
    fault its wording suspects an adapter or settings defect; no ERROR record calls it an adapter defect.
    #1363 O7a."""
    caplog.set_level(logging.INFO)
    d = _drive(tmp_path, "request", kind, detail=CUT)
    assert d.raised is None, d.raised
    lines = [r for r in caplog.records if r.levelno >= logging.WARNING and "REQCUT-1363" in r.getMessage()]
    shown = [(r.levelname, r.getMessage()) for r in lines]
    assert len(lines) == 1, f"expected one WARNING-or-above record for the fault, found {shown}"
    text = lines[0].getMessage()
    assert re.search(r"(?<![\w-])cmdb(?![\w-])", text), f"the record does not name the system: {text!r}"
    assert re.search(r"request", text, re.IGNORECASE), f"the record does not name the origin: {text!r}"
    if kind is ConfigFault:
        assert re.search(r"adapter|settings", text, re.IGNORECASE), f"a configuration fault is not suspected as a defect: {text!r}"
    defects = [r for r in caplog.records if r.levelno >= logging.ERROR and "adapter defect" in r.getMessage().lower()]
    assert defects == [], f"a request fault was logged as the adapter's defect: {[r.getMessage() for r in defects]}"


def _repeat_observed(tmp_path: Path, origin: str, kind: type[AdapterFault]) -> tuple[int, int, int, list[int]]:
    """Four identical failing calls: (backend calls, repeat-trip rows, the lead's requests, the exit codes of
    its cmdb rows)."""
    same = S.query("cmdb", "get-host", {"host": "web-1"})
    d = S.run_alert(
        tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
        leads={S.L3: [S.text(CORR)], LEAD: [same, same, same, same, S.text("Summary: stopped.")]},
        backend=S.Backend(fault=T.Fault(fail_on=("cmdb.get-host",)), exc=_proxied_fault(origin, kind, CUT)))
    assert d.raised is None, d.raised
    trips = [r for r in d.rows if r.get("query_id") == REPEAT_TRIP_QUERY_ID]
    return (len(d.backend.rec.calls), len(trips), d.router.requests(LEAD),
            [r.get("exit_code") for r in _cmdb_rows(d)])


def test_1363_o7a_the_repeat_guard_is_unchanged_the_third_identical_request_fault_dead_ends_the_lead(
        tmp_path: Path) -> None:
    """Two identical request-fault calls reach the backend; the third is stopped by the repeat guard exactly as the
    third identical exit-1 failure is (the control, a system-origin UpstreamFault): same backend calls, same
    trip, same lead conversation. #1363 O7a, D13."""
    control = _repeat_observed(tmp_path / "control", "system", UpstreamFault)
    assert control[:2] == (2, 1), f"control: the guard did not stop the third identical failure: {control}"
    cut = _repeat_observed(tmp_path / "cut", "request", TransportFault)
    assert cut[:3] == control[:3], f"request faults are counted by the guard differently: {cut} vs control {control}"
    assert cut[3][:2] == [RC.REQUEST_CUT_EXIT] * 2, cut
    assert cut[3][2:] == control[3][2:], f"the trip row differs from the control's: {cut} vs {control}"
