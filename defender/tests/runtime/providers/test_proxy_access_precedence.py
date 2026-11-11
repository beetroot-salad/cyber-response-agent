"""#1363 D10: which ending a run takes when `ProxyAccessLost` meets another ending, bare or inside an
exception group, at the driver's main loop, around lead zero, and at a gather lead. Driven through
`run.main` with faults injected at the model door, as `test_provider_down_run_end.py` does."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender import box
from defender.hooks.budget_enforcer import BudgetKill
from defender.providers import ProviderDown, ProviderRejected
from defender.records import run_end
from defender.records.run_end import CallRecordWriteFailed
from defender.systems.circuit_breaker import RunAborted
from defender.systems.verbs import ServingAbort
from defender.tests.runtime.providers import _spec1243 as P
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

LEAD = "l-001"
CORR = "CORR-1363: correlation summary delivered."
WHERE = pytest.mark.parametrize("where", ["main", "correlation", "gather"])


def _inject(tmp_path: Path, exc: Any, where: str, **kw: Any) -> S.Drive:
    """`exc` raised once by MAIN's model, the correlation lead's, or a gather lead's."""
    fault = S.LeadFault(raise_on=1, exc=exc)
    if where == "gather":
        return S.run_alert(tmp_path, main=[S.gather(LEAD, "cmdb"), S.text(S.DONE)],
                           leads={S.L3: [S.text(CORR)], LEAD: [S.text("x")]}, lead_faults={LEAD: fault}, **kw)
    main = S.MainScript([S.text(S.DONE)], fault=fault if where == "main" else S.CLEAN)
    return S.run_alert(tmp_path, main=main, leads={S.L3: [S.text(CORR)]},
                       lead_faults={S.L3: fault} if where == "correlation" else None, **kw)


def _group(*members: Any) -> Any:
    return lambda: ExceptionGroup("g", [m() for m in members])


def _named(d: S.Drive) -> str | None:
    rec = P.sidecar(d.folder) if d.run_dir is not None else None
    return None if rec is None else rec["truncated_by"]


def _down() -> BaseException:
    return ProviderDown(model="fake", status=503, attempts=4)


def _rejected() -> BaseException:
    return ProviderRejected(401, "the key no longer works")


@WHERE
@pytest.mark.parametrize("shape", ["bare", *sorted(P.GROUPED_PROXY_ACCESS)])
def test_1363_d10_proxy_access_ends_the_run_at_every_site_bare_or_in_any_group(tmp_path: Path, shape: str, where: str) -> None:
    """Bare, flat, nested or beside an ordinary error, it ends the run `proxy-access`, exit 8, at the main
    loop, the correlation lead and a gather lead. #1363 D10, O7."""
    exc = P.proxy_access_fault() if shape == "bare" else P.GROUPED_PROXY_ACCESS[shape](P.proxy_access_fault())
    stores: list = []
    d = _inject(tmp_path, exc, where, store_factory=S.store_factory(tmp_path, sink=stores), stores=stores)
    P.assert_ended_proxy_access(d)
    if where == "correlation":
        assert d.main.requests == 0, "MAIN was asked after the correlation lead lost access"
    if where == "gather":
        assert P.sessions(stores[-1].path).get(P.gather_agent(LEAD)) == P.PROXY_ACCESS, "the lead's session is not stamped"


@WHERE
@pytest.mark.parametrize("order", ["access-first", "other-first"])
@pytest.mark.parametrize("other", [_down, _rejected], ids=["provider-down", "provider-rejected"])
def test_1363_d10_proxy_access_overrides_provider_down_and_provider_rejected(
        tmp_path: Path, other: Any, order: str, where: str) -> None:
    """A group holding both ends the run `proxy-access`, whichever member comes first. Control: the other alone
    keeps its own ending. #1363 D10."""
    members = [P.proxy_access_fault(), other]
    d = _inject(tmp_path / "both", _group(*(members if order == "access-first" else members[::-1])), where)
    P.assert_ended_proxy_access(d)
    alone = _inject(tmp_path / "alone", other, where)
    assert (alone.summary or {}).get("truncated_by") in ("provider-down", "provider-rejected"), alone.summary
    assert alone.rc in (P.PROVIDER_DOWN_EXIT, 7), alone.rc


KILLS = {"budget": lambda: BudgetKill("run budget spent"), "aborted": lambda: RunAborted(5, ["cmdb"])}


@WHERE
@pytest.mark.parametrize("kill", list(KILLS))
def test_1363_d10_a_budget_kill_or_abort_beside_proxy_access_is_not_ended_proxy_access(
        tmp_path: Path, kill: str, where: str) -> None:
    """The kill outranks the access loss: the run is not named or exited `proxy-access` and the kill does not
    vanish. Control: the access loss alone ends `proxy-access`. #1363 D10."""
    d = _inject(tmp_path / "group", _group(KILLS[kill], P.proxy_access_fault()), where)
    assert d.rc != P.PROXY_ACCESS_EXIT, d.rc
    assert _named(d) in (None, kill), _named(d)
    if where != "correlation":  # there a mixed group is the lead's named dispatch failure, as before
        assert d.raised is not None or _named(d) == kill, "the group vanished without an ending"
    assert (d.summary or {}).get("truncated_by") != P.PROXY_ACCESS
    P.assert_ended_proxy_access(_inject(tmp_path / "alone", P.proxy_access_fault(), where))


@WHERE
@pytest.mark.parametrize("ending", ["box-lost", "box-output-limit"])
def test_1363_d10_a_box_ending_beside_proxy_access_wins(tmp_path: Path, ending: str, where: str) -> None:
    """The box's ending is named and exits its own code (5, 6), not 8. #1363 D10."""
    make = (lambda: box.BoxLost("the box is unusable")) if ending == "box-lost" else box.BoxOutputLimitExceeded
    d = _inject(tmp_path, _group(P.proxy_access_fault(), make), where)
    assert d.raised is None, d.raised
    assert _named(d) == ending, _named(d)
    assert d.rc == run_end.exit_code_of(ending) != P.PROXY_ACCESS_EXIT


def test_1363_d10_a_call_record_failure_beside_proxy_access_wins_in_the_main_loop(tmp_path: Path) -> None:
    """The failed record's own class is the ending, ahead of `proxy-access`. #1363 D10."""
    record = sorted(run_end.CALL_RECORDS)[0]
    d = _inject(tmp_path, _group(P.proxy_access_fault(), lambda: CallRecordWriteFailed(record, "test")), "main")
    assert _named(d) == record, _named(d)
    assert (d.summary or {}).get("truncated_by") == record


@pytest.mark.parametrize("serving", ["bare", "grouped-with-access", "group-without-access"])
def test_1363_d10_proxy_access_ranks_above_a_serving_abort_in_a_sibling(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, serving: str) -> None:
    """A sibling whose run holds both exits 8, not the unservable exit 3. Controls: a serving abort alone, or in
    a group without the access loss, exits 3. #1363 D10, D11."""
    from defender import run as run_mod

    abort = lambda: ServingAbort("the oracle gave up on the world")  # noqa: E731
    exc = {"bare": abort, "grouped-with-access": _group(abort, P.proxy_access_fault()),
           "group-without-access": _group(abort, P.ordinary_error())}[serving]
    ep = P.sibling_episode(tmp_path, monkeypatch)
    main = S.MainScript([S.text(S.DONE)], fault=S.LeadFault(raise_on=1, exc=exc))
    d = P.run_sibling(tmp_path / "sibling", ep, main)
    assert d.raised is None, d.raised
    assert d.rc == (P.PROXY_ACCESS_EXIT if serving == "grouped-with-access" else run_mod.UNSERVABLE_EXIT), d.rc
