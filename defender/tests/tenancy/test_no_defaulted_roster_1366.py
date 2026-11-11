"""#1366 R16: a tenant's systems are never defaulted. A surface that has a tenant and is handed no roster does not make one up
from the product checkout.

The tenant here has no record of `ticket` (the case system its case record names) and none of `cmdb`, both of which the
checkout's adapters carry. Each surface below is asked the way a caller that hands no roster asks it. What R16 says is
that such a call is refused; what the contract holds whichever way the code gets there (the first test) is that it never
answers over the checkout: it either refuses the call or answers as the tenant's own records do. The second test pins the
refusal itself, and is red until the optional defaults go.

The surfaces: the case-system judgement (`judge_case_system`, `case_verdict`), the ticket writer's record step, the driver's
run-start reads, and the lifecycle's drive function for a direct caller (the run's `main` always hands its verdict).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from defender.systems import case_system
from defender.systems.verb_grant import GrantError
from defender.tests.support.runtime.engine._spec767 import write_report
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: What the checkout carries and the tenant's records do not.
CASE_SYSTEM = "ticket"
OTHER = "cmdb"
#: How the case record's fault says the case system is not one the tenant has a record of (`case_system._adapter_of`).
NOT_A_SYSTEM = "not among the tenant's systems"
SURFACES = ["judge_case_system", "case_verdict", "record_step", "run_start_reads", "drive_investigation"]


class _Declined(Exception):
    """A surface handed no roster that refused to serve the tenant (its grants name systems the roster it made up lacks)."""


class _Refused(_Declined):
    """A surface handed no roster that refused the call for want of one."""


def _tenant(without: tuple[str, ...]) -> Any:
    """The fixture tenant's run record, built from the fixture's records less `without`."""
    spec = R.without(R.fixture_records(), *without)
    assert (CASE_SYSTEM in spec.systems) is (CASE_SYSTEM not in without), "fixture premise"
    return T.fixture_run_tenant(records=spec)


def _no_roster(surface: str, tenant: Any, tmp_path: Path) -> Any:
    """What `surface` answers for `tenant` when it is handed no roster: a refusal as `_Refused` (the call missed an argument it
    now requires), or its answer: `("fault", text)` / `("target",)` for the case-system surfaces, `("receipt", status,
    posts)` for the record step, `("roster", systems)` for the two run-side ones."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    try:
        return _answer(surface, tenant, tmp_path)
    except TypeError as missing:
        if "required" in str(missing) or "missing" in str(missing):
            raise _Refused(str(missing)) from None
        raise
    except GrantError as ungranted:  # the tenant's grants name a system the made-up roster lacks: not served over the checkout
        raise _Declined(str(ungranted)) from None


def _answer(surface: str, tenant: Any, tmp_path: Path) -> Any:
    if surface in ("judge_case_system", "case_verdict"):
        ask = getattr(case_system, surface)
        try:
            got = ask(tenant, defender_dir=T.DEFENDER)
        except case_system.CaseSettingsFault as fault:  # `judge_case_system` raises what `case_verdict` returns
            got = fault
        return ("fault", str(got)) if isinstance(got, case_system.CaseSettingsFault) else ("target",)
    if surface == "record_step":
        run_dir = tmp_path / fixture_uuid("run-r16")
        run_dir.mkdir()
        C.plant_record(run_dir)
        write_report(run_dir)
        proxy = S.ProxyStandIn(tmp_path / "proxy", S.store_answers_ok())
        # The writer itself, not `S.record_step`: that helper hands the verdict run start made (`case=`), which is
        # the very argument this surface is asked without.
        S.ticket_writer().record_case_ticket(
            S._run_handle_1165(run_dir), tenant=tenant, defender_dir=S.DEFENDER, env={},
            proxy_url=proxy.url, request_token="write-token-r16")
        receipt = S.receipt(run_dir) or {}
        return ("receipt", receipt.get("status"), [r for r in proxy.requests() if r["method"] == "POST"],
                receipt.get("reason") or "")
    if surface == "run_start_reads":
        from defender.investigation import driver
        from defender.skills.invlang.validate import _gating

        _gating.release_capabilities()
        try:
            roster, _verbs, _narrowed = driver._run_start_reads(T.DEFENDER, None, object(), tenant)
        except (TypeError, AttributeError, ValueError) as unaccepted:  # `None` is no longer a roster the reads accept
            raise _Refused(f"no roster handed: {unaccepted!r}") from None
        return ("roster", frozenset(roster.systems))
    assert surface == "drive_investigation"
    from defender import run

    seen: dict[str, Any] = {}
    run._drive_investigation(
        alert_path=tmp_path / "alert.json", run=None, defender_dir=T.DEFENDER, model_name="m", model_override=None,
        box=None, tenant=tenant, investigate=lambda **kw: seen.update(kw) or {})
    return ("roster", frozenset(seen["roster"].systems))


@pytest.mark.parametrize("surface", SURFACES)
def test_1366_r16_a_surface_handed_no_roster_never_answers_over_the_checkouts_adapters(tmp_path, surface):
    """For a tenant with no record of the case system or of cmdb: asked with no roster, each surface refuses the call or
    answers as the tenant's records do (the case system is not among its systems, so its record step posts no comment;
    the run's roster holds neither), never as the checkout's adapters would. The control (the tenant HAS the records)
    answers, so the refusal or the answer is about the records. (#1366 R16, O1)"""
    lacking = _tenant((CASE_SYSTEM, OTHER))
    control = _tenant(())

    try:
        got = _no_roster(surface, lacking, tmp_path / "lacking")
    except _Declined:
        return  # R16: the call is refused for want of the tenant's systems
    if surface in ("judge_case_system", "case_verdict"):
        assert got[0] == "fault", f"{surface} judged a case system the tenant has no record of: {got}"
        assert NOT_A_SYSTEM in got[1], got
    elif surface == "record_step":
        assert got[1] == "error", f"the record step did not refuse: {got}"
        assert got[2] == [], f"the record step posted a comment to a case system the tenant has no record of: {got[2]}"
        assert NOT_A_SYSTEM in got[3], got
    else:
        assert not {CASE_SYSTEM, OTHER} & got[1], f"{surface} read a roster holding systems the tenant has no record of: {sorted(got[1])}"
    # The control answers with the records, so the answer above is not a surface that refuses everything.
    try:
        kept = _no_roster(surface, control, tmp_path / "control")
    except _Declined:
        return
    if surface in ("judge_case_system", "case_verdict"):
        assert kept == ("target",), kept
    elif surface == "record_step":
        assert kept[1] != "error", kept
        assert len(kept[2]) == 1, kept
    else:
        assert {CASE_SYSTEM, OTHER} <= kept[1], sorted(kept[1])


@pytest.mark.parametrize("surface", SURFACES)
def test_1366_r16_a_surface_handed_no_roster_is_refused_not_defaulted(tmp_path, surface):
    """R16 itself: even a tenant that HAS its records gets no roster made up for it by the surface — the call is refused
    for want of the argument. Red until the optional defaults are gone. (#1366 R16)"""
    with pytest.raises(_Refused):
        _no_roster(surface, _tenant(()), tmp_path)
