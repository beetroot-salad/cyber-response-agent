"""The correlation lead's dispatch identity comes from the verb-grants table alone.

The table grants or withholds the lead and names the one system and query verb it holds
(#999). No saved query is bound (#1503, which retired #1003's `lead-zero.yaml`): the lead writes
its own query against that system.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.investigation.lead_zero import CorrelationDispatch, resolve_correlation_dispatch
from defender.systems.verb_grant import GrantError, VerbGrant
from defender.tests.support.invlang.validation._dispositions995 import grant_for, load_dispositions, write_table

#: The holder's name as the table spells it — a literal, as in `test_correlation_holder`.
HOLDER = "lead-zero-correlation"
BOTH = {"roles": ["gather", HOLDER]}
GATHER_ONLY = {"roles": ["gather"]}


def _grant(tmp_path: Path, rows: dict) -> VerbGrant:
    """The holder's grant from a table holding exactly `rows`, through the REAL loader."""
    return grant_for(HOLDER, load_dispositions(write_table(tmp_path / "settings" / "verb-grants.yaml", rows)))


def test_the_lead_dispatches_on_the_granted_system_with_no_saved_query(tmp_path):
    grant = _grant(tmp_path, {
        ("splunk", "search"): BOTH, ("splunk", "health-check"): BOTH,
        ("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): GATHER_ONLY,
    })
    assert resolve_correlation_dispatch(grant) == CorrelationDispatch(system="splunk", grant=grant)


def test_a_withheld_lead_has_no_system(tmp_path):
    withheld = _grant(tmp_path, {("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): BOTH})
    assert resolve_correlation_dispatch(withheld) == CorrelationDispatch(system=None, grant=withheld)


def test_health_check_alone_is_not_a_dispatch_target():
    ping = VerbGrant(role=HOLDER, entries=(("elastic", "health-check", "r"),))
    assert resolve_correlation_dispatch(ping).system is None


def test_a_grant_holding_two_query_pairs_is_refused_naming_both_and_the_table():
    two = VerbGrant(role=HOLDER, entries=(("elastic", "alerts", "r"), ("elastic", "query", "r")))
    with pytest.raises(GrantError) as caught:
        resolve_correlation_dispatch(two, table=Path("settings/verb-grants.yaml"))
    assert str(caught.value).startswith("settings/verb-grants.yaml: ")
    assert "elastic.alerts" in str(caught.value)
    assert "elastic.query" in str(caught.value)


def test_a_grant_reaching_two_systems_is_refused_naming_the_table():
    two = VerbGrant(role=HOLDER, entries=(("elastic", "alerts", "r"), ("splunk", "search", "r")))
    with pytest.raises(GrantError) as caught:
        resolve_correlation_dispatch(two, table=Path("settings/verb-grants.yaml"))
    assert str(caught.value).startswith("settings/verb-grants.yaml: ")
    assert "2 systems" in str(caught.value)


def test_the_run_start_frame_dispatches_only_a_fresh_run_with_a_registry(tmp_path):
    """The driver dispatches the lead from the identity run start resolved, from the tenant's grant
    alone; a resume or a run with no registry dispatches nothing, and a tenant resolved as not
    dispatching, handed to a run that would, is refused rather than dispatched unchecked."""
    from defender.investigation.driver import _correlation_dispatch_at_run_start
    from defender.tests.support.shared._fixture_uuid import fixture_uuid
    from defender.tests.support.tenancy import _tenants1106 as T1106
    from defender.tests.support.tenancy._systems1366 import run_tenant_for

    tree = tmp_path / "repo" / "defender"
    tree.mkdir(parents=True)
    T1106.place_tenant(tmp_path / "tenants", fixture_uuid("tenant:acme"), catalog=False)
    tenant = T1106.accept(tmp_path / "tenants", fixture_uuid("tenant:acme"))
    grants = T1106.run_grants(tenant.settings)

    dispatching = run_tenant_for(tenant, defender_dir=tree, dispatches_lead_zero=True)
    assert dispatching.correlation == CorrelationDispatch(system="elastic", grant=grants.correlation)
    assert _correlation_dispatch_at_run_start(
        tenant=dispatching, resume=None, lead_zero_verbs=object()) == dispatching.correlation

    resumed = run_tenant_for(tenant, defender_dir=tree, dispatches_lead_zero=False)
    assert resumed.correlation is None
    assert _correlation_dispatch_at_run_start(
        tenant=dispatching, resume=object(), lead_zero_verbs=object()) is None
    assert _correlation_dispatch_at_run_start(
        tenant=dispatching, resume=None, lead_zero_verbs=None) is None
    with pytest.raises(TypeError):
        _correlation_dispatch_at_run_start(tenant=resumed, resume=None, lead_zero_verbs=object())
