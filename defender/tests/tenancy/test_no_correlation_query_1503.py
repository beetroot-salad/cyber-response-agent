"""#1503: a tenant with no saved correlation query is a valid tenant.

Saved queries are a cache for the model, which can find the indices and the query shape itself
(owner, #1503). So a tenant whose `settings/` names no correlation template, with no
`lead-zero.yaml`, is accepted, passes the tenant check, and runs with the turn-zero
correlation lead skipped, as when the grants withhold the lead. A tenant whose grants give the
lead a query verb but which names no template is refused, naming the file to write: it granted
a step that has nothing to run. The product's starter tenant ships no saved query and no
binding (U15, #1108).
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from defender.cli._tenant_census import folder_findings
from defender.systems.correlation import correlation_grant
from defender.systems.lead_zero_config import LeadZeroConfigError, lead_zero_config_path
from defender.systems.run_tenant import catalog_templates, correlation_dispatch, refusals
from defender.systems.verb_dispositions import dispositions_path, load_dispositions
from defender.tenancy._tenant import check_knowledge_folder, check_run_settings
from defender.records._tenant_id import TenantRefused
from defender.tests.support.tenancy import _tenants1106 as T

TEMPLATE = T.REPO_ROOT / "knowledge" / "tenant-template"
FIXTURE = T.REPO_ROOT / "knowledge" / "tenant-fixture"


def _copy(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst, symlinks=True)
    return dst


def _dispatch(folder: Path):
    settings = folder / "settings"
    rows = load_dispositions(dispositions_path(settings))
    return correlation_dispatch(
        settings, catalog_templates(folder / "agent"), correlation_grant(rows))


def _unbound(folder: Path) -> Path:
    lead_zero_config_path(folder / "settings").unlink(missing_ok=True)
    return folder


# --- the starter ------------------------------------------------------------------------------

def test_the_starter_ships_no_saved_query_and_no_binding():
    assert not lead_zero_config_path(TEMPLATE / "settings").exists()
    queries = TEMPLATE / "agent" / "skills" / "gather" / "queries"
    assert sorted(queries.rglob("*.md")) == []
    assert catalog_templates(TEMPLATE / "agent") == []


# --- withheld lead, nothing named: accepted, skipped ---------------------------------------------

def test_a_tenant_naming_no_query_with_the_lead_withheld_is_accepted(tmp_path):
    folder = _unbound(_copy(TEMPLATE, tmp_path / "t"))
    check_knowledge_folder(folder, tenant_id=None)
    check_run_settings(folder / "settings")


def test_its_run_skips_the_correlation_lead(tmp_path):
    folder = _unbound(_copy(TEMPLATE, tmp_path / "t"))
    dispatch = _dispatch(folder)
    assert dispatch.system is None
    assert dispatch.template_id is None


def test_the_tenant_check_finds_no_fault_in_it(tmp_path):
    folder = _unbound(_copy(TEMPLATE, tmp_path / "t"))
    assert folder_findings(folder / "settings").lead_zero_fault is None


# --- granted lead, nothing named: refused, naming the file -------------------------------------

def test_a_tenant_granting_the_lead_but_naming_no_query_is_refused(tmp_path):
    folder = _unbound(_copy(FIXTURE, tmp_path / "t"))
    path = lead_zero_config_path(folder / "settings")
    # Any of run start's refusals: each names the file an operator edits.
    with pytest.raises(refusals()) as refused:
        _dispatch(folder)
    assert str(path) in str(refused.value)
    assert "lead-zero-correlation" in str(refused.value)
    fault = folder_findings(folder / "settings").lead_zero_fault
    assert fault is not None
    assert str(path) in fault


# --- a present file is still held to its rules ----------------------------------------------------

def test_a_present_but_empty_binding_is_still_refused(tmp_path):
    folder = _copy(TEMPLATE, tmp_path / "t")
    lead_zero_config_path(folder / "settings").write_text("", encoding="utf-8")
    with pytest.raises(LeadZeroConfigError):
        _dispatch(folder)


def test_a_binding_reached_through_a_link_is_still_refused(tmp_path):
    folder = _unbound(_copy(TEMPLATE, tmp_path / "t"))
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text("correlation_template: x.y\n", encoding="utf-8")
    lead_zero_config_path(folder / "settings").symlink_to(elsewhere)
    with pytest.raises(TenantRefused) as refused:
        check_knowledge_folder(folder, tenant_id=None)
    assert "lead-zero.yaml" in str(refused.value)


def test_a_run_copy_holding_a_linked_binding_is_refused(tmp_path):
    """A run's settings copy gets no link walk, only the plain-file rules: a present optional
    table is held to them as a required one is."""
    settings = _copy(TEMPLATE, tmp_path / "t") / "settings"
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text("correlation_template: x.y\n", encoding="utf-8")
    lead_zero_config_path(settings).symlink_to(elsewhere)
    with pytest.raises(TenantRefused) as refused:
        check_run_settings(settings)
    assert "lead-zero.yaml" in str(refused.value)


def test_a_directory_at_the_bindings_name_is_not_read_as_absent(tmp_path):
    from defender.systems.lead_zero_config import configured_template

    path = tmp_path / "lead-zero.yaml"
    path.mkdir()
    with pytest.raises(LeadZeroConfigError):
        configured_template(path)
