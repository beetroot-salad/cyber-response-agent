"""#1503: the step-zero correlation lead runs, but binds no saved query.

The lead stays (owner: it is intentional). Which system it searches is the grant's to say; the
query is the lead's own to write, with the catalog as a cache it may use (owner, #1503). So no
tenant names a correlation template: there is no `lead-zero.yaml`, run start dispatches the
lead from its grant alone, the lead's goal names no template to bind, and a leftover
`lead-zero.yaml` in a tenant repo is reported as retired and ignored.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from defender.cli._tenant_records_check import leftover_findings
from defender.investigation.lead_zero._items import correlation_contract
from defender.knowledge._corpus import iter_query_templates
from defender.systems.run_tenant import resolve_run_tenant
from defender.tenancy._tenant import check_knowledge_folder, check_run_settings
from defender.tests.support.tenancy import _tenants1106 as T

TEMPLATE = T.REPO_ROOT / "knowledge" / "tenant-template"
#: A table that grants the lead (and gather) the fixture's one query pair.
FIXTURE = T.FIXTURE_SETTINGS.parent


def _copy(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst, symlinks=True)
    return dst


def test_the_starter_names_no_correlation_query_and_ships_none():
    assert not (TEMPLATE / "settings" / "lead-zero.yaml").exists()
    assert list(iter_query_templates(TEMPLATE / "agent" / "skills" / "gather" / "queries")) == []


def test_a_tenant_without_the_file_is_accepted(tmp_path):
    folder = _copy(TEMPLATE, tmp_path / "t")
    (folder / "settings" / "lead-zero.yaml").unlink(missing_ok=True)
    check_knowledge_folder(folder, tenant_id=None)
    check_run_settings(folder / "settings")


def test_run_start_dispatches_the_granted_lead_with_no_saved_query(tmp_path):
    folder = _copy(FIXTURE, tmp_path / "t")
    (folder / "settings" / "lead-zero.yaml").unlink(missing_ok=True)
    shutil.rmtree(folder / "agent" / "skills" / "gather" / "queries", ignore_errors=True)
    readiness = resolve_run_tenant(folder / "settings", dispatches_lead_zero=True)
    assert readiness.correlation is not None
    assert readiness.correlation.system == "elastic"


def test_the_leads_goal_names_no_template_to_bind():
    goal, what = correlation_contract("alert.json")
    assert "Bind `" not in goal
    assert "template" not in " ".join(what)


def test_a_leftover_file_is_reported_retired_and_ignored(tmp_path):
    folder = _copy(TEMPLATE, tmp_path / "t")
    (folder / "settings" / "lead-zero.yaml").write_text(
        "correlation_template: elastic.correlate-alerts-by-entity\n", encoding="utf-8")
    [line] = [f for f in leftover_findings(folder) if "lead-zero.yaml" in f]
    assert "retired and ignored" in line


def test_a_tenant_still_holding_the_file_is_accepted_and_starts(tmp_path):
    """Every deployed tenant repo has the file: the upgrade must not refuse it, only report it."""
    folder = _copy(FIXTURE, tmp_path / "t")
    (folder / "settings" / "lead-zero.yaml").write_text(
        "correlation_template: elastic.no-such-template\n", encoding="utf-8")
    check_knowledge_folder(folder, tenant_id=None)
    check_run_settings(folder / "settings")
    readiness = resolve_run_tenant(folder / "settings", dispatches_lead_zero=True)
    assert readiness.correlation is not None
    assert readiness.correlation.system == "elastic"
