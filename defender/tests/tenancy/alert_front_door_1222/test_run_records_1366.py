"""#1366 slice R (read side): run start reads the tenant's current records and records which versions it used (O6, R8, O1).

Entry: `run.main` through `S.run_alert`, over a planted tenant whose directory is the memory twin (no database). The
twin is born NOT imported (R8): `planted.directory` seeds the records the planted `settings/` stands for
(`R.records_from_settings`); a test that needs other records builds its own directory with `records=` and hands it as
`directory=`. Every invented name is in `support/tenancy/_systems1366.py`.
"""
from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S


def _directory(planted: S.Planted, records: Any) -> Any:
    return tenant_directory(planted.root, planted.tenant_id, alert_mapping=S.current_mapping(planted), records=records)


def _planted() -> S.Planted:
    return S.plant_tenant(fixture_uuid("tenant:acme"))


def _warned(caplog: pytest.LogCaptureFixture, system: str) -> list[str]:
    """Warning lines that name `system` and a grant (the run ignored a grant on a system with no usable record)."""
    return [r.getMessage() for r in caplog.records
            if r.levelno >= logging.WARNING and system in r.getMessage() and "grant" in r.getMessage().lower()]


def _run(tmp_path: Path, planted: S.Planted, records: Any = R.DERIVED) -> S.Drive:
    return S.run_alert(tmp_path, tenant=planted, main=S.closing_main_turns(), directory=_directory(planted, records))


def test_1366_r8_a_run_of_a_tenant_not_yet_imported_is_refused_naming_the_import(tmp_path):
    """Before the import the run is refused naming `tenant.py import`, with no run folder and no model call; the same
    tenant with its records runs. (#1366 R8, O6)"""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"))

    refused = _run(tmp_path / "before", planted, records=None)

    assert refused.raised is None, refused.raised
    assert R.AUTHOR[R.IMPORT] in (refused.refusal or ""), refused.refusal
    assert (refused.run_dir, refused.main.requests) == (None, 0)

    ran = _run(tmp_path / "after", planted)
    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)


def test_1366_o6_a_run_uses_the_current_versions_and_records_them_beside_its_knowledge_record(tmp_path):
    """cmdb at version 2, change-mgmt disabled at version 4, the rest at 1: the run's roster is the enabled records'
    systems plus tacit-knowledge, and its record of what it used names every current version it read, the disabled one
    too, and the case version. (#1366 O6, O1, P3, R12)"""
    from defender.records._layout import RunPaths

    planted = S.plant_tenant(fixture_uuid("tenant:acme"))
    spec = R.records_from_settings(planted.settings)
    spec = R.edited(R.edited(spec, "cmdb", version=2), "change-mgmt", version=4, enabled=False)

    ran = _run(tmp_path / "run", planted, records=spec)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    assert set(ran.lifecycle_calls[0]["systems"].roster.systems) == (set(spec.systems) - {"change-mgmt"}) | {"tacit-knowledge"}
    used = json.loads(RunPaths(ran.run_dir).record_versions.read_text(encoding="utf-8"))
    assert used == {"systems": {s: v.version for s, v in spec.systems.items()}, "case": 1}


def test_1366_r8_not_imported_is_refused_before_the_missing_alert_mapping_is_looked_at(tmp_path):
    """A tenant with neither records nor an alert mapping is refused naming the import, not the mapping. (#1366 R8 order)"""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=None)

    refused = _run(tmp_path / "r", planted, records=None)

    assert R.AUTHOR[R.IMPORT] in (refused.refusal or ""), refused.refusal
    assert (refused.run_dir, refused.main.requests) == (None, 0)


def test_1366_o6_a_run_with_no_case_record_runs_and_records_no_case_version(tmp_path):
    """A tenant with systems and no case record runs, and its record of what it used has `case: null`. (#1366 O6, H7)"""
    from defender.records._layout import RunPaths

    planted = _planted()
    spec = R.RecordsSpec(R.records_from_settings(planted.settings).systems, None)

    ran = _run(tmp_path / "r", planted, records=spec)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    used = json.loads(RunPaths(ran.run_dir).record_versions.read_text(encoding="utf-8"))
    assert used == {"systems": {s: 1 for s in spec.systems}, "case": None}


@pytest.mark.parametrize("broken", ["settings", "access"])
def test_1366_o6_a_system_is_judged_from_its_record_not_its_folder(tmp_path, broken):
    """cmdb's folder is complete but its record's settings (CHANGE-ME) or access (not a declaration) are not: cmdb is down
    at run start while the rest runs. (#1366 O6, P2, R12 upgrade-invalidated row)"""
    planted = _planted()
    spec = R.records_from_settings(planted.settings)
    change = {"settings": {"CMDB_TIMEOUT_SEC": "CHANGE-ME"}} if broken == "settings" else {"access": "not: [a declaration"}

    ran = _run(tmp_path / "r", planted, records=R.edited(spec, "cmdb", **{broken: change[broken]}))

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    down = ran.lifecycle_calls[0]["systems"].down
    assert "cmdb" in down, dict(down)
    assert "elastic" not in down, dict(down)


def test_1366_o6_a_system_whose_folder_is_gone_runs_from_its_record(tmp_path):
    """cmdb has no `config.env` in the tenant's folder but a complete record: it is up. (#1366 O6, P1)"""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), omit_systems=("cmdb",))
    folders = R.records_from_settings(planted.settings)
    spec = R.RecordsSpec({**folders.systems, "cmdb": R.SysSpec({"CMDB_TIMEOUT_SEC": "10"}, R.declaration("http://soc-playground:8001"))},
                         folders.case)

    ran = _run(tmp_path / "r", planted, records=spec)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    assert "cmdb" in ran.lifecycle_calls[0]["systems"].roster.systems
    assert "cmdb" not in ran.lifecycle_calls[0]["systems"].down


@pytest.mark.parametrize("relation", ["disabled", "never-recorded"])
def test_1366_r12_a_granted_system_with_no_enabled_record_is_left_out_of_the_roster_with_one_warning(tmp_path, caplog, relation):
    """cmdb is granted, but its record is disabled or there is none: the run proceeds without it, its roster is the rest,
    and one warning names cmdb as a granted system that was ignored; elastic, still recorded, is in it. (#1366 R12)"""
    planted = _planted()
    spec = R.records_from_settings(planted.settings)
    spec = R.edited(spec, "cmdb", enabled=False) if relation == "disabled" else R.without(spec, "cmdb")

    with caplog.at_level(logging.WARNING):
        ran = _run(tmp_path / "r", planted, records=spec)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    roster = ran.lifecycle_calls[0]["systems"].roster.systems
    assert "cmdb" not in roster
    assert {"elastic", "tacit-knowledge"} <= set(roster)
    assert len(_warned(caplog, "cmdb")) == 1, caplog.text


def test_1366_r12_unrecorded_systems_nobody_granted_are_left_out_silently(tmp_path, caplog):
    """The template's ungranted systems have no record: the run proceeds, they are not in the roster, and nothing warns
    about them (the control of the warning rows above). (#1366 R12)"""
    planted = _planted()
    ungranted = ("identity", "host-state", "threat-intel", "change-mgmt")
    spec = R.without(R.records_from_settings(planted.settings), *ungranted)

    with caplog.at_level(logging.WARNING):
        ran = _run(tmp_path / "r", planted, records=spec)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    assert not set(ungranted) & set(ran.lifecycle_calls[0]["systems"].roster.systems)
    assert not [system for system in ungranted if _warned(caplog, system)], caplog.text


def test_1366_r12_a_grant_on_a_system_the_catalog_does_not_have_still_refuses_the_run(tmp_path):
    """A gather grant on `nonexistent-system`, recorded or not, is refused as today, naming it: the grants-without-records
    leniency is for catalog systems only. (#1366 R12 last row)"""
    table = S.TABLE_ELASTIC + "  nonexistent-system:\n    look: {roles: [gather]}\n"
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), table=table)

    refused = _run(tmp_path / "r", planted)

    assert "nonexistent-system" in (refused.refusal or ""), (refused.raised, refused.refusal)
    assert (refused.run_dir, refused.main.requests) == (None, 0)


def test_1366_r12_filtering_that_empties_gather_refuses_the_run_naming_the_grants_without_a_record(tmp_path):
    """Both systems gather is granted (cmdb, elastic) have no record: after the ignore nothing is left, so the run is
    refused under the empty-gather rule naming both. (#1366 R12 ordering)"""
    planted = _planted()
    spec = R.without(R.records_from_settings(planted.settings), "cmdb", "elastic")

    refused = _run(tmp_path / "r", planted, records=spec)

    assert refused.raised is None, refused.raised
    assert all(system in (refused.refusal or "") for system in ("cmdb", "elastic")), refused.refusal
    assert (refused.run_dir, refused.main.requests) == (None, 0)


@pytest.mark.parametrize("table", [S.TABLE_ELASTIC, S.TABLE_WITHHELD], ids=["granted", "withheld"])
def test_1366_r12_a_record_naming_an_adapter_an_upgrade_removed_refuses_the_run_naming_the_system(tmp_path, table):
    """cmdb is recorded (granted by one table, withheld by the other) but the checkout's adapters no longer include it:
    refused at start, naming cmdb, whatever the grants say; the same tenant over the whole checkout runs (control).
    (#1366 R12, design flow 'upgrade drops a catalog adapter')"""
    from defender.systems.verbs import read_roster

    planted = S.plant_tenant(fixture_uuid("tenant:acme"), table=table)
    adapters = tmp_path / "pruned" / "integrations"
    shutil.copytree(S.DEFENDER / "integrations", adapters, ignore=shutil.ignore_patterns("__pycache__"))
    (adapters / "cmdb_adapter.py").unlink()

    refused = S.run_alert(tmp_path / "removed", tenant=planted, main=S.closing_main_turns(), roster=read_roster(adapters),
                          directory=_directory(planted, R.DERIVED))
    ran = _run(tmp_path / "whole", planted)

    assert "cmdb" in (refused.refusal or ""), (refused.raised, refused.refusal)
    assert (refused.run_dir, refused.main.requests) == (None, 0)
    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
