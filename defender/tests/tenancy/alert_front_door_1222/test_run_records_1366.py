"""#1366 slice R (read side): run start reads the tenant's current records and records which versions it used (O6, R8, O1).

Entry: `run.main` through `S.run_alert`, over a planted tenant whose directory is the memory twin (no database). The
twin is born NOT imported (R8): `planted.directory` seeds the records the planted `settings/` stands for
(`R.records_from_settings`); a test that needs other records builds its own directory with `records=` and hands it as
`directory=`. Every invented name is in `support/tenancy/_systems1366.py`.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import shutil
from pathlib import Path
from typing import Any

import pytest

from defender.investigation import ticket_writer
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S1107

#: A catalog adapter an upgrade removed: a record can still name it (the accept-all seeder stores what it is given).
RETIRED = "legacy-widget"
#: A grants table whose gather grant is on the platform-served registry alone (no adapter system, so no record needed).
TABLE_TACIT_ONLY = """\
dispositions:
  tacit-knowledge:
    health-check: {roles: [gather]}
    lookup: {roles: [gather]}
"""


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


@pytest.mark.parametrize("recorded", ["others-recorded", "no-records-at-all"])
def test_1366_r12_filtering_that_empties_gather_refuses_the_run_naming_the_grants_without_a_record(tmp_path, recorded):
    """Both systems gather is granted (cmdb, elastic) have no record, whether the tenant records other systems or none at
    all (imported with zero records): after the ignore nothing is left, so the run is refused under the empty-gather rule
    naming both grants, and not naming the import (the tenant IS imported). (#1366 R12 ordering, R8)"""
    planted = _planted()
    spec = (R.without(R.records_from_settings(planted.settings), "cmdb", "elastic") if recorded == "others-recorded"
            else R.RecordsSpec())

    refused = _run(tmp_path / "r", planted, records=spec)

    assert refused.raised is None, refused.raised
    assert all(system in (refused.refusal or "") for system in ("cmdb", "elastic")), refused.refusal
    assert R.AUTHOR[R.IMPORT] not in (refused.refusal or ""), refused.refusal
    assert (refused.run_dir, refused.main.requests) == (None, 0)


def test_1366_r8_an_imported_tenant_with_no_records_runs_with_only_the_platform_served_system(tmp_path):
    """Imported with zero records is not `not imported`: a tenant whose gather grant is on `tacit-knowledge` alone runs,
    its roster is just `tacit-knowledge`, and nothing names the import. The same tenant NOT imported is refused naming it
    (control). (#1366 R8 second half, R11)"""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), table=TABLE_TACIT_ONLY, configs={})

    ran = _run(tmp_path / "imported", planted, records=R.RecordsSpec())
    refused = _run(tmp_path / "not-imported", planted, records=None)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    assert set(ran.lifecycle_calls[0]["systems"].roster.systems) == {"tacit-knowledge"}
    assert R.AUTHOR[R.IMPORT] in (refused.refusal or ""), refused.refusal


def test_1366_r11_a_tenant_made_by_the_create_request_is_read_as_imported_with_no_systems_through_the_directory():
    """Run start reads records through `TenantDirectory.current_records`: a tenant made by `request_create` reads imported,
    empty (so it runs with no import, per the row above), and a tenant row that was only added (pre-#1366) reads not
    imported. (#1366 R11, R8, R10)"""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin = InMemoryTenantRepository()
    made = asyncio.run(twin.request_create(now=datetime.datetime(2026, 11, 10, tzinfo=datetime.UTC)))
    old = fixture_uuid("tenant:before-1366")
    asyncio.run(twin.add_tenant(old, created_at=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC), state="active"))
    directory = TenantDirectory(lambda: twin)

    created, existing = directory.current_records(made.id), directory.current_records(old)

    assert (created.imported, dict(created.systems), created.case) == (True, {}, None)
    assert not existing.imported


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


def test_1366_r12_a_record_whose_adapter_is_no_longer_a_catalog_adapter_refuses_the_run_naming_the_system(tmp_path):
    """The tenant holds a record for `legacy-widget`, a catalog-backed record (the store makes its system id its adapter
    id) for an adapter the checkout's catalog no longer has (an upgrade removed it; the seeders store what they are
    given): the run is refused at start naming `legacy-widget`; the same tenant without that record runs (control). The
    seeding is a state the store can produce, not a record naming another adapter than its own id. (#1366 R12 row
    'adapter removed by an upgrade', B3)"""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"))
    spec = R.records_from_settings(planted.settings)

    refused = _run(tmp_path / "removed", planted, records=R.added(spec, RETIRED))
    ran = _run(tmp_path / "whole", planted, records=spec)

    assert RETIRED in (refused.refusal or ""), (refused.raised, refused.refusal)
    assert (refused.run_dir, refused.main.requests) == (None, 0)
    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)


# --- C5 at run start, over RECORDS (A1) -----------------------------------------------------------------------------

COMMENT_ROUTE = ("POST", "/tickets/*/comments")


def _with_routes(spec: R.RecordsSpec, reads: tuple, writes: tuple) -> R.RecordsSpec:
    """`spec` with the ticket record's access declaring exactly `reads` and `writes` (its base and auth kept)."""
    doc = json.loads(spec.systems["ticket"].access)
    doc["reads"] = [{"method": m, "path": p} for m, p in reads]
    doc["writes"] = [{"method": m, "path": p} for m, p in writes]
    return R.edited(spec, "ticket", access=json.dumps(doc, indent=2) + "\n")


def _comment_run(tmp_path: Path, reads: tuple, writes: tuple) -> tuple[S.Drive, S.TicketStore, S.Planted]:
    """One `run.main --update-ticket` run, the REAL ticket writer over a recording store, of a tenant whose ticket RECORD
    (the case system) declares exactly `reads` and `writes`. The tenant's published folder is irrelevant: the run's tenant
    is built from the records the directory holds."""
    planted = S.plant_tenant(fixture_uuid("tenant:acme"), alert_mapping=S.ticketed_mapping())
    spec = _with_routes(R.records_from_settings(planted.settings), reads, writes)
    sink = S.TicketStore(tmp_path)
    ran = S.run_alert(tmp_path, alert=S.ticketed_alert(), tenant=planted, tickets=S.ticket_writer(sink), update_ticket=True,
                      main=S.closing_main_turns(), directory=_directory(planted, spec))
    return ran, sink, planted


_UNCOVERED = {
    "no-write-route": ((), ()),
    "another-write-route": ((), (("POST", "/tickets/*/transitions"),)),
    "read-route-matching-the-comment-route": ((COMMENT_ROUTE,), (COMMENT_ROUTE,)),
    "read-route-literal-matching-the-comment-route": ((("POST", "/tickets/ABC-1/comments"),), (COMMENT_ROUTE,)),
}


@pytest.mark.parametrize("label", list(_UNCOVERED))
def test_1366_c5_a_run_whose_stored_case_record_does_not_cover_the_comment_route_posts_nothing_and_names_the_fault(
        tmp_path, label, caplog):
    """The case system's stored declaration lacks the comment route (no write, another write, or a read route matching
    it): the run still ends, no request reaches the case store, and the run's receipt is an error naming ticket as a
    case-settings fault rather than the proxy's refusal. The tenant is the records' alone: its folder covers the route.
    (#1366 C5 run side, C3 caller 3, r5 read-route ruling, A1)"""
    reads, writes = _UNCOVERED[label]
    caplog.set_level(logging.INFO)

    ran, sink, planted = _comment_run(tmp_path, reads, writes)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0), (label, ran.raised, ran.refusal)
    assert sink.calls == [], (label, sink.calls)
    receipt = S1107.receipt(ran.run_dir)
    assert receipt is not None, label
    assert (receipt["ok"], receipt["status"]) == (False, "error"), (label, receipt)
    assert "ticket" in receipt["reason"], (label, receipt)
    assert "the credential proxy refused" not in receipt["reason"].lower(), (label, receipt)
    # Carried over from the retired file-fault test (test_ticket_writer o6): the fault is logged by the ticket writer
    # (not by whatever else warns in a run), and its reason names no host path (the planted data root and settings
    # folder, as given and resolved: the data root is not under tmp_path).
    assert [r for r in caplog.records if r.levelno >= logging.WARNING and r.name == ticket_writer.__name__], \
        (label, "the ticket writer logged no warning", [(r.name, r.getMessage()) for r in caplog.records])
    for host in (planted.root, planted.settings, planted.knowledge):
        for spelled in {str(host), str(host.resolve())}:
            assert spelled not in receipt["reason"], (label, spelled, receipt)


def test_1366_c5_a_run_whose_stored_case_record_covers_the_comment_route_posts_the_comment(tmp_path):
    """Control of the rows above on the same channel: the comment route among unrelated reads and writes is covered, and
    the comment reaches the case store. (#1366 C5, C2)"""
    ran, sink, _ = _comment_run(tmp_path, (("POST", "/tickets/*/comments/x"),),
                             (("PUT", "/elsewhere/*"), COMMENT_ROUTE))

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    assert sink.paths(S.COMMENTS_SUFFIX) == [f"/tickets/{S.TICKET_KEY}/comments"], sink.calls
    receipt = S1107.receipt(ran.run_dir)
    assert receipt is not None
    assert (receipt["ok"], receipt["status"]) == (True, "commented"), receipt


# --- where the run's record of versions lives, and what the box is never given (C1, C2) -----------------------------

def test_1366_c1_the_record_of_versions_sits_beside_the_knowledge_record_outside_the_run_folder(tmp_path):
    """The run's record of the versions it used is a sidecar in the same container as the knowledge source record
    (host-only: beside the run folder, so the box, which mounts the run folder, can neither read it nor forge it), never a
    file inside the run folder. (#1366 O6 'beside its knowledge record', C1)"""
    from defender.records._layout import RunPaths

    planted = _planted()

    ran = _run(tmp_path / "r", planted)

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    paths = RunPaths(ran.run_dir)
    used = paths.record_versions
    assert used.is_file(), used
    assert used.parent == paths.knowledge_source().parent == ran.run_dir.parent
    assert ran.run_dir not in used.parents, f"{used} is inside the run folder the box mounts"
    assert not [p for p in ran.run_dir.rglob("*") if p.name == used.name], "a copy of it sits in the run folder"


def test_1366_c2_no_record_content_reaches_the_model_or_the_run_folder_the_box_mounts(tmp_path):
    """cmdb's record carries sentinel values in its settings and its access (base and a route); after the run no sentinel is
    in anything MAIN was told, nor in any file of the run folder (the tree the box mounts). The sentinels are real
    settings, so the control is that the run used them: cmdb is up. (#1366 O6 'no record content reaches the box', C2)"""
    from defender.records._layout import RunPaths

    planted = _planted()
    spec = R.records_from_settings(planted.settings)
    settings = {**spec.systems["cmdb"].settings, "CMDB_TIMEOUT_SEC": "7"}
    access = R.declaration("http://sentinel-base-1366.test", reads=(("GET", "/sentinel-route-1366"),))
    sentinels = ("sentinel-base-1366", "sentinel-route-1366")

    ran = _run(tmp_path / "r", planted, records=R.edited(spec, "cmdb", settings=settings, access=access))

    assert (ran.raised, ran.refusal, ran.rc) == (None, None, 0)
    judged = ran.lifecycle_calls[0]["systems"]
    assert "cmdb" in judged.roster.systems
    assert "cmdb" not in judged.down
    told = ran.opening_message + ran.main_instructions
    leaked = [(s, "MAIN") for s in sentinels if s in told]
    leaked += [(s, str(f.relative_to(ran.run_dir))) for f in ran.run_dir.rglob("*") if f.is_file()
               for s in sentinels if s.encode() in f.read_bytes() and f != RunPaths(ran.run_dir).record_versions]
    assert not leaked, leaked
