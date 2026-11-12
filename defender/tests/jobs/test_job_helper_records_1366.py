"""#1366 x #1170: a job's host helper reads the tenant's records once and hands them to its job container.

The container reads no database (#1170 O3), so the helper does every step that reads records: it refuses a tenant that
is not imported (R8) before the container exists, writes the run's record of versions (O6) beside the run folder, and
hands the records it read in the launch facts. The container builds its tenant from those records and judges its
systems itself, since that judgement runs adapter code (#1170 O5, N7)."""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.jobs._job_helper import ContainerStandIn, drive_helper, make_signer

process_state = J.process_state
scene = J.scene


def _records():
    from defender.tenancy.models import CaseRecord, SystemRecord, TenantRecords

    return TenantRecords(imported=True, systems={
        "elastic": SystemRecord(system_id="elastic", version=3, adapter_id="elastic", settings={"ELASTIC_URL": "u"},
                                access="kind: http-proxy\n", credential_generation=2),
        "crm": SystemRecord(system_id="crm", version=1, enabled=False, custom_ref=("adapters/crm.py", "abc123")),
    }, case=CaseRecord(version=4, system_id="ticket", comment_body="{summary}"))


def test_1366_records_handed_over_the_job_socket_read_back_as_they_were():
    """What the helper hands (`as_wire`) is plain JSON data that reads back (`from_wire`) to the same records, a
    disabled system, a custom adapter reference and the case record included; no case reads back as none."""
    from defender.tenancy.models import TenantRecords

    records = _records()
    assert TenantRecords.from_wire(json.loads(json.dumps(records.as_wire()))) == records
    bare = TenantRecords(imported=False)
    assert TenantRecords.from_wire(json.loads(json.dumps(bare.as_wire()))) == bare


@pytest.mark.parametrize("damage", ["missing", "not-a-mapping", "version-text", "version-bool", "settings-number",
                                    "ref-short", "case-text"])
def test_1366_records_that_are_not_as_the_helper_wrote_them_are_refused(damage):
    """Handed records the helper did not write in that shape are a `ValueError`, never records with a field guessed."""
    from defender.tenancy.models import TenantRecords

    wire = _records().as_wire()
    elastic = wire["systems"]["elastic"]
    if damage == "missing":
        wire = None
    elif damage == "not-a-mapping":
        wire = [wire]
    elif damage == "version-text":
        elastic["version"] = "3"
    elif damage == "version-bool":
        elastic["version"] = True
    elif damage == "settings-number":
        elastic["settings"] = {"ELASTIC_URL": 1}
    elif damage == "ref-short":
        wire["systems"]["crm"]["custom_ref"] = ["adapters/crm.py"]
    else:
        wire["case"] = "ticket"
    with pytest.raises(ValueError):  # noqa: PT011 — any ValueError naming the field
        TenantRecords.from_wire(wire)


def _investigation(scene) -> tuple[str, list[str]]:
    inv = str(uuid.uuid4())
    scene.plant(inv)
    return inv, scene.argv("investigation", inv)


@pytest.mark.postgres
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the helper is Linux only")
def test_1366_the_helper_hands_its_container_the_records_it_read_and_writes_the_runs_versions(scene):
    """The launch facts carry the tenant's current records as the database holds them, and the run's record of versions
    beside its run folder names those versions: one read, at the helper (O6)."""
    from defender.records import RunPaths
    from defender.systems.run_tenant import entry_directory
    from defender.tenancy import requested_tenant_id
    from defender.tenancy.models import TenantRecords

    inv, argv = _investigation(scene)
    got: dict = {}

    def job(c) -> int:
        got["launch"] = c.request("launch")
        return 0

    docker = ContainerStandIn(job)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.job_error is None, docker.job_error
    held = entry_directory(None).current_records(requested_tenant_id(scene.tenant))
    assert held.imported, "premise: the scene's tenant is imported"
    assert TenantRecords.from_wire(got["launch"]["records"]) == held
    versions = json.loads(RunPaths(Path(got["launch"]["run_dir"])).record_versions.read_text(encoding="utf-8"))
    assert versions == {"systems": {s: r.version for s, r in held.systems.items()},
                        "case": None if held.case is None else held.case.version}


@pytest.mark.postgres
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the helper is Linux only")
def test_1366_a_tenant_not_imported_is_refused_by_the_helper_and_no_container_starts(scene, capfd):
    """R8 at the helper: a tenant with no imported records is `setup: refused` naming the import, no container started,
    and its alert mapping never consulted (the refusal names the import though the mapping is gone too)."""
    from defender.records.job_facts import BOX_NOT_STARTED, SETUP_REFUSED
    from defender.records.job_lane import JobEnd
    from defender.tests.support.tenancy._systems1366 import drop_records

    inv, argv = _investigation(scene)
    drop_records(scene.dsn, scene.tenant)
    scene.unmap()  # were the mapping read first, the refusal would name the mapping
    docker = ContainerStandIn(lambda c: 0)
    ran = drive_helper(scene, argv, docker=docker, signer=make_signer())

    assert ran.raised is None, ran.raised
    assert docker.boxes == [], "a container was started for a tenant that is not imported"
    assert scene.end(inv) == JobEnd(SETUP_REFUSED, BOX_NOT_STARTED, False, False, None)
    from defender.systems.run_tenant import not_imported_text

    err = capfd.readouterr().err
    assert not_imported_text(scene.tenant) in err, err
