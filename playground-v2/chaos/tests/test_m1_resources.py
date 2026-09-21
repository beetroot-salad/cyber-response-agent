"""M1 — a fault is a change to named resources, recorded before it is made.

The controller snapshots what each resource (a host's CMDB overlay, an ingest
pipeline) held before touching it, writes that intent to the ledger, and only
then pushes. Revert restores the snapshot — not a guessed inverse. From that
one structure follow the properties pinned here:

  * undo puts back exactly what was there, including state the controller
    did not create (a pre-existing overlay field, a pre-existing processor);
  * two active records can never own the same resource, so no revert can
    silently un-apply someone else's fault;
  * there is never a moment with a live fault and no ledger record;
  * a ledger that cannot be written stops the push before it starts;
  * a half-failed revert keeps the record, marked, and a retry redoes only
    what is still applied.
"""
from __future__ import annotations

import json

import pytest
from _fakes import NOT_FOUND, FakeExecSeam, write_profile

from chaos import ctl
from chaos.ledger import read_records
from chaos.seam import SeamError

AUTH = "logs-system.auth@custom"
SYSLOG = "logs-system.syslog@custom"


def _activate(profile_id, profiles_dir, rules_dir, ledger_dir, execer, seed=42):
    return ctl.activate(
        profile_id, seed=seed, execer=execer, profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )


# -- undo is the recorded inverse -------------------------------------------------


def test_revert_restores_a_pre_existing_overlay_rather_than_deleting_it(profiles_dir, rules_dir, ledger_dir):
    """The host already carried an overlay field nobody's ledger explains
    (a manual edit). Field-flip merges onto it; revert must put back that
    exact overlay, not wipe the host's whole entry."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    execer = FakeExecSeam(cmdb={"GET /admin/overlay/*": (200, {"overlay": {"change_window": "manual"}})})
    record = _activate("flip", profiles_dir, rules_dir, ledger_dir, execer)
    host = record["resolved_mutations"][0]["host"]

    resource = record["resources"][0]
    assert resource["before"] == {"change_window": "manual"}
    assert resource["after"] == {"change_window": "manual", "owner": record["resolved_mutations"][0]["new_value"]}

    ctl.revert(record["ledger_ref"], execer=execer, ledger_dir=ledger_dir)
    restores = [c for c in execer.mutating_calls() if c["method"] in {"PUT", "DELETE"}]
    assert restores == [
        {"target": "cmdb", "method": "PUT", "path": f"/admin/overlay/{host}", "body": {"change_window": "manual"}}
    ]


def test_revert_restores_a_pre_existing_pipeline_body_rather_than_deleting_it(profiles_dir, rules_dir, ledger_dir):
    """An operator's own `@custom` processor was already installed. The
    controller's processor is appended, and revert puts the original body
    back — a DELETE would have taken the operator's processor with it."""
    existing = {"description": "ops-owned", "processors": [{"set": {"field": "labels.env", "value": "prod"}}]}
    write_profile(profiles_dir, "drop", "data-drop", {"dataset": "system.syslog", "rate": 10})
    execer = FakeExecSeam(es={f"GET /_ingest/pipeline/{SYSLOG}": (200, {SYSLOG: existing})})
    record = _activate("drop", profiles_dir, rules_dir, ledger_dir, execer)

    put = execer.calls_for(target="es", method="PUT", path_contains=SYSLOG)
    assert len(put) == 1
    assert put[0]["body"]["description"] == "ops-owned"
    assert put[0]["body"]["processors"][0] == existing["processors"][0]
    assert "drop" in put[0]["body"]["processors"][1]

    ctl.revert(record["ledger_ref"], execer=execer, ledger_dir=ledger_dir)
    restores = [c for c in execer.calls_for(target="es") if c["method"] in {"PUT", "DELETE"}][1:]
    assert restores == [{"target": "es", "method": "PUT", "path": f"/_ingest/pipeline/{SYSLOG}", "body": existing}]


def test_revert_of_a_pipeline_that_did_not_exist_deletes_it(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "drop", "data-drop", {"dataset": "system.syslog", "rate": 10})
    execer = FakeExecSeam(es={"GET /_ingest/pipeline/*": NOT_FOUND})
    record = _activate("drop", profiles_dir, rules_dir, ledger_dir, execer)
    assert record["resources"][0]["before"] is None

    ctl.revert(record["ledger_ref"], execer=execer, ledger_dir=ledger_dir)
    assert execer.calls_for(target="es", method="DELETE") == [
        {"target": "es", "method": "DELETE", "path": f"/_ingest/pipeline/{SYSLOG}", "body": None}
    ]


def test_the_ledger_records_before_and_after_for_every_resource(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "flip2", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 2})
    record = _activate("flip2", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    on_disk = read_records(ledger_dir)[0]
    assert on_disk["status"] == "active"
    assert len(on_disk["resources"]) == 2
    for res in on_disk["resources"]:
        assert res["kind"] == "cmdb-overlay"
        assert res["before"] is None
        assert res["applied"] is True
        assert set(res["after"]) == {"owner"}
    assert on_disk["live_fingerprint"] == record["live_fingerprint"]


# -- one owner per resource ---------------------------------------------------------


def test_a_second_activation_on_an_owned_pipeline_is_refused(profiles_dir, rules_dir, ledger_dir):
    """Every schema-drift profile targets the auth pipeline. Stacking a
    second one would let either revert take the other's fault down (or,
    with a whole-body PUT, silently overwrite it while its ledger record
    still says live)."""
    write_profile(profiles_dir, "drift-a", "schema-drift", {"rename": {"from": "user.name", "to": "user.id"}})
    write_profile(profiles_dir, "drift-b", "schema-drift", {"remove": "source.port"})
    execer = FakeExecSeam()
    first = _activate("drift-a", profiles_dir, rules_dir, ledger_dir, execer)

    second_seam = FakeExecSeam()
    with pytest.raises(ctl.OverlapRefused, match=first["ledger_ref"]):
        _activate("drift-b", profiles_dir, rules_dir, ledger_dir, second_seam)
    assert second_seam.mutating_calls() == []
    assert [r["profile_id"] for r in read_records(ledger_dir)] == ["drift-a"]

    # ...and after the first is reverted, the second is fine.
    ctl.revert(first["ledger_ref"], execer=execer, ledger_dir=ledger_dir)
    _activate("drift-b", profiles_dir, rules_dir, ledger_dir, second_seam)


def test_a_second_activation_on_an_owned_host_is_refused(profiles_dir, rules_dir, ledger_dir):
    """Same seed, same host every time (O3 — determinism is the point), so
    two cmdb-stale activations with the default seed collide on one host."""
    write_profile(profiles_dir, "owner", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    write_profile(profiles_dir, "crit", "cmdb-stale", {"variant": "field-flip", "field": "criticality", "hosts": 1})
    _activate("owner", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    with pytest.raises(ctl.OverlapRefused):
        _activate("crit", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())


def test_ownership_is_refused_at_plan_time_not_apply_time(profiles_dir, rules_dir, ledger_dir):
    """The runner posts the synthetic CR between plan and apply. Everything
    that can fail without a side effect belongs in plan — a collision with
    a `--keep-chaos` record included — or the CR is left open for a run
    that never fired."""
    write_profile(profiles_dir, "owner", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    _activate("owner", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    with pytest.raises(ctl.OverlapRefused):
        ctl.plan("owner", seed=42, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir,
                 ledger_dir=ledger_dir)


def test_plan_snapshots_and_apply_refuses_a_plan_the_world_moved_under(profiles_dir, rules_dir, ledger_dir):
    """The plan's before-state is what revert will restore. If the resource
    changed between plan and apply, applying would restore the wrong
    thing — so apply re-reads and refuses rather than trusting the plan."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    planned = ctl.plan("flip", seed=42, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir,
                       ledger_dir=ledger_dir)
    assert planned["resources"][0]["before"] is None, "plan did not snapshot"

    moved = FakeExecSeam(cmdb={"GET /admin/overlay/*": (200, {"overlay": {"owner": "someone.else"}})})
    with pytest.raises(ctl.PlanStale):
        ctl.apply(planned, execer=moved, ledger_dir=ledger_dir)
    assert moved.mutating_calls() == []
    assert read_records(ledger_dir) == []

    # The same plan against an unchanged world applies.
    ctl.apply(planned, execer=FakeExecSeam(), ledger_dir=ledger_dir)
    assert read_records(ledger_dir)[0]["status"] == "active"


def test_a_set_but_empty_overlay_is_a_before_state_not_absence(profiles_dir, rules_dir, ledger_dir):
    """The stub lists any name with an overlay, even `{}`. Restoring it as
    'absent' would DELETE the key and make the name vanish from /hosts."""
    write_profile(profiles_dir, "phantom", "cmdb-stale", {"variant": "phantom-host", "hosts": 1})
    execer = FakeExecSeam(cmdb={"GET /admin/overlay/*": (200, {"overlay": {}})})
    record = _activate("phantom", profiles_dir, rules_dir, ledger_dir, execer)
    assert record["resources"][0]["before"] == {}

    ctl.revert(record["ledger_ref"], execer=execer, ledger_dir=ledger_dir)
    restores = [c for c in execer.mutating_calls() if c["method"] in {"PUT", "DELETE"}]
    assert [(c["method"], c["body"]) for c in restores] == [("PUT", {})]


# -- intent before push -------------------------------------------------------------


def test_the_record_is_on_disk_before_the_first_mutation_is_pushed(profiles_dir, rules_dir, ledger_dir):
    """Observed from inside the seam: at the moment the first POST arrives,
    a pending record naming this profile already exists. A record written
    only after the push leaves a window — a crash, a ledger write failure —
    with a live fault nothing can find."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    seen: list[list[dict]] = []

    class _Observing(FakeExecSeam):
        def cmdb_request(self, method, path, body=None):
            if method == "POST":
                seen.append(read_records(ledger_dir))
            return super().cmdb_request(method, path, body)

    _activate("flip", profiles_dir, rules_dir, ledger_dir, _Observing())
    assert len(seen) == 1
    pending = seen[0]
    assert len(pending) == 1 and pending[0]["profile_id"] == "flip"
    assert pending[0]["status"] == "pending"
    assert pending[0]["activated_at"] is None
    assert all(res["applied"] is False for res in pending[0]["resources"])


def test_an_unwritable_ledger_stops_the_push_before_it_starts(profiles_dir, rules_dir, tmp_path):
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    not_a_dir = tmp_path / "ledger-as-file"
    not_a_dir.write_text("")
    execer = FakeExecSeam()
    with pytest.raises(OSError):
        _activate("flip", profiles_dir, rules_dir, not_a_dir, execer)
    assert execer.mutating_calls() == []


def test_a_ledger_write_failure_after_a_push_rolls_the_push_back(profiles_dir, rules_dir, ledger_dir):
    """The push landed; the record could not be updated to say so. Left
    alone, the stack holds a fault whose record says 'not applied' — revert
    would skip it and stamp it reverted. The whole step is the transaction:
    a write failure after the push rolls the push back."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})

    class _BreakLedgerOnPush(FakeExecSeam):
        def cmdb_request(self, method, path, body=None):
            result = super().cmdb_request(method, path, body)
            if method == "POST":
                # The record's atomic-write temp path becomes a directory,
                # so the next write_record raises.
                (pending,) = ledger_dir.glob("*.json")
                (ledger_dir / (pending.name + ".tmp")).mkdir()
            return result

    execer = _BreakLedgerOnPush()
    with pytest.raises(ctl.ChaosApplyError, match="rolled back"):
        _activate("flip", profiles_dir, rules_dir, ledger_dir, execer)

    assert [c["method"] for c in execer.mutating_calls()] == ["POST", "DELETE"], "the landed push was not restored"
    assert read_records(ledger_dir) == []


def test_a_failed_rollback_keeps_the_record_marked_failed(profiles_dir, rules_dir, ledger_dir):
    """Second host's POST fails, and the first host's restore fails too: the
    first host is live on the stack. That must stay findable — the record
    is kept, marked, with the live resource still `applied`."""
    write_profile(profiles_dir, "flip2", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 2})
    posts = 0

    class _Seam(FakeExecSeam):
        def cmdb_request(self, method, path, body=None):
            nonlocal posts
            if method == "POST":
                posts += 1
                if posts == 2:
                    raise SeamError("cmdb POST: HTTP 500", status=500)
            if method == "DELETE":
                raise SeamError("cmdb DELETE: transport failed", status=None)
            return super().cmdb_request(method, path, body)

    with pytest.raises(ctl.ChaosApplyError, match="rollback left resources live"):
        _activate("flip2", profiles_dir, rules_dir, ledger_dir, _Seam())

    (record,) = read_records(ledger_dir)
    assert record["status"] == "failed"
    assert [res["applied"] for res in record["resources"]] == [True, False]


# -- revert is retryable ------------------------------------------------------------


def test_a_partial_revert_keeps_going_then_raises_and_a_retry_finishes_the_job(
    profiles_dir, rules_dir, ledger_dir
):
    write_profile(profiles_dir, "flip2", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 2})
    record = _activate("flip2", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    hosts = [res["name"] for res in record["resources"]]

    class _FirstDeleteFails(FakeExecSeam):
        def cmdb_request(self, method, path, body=None):
            if method == "DELETE" and path.endswith(hosts[-1]):  # reverse order: last host first
                self.calls.append({"target": "cmdb", "method": "DELETE", "path": path, "body": body})
                raise SeamError("cmdb DELETE: HTTP 500", status=500)
            return super().cmdb_request(method, path, body)

    failing = _FirstDeleteFails()
    with pytest.raises(ctl.ChaosApplyError):
        ctl.revert(record["ledger_ref"], execer=failing, ledger_dir=ledger_dir)
    # Both restores were attempted despite the first failing.
    assert [c["path"] for c in failing.calls_for(method="DELETE")] == [f"/admin/overlay/{h}" for h in reversed(hosts)]

    (on_disk,) = read_records(ledger_dir)
    assert on_disk["status"] == "revert-failed"
    assert not on_disk.get("reverted_at")
    assert {res["name"]: res["applied"] for res in on_disk["resources"]} == {hosts[0]: False, hosts[1]: True}

    retry = FakeExecSeam()
    ctl.revert(record["ledger_ref"], execer=retry, ledger_dir=ledger_dir)
    assert [c["path"] for c in retry.calls_for(method="DELETE")] == [f"/admin/overlay/{hosts[1]}"]
    assert read_records(ledger_dir)[0]["status"] == "reverted"


def test_revert_all_attempts_every_record_and_reports_the_failures(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    write_profile(profiles_dir, "drop", "data-drop", {"dataset": "system.syslog", "rate": 10})
    a = _activate("flip", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    b = _activate("drop", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())

    execer = FakeExecSeam(cmdb={"DELETE /admin/overlay/*": (500, {"error": "cmdb 500"})})
    reverted, failed = ctl.revert_all(execer=execer, ledger_dir=ledger_dir)

    assert [r["ledger_ref"] for r in reverted] == [b["ledger_ref"]]
    assert set(failed) == {a["ledger_ref"]}
    assert execer.calls_for(target="es", method="DELETE"), "the second record was never attempted"


def test_a_malformed_ledger_file_is_reported_and_does_not_block_the_others(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """One hand-edited file must not take `status` and `revert --all` down
    with it — the valid records still need reverting."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    record = _activate("flip", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    (ledger_dir / "chaos-handedited.json").write_text('{"ledger_ref": "chaos-handedited", "oops": ,}')

    result = ctl.status(
        execer=FakeExecSeam(cmdb={"GET /hosts": (0, {"hosts": []})}, es={"GET /_ingest/pipeline/*": NOT_FOUND}),
        ledger_dir=ledger_dir,
    )
    assert [n["type"] for n in result["notes"]] == ["malformed-ledger-file"]
    assert result["notes"][0]["file"] == "chaos-handedited.json"

    reverted, failed = ctl.revert_all(execer=FakeExecSeam(), ledger_dir=ledger_dir)
    assert [r["ledger_ref"] for r in reverted] == [record["ledger_ref"]]
    assert failed == {}

    # ...but nothing new is planned while ownership cannot be established:
    # the unreadable file may be the one that owns the resource.
    with pytest.raises(ctl.OverlapRefused, match="unreadable"):
        ctl.plan("flip", seed=42, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir,
                 ledger_dir=ledger_dir)


def test_revert_cli_refuses_a_ref_combined_with_all():
    """`revert chaos-abc --all` used to silently ignore the ref and revert
    everything — including a fault another run was holding open."""
    parser = ctl.build_arg_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["revert", "chaos-abc123", "--all"])
    with pytest.raises(SystemExit):
        parser.parse_args(["revert"])
    assert parser.parse_args(["revert", "--all"]).all is True
    assert parser.parse_args(["revert", "chaos-abc123"]).ledger_ref == "chaos-abc123"


# -- the ledger file itself ---------------------------------------------------------


def test_ledger_writes_leave_no_temp_file_and_a_valid_record(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    record = _activate("flip", profiles_dir, rules_dir, ledger_dir, FakeExecSeam())
    files = sorted(p.name for p in ledger_dir.iterdir())
    assert files == [f"{record['ledger_ref']}.json"]
    json.loads((ledger_dir / files[0]).read_text())
