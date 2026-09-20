"""O1 — `status` reads live state and flags disagreement with the ledger.

Persistence is asymmetric and that is the whole point of this check:

  * the CMDB overlay is in-memory, so restarting the cmdb container silently
    reverts a stale-CMDB profile the ledger still calls active;
  * an ingest-pipeline processor lives in cluster state, so it silently survives
    restarts and lever cycles after the ledger says it was reverted.

So status must not trust the ledger. It fetches the live overlay (GET /hosts,
diffed against the *baked* /opt/cmdb/inventory.yaml read out of the container,
not the working-tree copy) and the live @custom pipelines, and reports drift
both ways.
"""
from __future__ import annotations

import json

import pytest

from _fakes import NOT_FOUND, FakeExecSeam, write_profile

from chaos import ctl
from chaos.seam import SeamError

BAKED_INVENTORY = "/opt/cmdb/inventory.yaml"


def _hosts_payload(inventory: dict, overrides: dict | None = None) -> dict:
    hosts = [dict(h) for h in inventory["hosts"]]
    for host in hosts:
        host.update((overrides or {}).get(host["name"], {}))
    return {"total": len(hosts), "hosts": hosts}


def _activate_stale(profiles_dir, rules_dir, ledger_dir, profile_id="stale-owner"):
    write_profile(
        profiles_dir,
        profile_id,
        "cmdb-stale",
        {"variant": "field-flip", "field": "owner", "hosts": 1},
    )
    return ctl.activate(
        profile_id,
        seed=42,
        execer=FakeExecSeam(),
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )


def test_status_flags_a_silently_reverted_overlay(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """Ledger says active; the cmdb container was restarted, so the overlay is gone."""
    record = _activate_stale(profiles_dir, rules_dir, ledger_dir)
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},  # pure base — overlay lost
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )

    result = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    drift = result["drift"]
    assert drift, "status trusted the ledger instead of the stack"
    blob = json.dumps(drift, default=str)
    assert record["profile_id"] in blob
    assert record["resolved_mutations"][0]["host"] in blob


def test_status_flags_a_stray_overlay_no_ledger_record_explains(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """An empty ledger — nothing was ever activated through this controller —
    but the live overlay disagrees with the baked inventory anyway (a manual
    admin edit, or a ledger that was lost). A status that only checks each
    ledger record's own claimed mutation sees nothing here; status must not
    trust the ledger's silence either."""
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory, {"db-1": {"owner": "team.mystery"}}))},
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )

    result = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    drift = result["drift"]
    assert drift, "an unattributed CMDB change was not reported just because no ledger record predicted it"
    assert "db-1" in json.dumps(drift, default=str)


def test_status_flags_a_pipeline_that_outlived_its_revert(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """Ledger says nothing is active; a drop processor is still in cluster state."""
    stray = {
        "logs-system.syslog@custom": {
            "processors": [
                {"drop": {"if": "ctx.message != null && ((ctx.message + '42').hashCode() & 0x7fffffff) % 100 < 25"}}
            ]
        }
    }
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": (0, stray)},
        files={BAKED_INVENTORY: inventory_text},
    )

    result = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    drift = result["drift"]
    assert drift, "a stray @custom pipeline was not reported"
    assert "logs-system.syslog@custom" in json.dumps(drift, default=str)


def test_status_is_quiet_when_live_state_matches_the_ledger(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """Positive control — otherwise 'flags drift' is satisfied by always shouting."""
    record = _activate_stale(profiles_dir, rules_dir, ledger_dir, "stale-owner-ok")
    mutation = record["resolved_mutations"][0]
    live = FakeExecSeam(
        cmdb={
            "GET /hosts": (
                0,
                _hosts_payload(inventory, {mutation["host"]: {"owner": mutation["new_value"]}}),
            )
        },
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )

    result = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)
    assert result["drift"] == []
    # ...and the profile is still reported as live, not simply forgotten.
    assert record["profile_id"] in json.dumps(result, default=str)


def test_status_reads_the_baked_inventory_not_the_working_tree(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """The image's copy can drift from the repo's; status must diff against the
    container's."""
    _activate_stale(profiles_dir, rules_dir, ledger_dir, "stale-owner-baked")
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )

    ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    reads = live.calls_for(target="file")
    assert reads, "status did not read the container's inventory at all"
    assert {c["path"] for c in reads} == {BAKED_INVENTORY}
    assert all(c["container"] == "cmdb" for c in reads)


def test_status_raises_on_an_unreachable_backend_rather_than_reporting_drift(
    profiles_dir, rules_dir, ledger_dir, inventory_text
):
    """cmdb down for a moment used to read as 'no live hosts' — eleven
    `cmdb-host-missing` entries indistinguishable from real drift, and an
    operator's `revert --all` on that output stamps still-live faults as
    reverted. A backend that cannot be read is an error, not a finding."""
    _activate_stale(profiles_dir, rules_dir, ledger_dir, "stale-owner-down")
    cmdb_down = FakeExecSeam(
        cmdb={"GET /hosts": (500, {"error": "connection refused"})},
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )
    with pytest.raises(SeamError):
        ctl.status(execer=cmdb_down, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    es_down = FakeExecSeam(
        cmdb={"GET /hosts": (0, {"total": 0, "hosts": []})},
        es={"GET /_ingest/pipeline/*": (500, {"error": "transport"})},
        files={BAKED_INVENTORY: inventory_text},
    )
    with pytest.raises(SeamError):
        ctl.status(execer=es_down, profiles_dir=profiles_dir, ledger_dir=ledger_dir)


def test_status_flags_a_pipeline_whose_body_no_longer_matches_the_record(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """Presence is not enough: the pipeline exists but somebody (a Fleet
    upgrade, a hand edit) replaced its processors. The record's after-state
    is what the stack must still hold."""
    write_profile(
        profiles_dir, "drop-syslog", "data-drop", {"target_stream": "logs-system.syslog-*", "rate": 25}
    )
    record = ctl.activate(
        "drop-syslog", seed=42, execer=FakeExecSeam(), profiles_dir=profiles_dir,
        rules_dir=rules_dir, ledger_dir=ledger_dir,
    )
    pipeline = record["resources"][0]["name"]
    overwritten = {pipeline: {"processors": [{"set": {"field": "x", "value": "y"}}]}}
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": (0, overwritten)},
        files={BAKED_INVENTORY: inventory_text},
    )
    drift = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)["drift"]
    assert [d["type"] for d in drift] == ["pipeline-mismatch"]
    assert drift[0]["pipeline"] == pipeline and drift[0]["profile_id"] == "drop-syslog"

    matching = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": (0, {pipeline: record["resources"][0]["after"]})},
        files={BAKED_INVENTORY: inventory_text},
    )
    assert ctl.status(execer=matching, profiles_dir=profiles_dir, ledger_dir=ledger_dir)["drift"] == []


def test_status_reports_a_record_whose_activation_never_completed(
    profiles_dir, rules_dir, ledger_dir, inventory, inventory_text
):
    """A pending record (the controller died between writing intent and
    finishing the push) is neither active nor absent; status names it so
    the operator reverts it rather than wondering why nothing is live."""
    from chaos.ledger import write_record

    write_record(
        ledger_dir,
        {
            "ledger_ref": "chaos-pending01",
            "profile_id": "stale-owner-pending",
            "seed": 1,
            "mode": "cmdb-stale",
            "resolved_mutations": [],
            "resources": [{"kind": "cmdb-overlay", "name": "web-1", "before": None, "after": {"owner": "x"},
                           "patches": [{"owner": "x"}], "applied": False}],
            "status": "pending",
            "activated_at": None,
            "live_fingerprint": "abc",
        },
    )
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )
    drift = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)["drift"]
    assert [d["type"] for d in drift] == ["incomplete-record"]
    assert drift[0]["ledger_ref"] == "chaos-pending01"
    # An unapplied resource is not expected on the stack — no phantom drift for it.


def test_activate_resolves_against_the_baked_inventory_not_the_working_tree(
    profiles_dir, rules_dir, ledger_dir, inventory
):
    """The image was built from an older inventory: one host has a different
    owner there, and one working-tree host does not exist in the container
    at all. The mutation must be resolved against what the stack serves —
    otherwise the ledger's old_value is wrong from the start and status
    immediately reports `baked-inventory-moved` against the controller's own
    record."""
    import copy

    import yaml

    stale = copy.deepcopy(inventory)
    stale["hosts"] = [h for h in stale["hosts"] if h["name"] != "office-ws-1"]
    for h in stale["hosts"]:
        h["owner"] = f"old.{h['owner']}"
    write_profile(
        profiles_dir, "stale-owner-baked", "cmdb-stale",
        {"variant": "field-flip", "field": "owner", "hosts": len(stale["hosts"])},
    )
    execer = FakeExecSeam(files={BAKED_INVENTORY: yaml.safe_dump(stale)})
    record = ctl.activate(
        "stale-owner-baked", seed=42, execer=execer, profiles_dir=profiles_dir,
        rules_dir=rules_dir, ledger_dir=ledger_dir,
    )
    hosts = {m["host"] for m in record["resolved_mutations"]}
    assert "office-ws-1" not in hosts, "resolved against a host the container does not have"
    assert all(m["old_value"].startswith("old.") for m in record["resolved_mutations"])
    assert all(m["new_value"].startswith("old.") for m in record["resolved_mutations"])


def test_status_never_mutates(profiles_dir, rules_dir, ledger_dir, inventory, inventory_text):
    _activate_stale(profiles_dir, rules_dir, ledger_dir, "stale-owner-ro")
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": NOT_FOUND},
        files={BAKED_INVENTORY: inventory_text},
    )
    ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)
    assert live.mutating_calls() == []
