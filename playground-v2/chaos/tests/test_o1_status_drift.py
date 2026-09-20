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

from _fakes import FakeExecSeam, write_profile

from chaos import ctl

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
        es={"GET /_ingest/pipeline/*": (1, {"error": "not found"})},
        files={BAKED_INVENTORY: inventory_text},
    )

    result = ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    drift = result["drift"]
    assert drift, "status trusted the ledger instead of the stack"
    blob = json.dumps(drift, default=str)
    assert record["profile_id"] in blob
    assert record["resolved_mutations"][0]["host"] in blob


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
        es={"GET /_ingest/pipeline/*": (1, {"error": "not found"})},
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
        es={"GET /_ingest/pipeline/*": (1, {"error": "not found"})},
        files={BAKED_INVENTORY: inventory_text},
    )

    ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)

    reads = live.calls_for(target="file")
    assert reads, "status did not read the container's inventory at all"
    assert {c["path"] for c in reads} == {BAKED_INVENTORY}
    assert all(c["container"] == "cmdb" for c in reads)


def test_status_never_mutates(profiles_dir, rules_dir, ledger_dir, inventory, inventory_text):
    _activate_stale(profiles_dir, rules_dir, ledger_dir, "stale-owner-ro")
    live = FakeExecSeam(
        cmdb={"GET /hosts": (0, _hosts_payload(inventory))},
        es={"GET /_ingest/pipeline/*": (1, {"error": "not found"})},
        files={BAKED_INVENTORY: inventory_text},
    )
    ctl.status(execer=live, profiles_dir=profiles_dir, ledger_dir=ledger_dir)
    assert live.mutating_calls() == []
