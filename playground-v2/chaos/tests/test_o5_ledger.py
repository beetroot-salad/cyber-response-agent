"""O5 — ground truth recorded where the scorer reads and the agent's tools do not.

An activate/revert cycle appends a record under `chaos/ledger/` (gitignored,
devcontainer-side) carrying `{profile_id, seed, mode, resolved_mutations,
activated_at, reverted_at?, live_fingerprint}`, plus the `ledger_ref` a run's
meta.json joins back on. The values are *stored*, not recomputed later: the
recorded mutations must be the ones actually pushed through the exec seam.

No scorer reads this yet (#1087) — the ledger and the meta.json join key are the
seam, and this pins their shape.
"""
from __future__ import annotations

from datetime import datetime

from _fakes import FakeExecSeam, write_profile

from chaos import ctl
from chaos.ledger import read_records

REQUIRED_KEYS = {"profile_id", "seed", "mode", "resolved_mutations", "activated_at", "live_fingerprint"}


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _stale_profile(profiles_dir, profile_id="stale-owner"):
    return write_profile(
        profiles_dir,
        profile_id,
        "cmdb-stale",
        {"variant": "field-flip", "field": "owner", "hosts": 1},
    )


def test_activate_appends_a_full_record(profiles_dir, rules_dir, ledger_dir):
    _stale_profile(profiles_dir)
    execer = FakeExecSeam()
    returned = ctl.activate(
        "stale-owner",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )

    records = read_records(ledger_dir)
    assert len(records) == 1
    record = records[0]
    assert REQUIRED_KEYS <= set(record), f"missing {REQUIRED_KEYS - set(record)}"
    assert record["profile_id"] == "stale-owner"
    assert record["seed"] == 42
    assert record["mode"] == "cmdb-stale"
    assert record["resolved_mutations"] == returned["resolved_mutations"]
    assert record["ledger_ref"] == returned["ledger_ref"]
    _iso(record["activated_at"])  # parseable timestamp, not a bare marker
    assert not record.get("reverted_at"), "a fresh activation is not already reverted"


def test_recorded_mutations_are_the_ones_actually_pushed(profiles_dir, rules_dir, ledger_dir):
    _stale_profile(profiles_dir, "stale-owner-push")
    execer = FakeExecSeam()
    ctl.activate(
        "stale-owner-push",
        seed=7,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )

    record = read_records(ledger_dir)[0]
    posted = execer.calls_for(target="cmdb", method="POST", path_contains="/admin/overlay/")
    assert [c["path"].rsplit("/", 1)[-1] for c in posted] == [
        m["host"] for m in record["resolved_mutations"]
    ]


def test_revert_stamps_reverted_at_on_the_same_record(profiles_dir, rules_dir, ledger_dir):
    _stale_profile(profiles_dir, "stale-owner-cycle")
    execer = FakeExecSeam()
    activated = ctl.activate(
        "stale-owner-cycle",
        seed=42,
        execer=execer,
        profiles_dir=profiles_dir,
        rules_dir=rules_dir,
        ledger_dir=ledger_dir,
    )
    ctl.revert(
        activated["ledger_ref"],
        execer=execer,
        profiles_dir=profiles_dir,
        ledger_dir=ledger_dir,
    )

    matching = [r for r in read_records(ledger_dir) if r["ledger_ref"] == activated["ledger_ref"]]
    assert matching, "the ledger lost the activation it recorded"
    reverted = [r for r in matching if r.get("reverted_at")]
    assert len(reverted) == 1, f"expected exactly one reverted record, got {matching}"
    record = reverted[0]
    assert _iso(record["reverted_at"]) >= _iso(record["activated_at"])
    assert record["resolved_mutations"] == activated["resolved_mutations"]


def test_a_second_profile_appends_rather_than_overwrites(profiles_dir, rules_dir, ledger_dir):
    _stale_profile(profiles_dir, "stale-a")
    write_profile(
        profiles_dir, "drop-b", "data-drop", {"target_stream": "logs-system.syslog-*", "rate": 10}
    )
    execer = FakeExecSeam()
    first = ctl.activate(
        "stale-a", seed=1, execer=execer, profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )
    ctl.revert(first["ledger_ref"], execer=execer, profiles_dir=profiles_dir, ledger_dir=ledger_dir)
    second = ctl.activate(
        "drop-b", seed=2, execer=execer, profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )

    refs = [r["ledger_ref"] for r in read_records(ledger_dir)]
    assert first["ledger_ref"] in refs and second["ledger_ref"] in refs
    assert first["ledger_ref"] != second["ledger_ref"]
    modes = {r["profile_id"]: r["mode"] for r in read_records(ledger_dir)}
    assert modes == {"stale-a": "cmdb-stale", "drop-b": "data-drop"}
