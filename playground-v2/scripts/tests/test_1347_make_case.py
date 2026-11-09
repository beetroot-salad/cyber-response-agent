"""#1347 r6.4.1 O13/A1/A5/A8: listing a freeze's candidate alerts and writing a case.

Entry points bound by this contract, `playground-v2/scripts/make_case.py` (the lab's case module):

* `MAX_AGE = timedelta(hours=6)`: its only owner (A8).
* `candidates(freeze_dir, *, ops, max_age=MAX_AGE) -> list[str]`: the `kibana.alert.uuid` of each
  alert in the freeze's snapshot with `@timestamp` in `[T - max_age, T]` (both bounds inclusive),
  no live run, no ticket reference, workflow status `open`. `ops.snapshot_alerts(freeze_dir)`,
  `ops.live_run_alerts()`, `ops.ticketed_alerts()`.
* `write_case(case_dir, *, freeze_dir, alert_uuid, overlay, patterns, parts_dir, lock_store, es, ops,
  clock, profiles_dir, inventory) -> held`: `overlay` is None or `{profile, seed, span_start}`.
  Takes the frozen-engine lock, readies the variant on `es` (same step as the launcher), runs the
  guard against `ops.freeze_rules(freeze_dir)` (the rules as of T), writes `alert.json` and
  `case.yaml` (`confirmed` stays empty), and returns `held` (`.token`, `.release()`, a context
  manager) with the lock still held for labelling. Any refusal or failure writes nothing and frees the lock.
"""
from __future__ import annotations

import ast
import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from _lab_fakes import (ALERT_DOCS, ALERTS, AUTH, FREEZE_ID, NGINX, PARTS, RUN_ID, SLUG, SPAN_START, SYSLOG, SYSLOG_AFTER_T, T,
                        LabRig, canonical_digest, content_of, counts_of, expected_copy, instant, stub_state)

from chaos.guard import GuardRefused, check_mutations
from chaos.mutations import resolve_mutations
from chaos.profiles import list_profiles, load_profile

PLAYGROUND = Path(__file__).resolve().parents[2]
SCRIPTS = PLAYGROUND / "scripts"
PROFILES = PLAYGROUND / "chaos" / "profiles"
INVENTORY = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
HEX64 = r"[0-9a-f]{64}"


def _drift_profiles(tmp_path: Path, field: str = "source.port") -> Path:
    d = tmp_path / "profiles"
    d.mkdir(exist_ok=True)
    (d / "drift-test.yaml").write_text(yaml.safe_dump({
        "id": "drift-test", "description": "t", "mode": "schema-drift", "seed": 1,
        "params": {"rename": {"from": field, "to": field + "_no"}}}))
    (d / "data-drop-syslog.yaml").write_text((PROFILES / "data-drop-syslog.yaml").read_text())
    (d / "cmdb-stale-owner.yaml").write_text((PROFILES / "cmdb-stale-owner.yaml").read_text())
    (d / "data-drop-auth.yaml").write_text(yaml.safe_dump({
        "id": "data-drop-auth", "description": "t", "mode": "data-drop", "seed": 1,
        "params": {"dataset": "system.auth", "rate": 25}}))
    return d


def _overlay(profile: str, seed: int = 7) -> dict:
    return {"profile": profile, "seed": seed, "span_start": SPAN_START}


def _mutations(profiles: Path, profile: str, seed: int = 7) -> list:
    return resolve_mutations(load_profile(profile, profiles_dir=profiles), seed=seed, inventory=INVENTORY)


# -- O13 ------------------------------------------------------------------------------------------


def test_candidates_are_the_alerts_within_max_age_of_T_with_no_live_trace(tmp_path):
    """O13: [T - 6 h, T] inclusive; excluded: older, stamped after T, live run, ticket, non-open status."""
    rig = LabRig(tmp_path)

    got = rig.make_module.candidates(rig.freeze_dir, ops=rig.ops)

    assert sorted(got) == ["at-T", "derived-in", "derived-pre", "edge", "syslog-alert", "young"]


def test_max_age_has_one_owner_and_the_default_is_six_hours(tmp_path):
    """A8/D17: `make_case.MAX_AGE` is 6 h and is the default; no other lab script defines one."""
    rig = LabRig(tmp_path)
    module = rig.make_module

    assert module.MAX_AGE == timedelta(hours=6)
    narrow = module.candidates(rig.freeze_dir, ops=rig.ops, max_age=timedelta(hours=1))
    assert sorted(narrow) == ["at-T", "derived-in", "syslog-alert", "young"]
    owners = [p.name for p in SCRIPTS.glob("*.py") if any(
        isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "MAX_AGE" for t in n.targets)
        for n in ast.walk(ast.parse(p.read_text())))]
    assert owners == ["make_case.py"], owners


# -- A1: write the case from the readied variant ----------------------------------------------------


def test_write_case_readies_the_variant_and_records_what_the_copy_holds(tmp_path):
    """A1/A8: counts = freeze counts minus the overlays' tallies, content, alert (canonical digest
    of the copy's alert _source), age in seconds; all digests bare hex; `confirmed` empty."""
    rig = LabRig(tmp_path)
    profiles = _drift_profiles(tmp_path)
    with rig.write_case("young", _overlay("data-drop-syslog"), profiles_dir=profiles):
        case = rig.case()
        state = expected_copy("drop")
        assert case["freeze"] == FREEZE_ID and case["confirmed"] in (None, {})
        assert case["counts"] == counts_of(state)
        assert case["counts"][SYSLOG] < rig.freeze["elastic"]["indices"][SYSLOG] - len(SYSLOG_AFTER_T)
        assert case["counts"][NGINX] == rig.freeze["elastic"]["indices"][NGINX]
        alert = state[ALERTS]["id-young"][1]
        assert case["alert"] == canonical_digest(alert)
        assert json.loads((rig.case_dir / "alert.json").read_text()) == alert
        assert case["age"] == 50 * 60
        stubs = stub_state({n: b for n, b in PARTS.items() if n != "detection-rules.tar"}, None)
        assert case["content"] == content_of(state, stubs)
        for key in ("alert", "content"):
            assert len(case[key]) == 64 and case[key] == case[key].lower() and ":" not in case[key]
        assert rig.cluster.state() == state


def test_the_recorded_counts_are_derived_not_read_from_a_run(tmp_path):
    """A1: counts are the freeze's minus the overlays' own tallies. A restore that returned another
    document count than the freeze recorded writes no case."""
    rig = LabRig(tmp_path)
    rig.cluster.content[AUTH]["auth-extra"] = {"_version": 1, "_source": {
        "@timestamp": "2026-10-20T05:05:00Z", "message": "not in the freeze count"}}
    rig.make_module
    with pytest.raises(Exception):
        rig.write_case("young", None, profiles_dir=_drift_profiles(tmp_path))

    assert not (rig.case_dir / "case.yaml").exists() and "frozen-engine" not in rig.store.records


def test_the_case_records_resolved_mutations_and_the_span_not_the_profile_and_seed(tmp_path):
    """A8: editing a profile or the resolver changes the case digest; so case.yaml holds the mutations."""
    rig = LabRig(tmp_path)
    profiles = _drift_profiles(tmp_path)
    with rig.write_case("young", _overlay("data-drop-syslog", 7), profiles_dir=profiles):
        pass

    case = rig.case()
    assert case["overlay"]["mutations"] == _mutations(profiles, "data-drop-syslog", 7)
    assert instant(case["overlay"]["span_start"]) == instant(SPAN_START)
    assert "profile" not in case["overlay"] and "seed" not in case["overlay"], case["overlay"]


def test_a_cmdb_stale_case_loads_its_mutations_at_stub_load_and_changes_no_document(tmp_path):
    """A3: cmdb-stale is a stub overlay; the ES copy is the base overlay's, and the content digest
    covers the flipped stub."""
    rig = LabRig(tmp_path)
    with rig.write_case("young", _overlay("cmdb-stale-owner", 3)):
        case = rig.case()
        assert case["overlay"]["mutations"] == _mutations(PROFILES, "cmdb-stale-owner", 3)
        assert rig.cluster.state() == expected_copy("none")
        assert rig.ops.stubs[2] == case["overlay"]["mutations"]
        assert case["content"] != content_of(expected_copy("none"), stub_state(
            {n: b for n, b in PARTS.items() if n != "detection-rules.tar"}, None))


def test_a_schema_drift_case_records_the_alert_as_the_overlay_rewrote_it(tmp_path):
    """A1/review 2: a derived alert's recorded sha and alert.json are the rewritten document, so
    they differ from the same alert under no overlay."""
    rig = LabRig(tmp_path)
    with rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path)):
        drifted = rig.case()
    plain_rig = LabRig(tmp_path / "plain")
    with plain_rig.write_case("young", None):
        plain = plain_rig.case()

    assert drifted["alert"] == canonical_digest(expected_copy("drift")[ALERTS]["id-young"][1])
    assert drifted["alert"] != plain["alert"]
    assert "source.port_no" in json.loads((rig.case_dir / "alert.json").read_text())


@pytest.mark.parametrize("uuid", ["future", "no-such-alert"])
def test_an_alert_that_is_not_in_the_variants_copy_writes_no_case(tmp_path, uuid):
    """A1: the alert is found in the copy by kibana.alert.uuid; one deleted by the base overlay
    (stamped after T) or never there is refused; the lock is freed."""
    rig = LabRig(tmp_path)
    rig.make_module
    with pytest.raises(Exception, match="(?i)alert"):
        rig.write_case(uuid, None)

    assert not (rig.case_dir / "case.yaml").exists() and "frozen-engine" not in rig.store.records


def test_an_alert_json_that_is_not_the_copys_alert_refuses_the_case(tmp_path):
    """A1/binding: a hand-placed alert.json that differs from the variant's alert document writes no case."""
    rig = LabRig(tmp_path)
    (rig.case_dir / "alert.json").write_text(json.dumps(ALERT_DOCS["young"]))   # the unrewritten one
    rig.make_module
    with pytest.raises(Exception, match="(?i)alert"):
        rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path))

    assert not (rig.case_dir / "case.yaml").exists() and "frozen-engine" not in rig.store.records


def test_a_failed_restore_writes_nothing_and_frees_the_lock(tmp_path):
    """A1/A2: a copy that cannot be made leaves no case.yaml, no alert.json and a free engine."""
    rig = LabRig(tmp_path, fail=lambda m, p, b: p.endswith("/_restore"))
    rig.make_module
    with pytest.raises(Exception):
        rig.write_case("young", None)

    assert not (rig.case_dir / "case.yaml").exists() and not (rig.case_dir / "alert.json").exists()
    assert "frozen-engine" not in rig.store.records


def test_a_damaged_freeze_part_refuses_before_anything_is_changed(tmp_path):
    """A2: the freeze's parts are verified before the copy is made, as at launch."""
    rig = LabRig(tmp_path)
    (rig.parts / FREEZE_ID / "stubs.tar").write_bytes(b"tampered")
    rig.make_module
    with pytest.raises(Exception, match="stubs.tar"):
        rig.write_case("young", None)

    assert rig.cluster.mutations == [] and not (rig.case_dir / "case.yaml").exists()


# -- the guard (A5, D22) --------------------------------------------------------------------------


def test_the_guard_runs_against_the_rules_as_of_T_and_refuses_before_the_copy_is_touched(tmp_path):
    """A5/P8: the freeze's rules key on source.port, so the drift profile is refused even though no
    committed rule does; nothing is written or changed and the lock is free. Control: rules not
    keying it admit the same profile (the tests above)."""
    keyed = {"r.json": {"rule_id": "r", "type": "query", "index": ["logs-system.auth-*"],
                        "query": "source.port:22 and event.outcome:failure"}}
    rig = LabRig(tmp_path, rules=keyed)
    rig.make_module
    with pytest.raises(GuardRefused):
        rig.write_case("young", _overlay("drift-test"), profiles_dir=_drift_profiles(tmp_path))

    assert rig.cluster.mutations == [] and not (rig.case_dir / "case.yaml").exists()
    assert "frozen-engine" not in rig.store.records


def test_a_data_drop_on_a_dataset_the_frozen_rules_read_is_refused(tmp_path):
    """A5/P8: system.auth is read by the frozen rules' index patterns."""
    rig = LabRig(tmp_path)
    rig.make_module
    with pytest.raises(GuardRefused):
        rig.write_case("young", _overlay("data-drop-auth"), profiles_dir=_drift_profiles(tmp_path))

    assert rig.cluster.mutations == [] and not (rig.case_dir / "case.yaml").exists()


def test_schema_drift_username_stays_refused_for_a_case(tmp_path):
    """D22: the committed user.name profile is refused by the guard for the rules at T."""
    rig = LabRig(tmp_path)
    rig.make_module
    with pytest.raises(GuardRefused):
        rig.write_case("young", _overlay("schema-drift-username"))

    assert not (rig.case_dir / "case.yaml").exists()


def test_a_committed_schema_drift_profile_on_a_field_no_rule_reads_makes_a_case(tmp_path):
    """D22: some committed schema-drift profile passes the guard against the committed detection
    rules (live chaos can use it) and a case can be made from it."""
    rules = PLAYGROUND / "detection-rules"
    usable = []
    for pid in list_profiles(profiles_dir=PROFILES):
        profile = load_profile(pid, profiles_dir=PROFILES)
        if profile.mode != "schema-drift":
            continue
        try:
            check_mutations(_mutations(PROFILES, pid), rules_dir=rules)
        except GuardRefused:
            continue
        usable.append(pid)
    assert usable, "no committed schema-drift profile passes the guard (D22 needs one, e.g. source.port)"

    rig = LabRig(tmp_path)
    rig.ops.freeze_rules = lambda freeze_dir: rules
    with rig.write_case("young", _overlay(usable[0])):
        mutations = rig.case()["overlay"]["mutations"]
    assert mutations and mutations[0]["kind"] == "schema-drift"


# -- the lock and the reference run (A1, O8) ---------------------------------------------------------


def test_the_engine_lock_is_held_through_labelling_and_the_reference_run_uses_the_kept_copy(tmp_path):
    """A1/O8: after write_case the lock is still held (another launch is refused); the reference run
    joins it with the token, restores nothing, writes no row; releasing frees the engine."""
    rig = LabRig(tmp_path)
    held = rig.write_case("young", _overlay("data-drop-syslog"), profiles_dir=_drift_profiles(tmp_path))
    assert "frozen-engine" in rig.store.records and held.token
    restores = rig.cluster.restores

    with pytest.raises(Exception):
        rig.launch(reference=True)
    assert rig.launch(reference=True, lock_token=held.token) == RUN_ID
    assert rig.cluster.restores == restores and not rig.index.exists()
    assert "frozen-engine" in rig.store.records

    held.release()
    assert "frozen-engine" not in rig.store.records


@pytest.mark.parametrize("overlay", [None, "data-drop-syslog", "drift-test", "cmdb-stale-owner"])
def test_a_written_case_launches_valid_on_a_fresh_cluster(tmp_path, overlay):
    """A1: one ready step: the counts, content and alert make-a-case wrote are what a later launch
    observes on a cluster restored from scratch, and with the case confirmed its row is valid."""
    rig = LabRig(tmp_path / "made")
    profiles = _drift_profiles(tmp_path)
    spec = None if overlay is None else _overlay(overlay, 7 if overlay != "cmdb-stale-owner" else 3)
    with rig.write_case("young", spec, profiles_dir=profiles):
        pass
    case = rig.case()
    case["confirmed"] = {"by": "op", "at": "2026-11-09T10:00:00Z", "reference_run": "r0"}

    later = LabRig(tmp_path / "later")
    (later.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
    (later.case_dir / "alert.json").write_text((rig.case_dir / "alert.json").read_text())
    later.launch()

    assert [r["verdict"] for r in later.rows()] == ["valid"], later.rows()
