"""#1347 r6.4.1 O13/A1/A5/A8: listing a freeze's candidate alerts and writing a case.

Entry points bound by this contract, `playground-v2/scripts/make_case.py` (the lab's case module):

* `MAX_AGE = timedelta(hours=6)`: its only owner (A8).
* `candidates(freeze_dir, *, ops, max_age=MAX_AGE) -> list[str]`: the `kibana.alert.uuid` of each
  alert in the freeze's snapshot with `@timestamp` in `[T - max_age, T]` (both bounds inclusive),
  no live run, no ticket reference, workflow status `open`. `ops.snapshot_alerts(freeze_dir)`,
  `ops.live_run_alerts()`, `ops.ticketed_alerts()`.
* `write_case(case_dir, *, freeze_dir, alert_uuid, overlay, tenant_settings, parts_dir, lock_store, es,
  ops, clock, profiles_dir, inventory) -> held`: `overlay` is None or `{profile, seed, span_start}`.
  Takes the frozen-engine lock, readies the variant on `es` by a WHOLE restore, whatever copy and marker
  it finds (D23), with the freeze's patterns (D24), runs the guard against
  `ops.freeze_rules(freeze_dir)` (the rules as of T), writes `alert.json` and `case.yaml`
  (`confirmed` stays empty), and returns `held` (`.token`, `.release()`, a context manager) with the
  lock still held for labelling. Any refusal or failure writes nothing, leaves the case directory
  as it was, and frees the lock. It refuses, before anything, when the freeze's patterns differ from
  those in `tenant_settings/systems/elastic/config.env` (D24), and for an alert that is not a
  candidate (O13), whatever the lab says about live runs and tickets.

`ops` is the REAL lab layer (`lab_ops.LabOps`, r6.4.3 C-rig), built by `_lab_fakes.LabRig` with only its outer
edge faked (docker, the frozen cluster through the real curl path `ops.frozen_es()`, the environment it reads:
`V2_RUNS_DIR`, `V2_FROZEN_PARTS_DIR`); see the launcher tests' docstring. r6.4.3 D25 and D15 revised hold for
make-a-case's restore as for a launch's.
"""
from __future__ import annotations

import ast
import json
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from _lab_fakes import (ALERT_DOCS, ALERTS, ALERTS_PATTERN, AUTH, EVENTS, FREEZE_ID, SCHEMA_DRIFT, NGINX, RUN_ID, SPAN_START, SYSLOG,
                        SYSLOG_AFTER_T, T, FaultJournal, LabRig, alert_doc, canonical_digest, counts_of,
                        expected_copy, instant, is_clean_marker, nested_alert)

from chaos.guard import GuardRefused, check_mutations
from chaos.mutations import resolve_mutations
from chaos.profiles import list_profiles, load_profile

PLAYGROUND = Path(__file__).resolve().parents[2]
SCRIPTS = PLAYGROUND / "scripts"
PROFILES = PLAYGROUND / "chaos" / "profiles"
INVENTORY = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
HEX64 = r"[0-9a-f]{64}"
_NOT_A_REFUSAL = (AttributeError, TypeError, NameError, ImportError)
ALERTS_ALT = ".internal.alerts-security.alerts-*"     # matches the same index as the old built-in default


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

    assert sorted(got) == ["at-T", "derived-decoy", "derived-dedup", "derived-dedup-pattern", "derived-in", "derived-pre", "edge",
                          "syslog-alert", "young"]


def test_max_age_has_one_owner_and_the_default_is_six_hours(tmp_path):
    """A8/D17: `make_case.MAX_AGE` is 6 h and is the default; no other lab script defines one."""
    rig = LabRig(tmp_path)
    module = rig.make_module

    assert module.MAX_AGE == timedelta(hours=6)
    narrow = module.candidates(rig.freeze_dir, ops=rig.ops, max_age=timedelta(hours=1))
    assert sorted(narrow) == ["at-T", "derived-decoy", "derived-dedup", "derived-dedup-pattern", "derived-in", "syslog-alert",
                      "young"]
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
        assert case["content"] == rig.expected_content(state, case["overlay"]["mutations"])
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
        flips = {m["host"]: {m["field"]: m["new_value"]} for m in case["overlay"]["mutations"] if m["kind"] == "field-flip"}
        assert flips and rig.stubs()["cmdb"]["overlays"] == flips, rig.stubs()["cmdb"]
        assert case["content"] != rig.expected_content(expected_copy("none"), None)


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


_KEYED = {"r.json": {"rule_id": "r", "type": "query", "index": ["logs-system.auth-*"],
                    "query": "source.port:22 and event.outcome:failure"}}


@pytest.mark.parametrize("exit_by", ["guard-refused-a-rule-key-field", "guard-refused-a-read-dataset", "case-written"])
def test_the_extracted_rules_directory_is_removed_on_every_exit(tmp_path, monkeypatch, exit_by):
    """r6.4.4 (finding 9): make-a-case's rules as of T are unpacked into a directory removed on every exit path,
    including a refusal before the launch (the guard refusing a mutation of a rule-key field, or a data drop on a
    dataset the rules read). Observed at the edge: temporary directories go under a directory this test owns,
    each one made is recorded, and none is left once write_case has returned or raised. Control: a written case."""
    import tempfile
    scratch = tmp_path / "tmp"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    made: list[Path] = []
    real_mkdtemp = tempfile.mkdtemp

    def mkdtemp(*a, **kw):
        made.append(Path(real_mkdtemp(*a, **kw)))
        return str(made[-1])

    monkeypatch.setattr(tempfile, "mkdtemp", mkdtemp)
    rig = LabRig(tmp_path / "rig", rules=_KEYED if exit_by == "guard-refused-a-rule-key-field" else None)
    profiles = _drift_profiles(tmp_path)
    rig.make_module
    if exit_by == "case-written":
        with rig.write_case("young", _overlay("drift-test"), profiles_dir=profiles):
            pass
    else:
        with pytest.raises(GuardRefused):
            rig.write_case("young", _overlay("drift-test" if exit_by.endswith("rule-key-field") else "data-drop-auth"),
                           profiles_dir=profiles)

    assert made, "no temporary directory was made: the rules were not unpacked where this test can see them"
    assert [d for d in made if d.exists()] == [], "a temporary directory was left behind"
    assert list(scratch.iterdir()) == [], list(scratch.iterdir())


def test_counts_agree_through_make_a_case_and_the_launch_when_an_index_holds_nested_documents(tmp_path):
    """r6.4.4 (counts, finding 4): the alerts index holds hidden nested documents, so `_cat/indices` `docs.count`
    exceeds `_count`. The freeze records top-level counts; make-a-case's count check and the launcher's count
    comparison both read top-level counts: the case is written with the freeze's counts and launches valid."""
    rig = LabRig(tmp_path / "made")
    for cluster in (rig.cluster, rig.live):
        cluster.nested = {ALERTS: 40}
    with rig.write_case("young", None):
        assert rig.case()["counts"] == counts_of(expected_copy("none"))
    case = rig.case()
    case["confirmed"] = {"by": "op", "at": "2026-11-09T10:00:00Z", "reference_run": "r0"}

    later = LabRig(tmp_path / "later")
    for cluster in (later.cluster, later.live):
        cluster.nested = {ALERTS: 40}
    (later.case_dir / "case.yaml").write_text(yaml.safe_dump(case))
    (later.case_dir / "alert.json").write_text((rig.case_dir / "alert.json").read_text())
    later.launch()

    assert [r["verdict"] for r in later.rows()] == ["valid"], later.rows()


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

    rig = LabRig(tmp_path, rules={p.name: json.loads(p.read_text()) for p in sorted(rules.glob("*.json"))})
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


# =====================================================================================================
# r6.4.2 repairs (attack batch 1): one test per family, whose input is the whole class
# =====================================================================================================


def _refused(rig, *args, **kw):
    """write_case raises something that is a refusal or failure, not a missing target or a wrong signature."""
    rig.make_module
    with pytest.raises(Exception) as caught:
        rig.write_case(*args, **kw)
    assert not isinstance(caught.value, _NOT_A_REFUSAL), repr(caught.value)
    return caught.value


# -- B2: a case is written exactly for a candidate ----------------------------------------------------------

_SECONDS_BEFORE_T = {"T-6h-1s": (21601, False), "T-6h": (21600, True), "T-3h": (10800, True), "T": (0, True),
                     "T+1s": (-1, False)}


def _at(seconds_before: int) -> str:
    return (instant(T) - timedelta(seconds=seconds_before)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _generated_alerts():
    """alert uuid -> (document, is a candidate by construction), across age x status x live run x ticket."""
    out = {}
    for age, (seconds_before, old_enough) in _SECONDS_BEFORE_T.items():
        for status in ("open", "acknowledged", "closed"):
            for live in (False, True):
                for ticket in (False, True):
                    uuid = f"gen-{age}-{status}-{'live' if live else 'quiet'}-{'ticket' if ticket else 'none'}"
                    out[uuid] = (alert_doc(uuid, _at(seconds_before), status=status),
                                 old_enough and status == "open" and not live and not ticket, live, ticket)
    return out


def test_a_case_is_written_exactly_for_an_alert_that_is_a_candidate_and_for_no_other(tmp_path):
    """B2/O13: across age at the max_age and T edges, workflow status, live run and ticket, write_case
    succeeds exactly when the alert is a candidate; a refusal writes nothing and frees the engine."""
    generated = _generated_alerts()
    rig = LabRig(tmp_path, extra_alerts={u: g[0] for u, g in generated.items()})
    rig.live_runs |= {u for u, g in generated.items() if g[2]}
    rig.tickets |= {u for u, g in generated.items() if g[3]}
    expected = {u: g[1] for u, g in generated.items()}
    expected.update({"at-T": True, "derived-in": True, "derived-pre": True, "edge": True, "syslog-alert": True,
                     "young": True, "derived-dedup": True, "derived-dedup-pattern": True, "derived-decoy": True,
                     "old": False, "future": False, "live-run": False, "ticketed": False,
                     "acknowledged": False})
    assert any(expected.values()) and not all(expected.values())
    assert {u for u in rig.make_module.candidates(rig.freeze_dir, ops=rig.ops)} == {u for u, ok in expected.items() if ok}

    for uuid, candidate in expected.items():
        if candidate:
            with rig.write_case(uuid, None):
                assert rig.case()["freeze"] == FREEZE_ID, uuid
                assert json.loads((rig.case_dir / "alert.json").read_text())["kibana.alert.uuid"] == uuid
            (rig.case_dir / "case.yaml").unlink()
            (rig.case_dir / "alert.json").unlink()
        else:
            _refused(rig, uuid, None)
            assert not (rig.case_dir / "case.yaml").exists() and not (rig.case_dir / "alert.json").exists(), uuid
        assert "frozen-engine" not in rig.store.records, uuid


@pytest.mark.parametrize("source", ["live_runs", "tickets"])
def test_an_exclusion_source_that_is_not_configured_refuses_the_listing_and_the_case(tmp_path, source):
    """B2/O13: when the lab cannot say which alerts have a live run (or a ticket), candidates and write_case
    raise; they never read the unknown as none excluded. A candidate writes nothing and the engine is free."""
    rig = LabRig(tmp_path)
    module = rig.make_module
    setattr(rig, source, None)
    with pytest.raises(Exception) as caught:
        module.candidates(rig.freeze_dir, ops=rig.ops)
    assert not isinstance(caught.value, _NOT_A_REFUSAL), repr(caught.value)

    _refused(rig, "young", None)

    assert not (rig.case_dir / "case.yaml").exists() and not (rig.case_dir / "alert.json").exists()
    assert "frozen-engine" not in rig.store.records


# -- C7: a span starts no later than T -------------------------------------------------------------------


@pytest.mark.parametrize("span_start, accepted", [
    (SPAN_START, True), ("2026-10-20T09:00:00Z", True), ("2026-10-20T09:00:01Z", False)],
    ids=["well-before-T", "exactly-T", "one-second-after-T"])
def test_a_span_starting_after_T_is_refused_and_one_starting_at_T_is_not(tmp_path, span_start, accepted):
    """C7/O7: the fault is live at T, so span_start <= T; one second later writes no case and frees the engine."""
    rig = LabRig(tmp_path)
    overlay = {**_overlay("data-drop-syslog"), "span_start": span_start}
    profiles = _drift_profiles(tmp_path)
    if accepted:
        with rig.write_case("young", overlay, profiles_dir=profiles):
            assert instant(rig.case()["overlay"]["span_start"]) == instant(span_start)
        return
    _refused(rig, "young", overlay, profiles_dir=profiles)

    assert not (rig.case_dir / "case.yaml").exists() and "frozen-engine" not in rig.store.records


# -- D23: make-a-case never trusts a copy ---------------------------------------------------------------


@pytest.mark.parametrize("prior", ["nothing", "launch-same-variant", "launch-other-variant", "write-case-same-variant"])
def test_make_a_case_restores_the_whole_snapshot_whatever_copy_and_marker_it_finds(tmp_path, prior):
    """D23/A1: one more whole restore per write_case, even over a clean marker of the same variant; a
    document left in the copy behind its back is gone from the copy and from the recorded counts."""
    rig = LabRig(tmp_path)
    profiles = _drift_profiles(tmp_path)
    overlay = _overlay("data-drop-syslog")
    if prior == "launch-same-variant":
        rig.write_expected_case("drop")
        rig.launch()
    elif prior == "launch-other-variant":
        rig.write_expected_case("drift")
        rig.launch()
    elif prior == "write-case-same-variant":
        rig.write_case("young", overlay, profiles_dir=profiles).release()
    if prior.startswith("launch"):
        for name in ("case.yaml", "alert.json"):
            (rig.case_dir / name).unlink()           # the earlier case's files are not this case's
    if prior != "nothing":
        assert is_clean_marker(rig.marker()), rig.marker()
        rig.cluster.put(NGINX, "nginx-99", {"@timestamp": "2026-10-20T05:00:00Z", "message": "stray",
                                            "event.dataset": "nginx.access"})
    restores = rig.cluster.restores

    with rig.write_case("young", overlay, profiles_dir=profiles):
        assert rig.cluster.restores == restores + 1
        assert rig.cluster.state() == expected_copy("drop")
        assert rig.case()["counts"] == counts_of(expected_copy("drop"))


# -- B5: a failed write_case leaves the case directory as it was -------------------------------------------


def _dir_state(path: Path) -> dict:
    return {p.name: (p.read_bytes() if p.is_file() else ("<dir>", sorted(c.name for c in p.iterdir())))
            for p in sorted(path.iterdir())}


@pytest.mark.parametrize("initial", ["bare", "previous-case"])
def test_a_failed_write_case_leaves_the_case_directory_as_it_was(tmp_path, initial):
    """B5/A1: cut at every step of the write, with either file unwritable, or refused (no such alert, one
    after T, ticketed, the rules read the field, a hand-placed alert.json): the directory is byte for byte as before."""
    profiles = _drift_profiles(tmp_path)
    overlay = _overlay("drift-test")
    keyed = {"r.json": {"rule_id": "r", "type": "query", "index": ["logs-system.auth-*"],
                        "query": "source.port:22 and event.outcome:failure"}}
    foreign = json.dumps(ALERT_DOCS["young"])

    def fresh(name, **kw):
        rig = LabRig(tmp_path / name, **kw)
        if initial == "previous-case":      # an earlier, unconfirmed case for this very alert, in its own formatting
            rig.write_variant_case(SCHEMA_DRIFT, confirmed=False)
            doc = json.loads((rig.case_dir / "alert.json").read_text())
            (rig.case_dir / "alert.json").write_text(json.dumps(doc, indent=2))
        return rig

    clean = FaultJournal()
    with fresh("clean", journal=clean).write_case("young", overlay, profiles_dir=profiles):
        pass
    assert len(clean.step_log) >= 10

    scenarios = [(f"cut at step {n}: {clean.step_log[n - 1]}", {"trip_at": n}, "young") for n in range(1, len(clean.step_log) + 1)]
    scenarios += [(f"{name} is unwritable", {"unwritable": name}, "young") for name in ("case.yaml", "alert.json")]
    scenarios += [(f"alert {uuid}", {}, uuid) for uuid in ("no-such-alert", "future", "ticketed")]
    scenarios += [("the rules read the field", {"rules": keyed}, "young"), ("a hand-placed alert.json", {"foreign": True}, "young")]
    for number, (label, how, uuid) in enumerate(scenarios):
        rig = fresh(f"s{number}", journal=FaultJournal(trip_at=how.get("trip_at")), rules=how.get("rules"))
        if "unwritable" in how:
            (rig.case_dir / how["unwritable"]).unlink(missing_ok=True)
            (rig.case_dir / how["unwritable"]).mkdir()
        if how.get("foreign"):
            (rig.case_dir / "alert.json").write_text(foreign)
        before = _dir_state(rig.case_dir)

        _refused(rig, uuid, overlay, profiles_dir=profiles)

        assert _dir_state(rig.case_dir) == before, label
        assert "frozen-engine" not in rig.store.records, label


# -- D24: the freeze owns the patterns ----------------------------------------------------------------------


def test_make_a_case_works_on_the_patterns_of_the_freeze_not_on_a_built_in_default(tmp_path):
    """D24: a freeze whose alerts pattern is spelled another way from any default makes a case and no
    request to the cluster carries the default spelling."""
    rig = LabRig(tmp_path, patterns=(EVENTS, ALERTS_ALT))
    with rig.write_case("young", _overlay("data-drop-syslog"), profiles_dir=_drift_profiles(tmp_path)):
        assert rig.case()["counts"] == counts_of(expected_copy("drop"))

    assert ALERTS_PATTERN not in json.dumps([[m, p, b] for m, p, b in rig.cluster.requests], default=str)


@pytest.mark.parametrize("now_configured", [
    ("logs-*,extra-*", ALERTS_ALT), ("logs-other-*", ALERTS_ALT), (EVENTS, ".internal.alerts-other-*"),
    ("logs-other-*", ".internal.alerts-other-*")], ids=["events-widened", "events-changed", "alerts-changed", "both-changed"])
def test_make_a_case_is_refused_before_anything_when_the_tenants_patterns_are_no_longer_the_freezes(tmp_path, now_configured):
    """D24/A2: nothing is requested of the cluster or written and the engine is free; with the tenant's
    patterns restored the same call writes the case."""
    rig = LabRig(tmp_path, patterns=(EVENTS, ALERTS_ALT))
    rig.set_tenant_patterns(*now_configured)

    _refused(rig, "young", None)

    assert not rig.cluster.requests and rig.docker.calls == []
    assert not (rig.case_dir / "case.yaml").exists() and "frozen-engine" not in rig.store.records
    rig.set_tenant_patterns(EVENTS, ALERTS_ALT)
    with rig.write_case("young", None):
        assert (rig.case_dir / "case.yaml").exists()


# =====================================================================================================
# r6.4.3 (finalize-stage review of PR #1461)
# =====================================================================================================


def test_a_case_is_written_through_the_real_lab_layer(tmp_path):
    """r6.4.3 finding 1 (C-rig): make-a-case's `write` runs against the lab layer that ships; a call it makes
    with a signature the layer does not have (the content digest without its patterns) fails here."""
    rig = LabRig(tmp_path)
    with rig.write_case("young", None) as held:
        assert held.token and rig.case()["content"] == rig.expected_content(expected_copy("none"), None)


@pytest.mark.parametrize("prior", ["nothing", "launch-same-variant", "launch-other-variant"])
def test_make_a_case_restores_into_a_fresh_node_whatever_it_finds(tmp_path, prior):
    """D25/D23: make-a-case's restore, like every restore, discards the old node container and its data
    volume, restores the whole snapshot into a new node, and sends no `_close` or index DELETE."""
    from test_1347_launcher import _assert_every_restore_went_into_a_fresh_node

    rig = LabRig(tmp_path)
    if prior != "nothing":
        rig.write_expected_case("drop" if prior == "launch-same-variant" else "drift")
        rig.launch()
        for name in ("case.yaml", "alert.json"):
            (rig.case_dir / name).unlink()
    with rig.write_case("young", _overlay("data-drop-syslog"), profiles_dir=_drift_profiles(tmp_path)):
        assert rig.cluster.state() == expected_copy("drop")
    _assert_every_restore_went_into_a_fresh_node(rig, prior)


def test_make_a_case_starts_every_frozen_node_with_its_offset_file_already_holding_T(tmp_path):
    """D15 revised/P1: the node make-a-case restores into never reads the real now."""
    from test_1347_launcher import _assert_every_node_start_already_holds_the_offset_for_T

    rig = LabRig(tmp_path)
    with rig.write_case("young", None):
        pass
    _assert_every_node_start_already_holds_the_offset_for_T(rig, "make-a-case")


def test_make_a_case_creates_the_offset_file_as_the_fixed_record_and_never_truncates_it(tmp_path):
    """r6.4.3 settlements/D15 revised: make-a-case's node, too, maps a 24-byte offset record created before it
    starts and only ever rewritten in place."""
    from test_1347_launcher import _assert_the_offset_file_is_a_fixed_record_rewritten_in_place

    rig = LabRig(tmp_path)
    with rig.write_case("young", None):
        pass
    _assert_the_offset_file_is_a_fixed_record_rewritten_in_place(rig, "make-a-case")


def test_an_alert_stored_nested_in_the_snapshot_is_a_candidate_like_a_flat_one(tmp_path):
    """r6.4.3 C-parse/O13: an alert whose `kibana.alert.*` fields the snapshot holds nested
    (`{"kibana": {"alert": {"uuid": U, ...}}}`) is listed by its uuid, as a flat one is."""
    nested = nested_alert(alert_doc("nested-young", "2026-10-20T08:15:00Z"))
    rig = LabRig(tmp_path, extra_alerts={"nested-young": nested})
    got = rig.make_module.candidates(rig.freeze_dir, ops=rig.ops)

    assert "nested-young" in got and "young" in got, got


def test_make_a_case_reads_a_span_start_given_without_an_offset_as_UTC_whatever_the_local_zone(tmp_path):
    """r6.4.3 C-parse (`frozen_copy.utc`): `make_case.py write ... --span-start 2026-10-20T07:00:00` means 07:00Z
    even where local time is two hours ahead (TZ=Etc/GMT-2); case.yaml records that instant with its zone."""
    import os
    import time
    from datetime import datetime

    rig = LabRig(tmp_path)
    naive = SPAN_START.removesuffix("Z")
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "Etc/GMT-2"
    time.tzset()
    try:
        with rig.write_case("young", {"profile": "data-drop-syslog", "seed": 7, "span_start": naive}):
            pass
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()

    recorded = rig.case()["overlay"]["span_start"]
    dt = recorded if isinstance(recorded, datetime) else datetime.fromisoformat(str(recorded).replace("Z", "+00:00"))
    assert dt.tzinfo is not None, f"case.yaml records a naive span start: {recorded!r}"
    assert dt == instant(SPAN_START), recorded


@pytest.mark.parametrize("shape", ["flat", "nested"])
def test_an_alert_with_a_live_run_is_no_candidate_whatever_the_shape_of_the_runs_alert_json(tmp_path, shape):
    """r6.4.3 finding 6 (C-parse)/O13: a live run's `alert.json` may carry the uuid flat
    (`{"kibana.alert.uuid": U}`) or nested (`{"kibana": {"alert": {"uuid": U}}}`); either way U is excluded."""
    rig = LabRig(tmp_path)
    rig.live_runs = set()
    if shape == "nested":
        rig.nested_live_runs = {"young"}
        rig.live_runs = set()       # rewrites the runs directory with the nested run
    else:
        rig.live_runs = {"young"}
    got = rig.make_module.candidates(rig.freeze_dir, ops=rig.ops)

    assert "young" not in got and "derived-in" in got, got
