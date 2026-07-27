"""Pins for the rebuilt recruiter (#711 §7).

The property under test is the one the rebuild exists for: **a cell whose activity trips
no detection rule still yields a case.** The previous recruiter polled for a rule and
then `return 2`, discarding telemetry the activity had already produced — which is what
made `persistence-authorized-keys` and `living-off-the-land` unrecruitable, two of the
pilot campaign's six cells.

Everything here runs against injected seams; none of it touches the live stack.
"""
from __future__ import annotations

import json

import pytest
import yaml

from defender.evals.oracle_golden import generate_case

META = {
    "run_id": "persistence-authorized-keys-31-4c3c161d",
    "scenario_id": "persistence-authorized-keys",
    "description": "Foothold appends an attacker SSH public key to authorized_keys.",
    "resolved": {"intensity": 1, "source_user": "root", "target_host": "db-1"},
    "started_at": "2026-07-26T09:00:51+00:00",
    "finished_at": "2026-07-26T09:00:53+00:00",
    "aborted": False,
    "steps": [{"step_index": 0, "source_host": "canary-1", "source_user": "root",
               "cmd": "echo key >> /root/.ssh/authorized_keys", "rc": 0}],
}

#: The nine keys `defender/run.py` consumes, taken from a real captured alert.
ALERT_KEYS = {"alert_id", "alert_timestamp", "rule", "reason", "host", "user",
              "ancestor_events", "signal_index", "threshold_result"}


# ------------------------------------------------------ the reason for the rebuild

def test_no_rule_firing_no_longer_discards_the_run(tmp_path, monkeypatch):
    """The whole point. `wait_for_alert` returning None used to end the recruitment;
    now it routes to synthesis and the captured telemetry survives."""
    monkeypatch.setattr(generate_case, "rules_fired_since", lambda *a, **k: [])
    out = tmp_path / "alert.json"
    fired = generate_case.wait_for_alert(None, generate_case.datetime.now(generate_case.UTC),
                                         out, attempts=2, sleep=lambda _: None)
    assert fired is None
    assert not out.exists()

    alert = generate_case.synthesise_alert(META, out)
    assert out.is_file()
    assert set(alert) == ALERT_KEYS


def test_a_synthesised_alert_never_claims_a_rule_that_did_not_fire():
    """A case asserting a detection that never happened is a fabricated record, and
    this whole suite is an argument about not fabricating records."""
    alert = generate_case.synthesise_alert(META, generate_case.Path("/dev/null"))
    assert alert["rule"]["id"] == "synthetic-persistence-authorized-keys"
    assert not alert["rule"]["id"].startswith("v2-"), "v2-* are the real rule ids"
    assert alert["threshold_result"] is None, "no threshold was met — none is reported"


def test_a_synthesised_alert_is_derived_from_what_the_activity_actually_did():
    alert = generate_case.synthesise_alert(META, generate_case.Path("/dev/null"))
    assert alert["host"]["name"] == "db-1"
    assert alert["user"]["name"] == "root"
    assert alert["alert_timestamp"] == META["finished_at"]
    assert META["description"] in alert["rule"]["description"]


def test_the_synthesised_alert_is_stable_for_a_given_run():
    """Same run record, same alert id — a re-recruited cell must not look like a new
    detection."""
    a = generate_case.synthesise_alert(META, generate_case.Path("/dev/null"))
    b = generate_case.synthesise_alert(META, generate_case.Path("/dev/null"))
    assert a["alert_id"] == b["alert_id"]
    other = generate_case.synthesise_alert({**META, "run_id": "other"},
                                           generate_case.Path("/dev/null"))
    assert other["alert_id"] != a["alert_id"]


def test_the_synthesis_is_disclosed_in_the_manifest_not_in_the_defender_s_input(tmp_path):
    """Provenance belongs where a reader looks for it. Telling the DEFENDER its alert is
    a test artifact would break the premise the case exists to preserve — that this is
    the envelope production actually issues."""
    alert_path = tmp_path / "alert.json"
    alert = generate_case.synthesise_alert(META, alert_path)
    body = alert_path.read_text(encoding="utf-8")
    assert "synthesised" not in body
    assert "test artifact" not in body

    manifest = tmp_path / "manifest.yaml"
    generate_case.write_manifest(
        manifest, case_id="case-006-x", split="dev", activity_family="persistence/T1098.004",
        capture_environment="playground-v2@live", scenario="persistence-authorized-keys",
        seed=31, meta=META, rule=alert["rule"]["id"], alert_source="synthesised")
    text = manifest.read_text(encoding="utf-8")
    assert "alert_source: synthesised" in text
    assert "alert_rule: synthetic-persistence-authorized-keys" in text


def test_a_captured_alert_is_recorded_as_captured(tmp_path):
    manifest = tmp_path / "manifest.yaml"
    generate_case.write_manifest(
        manifest, case_id="case-007-x", split="held-out", activity_family="brute-force/T1110.001",
        capture_environment="playground-v2@412854206", scenario="ssh-brute-force-canary",
        seed=42, meta=META, rule="v2-sshd-failed-auth-burst", alert_source="captured")
    text = manifest.read_text(encoding="utf-8")
    assert "alert_source: captured" in text
    assert "alert_rule: v2-sshd-failed-auth-burst" in text
    assert "split: held-out" in text


# --------------------------------------------------------------- alert selection

def _es(payload: dict, returncode: int = 0):
    def run(cmd, **kw):
        from types import SimpleNamespace
        return SimpleNamespace(returncode=returncode, stdout=json.dumps(payload), stderr="")
    return run


def test_the_rule_is_whatever_actually_fired_not_what_the_name_suggests():
    """`cross-tier-ssh-probe` against db-1 raises `v2-sshd-failed-auth-burst`. Waiting
    for a predicted rule recorded a reachable cell as unreachable while its alert sat in
    the index."""
    hits = {"hits": {"hits": [
        {"_source": {"kibana.alert.rule.rule_id": "v2-baseline-noise", "host.name": "web-1"}},
        {"_source": {"kibana.alert.rule.rule_id": "v2-sshd-failed-auth-burst",
                     "host.name": "db-1"}},
    ]}}
    got = generate_case.rules_fired_since(
        generate_case.datetime.now(generate_case.UTC), "db-1", run=_es(hits))
    assert got[0] == "v2-sshd-failed-auth-burst", "the target's own rule sorts first"
    assert "v2-baseline-noise" in got


def test_an_unreachable_stack_yields_no_candidates_rather_than_raising():
    got = generate_case.rules_fired_since(
        generate_case.datetime.now(generate_case.UTC), "db-1", run=_es({}, returncode=1))
    assert got == []


@pytest.mark.parametrize("payload", [{}, {"hits": {}}, {"hits": {"hits": [{}]}}])
def test_a_malformed_search_response_yields_no_candidates(payload):
    got = generate_case.rules_fired_since(
        generate_case.datetime.now(generate_case.UTC), None, run=_es(payload))
    assert got == []


def test_the_wait_is_short_because_its_outcome_no_longer_decides_the_case():
    """Ten minutes of polling was the price of treating a quiet cell as a failure."""
    assert generate_case.ALERT_ATTEMPTS * generate_case.ALERT_INTERVAL <= 300


def test_control_offsets_are_settable_because_a_default_window_can_be_dead():
    """The playground is levered up and down, so the default 7,14,21 can put a control
    in a window where the stack did not exist. case-006 was recruited on 2026-07-26,
    whose 7-day control lands on 07-19 — dead, along with 07-14..07-16 and 07-18..07-24.
    A dead window is not an empty baseline; it is a third of the evidence discarded."""
    parser = generate_case.build_parser()
    required = ["--scenario", "x", "--case-id", "c", "--split", "dev",
                "--activity-family", "f"]
    assert parser.parse_args(required).offsets_days is None, (
        "absent means controls.py keeps its own default")
    assert parser.parse_args([*required, "--offsets-days", "14,21,28"]
                             ).offsets_days == "14,21,28"


def test_the_offsets_reach_controls_py(tmp_path, monkeypatch):
    """The flag is worthless if main does not forward it."""
    seen = []
    monkeypatch.setattr(generate_case, "_run",
                        lambda cmd, **kw: seen.append([str(c) for c in cmd]) or "")
    monkeypatch.setattr(generate_case, "fire", lambda *a, **k: tmp_path / "run")
    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "meta.json").write_text(json.dumps(META), encoding="utf-8")
    monkeypatch.setattr(generate_case, "wait_for_alert", lambda *a, **k: None)
    monkeypatch.setattr(generate_case, "investigate", lambda *a, **k: tmp_path / "rundir")
    generate_case.main([
        "--scenario", "persistence-authorized-keys", "--case-id", "case-x",
        "--split", "dev", "--activity-family", "persistence/T1098.004",
        "--cases-dir", str(tmp_path / "cases"), "--offsets-days", "14,21,28"])
    controls = [c for c in seen if c and c[1].endswith("controls.py")]
    assert controls, "controls.py was never invoked"
    assert "--offsets-days" in controls[0]
    assert controls[0][controls[0].index("--offsets-days") + 1] == "14,21,28"


def test_a_recruited_case_gets_the_environment_notes_the_judge_requires(tmp_path):
    """`environment.yaml` is a REQUIRED judge input — `load_lead_inputs` reads it, and
    it carries the facts that decide whether a cross-window difference is real at all.
    A recruited case without one is a case the judge cannot read."""
    out = tmp_path / "environment.yaml"
    generate_case.write_environment(out, "playground-v2@412854206-restore-20260726")
    notes = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert notes["capture_environment"] == "playground-v2@412854206-restore-20260726"
    assert "source.ip" in notes["unstable_identifiers"]["columns"]
    assert notes["baseline_construction"]["liveness"]


def test_the_hand_written_and_generated_environment_notes_are_one_template(tmp_path):
    """Seven cases were written by hand before the template existed. They must not drift
    from what the recruiter now emits, or two cases in the same suite would be telling
    the judge different things about the same environment."""
    from defender.evals.oracle_golden import judge
    out = tmp_path / "environment.yaml"
    generate_case.write_environment(out, "playground-v2@409583061")
    generated = yaml.safe_load(out.read_text(encoding="utf-8"))
    hand = yaml.safe_load(
        (judge.GOLDEN_DIR / "cases" / "case-001-ssh-bruteforce-canary" / "environment.yaml")
        .read_text(encoding="utf-8"))
    assert generated == hand


# ------------------------------------------------------- the retarget guard (#711)

CATALOG = {"scenarios": [
    {"id": "local-only", "source_host": "canary-1", "target_host": "canary-1",
     "steps": [{"cmd": "echo key >> /root/.ssh/authorized_keys"}]},
    {"id": "retargetable", "source_host": "office-ws-1", "target_host": "db-1",
     "steps": [{"cmd": "ssh dev.dana@${target} id"}]},
]}


@pytest.fixture
def catalog(tmp_path):
    p = tmp_path / "catalog.yaml"
    p.write_text(yaml.safe_dump(CATALOG), encoding="utf-8")
    return p


def test_a_scenario_that_reads_the_target_can_be_retargeted(catalog):
    assert generate_case.retarget_problem("retargetable", "web-2",
                                          catalog_path=catalog) is None


def test_a_scenario_at_its_own_target_is_always_fine(catalog):
    assert generate_case.retarget_problem("local-only", "canary-1",
                                          catalog_path=catalog) is None
    assert generate_case.retarget_problem("local-only", None, catalog_path=catalog) is None


def test_retargeting_a_local_scenario_is_refused(catalog):
    """The check that cost two cases by being absent. `persistence-authorized-keys`
    appends to canary-1's OWN authorized_keys and `living-off-the-land` curls a URL and
    runs the result there; neither reads `${target}`. `runner.py` still records
    `resolved.target_host` from the override, so the record, the story's "directed at"
    header and the synthesised alert all name a host the commands never touched — and
    `defender/run.py` then gathers leads against that host. case-006's own capture is
    the proof: db-1's `/root/.ssh/authorized_keys` is empty and Falco has zero rows for
    db-1, because the key was written on canary-1."""
    problem = generate_case.retarget_problem("local-only", "db-1", catalog_path=catalog)
    assert problem is not None
    assert "never touched" in problem
    assert "canary-1" in problem, "it must name where the commands actually ran"


def test_the_guard_runs_before_the_stack_is_touched(catalog, tmp_path, monkeypatch,
                                                   capsys):
    """A refusal after `fire()` would still have levered the attack and burned the
    window. The exit is worth nothing if it happens second."""
    def explode(*a, **kw):
        raise AssertionError("fired the scenario despite an impossible target")

    monkeypatch.setattr(generate_case, "CATALOG", catalog)
    monkeypatch.setattr(generate_case, "fire", explode)
    # `main` reads the module-level CATALOG at call time, which is what the patch above
    # replaces — the guard takes its catalog as a required argument precisely so a
    # default bound at import time cannot outlive it.
    rc = generate_case.main(["--scenario", "local-only", "--target", "db-1",
                             "--case-id", "case-x", "--split", "dev",
                             "--activity-family", "persistence/T1098.004",
                             "--cases-dir", str(tmp_path / "cases")])
    assert rc == 2
    assert "never touched" in capsys.readouterr().err
    assert not (tmp_path / "cases").exists(), (
        "the refusal created a half-case directory — it must precede every side effect")


def test_the_guard_reads_the_real_catalog():
    """A guard keyed on a fixture only would not notice the catalog changing shape."""
    real = generate_case.CATALOG
    assert generate_case.retarget_problem(
        "persistence-authorized-keys", "db-1", catalog_path=real) is not None
    assert generate_case.retarget_problem(
        "cross-tier-ssh-probe", "web-2", catalog_path=real) is None


# --------------------------------------------------- the occupied-case-id guard (#711)

def test_a_free_case_id_is_not_refused(tmp_path):
    assert generate_case.occupancy_problem(tmp_path / "case-new") is None


@pytest.mark.parametrize("artifact", generate_case.CASE_ARTIFACTS)
def test_an_id_that_already_holds_a_capture_is_refused(tmp_path, artifact):
    """Two recruitments of one case id interleave rather than collide: the second
    overwrites `.generate/alert.json` while the first is still investigating. case-013's
    first attempt landed a story describing the 10:28 run against web-1, leads from an
    investigation of a web-2 alert, and a manifest window from a 10:16 run that had
    already been killed — every file well-formed, the case incoherent. That is the
    defect that retired case-009, and nothing downstream detects it."""
    d = tmp_path / "case-x"
    (d / artifact).mkdir(parents=True) if artifact in ("oracle_visible", "hidden") else (
        d.mkdir(parents=True), (d / artifact).write_text("x", encoding="utf-8"))
    problem = generate_case.occupancy_problem(d)
    assert problem is not None
    assert artifact in problem
    assert "two captures" in problem


def test_a_recruitment_already_in_flight_is_refused(tmp_path):
    d = tmp_path / "case-x" / ".generate"
    d.mkdir(parents=True)
    problem = generate_case.occupancy_problem(tmp_path / "case-x")
    assert problem is not None
    assert "in flight" in problem


def test_the_occupancy_guard_precedes_every_side_effect(tmp_path, catalog, monkeypatch,
                                                        capsys):
    def explode(*a, **kw):
        raise AssertionError("fired the scenario into an occupied case id")

    monkeypatch.setattr(generate_case, "CATALOG", catalog)
    monkeypatch.setattr(generate_case, "fire", explode)
    cases = tmp_path / "cases"
    (cases / "case-x" / "hidden").mkdir(parents=True)
    rc = generate_case.main(["--scenario", "retargetable", "--case-id", "case-x",
                             "--split", "dev", "--activity-family", "f",
                             "--cases-dir", str(cases)])
    assert rc == 2
    assert "two captures" in capsys.readouterr().err
