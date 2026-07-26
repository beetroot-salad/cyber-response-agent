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
