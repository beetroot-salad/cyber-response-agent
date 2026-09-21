"""O6/M7 — the audit checks agent-reachable payloads against the ledger.

`ctl audit` samples the documents and stub payloads the agent's gather role can
actually reach. The ledger knows exactly what the controller wrote, so the
decision is precise rather than lexical:

  * a controller processor body visible in a payload is a leak;
  * an ingest error (`event.kind: pipeline_error` / `error.message`) that
    names a field a controller processor touches is a leak — the managed
    pipeline's `on_failure` stamps both onto any doc a processor throws on;
  * an ingest error that names nothing of ours (the system integration's own
    grok rejecting a malformed line) is ordinary telemetry;
  * harness-shaped *words* are an advisory, never a finding: `fault` and
    `eval` are ordinary syslog vocabulary.

The positive control proves the sampler saw the fault's effect — the
mutated host state, or documents newer than activation on the targeted
stream — so a clean pass is never vacuous, without injecting anything into
agent-reachable state to prove it.
"""
from __future__ import annotations

from _fakes import FakeExecSeam, write_profile

from chaos import ctl
from chaos.audit import audit_payloads, scan_markers

CLEAN_AUTH_DOC = {
    "@timestamp": "2026-09-20T09:00:00.000Z",
    "host": {"name": "canary-1"},
    "process": {"name": "sshd"},
    "event": {"kind": "event", "outcome": "failure"},
    "user": {"name": "dev.dana"},
    "source": {"ip": "10.10.0.21", "port": 51344},
    "message": "Failed password for invalid user root from 10.10.0.21 port 51344 ssh2",
}
CLEAN_CMDB_PAYLOAD = {
    "name": "web-1",
    "role": "web",
    "criticality": "prod",
    "owner": "team.sre",
    "change_window": "tue 02:00-04:00 UTC",
}
RENAME_PROCESSOR = {
    "rename": {"field": "user.name", "target_field": "user.id", "ignore_missing": True, "ignore_failure": True}
}
DRIFT_RECORD = {
    "ledger_ref": "chaos-drift01",
    "profile_id": "schema-drift-username",
    "mode": "schema-drift",
    "resolved_mutations": [
        {
            "kind": "schema-drift",
            "dataset": "system.auth",
            "stream": "logs-system.auth-*",
            "pipeline": "logs-system.auth@custom",
            "processor": RENAME_PROCESSOR,
            "fields": ["user.name", "user.id"],
        }
    ],
}


# -- the decision -------------------------------------------------------------------


def test_ordinary_telemetry_is_not_flagged():
    assert audit_payloads([CLEAN_AUTH_DOC, CLEAN_CMDB_PAYLOAD], records=[DRIFT_RECORD]) == []


def test_a_pipeline_error_naming_a_controller_field_is_flagged():
    doc = dict(CLEAN_AUTH_DOC)
    doc["event"] = {"kind": "pipeline_error"}
    doc["error"] = {"message": "field [user.name] doesn't exist"}

    findings = audit_payloads([doc], records=[DRIFT_RECORD])
    assert findings, "a pipeline_error our processor caused, in an agent-read index, is the leak"
    assert "user.name" in " ".join(findings)


def test_a_bare_error_field_naming_a_controller_field_is_flagged():
    doc = dict(CLEAN_AUTH_DOC)
    doc["error"] = {"message": "field [user.id] already exists"}
    assert audit_payloads([doc], records=[DRIFT_RECORD])


def test_a_flattened_error_document_is_read_the_same_way():
    doc = {"@timestamp": "2026-09-20T09:00:00.000Z", "event.kind": "pipeline_error",
           "error.message": "field [user.name] doesn't exist"}
    assert audit_payloads([doc], records=[DRIFT_RECORD])


def test_the_integrations_own_grok_failure_is_not_flagged():
    """The system integration stamps the same `pipeline_error` shape onto a
    malformed syslog line. It names none of our fields, so it is not ours —
    flagging it would fail every audit on a stack with one bad log line."""
    doc = {
        "@timestamp": "2026-09-20T09:00:00.000Z",
        "event": {"kind": "pipeline_error"},
        "error": {"message": "Provided Grok expressions do not match field value: [garbage]"},
        "message": "garbage",
    }
    assert audit_payloads([doc], records=[DRIFT_RECORD]) == []


def test_a_controller_processor_body_in_a_payload_is_flagged():
    """If the agent can read pipeline definitions, our processor is the tell."""
    payload = {"logs-system.auth@custom": {"processors": [RENAME_PROCESSOR]}}
    assert audit_payloads([payload], records=[DRIFT_RECORD])


def test_with_no_records_nothing_is_attributable():
    doc = dict(CLEAN_AUTH_DOC, error={"message": "field [user.name] doesn't exist"})
    assert audit_payloads([doc], records=[]) == []


# -- the advisory word scan ------------------------------------------------------------


def test_harness_markers_are_advisories_wherever_they_sit():
    cases = [
        {"tags": ["chaos-profile"]},
        {"description": "fault injected by the test harness"},
        {"_meta": {"injected_by": "chaos/ctl.py"}},
        {"labels": {"defender_eval": "true"}},
    ]
    for payload in cases:
        assert scan_markers([payload]), f"not advised: {payload}"
        assert audit_payloads([payload], records=[DRIFT_RECORD]) == [], "a word is not a finding"


def test_ordinary_words_containing_a_marker_as_a_substring_do_not_trip_it():
    """A plain substring check would flag 'default' (contains 'fault') and
    'evaluate'/'medieval' (contain 'eval') — ordinary vocabulary an ES
    pipeline body or a real payload can legitimately carry."""
    docs = [
        {"pipeline": "default"},
        {"note": "the team will evaluate the medieval-era migration plan"},
        {"outcome": "failure"},
    ]
    assert scan_markers(docs) == []


def test_real_inventory_vocabulary_does_not_trip_the_scanner():
    """canary-1 is a real host and `outcome: failure` is ordinary — a scanner
    that flags them makes every audit useless."""
    docs = [
        {"host": {"name": "canary-1"}, "event": {"outcome": "failure"}},
        {"name": "canary-1", "role": "canary", "criticality": "sandbox", "owner": "team.sre"},
        {"message": "Accepted publickey for root from 172.18.0.1 port 40122 ssh2"},
    ]
    assert scan_markers(docs) == []


def test_real_syslog_lines_with_marker_words_are_advisories_not_findings():
    """`general protection fault` and `/usr/bin/eval` are real kernel and
    sudo lines. They may be worth a human's glance; they cannot fail an
    audit."""
    docs = [
        {"message": "kernel: traps: foo[123] general protection fault ip:7f3a sp:7ffd error:0"},
        {"message": "sudo:     root : TTY=pts/0 ; COMMAND=/usr/bin/eval"},
    ]
    assert scan_markers(docs), "the advisory tier went silent"
    assert audit_payloads(docs, records=[DRIFT_RECORD]) == []


# -- the live half: sampling and the positive control -----------------------------------


def _drop_activated(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "drop", "data-drop", {"dataset": "system.syslog", "rate": 10})
    return ctl.activate(
        "drop", seed=1, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )


def test_ctl_audit_samples_the_newest_documents_since_activation(profiles_dir, rules_dir, ledger_dir):
    """An unsorted `match_all` returns a stream's oldest documents — from
    long before the fault was live, where a controller-stamped error cannot
    be. The sample must be the window that matters: newest first, from the
    record's activation onward."""
    record = _drop_activated(profiles_dir, rules_dir, ledger_dir)
    execer = FakeExecSeam(
        cmdb={"GET /health": (0, {"status": "ok"}), "GET /hosts": (0, {"total": 0, "hosts": []})},
        es={"POST /logs-system.syslog-*/_search": (0, {"hits": {"hits": [{"_source": {"message": "x"}}]}})},
    )
    result = ctl.run_audit(execer=execer, ledger_dir=ledger_dir)

    (search,) = execer.calls_for(target="es", method="POST", path_contains="_search")
    body = search["body"]
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert body["query"] == {"range": {"@timestamp": {"gte": record["activated_at"]}}}
    assert result["control_passed"] is True
    assert ctl.audit_is_clean(result)


def test_the_positive_control_is_the_faults_own_effect_not_an_injected_marker(
    profiles_dir, rules_dir, ledger_dir, inventory
):
    """A stale-owner fault is live. The control passes only when the sampled
    `/hosts` shows the flipped owner — and nothing is POSTed into the CMDB
    to prove the sampler works, because that POST was itself a leak the
    agent could observe between injection and cleanup."""
    write_profile(profiles_dir, "flip", "cmdb-stale", {"variant": "field-flip", "field": "owner", "hosts": 1})
    record = ctl.activate(
        "flip", seed=42, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )
    mutation = record["resolved_mutations"][0]
    hosts = [dict(h) for h in inventory["hosts"]]

    unchanged = FakeExecSeam(cmdb={"GET /hosts": (0, {"total": len(hosts), "hosts": hosts})})
    result = ctl.run_audit(execer=unchanged, ledger_dir=ledger_dir)
    assert result["control_passed"] is False, "the sampler never saw the fault, yet the control passed"
    assert not ctl.audit_is_clean(result)
    assert unchanged.mutating_calls() == [], "the audit wrote into agent-reachable state"

    for h in hosts:
        if h["name"] == mutation["host"]:
            h["owner"] = mutation["new_value"]
    flipped = FakeExecSeam(cmdb={"GET /hosts": (0, {"total": len(hosts), "hosts": hosts})})
    result = ctl.run_audit(execer=flipped, ledger_dir=ledger_dir)
    assert result["control_passed"] is True
    assert ctl.audit_is_clean(result)
    assert result["sampled"] >= len(hosts)


def test_a_vacuous_audit_is_not_clean(profiles_dir, rules_dir, ledger_dir):
    """cmdb down: nothing sampled, the fault's effect unobservable. That is
    not a pass — an exit-code gate keyed on 'no findings' would let a run
    with zero payloads inspected through as clean."""
    _drop_activated(profiles_dir, rules_dir, ledger_dir)
    execer = FakeExecSeam(
        cmdb={"GET /health": (500, {"error": "down"}), "GET /hosts": (500, {"error": "down"})},
        es={"POST /*/_search": (500, {"error": "down"})},
    )
    result = ctl.run_audit(execer=execer, ledger_dir=ledger_dir)
    assert result["sampled"] == 0
    assert result["errors"], "a sample that could not be taken vanished silently"
    assert result["control_passed"] is False
    assert ctl.audit_is_clean(result) is False


def test_audit_is_clean_decision_table():
    healthy = {"findings": [], "advisories": [], "errors": [], "sampled": 12, "control_passed": True}
    assert ctl.audit_is_clean(healthy) is True
    assert ctl.audit_is_clean({**healthy, "control_passed": None}) is True  # no active fault: nothing to observe
    assert ctl.audit_is_clean({**healthy, "control_passed": False}) is False
    assert ctl.audit_is_clean({**healthy, "errors": ["search logs-x: HTTP 500"]}) is False
    assert ctl.audit_is_clean({**healthy, "findings": ["processor body"]}) is False
    assert ctl.audit_is_clean({**healthy, "advisories": ["token 'fault'"]}) is True


def test_ctl_audit_reports_a_finding_from_a_sampled_document(profiles_dir, rules_dir, ledger_dir):
    write_profile(profiles_dir, "drift", "schema-drift", {"rename": {"from": "user.name", "to": "user.id"}})
    ctl.activate(
        "drift", seed=1, execer=FakeExecSeam(), profiles_dir=profiles_dir, rules_dir=rules_dir, ledger_dir=ledger_dir
    )
    leaked = dict(CLEAN_AUTH_DOC, event={"kind": "pipeline_error"}, error={"message": "field [user.name] doesn't exist"})
    execer = FakeExecSeam(
        cmdb={"GET /health": (0, {"status": "ok"}), "GET /hosts": (0, {"total": 0, "hosts": []})},
        es={"POST /logs-system.auth-*/_search": (0, {"hits": {"hits": [{"_source": leaked}]}})},
    )
    result = ctl.run_audit(execer=execer, ledger_dir=ledger_dir)
    assert result["findings"], "a controller-caused ingest error in the sample was not flagged"
    assert not ctl.audit_is_clean(result)


def test_ctl_audit_never_mutates(profiles_dir, rules_dir, ledger_dir):
    _drop_activated(profiles_dir, rules_dir, ledger_dir)
    execer = FakeExecSeam()
    ctl.run_audit(execer=execer, ledger_dir=ledger_dir)
    assert execer.mutating_calls() == []
