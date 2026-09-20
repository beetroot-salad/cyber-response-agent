"""O6/M7 — the audit's payload scanner, with its positive control.

`ctl audit` samples the documents and stub payloads the agent's gather role can
actually reach and asserts none of them names the harness or carries a
controller-caused ingest error. The sampling needs the stack; the *decision* is
pure, so it is pinned here.

Two ways a fault becomes distinguishable from ordinary environmental decay:
a harness-shaped string in a payload, and an `event.kind: pipeline_error` /
`error.*` stamped by a processor the controller installed — the managed
pipeline's `on_failure` writes both onto any doc a processor throws on, and
those land in the agent-visible auth index.

The scanner must also be discriminating: `canary-1` is a real inventory host and
"failure" is an ordinary `event.outcome`, so neither may trip it.
"""
from __future__ import annotations

from chaos.audit import audit_payloads

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


def test_ordinary_telemetry_is_not_flagged():
    assert audit_payloads([CLEAN_AUTH_DOC, CLEAN_CMDB_PAYLOAD]) == []


def test_pipeline_error_is_flagged():
    doc = dict(CLEAN_AUTH_DOC)
    doc["event"] = {"kind": "pipeline_error"}
    doc["error"] = {"message": "field [source.port] doesn't exist"}

    findings = audit_payloads([doc])
    assert findings, "a pipeline_error doc in an agent-read index is the leak"
    assert "pipeline_error" in " ".join(findings)


def test_a_bare_error_field_is_flagged():
    doc = dict(CLEAN_AUTH_DOC)
    doc["error"] = {"message": "field [user.name] doesn't exist"}
    assert audit_payloads([doc])


def test_canary_field_positive_control():
    """M7's own check that a clean pass is never vacuous: a known marker is
    injected, the audit must flag it, and it is then removed."""
    tagged = dict(CLEAN_CMDB_PAYLOAD, owner="chaos-harness-canary")
    findings = audit_payloads([tagged])
    assert findings, "the audit cannot tell it is looking at an injected marker"
    assert audit_payloads([CLEAN_CMDB_PAYLOAD]) == []


def test_harness_markers_are_flagged_wherever_they_sit():
    cases = [
        {"tags": ["chaos-profile"]},
        {"description": "fault injected by the test harness"},
        {"_meta": {"injected_by": "chaos/ctl.py"}},
        {"labels": {"defender_eval": "true"}},
    ]
    for payload in cases:
        assert audit_payloads([payload]), f"not flagged: {payload}"


def test_real_inventory_vocabulary_does_not_trip_the_scanner():
    """canary-1 is a real host and `outcome: failure` is ordinary — a scanner
    that flags them makes every audit useless."""
    docs = [
        {"host": {"name": "canary-1"}, "event": {"outcome": "failure"}},
        {"name": "canary-1", "role": "canary", "criticality": "sandbox", "owner": "team.sre"},
        {"message": "Accepted publickey for root from 172.18.0.1 port 40122 ssh2"},
    ]
    assert audit_payloads(docs) == []
