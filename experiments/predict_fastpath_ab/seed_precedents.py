"""Hand-curated precedent corpus for the fast-path experiment.

The live `runs/` corpus is too thin (~6 finished investigations) to
exercise the IFF gate's exact-match path against multiple fixtures.
We seed a small synthetic precedent set here, modeled on the existing
archetype snapshots in `knowledge/signatures/*/archetypes/*/*.json`.

This is experiment-only data. Production fast-path retrieval would
read from the real corpus via invlang.
"""

from __future__ import annotations

from gate import Precedent


PRECEDENTS: list[Precedent] = [
    # ---- wazuh-rule-5710 monitoring-probe family ----
    Precedent(
        case_id="SEED-5710-PROBE-001",
        signature_id="wazuh-rule-5710",
        archetype="monitoring-probe",
        disposition="benign",
        prologue={
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "internal-monitoring-host", "identifier": "172.22.0.10"},
                {"id": "v-002", "type": "endpoint", "classification": "unclassified-endpoint", "identifier": "target-endpoint"},
                {"id": "v-003", "type": "identity", "classification": "monitoring-pattern", "identifier": "nagios"},
            ],
            "edges": [
                {"id": "e-001", "relation": "attempted_auth", "source_vertex": "v-001", "target_vertex": "v-002"},
            ],
        },
        selected_lead="approved-monitoring-sources",
        lead_kind="branching",
        fidelity_rate=0.92,
        discriminating_attrs={"data": {"srcip": "172.22.0.10", "srcuser": "nagios"}},
    ),
    Precedent(
        case_id="SEED-5710-PROBE-002",
        signature_id="wazuh-rule-5710",
        archetype="monitoring-probe",
        disposition="benign",
        prologue={
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "internal-monitoring-host", "identifier": "172.22.0.10"},
                {"id": "v-002", "type": "endpoint", "classification": "unclassified-endpoint", "identifier": "target-endpoint"},
                {"id": "v-003", "type": "identity", "classification": "monitoring-pattern", "identifier": "sensu"},
            ],
            "edges": [
                {"id": "e-001", "relation": "attempted_auth", "source_vertex": "v-001", "target_vertex": "v-002"},
            ],
        },
        selected_lead="approved-monitoring-sources",
        lead_kind="branching",
        fidelity_rate=0.90,
        discriminating_attrs={"data": {"srcip": "172.22.0.10", "srcuser": "sensu"}},
    ),
    Precedent(
        case_id="SEED-5710-EXTBRUTE-001",
        signature_id="wazuh-rule-5710",
        archetype="external-bruteforce",
        disposition="true_positive",
        prologue={
            "vertices": [
                {"id": "v-001", "type": "endpoint", "classification": "external-actor", "identifier": "203.0.113.47"},
                {"id": "v-002", "type": "endpoint", "classification": "unclassified-endpoint", "identifier": "target-endpoint"},
                {"id": "v-003", "type": "identity", "classification": "common-username", "identifier": "root"},
            ],
            "edges": [
                {"id": "e-001", "relation": "attempted_auth", "source_vertex": "v-001", "target_vertex": "v-002"},
            ],
        },
        selected_lead="external-bruteforce",
        lead_kind="interpretive",
        fidelity_rate=0.85,
        discriminating_attrs={"data": {"srcip": "203.0.113.47", "srcuser": "root"}},
    ),
    # ---- wazuh-rule-550 filebeat cert inode-flap ----
    Precedent(
        case_id="SEED-550-INODE-001",
        signature_id="wazuh-rule-550",
        archetype="syscheck-db-artifact",
        disposition="benign",
        prologue={
            "vertices": [
                {"id": "v-001", "type": "host", "classification": "wazuh-manager", "identifier": "wazuh.manager"},
                {"id": "v-002", "type": "file", "classification": "tls-cert", "identifier": "/etc/ssl/filebeat.pem"},
            ],
            "edges": [
                {"id": "e-001", "relation": "file_modified", "source_vertex": "v-001", "target_vertex": "v-002"},
            ],
        },
        selected_lead="syscheck-db-state",
        lead_kind="interpretive",
        fidelity_rate=0.80,
        discriminating_attrs={
            "syscheck": {
                "path": "/etc/ssl/filebeat.pem",
                "changed_attributes": ["inode"],
                "inode_before": 205768,
                "inode_after": 205768,
            }
        },
    ),
]


def for_signature(sig_id: str) -> list[Precedent]:
    return [p for p in PRECEDENTS if p.signature_id == sig_id]
