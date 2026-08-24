"""Load reusable root plans and completed packets from an immutable failed run."""

from __future__ import annotations

import json
from pathlib import Path

from .journal import RunJournal, digest
from .models import HarnessSpec, StrictModel
from .recursive_models import EvidencePacket, NodePlan, NodeTrace


class ReplayBundle(StrictModel):
    source_run: str
    root_plan: NodePlan
    plans: dict[str, NodePlan]
    packets: dict[str, EvidencePacket]
    traces: dict[str, NodeTrace]


def load_replay_bundle(run_directory: Path, spec: HarnessSpec) -> ReplayBundle:
    journal = RunJournal.open(run_directory)
    errors = journal.verify()
    if errors:
        raise ValueError(f"Replay source journal failed verification: {errors}")

    records: dict[tuple[str, str], dict] = {}
    for event in journal.manifest.get("events", []):
        records[(event["stage"], event["name"])] = json.loads(
            (journal.root / event["path"]).read_text(encoding="utf-8")
        )

    run_input = records.get(("00-input", "recursive-run"))
    if run_input is None:
        raise ValueError("Replay source is not a recursive run")
    if digest(run_input.get("spec")) != digest(spec):
        raise ValueError("Replay source task spec differs from the requested spec")

    root_plan_data = records.get(("10-node-plans", "root-round-01"))
    if root_plan_data is None:
        raise ValueError("Replay source has no completed root plan")

    plans = {
        name: NodePlan.model_validate(payload)
        for (stage, name), payload in records.items()
        if stage == "10-node-plans" and "-round-" in name
    }
    packets = {
        payload["node_id"]: EvidencePacket.model_validate(payload)
        for (stage, _), payload in records.items()
        if stage == "30-evidence-packets"
    }
    traces = {
        payload["node_id"]: NodeTrace.model_validate(payload)
        for (stage, _), payload in records.items()
        if stage == "31-node-traces"
    }
    return ReplayBundle(
        source_run=str(journal.root.resolve()),
        root_plan=NodePlan.model_validate(root_plan_data),
        plans=plans,
        packets=packets,
        traces=traces,
    )
