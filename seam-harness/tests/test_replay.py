from __future__ import annotations

import asyncio

from seam_harness.journal import RunJournal
from seam_harness.models import HarnessSpec, TaskFrame
from seam_harness.recursive import RecursiveHarness
from seam_harness.recursive_models import (
    EvidencePacket,
    LocalDecidability,
    NodeDisposition,
    NodePlan,
    NodeTask,
    NodeTrace,
    PacketSufficiency,
)
from seam_harness.replay import load_replay_bundle


def test_verified_packet_can_be_loaded_and_replayed_without_model_call(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(title="Replay", task="Answer it", product_intent="Test replay")
    )
    plan = NodePlan(
        disposition=NodeDisposition.SOLVE,
        account="Already solved in the source run.",
        decidability=LocalDecidability(
            context_complete=True,
            acceptance_mechanical=True,
            independent_of_future_siblings=True,
            account="The packet is complete.",
        ),
    )
    packet = EvidencePacket(
        id="packet:root",
        node_id="root",
        objective="Answer it",
        account="Replayed answer",
        claims=[],
        counterevidence=[],
        assumptions=[],
        unresolved=[],
        source_ids_consulted=[],
        boundary_findings=[],
        sufficiency=PacketSufficiency.READY,
        content_sha256="packet-digest",
    )
    trace = NodeTrace(
        node_id="root",
        parent_id=None,
        depth=0,
        proposed_disposition=NodeDisposition.SOLVE,
        effective_disposition="solve",
        child_ids=[],
        packet_id=packet.id,
        packet_sha256=packet.content_sha256,
    )
    source = RunJournal.create(tmp_path / "source", "replay source")
    source.write_record("00-input", "recursive-run", {"spec": spec, "policy": {}})
    source.write_record("10-node-plans", "root-round-01", plan)
    source.write_record("30-evidence-packets", "root", packet)
    source.write_record("31-node-traces", "root", trace)
    source.finish("failed")

    bundle = load_replay_bundle(source.root, spec)
    harness = RecursiveHarness(
        spec,
        runs_dir=tmp_path / "replayed",
        replay_root_plan=bundle.root_plan,
        replay_plans=bundle.plans,
        replay_packets=bundle.packets,
        replay_traces=bundle.traces,
        replay_source=bundle.source_run,
        test_model=True,
    )
    node = NodeTask(
        id="root",
        depth=0,
        objective="Answer it",
        rationale="Root task.",
        acceptance_condition="Return an answer.",
        expected_contribution="Final evidence.",
    )

    replayed = asyncio.run(harness._execute_node(node))

    assert replayed == packet
    assert harness.usage.dump() == {}
    assert harness.journal.verify() == []


def test_root_plan_only_failed_run_can_be_replayed(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Plan replay", task="Answer it", product_intent="Test plan replay"
        )
    )
    plan = NodePlan(
        disposition=NodeDisposition.SOLVE,
        account="Reusable root plan.",
        decidability=LocalDecidability(
            context_complete=True,
            acceptance_mechanical=True,
            independent_of_future_siblings=True,
            account="The plan is complete.",
        ),
    )
    source = RunJournal.create(tmp_path / "source-plan", "plan replay source")
    source.write_record("00-input", "recursive-run", {"spec": spec, "policy": {}})
    source.write_record("10-node-plans", "root-round-01", plan)
    source.write_record("10-node-plans", "root.01-round-01", plan)
    source.finish("failed")

    bundle = load_replay_bundle(source.root, spec)

    assert bundle.root_plan == plan
    assert bundle.plans == {
        "root-round-01": plan,
        "root.01-round-01": plan,
    }
    assert bundle.packets == {}
    assert bundle.traces == {}
