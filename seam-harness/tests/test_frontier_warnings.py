from seam_harness.models import HarnessSpec, TaskFrame
from seam_harness.recursive import RecursiveHarness
from seam_harness.recursive_models import (
    ClaimBasis,
    EvidenceClaimDraft,
    EvidenceDraft,
    NodeTask,
    PacketSufficiency,
)


def test_frontier_non_claim_provenance_is_warned_and_discarded(tmp_path) -> None:
    harness = RecursiveHarness(
        HarnessSpec(frame=TaskFrame(title="x", task="x", product_intent="x")),
        runs_dir=tmp_path,
    )
    node = NodeTask(
        id="root.01-angle",
        parent_id="root",
        depth=1,
        objective="Develop one angle.",
        rationale="Independent research.",
        demand_ids=["D3"],
        acceptance_condition="Return a claim.",
        expected_contribution="An argument.",
    )
    draft = EvidenceDraft(
        account="An argument.",
        claims=[
            EvidenceClaimDraft(
                local_id="argument",
                statement="The argument.",
                basis=ClaimBasis.INFERRED,
                derived_from_claim_ids=["D3"],
                confidence=0.8,
            )
        ],
        sufficiency=PacketSufficiency.READY,
    )

    packet = harness._make_packet(node, draft, child_packets=[])

    assert packet.claims[0].derived_from_claim_ids == []
    assert "D3" in packet.unresolved[-1]
