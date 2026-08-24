from seam_harness.models import HarnessSpec, TaskFrame
from seam_harness.recursive import RecursiveHarness
from seam_harness.recursive_models import (
    ClaimBasis,
    EvidenceClaimDraft,
    EvidenceDraft,
    NodeTask,
    PacketSufficiency,
)


def test_frontier_local_claim_references_become_canonical(tmp_path) -> None:
    harness = RecursiveHarness(
        HarnessSpec(frame=TaskFrame(title="x", task="x", product_intent="x")),
        runs_dir=tmp_path,
        test_model=True,
    )
    node = NodeTask(
        id="root.01-angle",
        parent_id="root",
        depth=1,
        objective="Develop an argument and qualification.",
        rationale="Independent angle.",
        acceptance_condition="Return both claims.",
        expected_contribution="Qualified argument.",
    )
    draft = EvidenceDraft(
        account="One argument with a qualification.",
        claims=[
            EvidenceClaimDraft(
                local_id="argument",
                statement="The argument.",
                basis=ClaimBasis.INFERRED,
                confidence=0.8,
            ),
            EvidenceClaimDraft(
                local_id="qualification",
                statement="The qualification.",
                basis=ClaimBasis.INFERRED,
                derived_from_claim_ids=["argument"],
                confidence=0.8,
            ),
        ],
        sufficiency=PacketSufficiency.READY,
    )

    packet = harness._make_packet(node, draft, child_packets=[])

    assert packet.claims[1].derived_from_claim_ids == ["root.01-angle:C001"]
