from __future__ import annotations

import asyncio
from typing import Any

from pydantic_ai import Agent

from seam_harness.models import Demand, HarnessSpec, TaskFrame
from seam_harness.orchestrator import Execution
from seam_harness.postmortem import build_postmortem
from seam_harness.recursive import RecursiveHarness
from seam_harness.recursive_models import (
    ChildProposal,
    ClaimBasis,
    EvidenceCitation,
    EvidenceClaim,
    EvidenceClaimDraft,
    EvidenceDraft,
    EvidencePacket,
    FinalArtifact,
    KnowledgeLinkProposal,
    KnowledgeRelation,
    LocalDecidability,
    NodeDisposition,
    NodePlan,
    NodeTask,
    PacketSufficiency,
    RecursivePolicy,
    SynthesisContract,
)


def _execution(output: Any, role: str) -> Execution[Any]:
    return Execution(
        output=output,
        call_id=f"scripted-{role}",
        role=role,
        model="scripted",
        input_sha256="scripted",
        elapsed_ms=1,
        usage={},
    )


class ScriptedRecursiveHarness(RecursiveHarness):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.active_research = 0
        self.max_active_research = 0
        self.completed_children: set[str] = set()
        self.research_board_answer_counts: list[int] = []
        self.synthesis_board_answer_ids: list[str] = []
        self.synthesis_board_question_ids: list[str] = []

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: Any,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
    ) -> Execution[Any]:
        if role == "recursive_planner":
            if deps.node.id == "root":
                output = NodePlan(
                    disposition=NodeDisposition.EXPAND,
                    account="Two independent observations feed one parent answer.",
                    decidability=LocalDecidability(
                        context_complete=True,
                        acceptance_mechanical=False,
                        independent_of_future_siblings=True,
                        account="The observations can be gathered separately.",
                    ),
                    children=[
                        ChildProposal(
                            local_id="left",
                            objective="Establish the left fact.",
                            rationale="It has its own referent.",
                            demand_ids=["D1"],
                            acceptance_condition="Return one evidence claim.",
                            expected_contribution="The left fact.",
                            no_future_sibling_dependency="No right result is required.",
                        ),
                        ChildProposal(
                            local_id="right",
                            objective="Establish the right fact.",
                            rationale="It has its own referent.",
                            demand_ids=["D1"],
                            acceptance_condition="Return one evidence claim.",
                            expected_contribution="The right fact.",
                            no_future_sibling_dependency="No left result is required.",
                        ),
                    ],
                    synthesis_contract=SynthesisContract(
                        parent_question="What follows from both facts?",
                        required_contributions=["left fact", "right fact"],
                        conflict_policy="Preserve a conflict if one appears.",
                        acceptance_condition="Use both child packets.",
                    ),
                )
            else:
                output = NodePlan(
                    disposition=NodeDisposition.SOLVE,
                    account="This evidence question is locally decidable.",
                    decidability=LocalDecidability(
                        context_complete=True,
                        acceptance_mechanical=True,
                        independent_of_future_siblings=True,
                        account="One bounded claim completes it.",
                    ),
                )
            return _execution(output, role)

        if role == "frontier_researcher":
            self.research_board_answer_counts.append(
                len(deps.knowledge_board.answers_by_id)
            )
            self.active_research += 1
            self.max_active_research = max(
                self.max_active_research, self.active_research
            )
            await asyncio.sleep(0.03)
            self.completed_children.add(deps.node.id)
            self.active_research -= 1
            return _execution(
                EvidenceDraft(
                    account=f"Evidence for {deps.node.id}",
                    claims=[
                        EvidenceClaimDraft(
                            local_id="fact",
                            statement=f"Claim from {deps.node.id}",
                            basis=ClaimBasis.INFERRED,
                            confidence=0.8,
                        )
                    ],
                    sufficiency=PacketSufficiency.READY,
                    next_observation=(
                        "Resolve the left-side uncertainty."
                        if deps.node.id.endswith("left")
                        else None
                    ),
                ),
                role,
            )

        if role == "synthesizer":
            assert len(self.completed_children) == 2
            self.synthesis_board_answer_ids = sorted(deps.knowledge_board.answers_by_id)
            self.synthesis_board_question_ids = sorted(
                deps.knowledge_board.questions_by_id
            )
            child_claim_ids = [
                claim.id for packet in deps.child_packets for claim in packet.claims
            ]
            return _execution(
                EvidenceDraft(
                    account="The two independent facts jointly answer the root.",
                    claims=[
                        EvidenceClaimDraft(
                            local_id="joint",
                            statement="Joint conclusion",
                            basis=ClaimBasis.INFERRED,
                            derived_from_claim_ids=child_claim_ids,
                            confidence=0.9,
                        )
                    ],
                    knowledge_links=[
                        KnowledgeLinkProposal(
                            source_id="answer:root.01-left",
                            target_id="answer:root.02-right",
                            relation=KnowledgeRelation.SUPPORTS,
                            rationale="The two independent observations jointly support the conclusion.",
                        ),
                        KnowledgeLinkProposal(
                            source_id="self",
                            target_id="question:root.01-left",
                            relation=KnowledgeRelation.ANSWERS,
                            rationale="The synthesis also resolves the left subquestion.",
                        ),
                    ],
                    sufficiency=PacketSufficiency.READY,
                ),
                role,
            )

        if role == "finalizer":
            return _execution(
                FinalArtifact(
                    content="Final answer from the assembled evidence.",
                    format="text",
                    evidence_claim_ids_used=[deps.root_packet.claims[0].id],
                ),
                role,
            )
        raise AssertionError(f"Unexpected role: {role}")


def test_recursive_children_overlap_and_parent_waits(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Recursive test",
            task="Combine two independently observable facts.",
            product_intent="Produce a grounded joint conclusion.",
            demands=[Demand(id="D1", statement="Use both facts")],
        )
    )
    harness = ScriptedRecursiveHarness(
        spec,
        runs_dir=tmp_path,
        policy=RecursivePolicy(
            max_depth=2,
            max_nodes=5,
            max_concurrency=2,
            require_root_expansion=True,
        ),
        test_model=False,
    )

    result = asyncio.run(harness.run())

    assert result.node_count == 3
    assert result.deepest_level == 1
    assert harness.max_active_research == 2
    assert result.root_packet.child_packet_ids == [
        "packet:root.01-left",
        "packet:root.02-right",
    ]
    assert result.root_packet.claims[0].derived_from_claim_ids == [
        "root.01-left:C001",
        "root.02-right:C001",
    ]
    assert harness.research_board_answer_counts == [0, 0]
    assert harness.synthesis_board_answer_ids == [
        "answer:root.01-left",
        "answer:root.02-right",
    ]
    board = result.knowledge_board
    assert set(board.questions_by_id) == {
        "question:root",
        "question:demand:D1",
        "question:root.01-left",
        "question:root.02-right",
        next(
            question_id
            for question_id in board.questions_by_id
            if question_id.startswith("question:raised:")
        ),
    }
    assert set(board.answers_by_id) == {
        "answer:root",
        "answer:root.01-left",
        "answer:root.02-right",
    }
    assert board.answer_ids_by_question["question:root"] == [
        "answer:root",
        "answer:root.01-left",
        "answer:root.02-right",
    ]
    assert board.question_ids_by_answer["answer:root"] == [
        "question:demand:D1",
        "question:root",
        "question:root.01-left",
    ]
    graph_edges = {
        (link.source_id, link.target_id, link.relation)
        for link in board.links_by_id.values()
    }
    assert (
        "question:root.01-left",
        "question:root",
        KnowledgeRelation.REFINES,
    ) in graph_edges
    assert (
        "answer:root",
        "answer:root.01-left",
        KnowledgeRelation.DERIVED_FROM,
    ) in graph_edges
    assert (
        "answer:root.01-left",
        "answer:root.02-right",
        KnowledgeRelation.SUPPORTS,
    ) in graph_edges
    assert (
        "answer:root.01-left",
        "question:demand:D1",
        KnowledgeRelation.PARTIALLY_ANSWERS,
    ) in graph_edges
    semantic_links = [
        link for link in board.links_by_id.values() if link.origin == "agent"
    ]
    assert len(semantic_links) == 2
    assert all(link.rationale for link in semantic_links)
    assert any(
        question_id.startswith("question:raised:")
        for question_id in harness.synthesis_board_question_ids
    )
    assert harness.journal.verify() == []
    report = build_postmortem(harness.journal)
    assert report["outcome"]["action"] == "finalized"
    assert report["topology"]["strategy"].startswith(
        "recursive_context_compiler (3 nodes, depth 1)"
    )
    assert report["knowledge_graph"]["question_count"] == 5
    assert report["knowledge_graph"]["answer_count"] == 3
    assert report["knowledge_graph"]["origin_counts"]["agent"] == 2
    assert len(report["knowledge_graph"]["agent_authored_links"]) == 2
    assert report["knowledge_graph"]["rejected_link_proposals"] == []
    assert report["knowledge_graph"]["multi_answer_questions"]["question:root"] == [
        "answer:root",
        "answer:root.01-left",
        "answer:root.02-right",
    ]
    assert report["knowledge_graph"]["contested_questions"] == {}


def test_frontier_self_citation_is_dropped_and_observed_claim_downgraded(
    tmp_path,
) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Provenance normalization",
            task="Establish a fact.",
            product_intent="Test frontier provenance.",
        )
    )
    harness = RecursiveHarness(spec, runs_dir=tmp_path / "runs")
    node = NodeTask(
        id="root.01-leaf",
        parent_id="root",
        depth=1,
        objective="Establish a fact.",
        rationale="Bounded leaf.",
        acceptance_condition="Return one claim.",
        expected_contribution="One fact.",
    )
    draft = EvidenceDraft(
        account="The fact holds.",
        claims=[
            EvidenceClaimDraft(
                local_id="fact",
                statement="The fact holds.",
                basis=ClaimBasis.OBSERVED,
                citations=[EvidenceCitation(source_id=node.id)],
                confidence=0.8,
            )
        ],
        sufficiency=PacketSufficiency.READY,
    )

    packet = harness._make_packet(node, draft, child_packets=[])

    assert packet.claims[0].citations == []
    assert packet.claims[0].basis == ClaimBasis.HYPOTHESIS
    assert any("discarded unknown citation" in item for item in packet.unresolved)
    assert any("downgraded unsupported observed" in item for item in packet.unresolved)


def test_synthesis_packet_citation_becomes_child_claim_provenance(tmp_path) -> None:
    spec = HarnessSpec(
        frame=TaskFrame(
            title="Packet alias",
            task="Combine evidence.",
            product_intent="Test internal provenance aliases.",
        )
    )
    harness = RecursiveHarness(spec, runs_dir=tmp_path / "runs")
    child = EvidencePacket(
        id="packet:root.01-child",
        node_id="root.01-child",
        objective="Establish the child fact.",
        account="Child fact.",
        claims=[
            EvidenceClaim(
                id="root.01-child:C001",
                statement="Child fact.",
                basis=ClaimBasis.INFERRED,
                citations=[],
                derived_from_claim_ids=[],
                counterevidence=[],
                confidence=0.9,
            )
        ],
        counterevidence=[],
        assumptions=[],
        unresolved=[],
        source_ids_consulted=[],
        boundary_findings=[],
        sufficiency=PacketSufficiency.READY,
        content_sha256="child-digest",
    )
    node = NodeTask(
        id="root",
        depth=0,
        objective="Combine evidence.",
        rationale="Parent join.",
        acceptance_condition="Use child evidence.",
        expected_contribution="Combined fact.",
    )
    draft = EvidenceDraft(
        account="Combined fact.",
        claims=[
            EvidenceClaimDraft(
                local_id="combined",
                statement="Combined fact.",
                basis=ClaimBasis.INFERRED,
                citations=[
                    EvidenceCitation(source_id=child.id),
                    EvidenceCitation(source_id=node.id),
                ],
                confidence=0.9,
            )
        ],
        sufficiency=PacketSufficiency.READY,
    )

    packet = harness._make_packet(node, draft, child_packets=[child])

    assert packet.claims[0].citations == []
    assert packet.claims[0].derived_from_claim_ids == ["root.01-child:C001"]
    assert any("converted child packet citations" in item for item in packet.unresolved)
    assert any("discarded unknown citation" in item for item in packet.unresolved)
