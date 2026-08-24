from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from pydantic_ai import Agent

from seam_harness.adaptive_agents import RequireTypedOutputAfterRetry

from seam_harness.adaptive import AdaptiveHarness
from seam_harness.adaptive_models import (
    AdaptiveAssignment,
    AdaptiveDeps,
    AdaptiveFinalArtifact,
    KnowledgePost,
    ParticipantTurn,
    QuestionResponse,
    ResponseEffect,
)
from seam_harness.cli import _parser
from seam_harness.experiments import (
    ModelAuthoredPythonAdapter,
    TextStatisticsAdapter,
    experiment_adapters,
)
from seam_harness.journal import RunJournal
from seam_harness.knowledge_tools import KnowledgeNavigator
from seam_harness.models import (
    Demand,
    HarnessSpec,
    SourceEnvelope,
    SourceMaterial,
    TaskFrame,
)
from seam_harness.orchestrator import Execution
from seam_harness.postmortem import build_postmortem
from seam_harness.recursive_models import KnowledgeRelation, RecursivePolicy


def test_participant_retry_exposes_only_output_tool() -> None:
    resolver = RequireTypedOutputAfterRetry().get_model_settings()
    assert resolver is not None
    assert resolver(SimpleNamespace(retry=0)) == {}  # type: ignore[arg-type]
    forced = resolver(SimpleNamespace(retry=1))  # type: ignore[arg-type]
    choice = forced["tool_choice"]
    assert choice is not None
    assert choice.function_tools == []


class ScriptedParticipantHarness(AdaptiveHarness):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.turns_by_node: dict[str, int] = {}
        self.participant_deps: list[AdaptiveDeps] = []
        self.public_contexts: list[dict[str, Any]] = []

    async def _bounded_call(
        self,
        agent: Agent[Any, Any],
        deps: AdaptiveDeps,
        *,
        role: str,
        model_name: str,
        max_tokens: int,
        transcript: Any = None,
        prompt: str | None = None,
    ) -> Execution[Any]:
        del agent, model_name, max_tokens, transcript, prompt
        self._call_sequence += 1
        call_id = f"scripted-{self._call_sequence:03d}-{role}"
        self.public_contexts.append(deps.model_dump(mode="json"))

        if role.startswith("adaptive_participant"):
            self.participant_deps.append(deps)
            navigator = KnowledgeNavigator(deps)
            navigator.search_questions("", unanswered_only=True, limit=8)
            if deps.assignment.depth > 0:
                navigator.search_sources("needle", limit=2)
            output = self._participant_output(deps, navigator)
        elif role == "adaptive_finalizer":
            output = AdaptiveFinalArtifact(
                content="Adaptive participant result",
                format="text",
                limitations=[],
            )
        else:  # pragma: no cover
            raise AssertionError(role)

        await self._record_knowledge_queries(call_id, deps)
        execution = Execution(
            output=output,
            call_id=call_id,
            role=role,
            model="scripted",
            input_sha256=deps.knowledge_summary.snapshot_sha256,
            elapsed_ms=1,
            usage={},
        )
        self.usage.add(role, execution)
        return execution

    def _participant_output(
        self, deps: AdaptiveDeps, navigator: KnowledgeNavigator
    ) -> ParticipantTurn:
        node_id = deps.assignment.id
        turn = self.turns_by_node.get(node_id, 0) + 1
        self.turns_by_node[node_id] = turn
        own_question = f"question:{node_id}"

        if node_id == "root":
            return self._root_turn(turn, deps, navigator)
        if node_id.endswith("angle-a") and turn == 1:
            return ParticipantTurn.model_validate(
                {
                    "account": "Angle A needs one recursively narrower observation.",
                    "contribution": None,
                    "action": {
                        "kind": "delegate",
                        "wave_rationale": "One grounded subquestion is sufficient.",
                        "delegations": [
                            {
                                "local_id": "detail",
                                "question": "What concrete detail supports angle A?",
                                "rationale": "Ground the broader angle.",
                                "acceptance_condition": "Return one bounded observation.",
                                "target_question_ids": [own_question],
                                "demand_ids": ["D1"],
                                "tags": ["evidence"],
                                "independence_account": "It is the only delegation.",
                            }
                        ],
                    },
                }
            )

        visible_answers = list(deps.knowledge_board.answers_by_id)
        links: list[dict[str, Any]] = []
        if visible_answers:
            target = visible_answers[-1]
            navigator.entry(target)
            links = [
                {
                    "target_id": target,
                    "relation": "derived_from",
                    "rationale": "The local answer incorporates the retrieved result.",
                }
            ]
        responses = [
            {
                "question_id": own_question,
                "effect": "resolves",
                "scope_or_reason": "The bounded local mandate is answered.",
            }
        ]
        if "question:root" in deps.knowledge_board.questions_by_id:
            responses.append(
                {
                    "question_id": "question:root",
                    "effect": "advances",
                    "scope_or_reason": "This is one input to the root synthesis.",
                }
            )
        return ParticipantTurn.model_validate(
            {
                "account": "Publish the local posterior and return it to the parent.",
                "contribution": {
                    "body": f"Posterior observation for {node_id}",
                    "responds_to": responses,
                    "new_questions": [],
                    "links": links,
                    "seam_signal": None,
                },
                "action": {
                    "kind": "finish",
                    "answer_ids": ["self"],
                    "rationale": "The local question is answered.",
                    "unresolved_question_ids": [],
                },
            }
        )

    def _root_turn(
        self,
        turn: int,
        deps: AdaptiveDeps,
        navigator: KnowledgeNavigator,
    ) -> ParticipantTurn:
        if turn == 1:
            return ParticipantTurn.model_validate(
                {
                    "account": "Sample two problem-shaped angles before synthesis.",
                    "contribution": None,
                    "action": {
                        "kind": "delegate",
                        "wave_rationale": "The angles share no future wave output.",
                        "delegations": [
                            {
                                "local_id": "angle-a",
                                "question": "What supports angle A?",
                                "rationale": "Establish one account.",
                                "acceptance_condition": "Return bounded evidence.",
                                "target_question_ids": ["question:root"],
                                "demand_ids": ["D1"],
                                "tags": ["evidence"],
                                "independence_account": "No angle B output is needed.",
                            },
                            {
                                "local_id": "angle-b",
                                "question": "What supports angle B?",
                                "rationale": "Establish a distinct account.",
                                "acceptance_condition": "Return bounded evidence.",
                                "target_question_ids": ["question:root"],
                                "demand_ids": ["D1"],
                                "tags": ["counterexample"],
                                "independence_account": "No angle A output is needed.",
                            },
                        ],
                    },
                }
            )

        if turn == 2:
            child_answers = [
                answer_id
                for answer_id, answer in deps.knowledge_board.answers_by_id.items()
                if answer.node_id != "root"
            ]
            for answer_id in child_answers:
                navigator.entry(answer_id)
            return ParticipantTurn.model_validate(
                {
                    "account": "Synthesize the returned angles and expose the gap.",
                    "contribution": {
                        "body": "Posterior root synthesis exposes a boundary ambiguity.",
                        "responds_to": [
                            {
                                "question_id": "question:root",
                                "effect": "advances",
                                "scope_or_reason": "The main accounts are integrated but one discriminator remains.",
                            }
                        ],
                        "new_questions": [
                            {
                                "local_id": "boundary",
                                "text": "Which boundary condition distinguishes the accounts?",
                                "rationale": "The synthesis exposed a material ambiguity.",
                                "acceptance_condition": "Identify a discriminating condition.",
                                "target_question_ids": ["question:root"],
                                "tags": ["uncertainty"],
                            }
                        ],
                        "links": [
                            {
                                "target_id": answer_id,
                                "relation": "derived_from",
                                "rationale": "The synthesis uses this retrieved answer.",
                            }
                            for answer_id in child_answers
                        ],
                        "seam_signal": {
                            "finding": "The initial angle split omitted a shared boundary condition.",
                            "affected_question_ids": ["question:root"],
                            "smallest_scope": "The root angle interface",
                            "consequence_if_absorbed": "Both leaves could look correct while using different boundaries.",
                            "contract_id": None,
                        },
                    },
                    "action": {
                        "kind": "continue",
                        "rationale": "The new first-class question needs its own action.",
                    },
                }
            )

        if turn == 3:
            raised = next(
                question_id
                for question_id in deps.knowledge_board.questions_by_id
                if question_id.startswith("question:raised:")
            )
            return ParticipantTurn.model_validate(
                {
                    "account": "Delegate the posterior question rather than following a stale plan.",
                    "contribution": None,
                    "action": {
                        "kind": "delegate",
                        "wave_rationale": "Resolve the newly observed ambiguity.",
                        "delegations": [
                            {
                                "local_id": "follow-up",
                                "question": "Resolve the boundary condition.",
                                "rationale": "This question arose from synthesis.",
                                "acceptance_condition": "Return a discriminating account.",
                                "target_question_ids": [raised],
                                "demand_ids": ["D1"],
                                "tags": ["uncertainty"],
                                "independence_account": "This is one follow-up.",
                            }
                        ],
                    },
                }
            )

        if turn == 4:
            answers = list(deps.knowledge_board.answers_by_id)
            for answer_id in answers:
                navigator.entry(answer_id)
            prior_root = next(
                answer_id
                for answer_id, answer in deps.knowledge_board.answers_by_id.items()
                if answer.node_id == "root"
            )
            return ParticipantTurn.model_validate(
                {
                    "account": "Revise the synthesis and verify a concrete property.",
                    "contribution": {
                        "body": "Revised root synthesis incorporates the boundary condition.",
                        "responds_to": [
                            {
                                "question_id": "question:root",
                                "effect": "advances",
                                "scope_or_reason": "The semantic account is assembled; a bounded check remains.",
                            }
                        ],
                        "new_questions": [],
                        "links": [
                            {
                                "target_id": answer_id,
                                "relation": "derived_from",
                                "rationale": "The revision uses this retrieved answer.",
                            }
                            for answer_id in answers
                        ],
                        "seam_signal": None,
                    },
                    "action": {
                        "kind": "verify",
                        "proposition": "The supplied corpus has measurable content.",
                        "adapter": "text_statistics",
                        "arguments": {"source_id": "corpus"},
                        "target_entry_ids": [prior_root],
                        "target_question_ids": ["question:root"],
                        "rationale": "Exercise the generic answer-producing verification path.",
                        "acceptance_condition": "Record deterministic text statistics.",
                    },
                }
            )

        answers = list(deps.knowledge_board.answers_by_id)
        for answer_id in answers:
            navigator.entry(answer_id)
        return ParticipantTurn.model_validate(
            {
                "account": "Integrate the verification result and finish.",
                "contribution": {
                    "body": "Final posterior synthesis with the grounded verification result.",
                    "responds_to": [
                        {
                            "question_id": "question:root",
                            "effect": "resolves",
                            "scope_or_reason": "The requested task is answered from the assembled context.",
                        },
                        {
                            "question_id": "question:demand:D1",
                            "effect": "resolves",
                            "scope_or_reason": "The final synthesis grounds the numbered demand.",
                        },
                    ],
                    "new_questions": [],
                    "links": [
                        {
                            "target_id": answer_id,
                            "relation": "derived_from",
                            "rationale": "The final synthesis uses this retrieved answer.",
                        }
                        for answer_id in answers
                    ],
                    "seam_signal": None,
                },
                "action": {
                    "kind": "finish",
                    "answer_ids": ["self"],
                    "rationale": "A root-owned posterior answer now exists.",
                    "unresolved_question_ids": [],
                },
            }
        )


def _spec() -> HarnessSpec:
    return HarnessSpec(
        frame=TaskFrame(
            title="Adaptive participant test",
            task="Resolve a research question.",
            product_intent="Test posterior-shaped recursive execution.",
            demands=[Demand(id="D1", statement="Ground the conclusion.")],
        ),
        source_envelope=SourceEnvelope(
            raw_request="Resolve a research question.",
            materials=[
                SourceMaterial(
                    id="corpus",
                    label="Tiny corpus",
                    content="A needle marks the relevant observation.",
                )
            ],
        ),
    )


def test_recursive_participant_synthesizes_controls_and_verifies(
    tmp_path: Path,
) -> None:
    harness = ScriptedParticipantHarness(
        _spec(),
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(
            max_adaptive_steps=12,
            max_nodes=10,
            max_depth=3,
            max_concurrency=4,
        ),
    )
    result = asyncio.run(harness.run())

    actions = sorted(result.actions, key=lambda action: action.sequence)
    assert all(
        set(action.input_entry_ids).isdisjoint(action.output_entry_ids)
        for action in actions
    )
    assert [action.kind.value for action in actions] == [
        "delegate",
        "delegate",
        "finish",
        "finish",
        "finish",
        "continue",
        "delegate",
        "finish",
        "verify",
        "finish",
    ]
    assert actions[0].actor_id == "root"
    assert any(action.actor_depth == 2 for action in actions)
    assert result.deepest_participant_level == 2
    assert result.final_artifact.content == "Adaptive participant result"
    assert result.root_answer_id == result.selected_answer_ids[-1]

    board = result.knowledge_board
    response_links = [
        link
        for link in board.links_by_id.values()
        if link.relation == KnowledgeRelation.RESPONDS_TO
    ]
    assert {link.response_effect for link in response_links} >= {
        "advances",
        "resolves",
    }
    assert all(
        answer.sufficiency is None
        for answer in board.answers_by_id.values()
        if answer.post_id is not None
    )
    assert any(
        question_id.startswith("question:raised:")
        for question_id in board.questions_by_id
    )
    assert any(
        question_id.startswith("question:seam:")
        for question_id in board.questions_by_id
    )
    assert any(
        answer.node_id.startswith("root.verify-")
        for answer in board.answers_by_id.values()
    )

    for context in harness.public_contexts:
        assert "knowledge_board" not in context
        assert "workspace_documents_by_path" not in context
        assert "source_materials_by_id" not in context
        assert "packets_by_id" not in context
        assert "posts_by_id" not in context
        assert "knowledge_summary" in context

    journal = RunJournal.open(Path(result.run_directory))
    assert journal.verify() == []
    report = build_postmortem(journal)
    assert report["topology"]["strategy"].startswith("recursive_participant_action_dag")


def test_posts_and_questions_are_queryable_with_read_set_provenance(
    tmp_path: Path,
) -> None:
    harness = ScriptedParticipantHarness(
        _spec(),
        runs_dir=tmp_path / "runs",
        policy=RecursivePolicy(max_adaptive_steps=12, max_nodes=10, max_depth=3),
    )
    result = asyncio.run(harness.run())
    board = result.knowledge_board
    deps = harness._deps(
        role="participant",
        board=board,
        step=12,
        assignment=AdaptiveAssignment(
            id="query-test",
            objective="Inspect the forum graph.",
            rationale="Validate pull retrieval.",
            acceptance_condition="Retrieve typed objects.",
        ),
    )
    navigator = KnowledgeNavigator(deps)

    question_hits = navigator.search_questions("boundary condition")
    assert any(hit.id.startswith("question:raised:") for hit in question_hits.hits)
    answer_hits = navigator.search_answers("posterior", question_ids=["question:root"])
    assert len(answer_hits.hits) >= 2
    thread = navigator.thread("question:root")
    assert len(thread.answers) >= 2

    answer_id = next(
        answer_id
        for answer_id, answer in board.answers_by_id.items()
        if answer.post_id is not None and answer.node_id != "root"
    )
    entry = navigator.entry(answer_id)
    assert entry.kind == "answer"
    assert "post" in entry.content
    post = entry.content["post"]
    assert "status" not in post
    assert "claims" not in post
    assert post["read_entry_ids"]

    synthesis_action = next(
        action
        for action in result.actions
        if action.actor_id == "root" and action.kind.value == "continue"
    )
    assert any(
        entry_id.startswith("answer:root.")
        for entry_id in synthesis_action.input_entry_ids
    )

    source_hits = navigator.search_sources("needle")
    assert source_hits.hits[0].source_id == "corpus"
    source = navigator.read_source("corpus")
    assert "needle" in source.content
    assert "corpus" in deps.disclosed_source_ids


def test_checkpoint_resume_preserves_transitive_action_lineage(
    tmp_path: Path,
) -> None:
    policy = RecursivePolicy(
        max_adaptive_steps=14,
        max_nodes=20,
        max_depth=3,
    )
    first = ScriptedParticipantHarness(
        _spec(), runs_dir=tmp_path / "runs", policy=policy
    )
    first_result = asyncio.run(first.run())
    second = ScriptedParticipantHarness(
        _spec(),
        runs_dir=tmp_path / "runs",
        policy=policy,
        resume_run=Path(first_result.run_directory),
    )
    second_result = asyncio.run(second.run())

    assert [action.sequence for action in first_result.actions] == list(range(1, 11))
    assert [action.sequence for action in second_result.actions] == list(range(1, 15))
    second_journal = RunJournal.open(Path(second_result.run_directory))
    assert second_journal.verify() == []
    report = build_postmortem(second_journal)
    assert [action["sequence"] for action in report["topology"]["actions"]] == list(
        range(1, 15)
    )


def test_post_link_schema_offers_only_authorable_relations() -> None:
    """The model must not be able to write a link the runtime will reject."""
    from pydantic import ValidationError

    from seam_harness.adaptive_models import ParticipantTurn, PostLink

    schema = ParticipantTurn.model_json_schema()
    offered = set(schema["$defs"]["PostLink"]["properties"]["relation"]["enum"])
    assert offered == {"derived_from", "supports", "contradicts", "supersedes", "duplicates"}
    assert "source_id" not in schema["$defs"]["PostLink"]["properties"]
    for runtime_owned in ("refines", "depends_on", "responds_to", "raises", "answers"):
        try:
            PostLink(target_id="answer:x", relation=runtime_owned, rationale="r")
        except ValidationError:
            continue
        raise AssertionError(f"{runtime_owned} should not be authorable by a post")


def test_no_claim_does_not_mark_a_question_substantively_answered() -> None:
    post = KnowledgePost(
        body="The dossier lacks the required interface.",
        responds_to=[
            QuestionResponse(
                question_id="question:x",
                effect=ResponseEffect.NO_CLAIM,
                scope_or_reason="The interface is absent.",
            )
        ],
    )
    assert post.responds_to[0].effect == ResponseEffect.NO_CLAIM
    assert "sufficiency" not in post.model_dump()


def test_solve_cli_defaults_to_adaptive_execution() -> None:
    args = _parser().parse_args(["solve", "task.json"])
    assert args.execution == "adaptive"


def test_experiment_adapters_are_typed_bounded_and_opt_in() -> None:
    source = SourceMaterial(
        id="sample", label="Sample", content="one two\none two three\n"
    )
    result = asyncio.run(
        TextStatisticsAdapter().run(
            {"source_id": "sample"},
            snapshot=None,
            source_materials={"sample": source},
            timeout_seconds=1,
        )
    )
    assert result.status == "completed"
    assert "words=5" in result.summary
    assert set(experiment_adapters(RecursivePolicy())) == {"text_statistics"}
    enabled = RecursivePolicy(
        enabled_experiment_adapters=[
            "text_statistics",
            "pytest",
            "python_checker",
        ]
    )
    adapters = experiment_adapters(enabled)
    assert set(adapters) == {"text_statistics", "pytest", "python_checker"}
    assert adapters["python_checker"].info.executes_model_authored_code is True

    checked = asyncio.run(
        ModelAuthoredPythonAdapter().run(
            {"code": "print(6 * 7)", "argv": []},
            snapshot=None,
            source_materials={},
            timeout_seconds=2,
        )
    )
    assert checked.status == "completed"
    assert checked.stdout.strip() == "42"
