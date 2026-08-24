"""Deterministic post-mortem fields for recursive participant runs."""

from __future__ import annotations

import json
from typing import Any

from .journal import RunJournal
from .recursive_postmortem import build_recursive_fields


def _stage_records(journal: RunJournal, stage: str) -> list[dict[str, Any]]:
    return [
        json.loads((journal.root / event["path"]).read_text(encoding="utf-8"))
        for event in journal.manifest.get("events", [])
        if event.get("stage") == stage
    ]


def build_adaptive_fields(
    journal: RunJournal, result: dict[str, Any]
) -> dict[str, Any]:
    """Build the action DAG, forum provenance, and verification account."""

    recursive_shape = {
        **result,
        "node_traces": [],
        "node_count": result.get("work_item_count", 0),
        "deepest_level": result.get("deepest_participant_level", 0),
    }
    fields = build_recursive_fields(journal, recursive_shape)

    # Resumed results contain locally emitted records plus imported state. The
    # verified resume chain is authoritative for the transitive action DAG.
    from .adaptive import AdaptiveHarness

    actions = [
        action.model_dump(mode="json")
        for action in AdaptiveHarness._checkpoint_action_lineage(journal)
    ]
    queries = _stage_records(journal, "04-knowledge-queries")
    experiments = _stage_records(journal, "21-experiments")
    rejections = _stage_records(journal, "11-participant-rejections")
    posts = _stage_records(journal, "30-knowledge-posts")
    seam_signals = _stage_records(journal, "09-seam-signals")
    operational_failures = _stage_records(journal, "22-participant-failures")

    query_counts: dict[str, int] = {}
    disclosed_result_ids: set[str] = set()
    for call in queries:
        for query in call.get("queries", []):
            tool = query.get("tool", "unknown")
            query_counts[tool] = query_counts.get(tool, 0) + 1
            disclosed_result_ids.update(query.get("result_ids", []))

    board = result.get("knowledge_board", {})
    root_answer_id = result.get("root_answer_id")
    root_effects = sorted(
        {
            link.get("response_effect")
            for link in board.get("links_by_id", {}).values()
            if link.get("source_id") == root_answer_id
            and link.get("relation") == "responds_to"
            and link.get("response_effect") is not None
        }
    )
    deepest = result.get("deepest_participant_level", 0)
    selected = result.get("selected_answer_ids", [])

    fields["outcome"].update(
        {
            "decision": (
                f"Finalized root answer {root_answer_id} from selected forum "
                f"answers: {', '.join(selected)}"
            ),
            "affected_leaf_ids": [
                work_id
                for action in actions
                for work_id in action.get("work_item_ids", [])
            ],
            "observation_that_would_reverse_decision": None,
            "residual_risk": [
                *result.get("final_artifact", {}).get("limitations", []),
                *result.get("final_artifact", {}).get("unresolved_question_ids", []),
            ],
        }
    )
    fields["topology"] = {
        "strategy": (
            "recursive_participant_action_dag "
            f"({len(actions)} actions, "
            f"{result.get('work_item_count', 0)} work items, depth {deepest})"
        ),
        "leaf_ids": [
            work_id for action in actions for work_id in action.get("work_item_ids", [])
        ],
        "contract_ids": [],
        "planning_rounds": 0,
        "final_readiness": root_effects,
        "root_answer_id": root_answer_id,
        "deepest_participant_level": deepest,
        "actions": actions,
        "edges": [
            {
                "action_id": action.get("action_id"),
                "actor_id": action.get("actor_id", "root"),
                "actor_depth": action.get("actor_depth", 0),
                "reads": action.get("input_entry_ids", []),
                "writes": action.get("output_entry_ids", []),
                "snapshot_before": action.get("snapshot_before_sha256"),
                "snapshot_after": action.get("snapshot_after_sha256"),
            }
            for action in actions
        ],
    }
    fields["signals"].update(
        {
            "participant_rejections": rejections,
            "knowledge_queries": queries,
            "query_counts_by_tool": dict(sorted(query_counts.items())),
            "retrieved_entry_ids": sorted(disclosed_result_ids),
            "knowledge_posts": posts,
            "post_read_sets": [
                {
                    "post_id": post.get("id"),
                    "node_id": post.get("node_id"),
                    "read_entry_ids": post.get("read_entry_ids", []),
                    "read_source_ids": post.get("read_source_ids", []),
                }
                for post in posts
            ],
            "experiments": experiments,
            "seam_signals": seam_signals,
            "operational_failures": operational_failures,
            "raised_question_ids": sorted(
                question_id
                for question_id in board.get("questions_by_id", {})
                if question_id.startswith(("question:raised:", "question:seam:"))
            ),
        }
    )
    return fields
