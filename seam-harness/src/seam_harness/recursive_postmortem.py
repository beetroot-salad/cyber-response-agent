"""Deterministic post-mortem fields for recursive context-compiler runs."""

from __future__ import annotations

import json
from typing import Any

from .journal import RunJournal


def build_recursive_fields(
    journal: RunJournal, result: dict[str, Any]
) -> dict[str, Any]:
    packets: list[dict[str, Any]] = []
    for event in journal.manifest.get("events", []):
        if event.get("stage") != "30-evidence-packets":
            continue
        packets.append(
            json.loads((journal.root / event["path"]).read_text(encoding="utf-8"))
        )

    link_rejections: list[dict[str, Any]] = []
    for event in journal.manifest.get("events", []):
        if event.get("stage") != "08-knowledge-link-rejections":
            continue
        link_rejections.append(
            json.loads((journal.root / event["path"]).read_text(encoding="utf-8"))
        )

    traces = result.get("node_traces", [])
    root = result.get("root_packet", {})
    artifact = result.get("final_artifact", {})
    boundary_findings = [
        {"node_id": packet.get("node_id"), "finding": finding}
        for packet in packets
        for finding in packet.get("boundary_findings", [])
    ]
    unresolved = [
        {"node_id": packet.get("node_id"), "item": item}
        for packet in packets
        for item in packet.get("unresolved", [])
    ]
    blocked = [
        {
            "node_id": packet.get("node_id"),
            "sufficiency": packet.get("sufficiency"),
            "next_observation": packet.get("next_observation"),
        }
        for packet in packets
        if packet.get("sufficiency") in {"partial", "blocked", "coupled"}
    ]
    stopped = [
        {
            "node_id": trace.get("node_id"),
            "effective_disposition": trace.get("effective_disposition"),
            "stop_reason": trace.get("stop_reason"),
        }
        for trace in traces
        if trace.get("stop_reason")
    ]
    board = result.get("knowledge_board", {})
    questions = board.get("questions_by_id", {})
    answers = board.get("answers_by_id", {})
    links = board.get("links_by_id", {})
    relation_counts: dict[str, int] = {}
    origin_counts: dict[str, int] = {}
    agent_authored_links: list[dict[str, Any]] = []
    for link in links.values():
        relation = link.get("relation", "unknown")
        relation_counts[relation] = relation_counts.get(relation, 0) + 1
        origin = link.get("origin", "runtime")
        origin_counts[origin] = origin_counts.get(origin, 0) + 1
        if origin == "agent":
            agent_authored_links.append(
                {
                    "source_id": link.get("source_id"),
                    "target_id": link.get("target_id"),
                    "relation": relation,
                    "rationale": link.get("rationale"),
                    "proposed_by_node_id": link.get("proposed_by_node_id"),
                }
            )
    multi_answer_questions = {
        question_id: answer_ids
        for question_id, answer_ids in board.get("answer_ids_by_question", {}).items()
        if len(answer_ids) > 1
    }
    questions_by_answer = board.get("question_ids_by_answer", {})
    contested_sets: dict[str, set[str]] = {}
    contested_answer_pairs: list[dict[str, str]] = []
    for link in links.values():
        if link.get("relation") != "contradicts":
            continue
        source_id = link.get("source_id", "")
        target_id = link.get("target_id", "")
        contested_answer_pairs.append({"source_id": source_id, "target_id": target_id})
        shared_questions = set(questions_by_answer.get(source_id, [])) & set(
            questions_by_answer.get(target_id, [])
        )
        for question_id in shared_questions:
            contested_sets.setdefault(question_id, set()).update({source_id, target_id})
    contested_questions = {
        question_id: sorted(answer_ids)
        for question_id, answer_ids in sorted(contested_sets.items())
    }
    unanswered_questions = sorted(
        set(questions) - set(board.get("answer_ids_by_question", {}))
    )
    node_count = result.get("node_count", len(traces))
    deepest = result.get("deepest_level", 0)
    return {
        "outcome": {
            "action": "finalized",
            "decision": (
                f"Emitted artifact format {artifact.get('format', 'text')} from root packet "
                f"{root.get('id', 'unknown')}."
            ),
            "smallest_intervention": None,
            "affected_contract_ids": [],
            "affected_leaf_ids": [],
            "observation_that_would_reverse_decision": root.get("next_observation"),
            "residual_risk": [
                *artifact.get("limitations", []),
                *artifact.get("unresolved", []),
            ],
        },
        "topology": {
            "strategy": (
                f"recursive_context_compiler ({node_count} nodes, depth {deepest})"
            ),
            "leaf_ids": [
                trace.get("node_id") for trace in traces if not trace.get("child_ids")
            ],
            "contract_ids": [],
            "planning_rounds": sum(
                1
                for event in journal.manifest.get("events", [])
                if event.get("stage") == "10-node-plans"
            ),
            "final_readiness": root.get("sufficiency"),
            "node_traces": traces,
        },
        "signals": {
            "probe_counts": {"all": 0, "discovery": 0, "holdout": 0},
            "final_referent_failures": [],
            "final_unowned_invariants": [],
            "leaf_interface_findings": boundary_findings,
            "audit_unanticipated_observations": [],
            "blind_tensions": [],
            "correlated_assumptions": [],
            "refusals_or_overreach": [],
            "missing_evidence": blocked,
            "likely_learning": [],
            "likely_handoff_loss": [],
            "likely_silent_coupling": stopped,
            "unresolved": unresolved,
            "minimum_sufficient_next_step": root.get("next_observation"),
        },
        "knowledge_graph": {
            "digest": board.get("content_sha256"),
            "version": board.get("version", 0),
            "question_count": len(questions),
            "answer_count": len(answers),
            "link_count": len(links),
            "relation_counts": dict(sorted(relation_counts.items())),
            "origin_counts": dict(sorted(origin_counts.items())),
            "agent_authored_links": agent_authored_links,
            "rejected_link_proposals": link_rejections,
            "multi_answer_questions": multi_answer_questions,
            "contested_questions": contested_questions,
            "contested_answer_pairs": contested_answer_pairs,
            "unanswered_question_ids": unanswered_questions,
            "entry_ids_by_tag": board.get("entry_ids_by_tag", {}),
        },
        "usage_by_role": result.get("usage_by_role", {}),
    }
