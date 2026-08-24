"""Deterministic post-mortem views over an immutable run journal."""

from __future__ import annotations

import json
from typing import Any

from .adaptive_postmortem import build_adaptive_fields
from .journal import RunJournal
from .recursive_postmortem import build_recursive_fields


def _read_event(journal: RunJournal, event: dict[str, Any]) -> Any:
    return json.loads((journal.root / event["path"]).read_text(encoding="utf-8"))


def _find_event(
    journal: RunJournal, stage: str, name: str
) -> tuple[dict[str, Any], Any] | None:
    for event in journal.manifest.get("events", []):
        if event.get("stage") == stage and event.get("name") == name:
            return event, _read_event(journal, event)
    return None


def _call_trace(journal: RunJournal) -> list[dict[str, Any]]:
    calls: dict[str, dict[str, Any]] = {}
    for event in journal.manifest.get("events", []):
        metadata = event.get("metadata", {})
        if event.get("stage") == "01-call-inputs":
            payload = _read_event(journal, event)
            call_id = payload["call_id"]
            calls[call_id] = {
                "call_id": call_id,
                "role": payload.get("role"),
                "model": payload.get("model"),
                "dependency_type": payload.get("dependency_type"),
                "input_sha256": payload.get("input_sha256"),
                "input_record": event.get("path"),
                "status": "started",
            }
            continue

        call_id = metadata.get("call_id")
        if not call_id:
            continue
        trace = calls.setdefault(
            call_id,
            {
                "call_id": call_id,
                "role": metadata.get("role"),
                "model": metadata.get("model"),
                "input_sha256": metadata.get("input_sha256"),
                "status": "unknown",
            },
        )
        if event.get("stage") == "02-call-errors":
            trace["status"] = "failed"
            trace["error"] = _read_event(journal, event)
            trace["error_record"] = event.get("path")
        else:
            trace.update(
                {
                    "status": "completed",
                    "output_stage": event.get("stage"),
                    "output_name": event.get("name"),
                    "output_record": event.get("path"),
                    "elapsed_ms": metadata.get("elapsed_ms"),
                    "usage": metadata.get("usage", {}),
                }
            )
    return list(calls.values())


def build_postmortem(journal: RunJournal) -> dict[str, Any]:
    """Build a machine-readable report without asking another model to reinterpret it."""

    integrity = journal.summary()
    result_event = _find_event(journal, "99-result", "harness-result")
    recursive_result_event = _find_event(journal, "99-result", "recursive-result")
    adaptive_result_event = _find_event(journal, "99-result", "adaptive-result")
    failure_event = _find_event(journal, "99-result", "failure")
    spec_event = (
        _find_event(journal, "00-input", "spec")
        or _find_event(journal, "00-input", "adaptive-run")
        or _find_event(journal, "00-input", "recursive-run")
    )
    intake_report = None
    spec_payload = spec_event[1] if spec_event else {}
    if "spec" in spec_payload:
        spec_payload = spec_payload["spec"]
    if spec_payload.get("intake"):
        intake = spec_payload["intake"]
        assessment = intake.get("assessment", {})
        intake_report = {
            "readiness": assessment.get("readiness"),
            "generated_by_model": intake.get("generated_by_model"),
            "source_sha256": intake.get("source_sha256"),
            "frame_sha256": intake.get("frame_sha256"),
            "elapsed_ms": intake.get("elapsed_ms"),
            "usage": intake.get("usage", {}),
            "derivations": assessment.get("derivations", []),
            "assumptions": assessment.get("assumptions", []),
            "unresolved": assessment.get("unresolved", []),
            "clarification_questions": assessment.get("clarification_questions", []),
            "framing_notes": assessment.get("framing_notes"),
        }
    report: dict[str, Any] = {
        "integrity": integrity,
        "failure": failure_event[1] if failure_event else None,
        "intake": intake_report,
        "outcome": None,
        "topology": None,
        "signals": None,
        "usage_by_role": {},
        "calls": _call_trace(journal),
        "timeline": [
            {
                "index": event.get("index"),
                "timestamp": event.get("timestamp"),
                "stage": event.get("stage"),
                "name": event.get("name"),
                "path": event.get("path"),
            }
            for event in journal.manifest.get("events", [])
        ],
    }
    if adaptive_result_event:
        report.update(build_adaptive_fields(journal, adaptive_result_event[1]))
        return report
    if recursive_result_event:
        report.update(build_recursive_fields(journal, recursive_result_event[1]))
        return report
    if not result_event:
        return report

    result = result_event[1]
    adjudication = result.get("adjudication", {})
    plan = result.get("final_plan", {})
    probes = result.get("probes", [])
    rounds = result.get("planning_rounds", [])
    final_critique = rounds[-1].get("critique", {}) if rounds else {}
    frozen = result.get("frozen_results", [])
    audits = result.get("audits", [])
    interpretation = result.get("blind_interpretation", {})
    diagnosis = result.get("diagnosis", {})

    report.update(
        {
            "outcome": {
                "action": adjudication.get("action"),
                "decision": adjudication.get("decision"),
                "smallest_intervention": adjudication.get("smallest_intervention"),
                "affected_contract_ids": adjudication.get("affected_contract_ids", []),
                "affected_leaf_ids": adjudication.get("affected_leaf_ids", []),
                "observation_that_would_reverse_decision": adjudication.get(
                    "observation_that_would_reverse_decision"
                ),
                "residual_risk": adjudication.get("residual_risk", []),
            },
            "topology": {
                "strategy": plan.get("strategy"),
                "leaf_ids": [leaf.get("id") for leaf in plan.get("leaves", [])],
                "contract_ids": [
                    contract.get("id") for contract in plan.get("contracts", [])
                ],
                "planning_rounds": len(rounds),
                "final_readiness": final_critique.get("readiness"),
            },
            "signals": {
                "probe_counts": {
                    "all": len(probes),
                    "discovery": sum(
                        probe.get("exposure") == "discovery" for probe in probes
                    ),
                    "holdout": sum(
                        probe.get("exposure") == "holdout" for probe in probes
                    ),
                },
                "final_referent_failures": final_critique.get("referent_failures", []),
                "final_unowned_invariants": final_critique.get(
                    "unowned_invariants", []
                ),
                "leaf_interface_findings": [
                    {
                        "leaf_id": item.get("leaf_id"),
                        "findings": item.get("work", {}).get("interface_findings", []),
                    }
                    for item in frozen
                    if item.get("work", {}).get("interface_findings")
                ],
                "audit_unanticipated_observations": [
                    {
                        "leaf_id": audit.get("leaf_id"),
                        "observations": audit.get(
                            "observations_not_anticipated_by_probes", []
                        ),
                    }
                    for audit in audits
                    if audit.get("observations_not_anticipated_by_probes")
                ],
                "blind_tensions": interpretation.get("tensions", []),
                "correlated_assumptions": interpretation.get(
                    "correlated_assumptions", []
                ),
                "refusals_or_overreach": interpretation.get(
                    "refusals_or_overreach", []
                ),
                "missing_evidence": interpretation.get("missing_evidence", []),
                "likely_learning": diagnosis.get("likely_learning", []),
                "likely_handoff_loss": diagnosis.get("likely_handoff_loss", []),
                "likely_silent_coupling": diagnosis.get("likely_silent_coupling", []),
                "unresolved": diagnosis.get("unresolved", []),
                "minimum_sufficient_next_step": diagnosis.get(
                    "minimum_sufficient_next_step"
                ),
            },
            "usage_by_role": result.get("usage_by_role", {}),
        }
    )
    return report


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _items(values: list[Any]) -> list[str]:
    if not values:
        return ["- None recorded."]
    rendered = []
    for value in values:
        if isinstance(value, dict):
            value = json.dumps(value, sort_keys=True, ensure_ascii=False)
        rendered.append(f"- {value}")
    return rendered


def render_markdown(report: dict[str, Any]) -> str:
    """Render the deterministic report for a human investigation."""

    integrity = report["integrity"]
    intake = report.get("intake") or {}
    outcome = report.get("outcome") or {}
    topology = report.get("topology") or {}
    signals = report.get("signals") or {}
    knowledge_graph = report.get("knowledge_graph") or {}
    lines = [
        f"# Post-mortem: {integrity['run_id']}",
        "",
        f"- Status: `{integrity.get('status')}`",
        f"- Hash chain valid: `{integrity.get('chain_valid')}`",
        f"- Records: `{integrity.get('record_count')}`",
        f"- Intake readiness: `{(report.get('intake') or {}).get('readiness', 'not recorded')}`",
        f"- Action: `{outcome.get('action', 'unavailable')}`",
        f"- Strategy: `{topology.get('strategy', 'unavailable')}`",
        "",
    ]
    if report.get("failure"):
        lines.extend(
            [
                "## Failure",
                "",
                f"```json\n{json.dumps(report['failure'], indent=2)}\n```",
                "",
            ]
        )
    if intake:
        lines.extend(
            [
                "## Intake framing",
                "",
                f"Generated by: `{intake.get('generated_by_model')}`",
                "",
                str(intake.get("framing_notes") or "No framing notes recorded."),
                "",
                "Clarification questions:",
                "",
                *_items(intake.get("clarification_questions", [])),
                "",
                "Assumptions:",
                "",
                *_items(intake.get("assumptions", [])),
                "",
                "Unresolved:",
                "",
                *_items(intake.get("unresolved", [])),
                "",
            ]
        )
    if outcome:
        lines.extend(
            [
                "## Decision",
                "",
                str(outcome.get("decision") or "No decision recorded."),
                "",
                f"Smallest intervention: {outcome.get('smallest_intervention') or '—'}",
                "",
                "Residual risk:",
                "",
                *_items(outcome.get("residual_risk", [])),
                "",
            ]
        )
    if signals:
        lines.extend(["## Diagnostic signals", ""])
        for label, key in (
            ("Likely learning", "likely_learning"),
            ("Likely handoff loss", "likely_handoff_loss"),
            ("Likely silent coupling", "likely_silent_coupling"),
            ("Correlated assumptions", "correlated_assumptions"),
            ("Missing evidence", "missing_evidence"),
            ("Unresolved", "unresolved"),
        ):
            lines.extend([f"### {label}", "", *_items(signals.get(key, [])), ""])

    if knowledge_graph:
        lines.extend(
            [
                "## Knowledge graph",
                "",
                f"- Questions: `{knowledge_graph.get('question_count', 0)}`",
                f"- Answers: `{knowledge_graph.get('answer_count', 0)}`",
                f"- Links: `{knowledge_graph.get('link_count', 0)}`",
                f"- Relations: `{json.dumps(knowledge_graph.get('relation_counts', {}), sort_keys=True)}`",
                f"- Origins: `{json.dumps(knowledge_graph.get('origin_counts', {}), sort_keys=True)}`",
                "",
                "Questions with multiple answers:",
                "",
                *_items(knowledge_graph.get("multi_answer_questions", [])),
                "",
                "Questions with explicit answer contradictions:",
                "",
                *_items(knowledge_graph.get("contested_questions", [])),
                "",
                "Agent-authored semantic links:",
                "",
                *_items(knowledge_graph.get("agent_authored_links", [])),
                "",
                "Rejected semantic-link proposals:",
                "",
                *_items(knowledge_graph.get("rejected_link_proposals", [])),
                "",
                "Unanswered questions:",
                "",
                *_items(knowledge_graph.get("unanswered_question_ids", [])),
                "",
            ]
        )

    lines.extend(
        [
            "## Model-call trace",
            "",
            "| Call | Role | Model | Context type | Status | Elapsed ms | Input tokens | Output tokens |",
            "|---|---|---|---|---:|---:|---:|---:|",
        ]
    )
    for call in report.get("calls", []):
        usage = call.get("usage", {})
        lines.append(
            "| "
            + " | ".join(
                _cell(value)
                for value in (
                    call.get("call_id"),
                    call.get("role"),
                    call.get("model"),
                    call.get("dependency_type"),
                    call.get("status"),
                    call.get("elapsed_ms"),
                    usage.get("input_tokens"),
                    usage.get("output_tokens"),
                )
            )
            + " |"
        )
    lines.append("")
    return "\n".join(lines)
