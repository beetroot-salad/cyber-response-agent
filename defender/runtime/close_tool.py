"""#774 — the close tool: the ONLY writer of report.md once R1 lands, and the seam through
which a confident disposition passes the live write-time challenge gate before it commits.

`close_investigation(deps, disposition, *, stages, bounds=None) -> CloseResult` is the SYNC
host-level close (what a test, or any synchronous host caller, drives directly).
`_tool_close_investigation` is its ASYNC model-facing adapter — the two share
`_close_investigation_async`, so `close_investigation` is never called from inside a running
event loop (it would raise) and the tool body never blocks on a nested `asyncio.run`.

`register_close_tool` registers the tool at MAIN's composition root ONLY (K14: a verb grant
cannot express this — verbs are data-source operations, and a non-empty grant on any other
role fails policy compile). Role admission is ALSO checked host-side, in
`_close_investigation_async` itself, so the negative holds even for a direct call that never
goes through tool registration at all.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._artifact_schema import DISPOSITION_ENUM, validate_artifact
from defender._untrusted import wrap as _wrap
from defender.hooks.budget_enforcer import BUDGET_EXEMPT_TOOLS  # noqa: F401 — re-export, RS16

from . import challenge_gate
from .agent_role import AgentRole
from .tools import AgentDeps

UNCHALLENGED = "closed-unchallenged"
REFUTED = "closed-refuted"
INCOHERENT = "closed-incoherent"
DECLINED = "closed-declined"
REVIEW_FAILED = "forced-inconclusive-review-failed"
MALFORMED = "closed-malformed"
CHALLENGED = "challenged"
FORCED_NONDISCRIMINATING = "forced-inconclusive-nondiscriminating"
FORCED_CAP = "forced-inconclusive-cap"
EVIDENCE_SILENT = "closed-evidence-cannot-speak"

CLOSE_OUTCOMES: tuple[str, ...] = (
    UNCHALLENGED, REFUTED, INCOHERENT, DECLINED, REVIEW_FAILED, MALFORMED, CHALLENGED,
    FORCED_NONDISCRIMINATING, FORCED_CAP, EVIDENCE_SILENT,
)


@dataclass(frozen=True)
class RecommendedLead:
    lead_id: str
    requirement: str
    origin: str


@dataclass(frozen=True)
class CloseResult:
    outcome: str
    message: str
    material: tuple[RecommendedLead, ...]
    record_path: Path | None
    reason: str
    turns_used: int = 0
    rounds_used: int = 0
    failure_kind: str | None = None


def render_report(
    disposition: str, *, outcome: str, reason: str | None = None, evidence: str | None = None,
) -> str:
    """RS12. The body is HOST-RENDERED from typed arguments — the tool accepts no
    model-supplied body. `reason` is a typed close-outcome ARM, never raw payload prose
    (that is what keeps it inside the 512-byte frontmatter cap and out of the raw-render
    exposure)."""
    reason_value = reason if reason is not None else outcome
    body = f"Disposition recorded by the close gate. outcome={outcome}."
    if evidence:
        body += f" {evidence}"
    return (
        "---\n"
        f"disposition: {disposition}\n"
        f"reason: {reason_value}\n"
        "---\n"
        f"{body}\n"
    )


def _render_challenged_message(material: tuple[RecommendedLead, ...], deps: AgentDeps) -> str:
    if not material:
        return "The gate challenged this close but left nothing new to investigate."
    lines = [f"- {lead.lead_id}: {lead.requirement}" for lead in material]
    # O6/O7: the discriminating material is derived from a payload-influenced role's output —
    # it returns inside the SAME run-salted untrusted frame the gather subagent's return
    # already uses (`defender._untrusted.wrap`, keyed on the INVESTIGATION's own salt, never
    # the review role's own — the review role minted a fresh one and never held this one).
    framed = _wrap("\n".join(lines), "untrusted", deps.salt)
    return (
        f"The gate challenged this close — {len(material)} discriminating lead(s) remain. "
        f"Investigate further before re-closing:\n{framed}"
    )


def _record_dict(verdict: challenge_gate.GateVerdict, disposition: str, deps: AgentDeps) -> dict:
    return {
        "verdict": verdict.outcome,
        "direction": verdict.direction,
        "attacked_disposition": disposition,
        "requirement_list": (
            _wrap(json.dumps(verdict.requirement_list), "untrusted", deps.salt)
            if verdict.requirement_list else ""
        ),
        "projection_response": (
            _wrap(json.dumps(verdict.projection_rows), "untrusted", deps.salt)
            if verdict.projection_rows else ""
        ),
        "rounds_consumed": verdict.rounds_used,
        "failure_kind": verdict.failure_kind,
    }


@dataclass(frozen=True)
class _CloseFields:
    """The scalar fields `_commit` needs beyond `deps`/`disposition`/`record` — bundled so
    the function stays under the arg-count lint rather than growing an 11th parameter."""

    outcome: str
    result_reason: str
    material: tuple[RecommendedLead, ...]
    turns_used: int
    rounds_used: int
    failure_kind: str | None


def _commit(
    deps: AgentDeps, disposition: str, fields: _CloseFields, record: dict, *,
    evidence: str | None = None,
) -> CloseResult:
    """RS19. Record FIRST, report SECOND — both attempted regardless of the other's fault,
    and any fault is held until both writes have been attempted (never silently dropping
    the second write). `fields.result_reason` is the DETAILED reason on the returned
    `CloseResult` (may name a failed stage); the report's own frontmatter `reason` is
    always the TYPED outcome arm — `render_report` defaults it to `outcome` when not
    overridden."""
    state = challenge_gate.ReviewState.of(deps)
    turn_for_record = state.turns + 1
    record_path = challenge_gate.review_record_path(deps.run_dir, turn_for_record)

    record_error: BaseException | None = None
    try:
        challenge_gate.write_review_record(deps.run_dir, turn_for_record, record)
    except OSError as e:
        record_error = e

    body = render_report(disposition, outcome=fields.outcome, evidence=evidence)
    schema_reason = validate_artifact("report.md", body, None)
    report_error: BaseException | None = None
    if schema_reason is not None:
        report_error = ModelRetry(schema_reason)
    else:
        report_path = deps.run_dir / "report.md"
        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(body, encoding="utf-8")
        except OSError as e:
            report_error = e

    if record_error is not None or report_error is not None:
        raise record_error if record_error is not None else report_error  # type: ignore[misc]

    state.closed = True
    state.disposition = disposition
    return CloseResult(
        outcome=fields.outcome, message=f"closed: {fields.outcome} (disposition={disposition})",
        material=fields.material, record_path=record_path, reason=fields.result_reason,
        turns_used=fields.turns_used, rounds_used=fields.rounds_used,
        failure_kind=fields.failure_kind,
    )


async def _close_investigation_async(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
    evidence: str | None = None,
) -> CloseResult:
    if deps.role is not AgentRole.MAIN:
        raise ModelRetry(
            "close_investigation is reachable only from the investigator (main) role — "
            f"not from {deps.role.value}"
        )
    if disposition not in DISPOSITION_ENUM:
        raise ModelRetry(
            f"disposition must be exactly one of {sorted(DISPOSITION_ENUM)} (got "
            f"{disposition!r}) — a typed enum, not free text"
        )
    bounds = bounds if bounds is not None else challenge_gate.default_bounds()

    if disposition == "inconclusive":
        record = {
            "verdict": UNCHALLENGED, "direction": None, "attacked_disposition": disposition,
            "requirement_list": "", "projection_response": "",
            "rounds_consumed": 0, "failure_kind": None,
        }
        fields = _CloseFields(
            outcome=UNCHALLENGED, result_reason=UNCHALLENGED, material=(),
            turns_used=0, rounds_used=0, failure_kind=None,
        )
        return _commit(deps, disposition, fields, record, evidence=evidence)

    verdict = await challenge_gate.challenge_gate(deps, disposition, stages=stages, bounds=bounds)
    material = tuple(
        RecommendedLead(lead_id=lid, requirement=req, origin="review")
        for lid, req in verdict.material
    )
    record = _record_dict(verdict, disposition, deps)

    if verdict.outcome == CHALLENGED:
        state = challenge_gate.ReviewState.of(deps)
        turn = state.turns  # already incremented inside challenge_gate for this attempt
        record_path = challenge_gate.review_record_path(deps.run_dir, turn)
        challenge_gate.write_review_record(deps.run_dir, turn, record)
        return CloseResult(
            outcome=CHALLENGED, message=_render_challenged_message(material, deps),
            material=material, record_path=record_path, reason=verdict.reason,
            turns_used=verdict.turns_used, rounds_used=verdict.rounds_used,
            failure_kind=verdict.failure_kind,
        )

    fields = _CloseFields(
        outcome=verdict.outcome, result_reason=verdict.reason, material=material,
        turns_used=verdict.turns_used, rounds_used=verdict.rounds_used,
        failure_kind=verdict.failure_kind,
    )
    return _commit(deps, verdict.disposition, fields, record, evidence=evidence)


def close_investigation(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
    evidence: str | None = None,
) -> CloseResult:
    """The SYNC host-level close. Never call this from inside a running event loop."""
    return asyncio.run(_close_investigation_async(
        deps, disposition, stages=stages, bounds=bounds, evidence=evidence,
    ))


async def _tool_close_investigation(
    deps: AgentDeps, disposition: str, *, stages: Any, bounds: challenge_gate.Bounds | None = None,
) -> str:
    result = await _close_investigation_async(deps, disposition, stages=stages, bounds=bounds)
    return result.message


def register_close_tool(agent, *, stages: Any, bounds: challenge_gate.Bounds | None = None) -> None:
    """MAIN's composition root ONLY — never called for any other role's agent build."""

    @agent.tool
    async def close_investigation(ctx: RunContext[AgentDeps], disposition: str) -> str:
        """Commit this investigation's disposition once ANALYZE has reached a confident
        finding. `disposition` is the typed enum (benign | inconclusive | malicious), never
        free text. This is the ONLY way to record report.md — write_file/edit_file cannot
        reach it. A confident disposition passes a live challenge gate before it commits;
        if the gate is not satisfied yet, this call returns without committing and the
        investigation continues for another ANALYZE/GATHER turn."""
        return await _tool_close_investigation(ctx.deps, disposition, stages=stages, bounds=bounds)


__all__ = [
    "BUDGET_EXEMPT_TOOLS",
    "CHALLENGED",
    "CLOSE_OUTCOMES",
    "DECLINED",
    "EVIDENCE_SILENT",
    "FORCED_CAP",
    "FORCED_NONDISCRIMINATING",
    "INCOHERENT",
    "MALFORMED",
    "REFUTED",
    "REVIEW_FAILED",
    "UNCHALLENGED",
    "CloseResult",
    "RecommendedLead",
    "close_investigation",
    "register_close_tool",
    "render_report",
]
