"""Judge stage — grounded outcome classifier for both directions.

One driver, parametrized by ``JudgeWiring`` (the adversarial vs benign prompt/model/
effort + disjoint comparison/settings names + the benign-only closed-ticket read), so
the per-direction variation is pure config — there is no separate benign driver. The
comparison join + synthesis (the structural grounding) live in ``compare.py``; the two
prompts are ``malicious.md`` / ``benign.md`` in this package.
"""
from __future__ import annotations

import json
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender.learning import lead_repository
from defender._run_paths import RunPaths
from defender.learning.core.config import JudgeWiring, _log
from defender.learning.core.runner import _copy_transcript, _run_claude, _section
from defender.learning.pipeline.judge.compare import (
    build_comparison,
    judge_settings_dict,
    parse_investigation_companion,
    render_manifest,
    render_synthesis,
    write_comparison_files,
)
from defender.learning.tickets import ticket_seeds
from defender.scripts.case_history import case_ticket


@dataclass(frozen=True)
class _ToolScope:
    """The tool-surface scoping kwargs forwarded to ``_run_claude`` — settings file,
    add-dir(s), and permission mode."""

    settings_path: Path | None = None
    add_dir: Path | list[Path] | None = None
    permission_mode: str | None = None


# Frozen → safe to share one default instance (no mutable-default aliasing).
_DEFAULT_TOOL_SCOPE = _ToolScope()


def _run_judge_claude(
    prompt_path: Path,
    model: str,
    effort: str,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    *,
    scope: _ToolScope = _DEFAULT_TOOL_SCOPE,
) -> str:
    """Shared tail for both judge paths: session id + ``claude -p`` + transcript copy."""
    settings_path, add_dir, permission_mode = (
        scope.settings_path, scope.add_dir, scope.permission_mode
    )
    session_id = str(uuid.uuid4())
    _log(f"step={label} session_id={session_id}")
    try:
        return _run_claude(
            prompt_path, user, model=model, session_id=session_id, effort=effort,
            settings_path=settings_path, add_dir=add_dir, permission_mode=permission_mode,
        )
    finally:
        _copy_transcript(session_id, learning_run_dir / trace_name)


@dataclass(frozen=True)
class JudgeInvocation:
    """The assembled grounded-judge call (either direction) — a pure-ish seam for testing."""

    user_text: str
    add_dirs: list
    settings_path: Path
    comparison_paths: list


def _ticket_cli_path() -> Path:
    """The read-only ticket adapter path — the single source is ``ticket_seeds._TICKET_CLI``."""
    return ticket_seeds._TICKET_CLI


def _cited_policy_read_section(
    run_dir: Path, learning_run_dir: Path, py: str, ticket_cli: Path
) -> str:
    """The benign judge's scoped closed-ticket read instructions (issue #338): the
    exact closed-only commands, the in-flight key it must never read, and the seed menu
    of candidate closed cases the actor was offered (its citations should be among them).
    Best-effort: a thin alert / absent menu degrades the hint, never the section."""
    inflight_key = learning_run_dir.name
    try:
        alert = json.loads(RunPaths(run_dir).alert.read_text())
        sig_label = case_ticket.signature_label(alert) or "<sig:RULE_ID>"
    except Exception:  # noqa: BLE001 — the label is a convenience hint only
        sig_label = "<sig:RULE_ID>"
    menu_path = learning_run_dir / "past_tickets.txt"
    seed_menu = menu_path.read_text().strip() if menu_path.is_file() else ""
    body = (
        "Confirm a CITED past case against the case-history store with a scoped, "
        "CLOSED-ONLY read — closed cases only, never the in-flight ticket. Use exactly:\n"
        f"  {py} {ticket_cli} list-tickets --status closed --require-closed --label {sig_label} --raw\n"
        f"  {py} {ticket_cli} get-ticket <case-id> --require-closed --raw\n"
        f"The in-flight ticket for the alert you are scoring is `{inflight_key}` — never "
        "read it (it is open; --require-closed refuses it on both commands). A cited seed "
        "the store can't "
        "confirm, or whose grounded conditions these actuals contradict, does not survive "
        "on that basis."
    )
    if seed_menu:
        body += (
            "\n\nCandidate closed cases the actor was offered as covering-policy seeds "
            "(its citations should be among these):\n" + seed_menu
        )
    return _section(
        "cited_policy_read", body,
        "scoped closed-ticket read — confirm a cited closed case's policy here",
    )


def build_judge_invocation(
    run_dir: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
    *,
    comparison_dirname: str = "comparison",
    settings_name: str = "judge-settings.resolved.json",
    closed_ticket_read: bool = False,
) -> JudgeInvocation:
    """Assemble the grounded judge call: write the per-lead comparison files + the per-run
    read-only settings, and build the context message. The comparison join + synthesis are
    the structural grounding (the judge can't avoid seeing the actuals); jq over the
    add-dir'd ``gather_raw/`` is its discretionary verification surface for absence-checks.

    ``comparison_dirname`` / ``settings_name`` are per-direction so the adversarial and
    benign legs — which run **concurrently** on an ``inconclusive`` case over a shared
    ``learning_run_dir`` — write disjoint files: their projections differ, so a single
    shared ``comparison/{lead_id}.md`` would let one leg clobber the other's grounding.

    ``closed_ticket_read`` (benign only, #338) grants the scoped closed-only case-history
    read and injects the policy-confirm instructions, so the judge can confirm a cited
    closed case exists + its grounded conditions hold before letting it carry a survive.
    """
    run_dir = Path(run_dir)
    learning_run_dir = Path(learning_run_dir)
    gather_raw = RunPaths(run_dir).gather_raw
    comparison_dir = learning_run_dir / comparison_dirname

    companion = parse_investigation_companion(run_dir)
    comparisons = build_comparison(run_dir, projected_telemetry_path, companion=companion)
    comparison_paths = write_comparison_files(comparisons, comparison_dir, gather_raw)

    py, ticket_cli = sys.executable, _ticket_cli_path()
    settings_path = learning_run_dir / settings_name
    settings_path.write_text(
        json.dumps(
            judge_settings_dict(
                gather_raw, comparison_dir,
                closed_ticket_read=(py, ticket_cli) if closed_ticket_read else None,
            ),
            indent=2,
        )
    )
    add_dirs = [d for d in (gather_raw, comparison_dir) if d.is_dir()]

    report = RunPaths(run_dir).report
    user = (
        _section("alert", RunPaths(run_dir).alert.read_text())
        + _section(
            "report", report.read_text() if report.is_file() else "(report.md missing)",
            "the defender's disposition + rationale — the claim you are scoring",
        )
        + _section("actor_story", actor_story_path.read_text())
        + _section(
            "synthesis", render_synthesis(companion),
            "the defender's cross-lead hypotheses, belief movement, authorization "
            "reasoning, and conclusion — WHY it reached the disposition",
        )
        + _section(
            "coverage_manifest", lead_repository.render_joined_yaml(run_dir),
            "the authoritative record of what was queried per lead (id, params, "
            "status) — ground truth for coverage",
        )
        + _section(
            "comparison_files", render_manifest(comparisons),
            f"per-lead projection-vs-actual files under {comparison_dir} — read each at "
            f"its turn; query the full payloads under {gather_raw} with jq to check "
            "absence (the refute primitive), never inferring it from the sample",
        )
    )
    if closed_ticket_read:
        user += _cited_policy_read_section(run_dir, learning_run_dir, py, ticket_cli)
    return JudgeInvocation(
        user_text=user, add_dirs=add_dirs, settings_path=settings_path,
        comparison_paths=comparison_paths,
    )


def invoke_judge(wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
                 projected_telemetry_path: Path, learning_run_dir: Path,
                 *, judge_fn: Callable[..., str] = _run_judge_claude) -> str:
    """Grounded judge for either direction: write the per-lead comparison files +
    read-only settings (under the wiring's per-direction names), then score against the
    actual evidence (per-lead comparison files + jq over ``gather_raw/``), not the
    narrative. The direction rides in ``wiring`` (adversarial vs benign prompt/model/
    effort + disjoint comparison/settings names + the benign-only closed-ticket read);
    for the benign leg, a routine story that SURVIVES is the FP signal."""
    inv = build_judge_invocation(
        run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        comparison_dirname=wiring.comparison_dirname, settings_name=wiring.settings_name,
        closed_ticket_read=wiring.closed_ticket_read,
    )
    return judge_fn(
        wiring.prompt_path, wiring.model, wiring.effort, wiring.trace_name, wiring.label,
        inv.user_text, learning_run_dir,
        scope=_ToolScope(settings_path=inv.settings_path, add_dir=inv.add_dirs),
    )
