from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender.learning import lead_repository
from defender._run_paths import RunPaths
from defender.learning.core.config import JudgeWiring
from defender.learning.pipeline._prompt import _section
from defender.learning.pipeline.judge.compare import (
    build_comparison,
    parse_investigation_companion,
    render_manifest,
    render_synthesis,
    write_comparison_files,
)
from defender.scripts.case_history import case_ticket


@dataclass(frozen=True)
class _ToolScope:

    add_dir: Path | list[Path] | None = None
    closed_ticket_read: bool = False


@dataclass(frozen=True)
class JudgeInvocation:

    user_text: str
    add_dirs: list
    comparison_paths: list


def _cited_policy_read_section(run_dir: Path, learning_run_dir: Path) -> str:
    inflight_key = learning_run_dir.name
    try:
        alert = json.loads(RunPaths(run_dir).alert.read_text(encoding="utf-8"))
        sig_label = case_ticket.signature_label(alert) or "<sig:RULE_ID>"
    except Exception:  # noqa: BLE001 — the label is a convenience hint only
        sig_label = "<sig:RULE_ID>"
    menu_path = learning_run_dir / "past_tickets.txt"
    seed_menu = menu_path.read_text(encoding="utf-8").strip() if menu_path.is_file() else ""
    body = (
        "Confirm a CITED past case against the case-history store with the closed-only "
        "typed tools — closed cases only, by construction:\n"
        f"  list_closed_tickets(label=\"{sig_label}\") — find the precedent among closed cases\n"
        "  get_closed_ticket(key=\"<case-id>\") — confirm the one you cite\n"
        f"The in-flight ticket for the alert you are scoring is `{inflight_key}` — never read "
        "it; both tools refuse it (it is the answer key). Cached gather_raw payloads are "
        "context, never confirmation: only the live closed-only read can say 'the store "
        "confirmed it'. A cited seed the store can't confirm, or whose grounded conditions "
        "these actuals contradict, does not survive on that basis."
    )
    if seed_menu:
        body += (
            "\n\nCandidate closed cases the actor was offered as covering-policy seeds "
            "(its citations should be among these):\n" + seed_menu
        )
    return _section(
        "cited_policy_read", body,
        "closed-ticket tools — confirm a cited closed case's policy here",
    )


def build_judge_invocation(
    run_dir: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
    *,
    comparison_dirname: str = "comparison",
    closed_ticket_read: bool = False,
) -> JudgeInvocation:
    run_dir = Path(run_dir)
    learning_run_dir = Path(learning_run_dir)
    gather_raw = RunPaths(run_dir).gather_raw
    comparison_dir = learning_run_dir / comparison_dirname

    companion = parse_investigation_companion(run_dir)
    comparisons = build_comparison(run_dir, projected_telemetry_path, companion=companion)
    comparison_paths = write_comparison_files(comparisons, comparison_dir, gather_raw)

    add_dirs = [d for d in (gather_raw, comparison_dir) if d.is_dir()]

    report = RunPaths(run_dir).report
    user = (
        _section("alert", RunPaths(run_dir).alert.read_text(encoding="utf-8"))
        + _section(
            "report", report.read_text(encoding="utf-8") if report.is_file() else "(report.md missing)",
            "the defender's disposition + rationale — the claim you are scoring",
        )
        + _section("actor_story", actor_story_path.read_text(encoding="utf-8"))
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
            f"its turn; query the full payloads under {gather_raw} by piping one into "
            "defender-sql (`cat <payload> | defender-sql '<SQL>'`, table `data`) to check "
            "absence (the refute primitive), never inferring it from the sample, and "
            "never reading a truncated or empty payload as absence",
        )
    )
    if closed_ticket_read:
        user += _cited_policy_read_section(run_dir, learning_run_dir)
    return JudgeInvocation(
        user_text=user, add_dirs=add_dirs, comparison_paths=comparison_paths,
    )


def invoke_judge(wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
                 projected_telemetry_path: Path, learning_run_dir: Path,
                 *, judge_fn: Callable[..., str]) -> str:
    inv = build_judge_invocation(
        run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        comparison_dirname=wiring.comparison_dirname,
        closed_ticket_read=wiring.closed_ticket_read,
    )
    return judge_fn(
        wiring.prompt_path, wiring.model, wiring.effort, wiring.trace_name, wiring.label,
        inv.user_text, learning_run_dir,
        scope=_ToolScope(
            add_dir=inv.add_dirs, closed_ticket_read=wiring.closed_ticket_read,
        ),
    )
