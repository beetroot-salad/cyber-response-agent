"""Judge stage — grounded outcome classifier for both directions.

One driver, parametrized by ``JudgeWiring`` (the adversarial vs benign prompt/model/
effort + disjoint comparison dirname + the benign-only closed-ticket read), so
the per-direction variation is pure config — there is no separate benign driver. The
comparison join + synthesis (the structural grounding) live in ``compare.py``; the two
prompts are ``malicious.md`` / ``benign.md`` in this package.
"""
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
    """The tool-surface scoping forwarded to a ``judge_fn`` — the read add-dir(s) and the
    benign-only ``closed_ticket_read`` bit that turns on the judge's two closed-ticket tools
    (#672; False on the adversarial leg — absence by registration)."""

    add_dir: Path | list[Path] | None = None
    closed_ticket_read: bool = False


@dataclass(frozen=True)
class JudgeInvocation:
    """The assembled grounded-judge call (either direction) — a pure-ish seam for testing."""

    user_text: str
    add_dirs: list
    comparison_paths: list


def _cited_policy_read_section(run_dir: Path, learning_run_dir: Path) -> str:
    """The benign judge's closed-ticket read instructions (#672, superseding #338's bash
    commands): the TWO typed tools by their frozen names, the in-flight key it must never read
    (excluded structurally now, so the teaching no longer asserts the ticket's state), the Fork D
    rule that a cached payload is context and only the live read confirms, and the seed menu of
    candidate closed cases the actor was offered (its citations should be among them).
    Best-effort: a thin alert / absent menu degrades the hint, never the section."""
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
    """Assemble the grounded judge call: write the per-lead comparison files and build the
    context message. The comparison join + synthesis are the structural grounding (the
    judge can't avoid seeing the actuals); SQL over the add-dir'd ``gather_raw/`` is its
    discretionary verification surface for absence-checks.

    ``comparison_dirname`` is per-direction so the adversarial and benign legs — which run
    **concurrently** on an ``inconclusive`` case over a shared ``learning_run_dir`` — write
    disjoint files: their projections differ, so a single shared ``comparison/{lead_id}.md``
    would let one leg clobber the other's grounding.

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
    """Grounded judge for either direction: write the per-lead comparison files, then score
    against the actual evidence (per-lead comparison files + SQL over ``gather_raw/``), not
    the narrative. The direction rides in ``wiring`` (adversarial vs benign prompt/model/
    effort + disjoint comparison dirname + the benign-only closed-ticket read); for the
    benign leg, a routine story that SURVIVES is the FP signal. ``judge_fn`` is the engine
    (``_run_judge_pydantic`` in production; a fake in tests) — the composition root picks
    it, so this stays engine-agnostic."""
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
