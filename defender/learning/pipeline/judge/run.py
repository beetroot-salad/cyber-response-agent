from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4
from dataclasses import dataclass
from pathlib import Path

from defender._untrusted import wrap
from defender.learning import lead_repository
from defender._run_paths import RunPaths
from defender.learning.core.config import JudgeWiring
from defender.learning.pipeline._prompt import stage_user_message
from defender.learning.pipeline.judge.compare import (
    build_comparison,
    parse_investigation_companion,
    render_manifest,
    render_synthesis,
    write_comparison_files,
)


@dataclass(frozen=True)
class _ToolScope:

    add_dir: Path | list[Path] | None = None
    closed_ticket_read: bool = False


@dataclass(frozen=True)
class JudgeInvocation:

    user_text: str
    add_dirs: list
    comparison_paths: list


def _cited_policy_read_body(learning_run_dir: Path) -> str:
    menu_path = learning_run_dir / "past_tickets.txt"
    return menu_path.read_bytes().decode("utf-8") if menu_path.is_file() else ""


def build_judge_invocation(
    run_dir: Path,
    actor_story_path: Path,
    projected_telemetry_path: Path,
    learning_run_dir: Path,
    *,
    comparison_dirname: str = "comparison",
    closed_ticket_read: bool = False,
    salt: str | None = None,
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
    stage_salt = salt if salt is not None else uuid4().hex
    sections = [
        wrap(RunPaths(run_dir).alert.read_text(encoding="utf-8"), "alert", stage_salt),
        wrap(
            report.read_text(encoding="utf-8")
            if report.is_file()
            else "(report.md missing)",
            "report",
            stage_salt,
        ),
        wrap(actor_story_path.read_text(encoding="utf-8"), "actor_story", stage_salt),
        wrap(render_synthesis(companion), "synthesis", stage_salt),
        wrap(
            lead_repository.render_joined_yaml(run_dir), "coverage_manifest", stage_salt
        ),
        wrap(render_manifest(comparisons), "comparison_files", stage_salt),
    ]
    if closed_ticket_read:
        sections.append(
            wrap(
                _cited_policy_read_body(learning_run_dir),
                "cited_policy_read",
                stage_salt,
            )
        )
    user = stage_user_message(stage_salt, *sections)
    return JudgeInvocation(
        user_text=user, add_dirs=add_dirs, comparison_paths=comparison_paths,
    )


def invoke_judge(wiring: JudgeWiring, run_dir: Path, actor_story_path: Path,
                 projected_telemetry_path: Path, learning_run_dir: Path,
                 *, judge_fn: Callable[..., str], salt: str | None = None) -> str:
    stage_salt = salt if salt is not None else uuid4().hex
    inv = build_judge_invocation(
        run_dir, actor_story_path, projected_telemetry_path, learning_run_dir,
        comparison_dirname=wiring.comparison_dirname,
        closed_ticket_read=wiring.closed_ticket_read,
        salt=stage_salt,
    )
    return judge_fn(
        wiring.prompt_path, wiring.model, wiring.effort, wiring.trace_name, wiring.label,
        inv.user_text, learning_run_dir,
        scope=_ToolScope(
            add_dir=inv.add_dirs, closed_ticket_read=wiring.closed_ticket_read,
        ),
        salt=stage_salt,
    )
