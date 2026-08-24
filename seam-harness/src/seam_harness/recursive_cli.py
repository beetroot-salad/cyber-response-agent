"""CLI integration kept separate from the legacy experiment command."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .adaptive import AdaptiveHarness
from .journal import digest
from .models import HarnessSpec, IntakeReadiness
from .recursive import RecursiveHarness, ensure_recursive_credentials
from .replay import load_replay_bundle
from .recursive_models import RecursivePolicy


def add_solve_parser(subparsers: Any) -> None:
    solve = subparsers.add_parser(
        "solve",
        help="Adaptively investigate and synthesize, or run the fixed recursive comparator",
    )
    solve.add_argument("spec", type=Path, help="Path to a HarnessSpec JSON file")
    solve.add_argument(
        "--execution",
        choices=("adaptive", "recursive"),
        default="adaptive",
        help="Adaptive posterior control (default) or the fixed recursive comparator",
    )
    solve.add_argument("--runs-dir", type=Path, default=Path("runs"))
    solve.add_argument(
        "--workspace",
        type=Path,
        help="Optional read-only source tree exposed through content-addressed dossiers",
    )
    solve.add_argument("--output", type=Path, help="Write the final artifact as text")
    solve.add_argument(
        "--replay-run",
        type=Path,
        help="Reuse a verified root plan and completed evidence packets",
    )
    solve.add_argument(
        "--resume-run",
        type=Path,
        help="Import committed adaptive evidence and choose a fresh posterior action",
    )
    solve.add_argument("--model", help="Override the recursive planner model")
    solve.add_argument("--research-model", help="Override the frontier research model")
    solve.add_argument("--synthesis-model", help="Override parent synthesis models")
    solve.add_argument("--final-model", help="Override the finalizer model")
    for tier in ("root", "research", "synthesis", "final"):
        solve.add_argument(
            f"--{tier}-thinking",
            choices=("off", "minimal", "low", "medium", "high", "xhigh"),
            help=f"Override {tier} reasoning effort; off disables model thinking",
        )
    solve.add_argument("--max-depth", type=int)
    solve.add_argument("--max-nodes", type=int)
    solve.add_argument("--max-children", type=int)
    solve.add_argument("--max-concurrency", type=int)
    solve.add_argument("--max-adaptive-steps", type=int)
    solve.add_argument("--max-adaptive-wave", type=int)
    solve.add_argument("--adaptive-request-limit", type=int)
    solve.add_argument("--request-timeout-seconds", type=int)
    solve.add_argument(
        "--no-stream-responses", dest="stream_responses", action="store_false", default=None
    )
    solve.add_argument("--max-experiment-seconds", type=int)
    solve.add_argument(
        "--enable-experiment-adapter",
        action="append",
        dest="enabled_experiment_adapters",
        help="Enable an experiment adapter; repeat for multiple adapters",
    )
    solve.add_argument("--planner-max-tokens", type=int)
    solve.add_argument("--research-max-tokens", type=int)
    solve.add_argument("--synthesis-max-tokens", type=int)
    solve.add_argument("--final-max-tokens", type=int)
    solve.add_argument(
        "--transcript-token-budget",
        type=int,
        help="Prune a participant's message history once its estimated size exceeds this",
    )
    solve.add_argument(
        "--transcript-keep-recent-turns",
        type=int,
        help="Number of a node's most recent turns pruning never touches",
    )
    solve.add_argument(
        "--no-push-wave-results",
        action="store_false",
        dest="push_wave_results",
        default=True,
        help="Do not inject a completed delegate/verify wave's results into the next turn",
    )
    solve.add_argument(
        "--require-root-expansion",
        action="store_true",
        help="Force one root research fanout for controlled decomposition experiments",
    )
    solve.add_argument(
        "--allow-unresolved-intake",
        action="store_true",
        help="Solve despite exploratory or clarification-needed intake",
    )
    solve.add_argument(
        "--test-model",
        action="store_true",
        help="Use Pydantic AI TestModel; checks wiring but produces meaningless content",
    )


def run_solve(args: argparse.Namespace) -> int:
    spec = _load_spec(args.spec)
    _validate_dispatchable(spec, args.allow_unresolved_intake)
    policy = _policy(spec, args)
    ensure_recursive_credentials(policy, args.test_model)
    if args.output is not None and args.output.exists():
        raise SystemExit(f"Refusing to overwrite existing file: {args.output}")

    if args.execution == "adaptive":
        if args.replay_run is not None:
            raise SystemExit("Replay is currently available only for recursive mode.")
        harness = AdaptiveHarness(
            spec,
            runs_dir=args.runs_dir,
            policy=policy,
            workspace_root=args.workspace,
            test_model=args.test_model,
            resume_run=args.resume_run,
        )
    else:
        if args.resume_run is not None:
            raise SystemExit("Checkpoint resume is available only for adaptive mode.")
        replay = (
            load_replay_bundle(args.replay_run, spec)
            if args.replay_run is not None
            else None
        )
        harness = RecursiveHarness(
            spec,
            runs_dir=args.runs_dir,
            policy=policy,
            workspace_root=args.workspace,
            test_model=args.test_model,
            replay_root_plan=replay.root_plan if replay else None,
            replay_plans=replay.plans if replay else None,
            replay_packets=replay.packets if replay else None,
            replay_traces=replay.traces if replay else None,
            replay_source=replay.source_run if replay else None,
        )
    result = asyncio.run(harness.run())
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(result.final_artifact.content.rstrip() + "\n")
    summary = {
        "run_id": result.run_id,
        "run_directory": result.run_directory,
        "execution": args.execution,
        "output": str(args.output.resolve()) if args.output else None,
        "root_sufficiency": (
            None if args.execution == "adaptive" else result.root_packet.sufficiency
        ),
        "knowledge_board": {
            "questions": len(result.knowledge_board.questions_by_id),
            "answers": len(result.knowledge_board.answers_by_id),
            "links": len(result.knowledge_board.links_by_id),
            "digest": result.knowledge_board.content_sha256,
        },
        "usage_by_role": result.usage_by_role,
    }
    if args.execution == "adaptive":
        summary.update(
            {
                "work_item_count": result.work_item_count,
                "action_count": len(result.actions),
                "selected_answer_ids": result.selected_answer_ids,
                "root_answer_id": result.root_answer_id,
                "deepest_participant_level": result.deepest_participant_level,
            }
        )
    else:
        summary.update(
            {
                "node_count": result.node_count,
                "deepest_level": result.deepest_level,
            }
        )
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0


def _load_spec(path: Path) -> HarnessSpec:
    try:
        return HarnessSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Spec file does not exist: {path}") from exc
    except ValidationError as exc:
        raise SystemExit(f"Invalid harness spec:\n{exc}") from exc


def _validate_dispatchable(spec: HarnessSpec, allow_unresolved: bool) -> None:
    if spec.intake is not None:
        if spec.source_envelope is None:
            raise SystemExit("Intake provenance is missing its source envelope.")
        if digest(spec.source_envelope) != spec.intake.source_sha256:
            raise SystemExit(
                "Intake source changed; compile intake again before dispatch."
            )
        if digest(spec.frame) != spec.intake.frame_sha256:
            raise SystemExit(
                "Compiled frame changed; compile intake again before dispatch."
            )
        if (
            spec.intake.assessment.readiness != IntakeReadiness.READY
            and not allow_unresolved
        ):
            readiness = spec.intake.assessment.readiness.value
            raise SystemExit(
                f"Intake is {readiness}; resolve its clarification questions or pass "
                "--allow-unresolved-intake explicitly."
            )


def _thinking(value: str | None) -> str | bool | None:
    return False if value == "off" else value


def _policy(spec: HarnessSpec, args: argparse.Namespace) -> RecursivePolicy:
    defaults = RecursivePolicy(
        root_model=spec.policy.root_model,
        synthesis_model=spec.policy.root_model,
        final_model=spec.policy.root_model,
    )
    updates = {
        field: value
        for field, value in {
            "root_model": args.model,
            "research_model": args.research_model,
            "synthesis_model": args.synthesis_model,
            "final_model": args.final_model,
            "root_thinking": _thinking(args.root_thinking),
            "research_thinking": _thinking(args.research_thinking),
            "synthesis_thinking": _thinking(args.synthesis_thinking),
            "final_thinking": _thinking(args.final_thinking),
            "max_depth": args.max_depth,
            "max_nodes": args.max_nodes,
            "max_children": args.max_children,
            "max_concurrency": args.max_concurrency,
            "max_adaptive_steps": args.max_adaptive_steps,
            "max_adaptive_wave": args.max_adaptive_wave,
            "adaptive_request_limit_per_call": args.adaptive_request_limit,
            "request_timeout_seconds": args.request_timeout_seconds,
            "stream_responses": args.stream_responses,
            "max_experiment_seconds": args.max_experiment_seconds,
            "enabled_experiment_adapters": (
                list(
                    dict.fromkeys(
                        [
                            *defaults.enabled_experiment_adapters,
                            *(args.enabled_experiment_adapters or []),
                        ]
                    )
                )
                if args.enabled_experiment_adapters is not None
                else None
            ),
            "planner_max_tokens": args.planner_max_tokens,
            "research_max_tokens": args.research_max_tokens,
            "synthesis_max_tokens": args.synthesis_max_tokens,
            "final_max_tokens": args.final_max_tokens,
            "transcript_token_budget": args.transcript_token_budget,
            "transcript_keep_recent_turns": args.transcript_keep_recent_turns,
            "push_wave_results": args.push_wave_results,
            "require_root_expansion": args.require_root_expansion,
        }.items()
        if value is not None
    }
    return RecursivePolicy.model_validate(
        {**defaults.model_dump(mode="python"), **updates}
    )
