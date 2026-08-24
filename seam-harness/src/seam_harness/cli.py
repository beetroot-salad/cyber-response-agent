"""Command-line interface for running and inspecting seam experiments."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from .intake import compile_intake
from .journal import RunJournal, digest
from .models import (
    Demand,
    HarnessSpec,
    IntakeReadiness,
    ModelPolicy,
    SourceEnvelope,
    SourceMaterial,
    TaskFrame,
)
from .orchestrator import (
    SeamHarness,
    ensure_model_credentials,
    ensure_model_names_credentials,
)
from .postmortem import build_postmortem, render_markdown
from .recursive_cli import add_solve_parser, run_solve


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seam-harness",
        description="Instrument speculative decomposition with independent inquiry.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="Run a complete decomposition experiment")
    run.add_argument("spec", type=Path, help="Path to a HarnessSpec JSON file")
    run.add_argument("--runs-dir", type=Path, default=Path("runs"))
    run.add_argument("--model", help="Override the root model string")
    run.add_argument("--leaf-model", help="Override the leaf model string")
    run.add_argument(
        "--allow-unresolved-intake",
        action="store_true",
        help="Dispatch despite exploratory or clarification-needed intake",
    )
    run.add_argument(
        "--test-model",
        action="store_true",
        help="Use Pydantic AI TestModel; checks wiring but produces meaningless content",
    )

    intake = subparsers.add_parser(
        "intake", help="Compile a natural request into a reviewable HarnessSpec"
    )
    intake.add_argument("output", type=Path)
    request_source = intake.add_mutually_exclusive_group(required=True)
    request_source.add_argument("--request", help="Natural-language task request")
    request_source.add_argument(
        "--request-file", type=Path, help="UTF-8 file containing the task request"
    )
    intake.add_argument("--title", dest="title_hint")
    intake.add_argument(
        "--decision",
        action="append",
        default=[],
        help="Explicit user decision; repeat for multiple decisions",
    )
    intake.add_argument(
        "--material",
        action="append",
        type=Path,
        default=[],
        help="UTF-8 source artifact to include; repeat for multiple artifacts",
    )
    intake.add_argument("--intake-model", help="Override the intake model only")
    intake.add_argument(
        "--force", action="store_true", help="Replace an existing intake output"
    )
    intake.add_argument(
        "--test-model",
        action="store_true",
        help="Use Pydantic AI TestModel; output is structurally valid but meaningless",
    )

    inspect = subparsers.add_parser(
        "inspect", help="Verify and summarize a run journal"
    )
    inspect.add_argument("run_directory", type=Path)
    inspect.add_argument(
        "--format", choices=("summary", "json", "markdown"), default="summary"
    )

    postmortem = subparsers.add_parser(
        "postmortem", help="Build a deterministic diagnostic report from a run"
    )
    postmortem.add_argument("run_directory", type=Path)
    postmortem.add_argument(
        "--format", choices=("json", "markdown"), default="markdown"
    )

    init = subparsers.add_parser("init", help="Create a runnable task-spec skeleton")
    init.add_argument("output", type=Path)
    init.add_argument("--title", required=True)
    init.add_argument("--task", required=True)
    init.add_argument("--intent", required=True)
    init.add_argument(
        "--demand",
        action="append",
        required=True,
        help="Whole-task demand; repeat this option for each demand",
    )

    schema = subparsers.add_parser("schema", help="Print the input JSON Schema")
    schema.add_argument("--indent", type=int, default=2)
    add_solve_parser(subparsers)
    return parser


def _load_spec(path: Path) -> HarnessSpec:
    try:
        return HarnessSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"Spec file does not exist: {path}") from exc
    except ValidationError as exc:
        raise SystemExit(f"Invalid harness spec:\n{exc}") from exc


def _read_utf8(path: Path, label: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise SystemExit(f"{label} does not exist: {path}") from exc
    except UnicodeDecodeError as exc:
        raise SystemExit(f"{label} is not UTF-8 text: {path}") from exc


def _source_envelope(args: argparse.Namespace) -> SourceEnvelope:
    raw_request = (
        args.request
        if args.request is not None
        else _read_utf8(args.request_file, "Request file")
    )
    materials = [
        SourceMaterial(
            id=f"material:{index:03d}",
            kind="file",
            label=path.name,
            content=_read_utf8(path, "Source material"),
            locator=str(path.resolve()),
        )
        for index, path in enumerate(args.material, start=1)
    ]
    return SourceEnvelope(
        raw_request=raw_request,
        title_hint=args.title_hint,
        conversation_decisions=args.decision,
        materials=materials,
    )


def _override_policy(spec: HarnessSpec, args: argparse.Namespace) -> HarnessSpec:
    updates = {}
    if args.model:
        updates["root_model"] = args.model
    if args.leaf_model:
        updates["leaf_model"] = args.leaf_model
    if not updates:
        return spec
    return spec.model_copy(update={"policy": spec.policy.model_copy(update=updates)})


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "solve":
        return run_solve(args)
    if args.command == "intake":
        if args.output.exists() and not args.force:
            raise SystemExit(f"Refusing to overwrite existing file: {args.output}")
        source_envelope = _source_envelope(args)
        intake_model = args.intake_model or ModelPolicy().root_model
        ensure_model_names_credentials([intake_model], args.test_model)
        execution = asyncio.run(
            compile_intake(
                source_envelope,
                model=intake_model,
                test_model=args.test_model,
            )
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        content = execution.spec.model_dump_json(indent=2) + "\n"
        if args.force:
            args.output.write_text(content, encoding="utf-8")
        else:
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(content)
        assessment = execution.spec.intake.assessment
        print(
            json.dumps(
                {
                    "output": str(args.output.resolve()),
                    "readiness": assessment.readiness,
                    "clarification_questions": [
                        question.model_dump(mode="json")
                        for question in assessment.clarification_questions
                    ],
                    "assumptions": assessment.assumptions,
                    "unresolved": assessment.unresolved,
                    "model": execution.model,
                    "usage": execution.usage,
                },
                indent=2,
                sort_keys=True,
                default=str,
            )
        )
        return 0
    if args.command == "init":
        if args.output.exists():
            raise SystemExit(f"Refusing to overwrite existing file: {args.output}")
        spec = HarnessSpec(
            frame=TaskFrame(
                title=args.title,
                task=args.task,
                product_intent=args.intent,
                demands=[
                    Demand(id=f"D{index}", statement=statement)
                    for index, statement in enumerate(args.demand, start=1)
                ],
            )
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(spec.model_dump_json(indent=2) + "\n")
        print(args.output.resolve())
        return 0
    if args.command == "schema":
        print(
            json.dumps(
                HarnessSpec.model_json_schema(), indent=args.indent, sort_keys=True
            )
        )
        return 0
    if args.command == "inspect":
        journal = RunJournal.open(args.run_directory)
        if args.format == "summary":
            output = journal.summary()
            print(json.dumps(output, indent=2, sort_keys=True))
        else:
            output = build_postmortem(journal)
            print(
                render_markdown(output)
                if args.format == "markdown"
                else json.dumps(output, indent=2, sort_keys=True)
            )
        return 0 if journal.summary()["chain_valid"] else 1
    if args.command == "postmortem":
        journal = RunJournal.open(args.run_directory)
        output = build_postmortem(journal)
        print(
            render_markdown(output)
            if args.format == "markdown"
            else json.dumps(output, indent=2, sort_keys=True)
        )
        return 0 if output["integrity"]["chain_valid"] else 1

    spec = _override_policy(_load_spec(args.spec), args)
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
        spec.intake is not None
        and spec.intake.assessment.readiness != IntakeReadiness.READY
        and not args.allow_unresolved_intake
    ):
        readiness = spec.intake.assessment.readiness.value
        raise SystemExit(
            f"Intake is {readiness}; resolve its clarification questions or pass "
            "--allow-unresolved-intake explicitly."
        )
    ensure_model_credentials(spec, args.test_model)
    harness = SeamHarness(spec, runs_dir=args.runs_dir, test_model=args.test_model)
    result = asyncio.run(harness.run())
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "run_directory": result.run_directory,
                "action": result.adjudication.action,
                "decision": result.adjudication.decision,
                "usage_by_role": result.usage_by_role,
            },
            indent=2,
            sort_keys=True,
            default=str,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
