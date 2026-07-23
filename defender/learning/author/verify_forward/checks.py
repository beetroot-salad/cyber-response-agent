from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender._run_paths import resolve_run_bundle
from defender.learning.author.verify_forward import actor, env, forward
from defender.learning.author.verify_forward.shared import (
    data_section,
    load_observation,
    parse_verdict,
)
from defender.learning.core import config


@dataclass(frozen=True)
class CheckContext:

    check: ForwardCheck
    lesson_path: Path
    lesson_text: str
    source_id: str
    direction: str
    runs_dir: Path
    pending: Path
    corpus_dir: Path
    repo_root: Path
    check_index: int
    run_verify: Callable[..., str]


@dataclass(frozen=True)
class ForwardCheck:

    error_prefix: str
    prompt_path: Path | None
    run: Callable[[CheckContext], str]


def _verify(ctx: CheckContext, user: str, source_run_dir: Path) -> str:
    stem = ctx.lesson_path.stem
    prefix = ctx.check.error_prefix
    raw = ctx.run_verify(
        prompt_path=ctx.check.prompt_path,
        model=config.VERIFIER_MODEL,
        effort=config.VERIFIER_EFFORT,
        trace_name=f"{prefix}.{stem}.{ctx.check_index}.trace.jsonl",
        label=f"{prefix}:{stem}",
        user=user,
        source_run_dir=source_run_dir,
        defender_dir=ctx.repo_root / "defender",
        wall_clock_timeout=config.VERIFIER_TIMEOUT,
    )
    return parse_verdict(raw, error_prefix=prefix)


def _run_findings(ctx: CheckContext) -> str:
    transcript, recorded = forward.load_run_context(ctx.source_id, runs_dir=ctx.runs_dir)
    disposition = forward.expected_disposition(ctx.direction, recorded)
    cited_policy = (
        forward.load_cited_policy(ctx.source_id, runs_dir=ctx.runs_dir)
        if ctx.direction == "benign"
        else forward._NO_CITED_POLICY
    )
    user = "\n\n".join((
        data_section("CASE TRANSCRIPT (the original investigation, including its actual evidence and disposition)", transcript),
        data_section("CANDIDATE LESSON", ctx.lesson_text),
        data_section("CASE GROUND-TRUTH DISPOSITION", disposition),
        data_section("CITED COVERING POLICY (closed prior cases this lesson's routing may lean on; benign/FP lessons only — adversarial lessons cite none)", cited_policy),
    ))
    return _verify(ctx, user, ctx.runs_dir / ctx.source_id)


def _run_actor(ctx: CheckContext) -> str:
    prefix = ctx.check.error_prefix
    row = load_observation(ctx.source_id, ctx.pending, error_prefix=prefix)
    observation_text = (row.get("observation") or "").strip()
    src = (row.get("source_run_dir") or "").strip()
    if not observation_text or not src:
        raise SystemExit(f"{prefix}: observation row missing observation/source_run_dir: {row!r}")
    bundle = resolve_run_bundle(ctx.runs_dir, src)
    user = "\n\n".join((
        data_section("ACTOR STORY (the original Section 0 + body the judge graded)", actor.load_story(bundle)),
        data_section("JUDGE OBSERVATION (the failure the lesson is trying to teach against)", observation_text),
        data_section("CANDIDATE LESSON", ctx.lesson_text),
    ))
    return _verify(ctx, user, bundle)


def _run_env(ctx: CheckContext) -> str:
    row = load_observation(ctx.source_id, ctx.pending, error_prefix=ctx.check.error_prefix)
    rule_ids = env.rule_ids_arg(row.get("alert_rule_key"))
    entities = env.case_entities_arg(row, ctx.runs_dir)
    returned = env.run_retrieval(rule_ids, entities, ctx.corpus_dir)
    hit = env.lesson_returned(ctx.lesson_path, returned, repo_root=ctx.repo_root)
    return "GOOD" if hit else "BAD"


FINDINGS_CHECK = ForwardCheck(
    error_prefix="verify_forward",
    prompt_path=forward.PROMPT_PATH,
    run=_run_findings,
)

ACTOR_CHECK = ForwardCheck(
    error_prefix="verify_forward_actor",
    prompt_path=actor.PROMPT_PATH,
    run=_run_actor,
)

ENV_CHECK = ForwardCheck(
    error_prefix="verify_forward_env",
    prompt_path=None,
    run=_run_env,
)
