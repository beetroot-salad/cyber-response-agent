"""The curators' forward checks, as data (#558).

One ``ForwardCheck`` per distinct check — findings (A), actor tradecraft (B), and the
deterministic environment retrieval (C/D share it). The curator's orchestrator binds ONE
onto ``CuratorDeps.check`` at spawn, so the ``forward_check`` tool never takes a script or
program operand: *which* check runs is not something the model can say. That is the
subtraction — the bash lane pinned a program token but could not constrain the operands the
pinned program then executed (#565), because a regex over argv structurally cannot.

Each check is a pure ``run(ctx)`` over a ``CheckContext``: every root it reads (the run
bundle, the pending queue, the corpus) arrives on the context, never from a module-level
``DEFAULT_PATHS`` constant frozen at import. In-process that distinction is load-bearing —
the curator's modules are imported from the main checkout but it edits a throwaway worktree,
so a module-const corpus would forward-check the wrong lesson.

The two model-backed checks call ``ctx.run_verify`` (the transport carried on the deps — the
only injection seam a pydantic-ai tool, handed just ``(ctx, args)``, admits) and parse a
GOOD/BAD verdict out of the raw text. The environment check runs no model at all: it re-runs
the real retrieval and asks whether the lesson comes back, so it writes no trace and spends
no metered request.
"""
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
    """Everything one check needs, resolved from the curator's deps and its own pair.

    ``lesson_path`` is already gated (resolved, denylist-screened, confined to this spawn's
    own corpus) and ``lesson_text`` already read, so a check never re-decides policy.
    ``check_index`` is the per-check counter that keys the trace file: in-process
    ``os.getpid()`` is constant across a batch, so the pre-port trace name collided for two
    checks of the same lesson stem in one bundle (the same lesson in both directions) and
    ``RequestLogger``'s truncate-mode open silently clobbered one of them.
    """

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
    """One curator's forward check. ``prompt_path`` is ``None`` for a deterministic check
    (no model, no trace). ``error_prefix`` names the check in verdict-parse errors and in
    the trace filename, and is the identity the curators differ by."""

    error_prefix: str
    prompt_path: Path | None
    run: Callable[[CheckContext], str]


def _verify(ctx: CheckContext, user: str, source_run_dir: Path) -> str:
    """Send one model-backed check through the transport on the deps and parse its verdict.

    The metered key is NOT sourced here: the curator spawn sourced it once, and a per-check
    sourcing would re-read ``.env`` N times for one batch. The nested run carries its own
    ``UsageLimits``, so verify requests never eat the curator's own request cap.
    """
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
        wall_clock_timeout=config.VERIFIER_TIMEOUT,
    )
    return parse_verdict(raw, error_prefix=prefix)


def _run_findings(ctx: CheckContext) -> str:
    """Curator A: with this lesson loaded at PLAN time, would the agent still reach the
    case's ground-truth disposition? The target is direction-aware — a benign (FP) lesson
    must drive the agent OFF the recorded malicious call, so its target is ``benign``."""
    transcript, recorded = forward.load_run_context(ctx.source_id, runs_dir=ctx.runs_dir)
    disposition = forward.expected_disposition(ctx.direction, recorded)
    # A benign lesson routes to a cited covering policy; load it so the verifier can
    # reproduce the close using that policy. Adversarial lessons cite none.
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
    """Curator B: does this lesson teach against the failure the judge observed on the
    actor story it was authored from?"""
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
    """Curators C/D: a deterministic retrieval check, not an LLM judgment. Re-run the
    environment retrieval with the inputs the runtime actor uses — the source case's
    canonical rule key and its re-extracted prologue entities — and confirm the lesson comes
    back. Keying off the real prologue (not the keys the curator wrote) is what stops a
    mis-keyed selector from self-confirming."""
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

# Curators C (env-benign) and D (env-adversarial) share one corpus and one check; they
# differ only in which pending queue their deps name.
ENV_CHECK = ForwardCheck(
    error_prefix="verify_forward_env",
    prompt_path=None,
    run=_run_env,
)
