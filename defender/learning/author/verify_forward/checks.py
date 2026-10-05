from __future__ import annotations

from collections.abc import Callable
from defender._model import complete, model
from pathlib import Path

from uuid import uuid4
from defender._run_paths import WIRE_LOG_NAMES
from defender._untrusted import wrap
from defender.learning.author.verify_forward import forward
from defender.learning.author.verify_forward.shared import (
    parse_verdict,
    reasoning_text,
)
from defender.learning.core import config
from defender.learning.core.config import FatalConfigError
from defender.learning._prompt import stage_user_message


@model(frozen=True)
class CheckContext:

    check: ForwardCheck
    lesson_path: Path
    lesson_text: str
    source_id: str
    direction: str
    runs_dir: Path
    corpus_dir: Path
    repo_root: Path
    check_index: int
    run_verify: Callable[..., str]


@model(frozen=True)
class ForwardCheck:

    error_prefix: str
    prompt_path: Path | None
    #: `(verdict, reasoning)` — GOOD or BAD. EXEMPT is decided by the drain via
    #: `cfg.exempt(row)`, never by the check.
    run: Callable[[CheckContext], tuple[str, str]]


# The two records reference each other, so `CheckContext` is completed here once rather than
# lazily by the first constructor, which runs inside `_Judgement.mint`'s worker pool.
complete(CheckContext)


def _verify(ctx: CheckContext, user: str, source_run_dir: Path, *, salt: str) -> tuple[str, str]:
    stem = ctx.lesson_path.stem
    prefix = ctx.check.error_prefix
    # The model-backed lane needs a prompt; a mechanical check (`prompt_path=None`) never
    # reaches here. Checked rather than asserted (`python -O`), and `FatalConfigError` so the
    # drain's per-pair retry propagates it instead of degrading it to BAD.
    prompt_path = ctx.check.prompt_path
    if prompt_path is None:
        raise FatalConfigError(
            f"{prefix}: this forward-check carries no verifier prompt, so it cannot run the "
            "model-backed verify lane"
        )
    raw = ctx.run_verify(
        config.StageWiring(
            prompt_path=prompt_path,
            model=config.verifier_model(),
            effort=config.verifier_effort(),
            trace_name=WIRE_LOG_NAMES.forward_check(prefix, stem, ctx.check_index),
            label=f"{prefix}:{stem}",
        ),
        user=user,
        source_run_dir=source_run_dir,
        defender_dir=ctx.repo_root / "defender",
        wall_clock_timeout=config.verifier_timeout(),
        salt=salt,
    )
    return parse_verdict(raw, error_prefix=prefix), reasoning_text(raw)


def _run_findings(ctx: CheckContext, *, salt: str | None = None) -> tuple[str, str]:
    stage_salt = salt if salt is not None else uuid4().hex
    transcript, recorded = forward.load_run_context(ctx.source_id, runs_dir=ctx.runs_dir)
    disposition = forward.expected_disposition(ctx.direction, recorded)
    user = stage_user_message(
        stage_salt,
        wrap(transcript, "case_transcript", stage_salt),
        wrap(ctx.lesson_text, "candidate_lesson", stage_salt),
        wrap(disposition, "case_ground_truth_disposition", stage_salt),
    )
    return _verify(ctx, user, ctx.runs_dir / ctx.source_id, salt=stage_salt)






def skips_forward_check(row: dict) -> bool:
    """A `direction: family` row is exempt from the forward check.

    Its ground truth is on the family record, and its `run_id` is an episode id, not a run
    under the runs dir the check reads. Wired as the lessons channel's
    `CorpusAuthorConfig.exempt`, so the drain mints EXEMPT before any verifier call; also
    read by `lessons.run._gate_findings` to route family rows past the disposition gate."""
    return row.get("direction") == "family"


FINDINGS_CHECK = ForwardCheck(
    error_prefix="verify_forward",
    prompt_path=forward.PROMPT_PATH,
    run=_run_findings,
)


