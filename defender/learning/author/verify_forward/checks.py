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
    pending: Path
    corpus_dir: Path
    repo_root: Path
    check_index: int
    run_verify: Callable[..., str]


@model(frozen=True)
class ForwardCheck:

    error_prefix: str
    prompt_path: Path | None
    #: `(verdict, reasoning)` — verdict is GOOD or BAD; EXEMPT is the drain's own, via
    #: `cfg.exempt(row)`, never the check's (M2's own data-model note).
    run: Callable[[CheckContext], tuple[str, str]]


# The two records name each other, so whichever is decorated first cannot see the other:
# `CheckContext.check` is finished here, once, rather than by the first thread to construct
# one — which is inside `_Judgement.mint`'s worker pool.
complete(CheckContext)


def _verify(ctx: CheckContext, user: str, source_run_dir: Path, *, salt: str) -> tuple[str, str]:
    stem = ctx.lesson_path.stem
    prefix = ctx.check.error_prefix
    # `_verify` is the MODEL-BACKED lane, so the check it runs for must carry a prompt.
    # A ForwardCheck may carry `prompt_path=None` — a check whose verdict is mechanical
    # (pure retrieval) — it never reaches here. Checked rather than asserted: `StageWiring`
    # takes a non-optional `Path`, and an assert would be stripped under `python -O`.
    # `FatalConfigError`, not a bare raise: this is a fatal CONFIGURATION fault (O10, "a
    # check with no prompt"), never a per-finding verdict — the drain's per-pair retry
    # handler must let it propagate rather than degrade it to BAD.
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
    # #767 D5: the cited-covering-policy prompt section is deleted along with the
    # resolution-decoding lane it read through — `forward.load_cited_policy` keyed on a
    # cross-run citation menu no non-test code writes (c5), so this section was always the
    # same neutral placeholder in production. Removing it closes the second model-facing read
    # path structurally, rather than leaving a prompt section that never varies.
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
    """J12: a `direction: family` row is exempt from the forward check.

    Its ground truth is `disposition_declared` on the family record, not a `source_refs.yaml`
    it does not have — `forward.expected_disposition`/`load_run_context` resolve a row's
    `run_id` under the RUNS dir, and a family row's `run_id` is an episode id under the
    EPISODES root, a different tree entirely. Wired as the lessons channel's
    `CorpusAuthorConfig.exempt` (#773 M2): the drain consults it per (file, finding) pair
    BEFORE any verifier call and mints EXEMPT, so a family row never reaches `_run_findings`
    at all — the exemption is a ROUTE, and the `direction` literal the check reads stays
    `Literal["adversarial", "benign"]`, unwidened. `lessons.run._gate_findings` reads the
    same predicate to route a family row past the disposition gate."""
    return row.get("direction") == "family"


FINDINGS_CHECK = ForwardCheck(
    error_prefix="verify_forward",
    prompt_path=forward.PROMPT_PATH,
    run=_run_findings,
)


